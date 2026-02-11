#include <efi.h>
#include <csmwrap.h>
#include <bootdev.h>
#include <printf.h>

/*
 * Boot device detection and BBS table building for CSMWrap
 *
 * This module detects which drive CSMWrap was booted from and creates
 * a BBS table that prioritizes that drive for SeaBIOS boot order.
 */

/*
 * Parse device path to extract boot device information
 */
static bool parse_device_path(EFI_DEVICE_PATH_PROTOCOL *device_path,
                              struct boot_device_info *info)
{
    EFI_DEVICE_PATH_PROTOCOL *node;
    bool found_pci = false;

    if (!device_path || !info) {
        return false;
    }

    memset(info, 0, sizeof(*info));
    info->device_type = BBS_HARDDISK;  /* Default to hard disk */

    /* Walk the device path to extract information */
    for (node = device_path; !IsDevicePathEnd(node); node = NextDevicePathNode(node)) {
        uint8_t type = DevicePathType(node);
        uint8_t subtype = DevicePathSubType(node);

        switch (type) {
        case HARDWARE_DEVICE_PATH:
            if (subtype == HW_PCI_DP) {
                PCI_DEVICE_PATH *pci = (PCI_DEVICE_PATH *)node;
                info->bus = 0;  /* Will be updated if we find ACPI path first */
                info->device = pci->Device;
                info->function = pci->Function;
                found_pci = true;
            }
            break;

        case MESSAGING_DEVICE_PATH:
            switch (subtype) {
            case MSG_SATA_DP:
                {
                    SATA_DEVICE_PATH *sata = (SATA_DEVICE_PATH *)node;
                    info->sata_port = sata->HBAPortNumber;
                    info->device_type = BBS_HARDDISK;
                }
                break;
            case MSG_USB_DP:
                info->is_usb = true;
                info->device_type = BBS_USB;
                break;
            case MSG_ATAPI_DP:
                {
                    ATAPI_DEVICE_PATH *atapi = (ATAPI_DEVICE_PATH *)node;
                    /* Check if this is a CD-ROM based on typical ATAPI usage */
                    (void)atapi;  /* May use later for more specific detection */
                }
                break;
            case MSG_SCSI_DP:
                info->device_type = BBS_HARDDISK;
                break;
            }
            break;

        case MEDIA_DEVICE_PATH:
            switch (subtype) {
            case MEDIA_HARDDRIVE_DP:
                info->device_type = BBS_HARDDISK;
                break;
            case MEDIA_CDROM_DP:
                info->device_type = BBS_CDROM;
                break;
            }
            break;
        }
    }

    info->valid = found_pci;
    return found_pci;
}

/*
 * Get PCI bus number by walking up to the PCI I/O protocol
 */
static bool get_pci_location(EFI_HANDLE device_handle, struct boot_device_info *info)
{
    EFI_STATUS status;
    EFI_GUID pci_io_guid = EFI_PCI_IO_PROTOCOL_GUID;
    EFI_GUID device_path_guid = EFI_DEVICE_PATH_PROTOCOL_GUID;
    EFI_DEVICE_PATH_PROTOCOL *device_path;
    EFI_PCI_IO_PROTOCOL *pci_io;
    EFI_HANDLE pci_handle;
    UINTN seg, bus, dev, func;

    /* First get the device path */
    status = gBS->HandleProtocol(device_handle, &device_path_guid,
                                  (void **)&device_path);
    if (EFI_ERROR(status) || !device_path) {
        printf("bootdev: Failed to get device path: %d\n", (int)status);
        return false;
    }

    /* Parse the device path for basic info */
    parse_device_path(device_path, info);

    /* Try to find PCI I/O protocol on this device path */
    status = gBS->LocateDevicePath(&pci_io_guid, &device_path, &pci_handle);
    if (EFI_ERROR(status)) {
        printf("bootdev: No PCI I/O on device path: %d\n", (int)status);
        return info->valid;  /* Return what we got from device path parsing */
    }

    /* Get the PCI I/O protocol */
    status = gBS->HandleProtocol(pci_handle, &pci_io_guid, (void **)&pci_io);
    if (EFI_ERROR(status)) {
        printf("bootdev: Failed to get PCI I/O protocol: %d\n", (int)status);
        return info->valid;
    }

    /* Get the actual PCI location */
    status = pci_io->GetLocation(pci_io, &seg, &bus, &dev, &func);
    if (EFI_ERROR(status)) {
        printf("bootdev: Failed to get PCI location: %d\n", (int)status);
        return info->valid;
    }

    info->bus = (uint8_t)bus;
    info->device = (uint8_t)dev;
    info->function = (uint8_t)func;
    info->valid = true;

    /* Read PCI class code from config space offset 0x0B (class) and 0x0A (subclass) */
    uint8_t class_code[2];
    status = pci_io->Pci.Read(pci_io, EfiPciIoWidthUint8, 0x0A, 2, class_code);
    if (!EFI_ERROR(status)) {
        info->pci_subclass = class_code[0];  /* Offset 0x0A */
        info->pci_class = class_code[1];     /* Offset 0x0B */
    }

    printf("bootdev: PCI location %02x:%02x.%x class=%02x subclass=%02x\n",
           info->bus, info->device, info->function, info->pci_class, info->pci_subclass);

    return true;
}

/*
 * Check if two boot device info structures match (same controller)
 */
static bool devices_match(const struct boot_device_info *a,
                         const struct boot_device_info *b)
{
    if (!a->valid || !b->valid) {
        return false;
    }

    return (a->bus == b->bus &&
            a->device == b->device &&
            a->function == b->function);
}

/*
 * Get device type string for debug output
 */
static const char *device_type_str(uint16_t type)
{
    switch (type) {
    case BBS_FLOPPY:    return "Floppy";
    case BBS_HARDDISK:  return "HDD";
    case BBS_CDROM:     return "CDROM";
    case BBS_PCMCIA:    return "PCMCIA";
    case BBS_USB:       return "USB";
    case BBS_EMBED_NETWORK: return "Network";
    default:            return "Unknown";
    }
}

/*
 * Add a BBS entry for a block device
 *
 * priority: 0 = highest (boot device), 1+ = lower priority
 */
static void add_bbs_entry(struct low_stub *low_stub,
                         const struct boot_device_info *info,
                         int priority)
{
    BBS_TABLE *entry;
    char *desc;
    size_t idx;

    if (low_stub->bbs_entry_count >= MAX_BBS_ENTRIES) {
        printf("bootdev: BBS table full, skipping device\n");
        return;
    }

    idx = low_stub->bbs_entry_count;
    entry = &low_stub->bbs_entries[idx];
    desc = low_stub->bbs_desc_strings[idx];

    memset(entry, 0, sizeof(*entry));

    /* Set boot priority - 0 is highest, higher numbers = lower priority */
    entry->BootPriority = priority;

    /* PCI location */
    entry->Bus = info->bus;
    entry->Device = info->device;
    entry->Function = info->function;

    /* Device type */
    entry->DeviceType = info->device_type;

    /* PCI class codes - use actual values from device */
    entry->Class = info->pci_class;
    entry->SubClass = info->pci_subclass;

    /* Status flags - mark as enabled and media present */
    entry->StatusFlags.Enabled = 1;
    entry->StatusFlags.MediaPresent = 2;  /* Media present and bootable */

    /* Description string - stored in low memory */
    if (priority == 0) {
        snprintf(desc, BBS_DESC_STRING_SIZE, "Boot %s %02x:%02x.%x",
                 device_type_str(info->device_type),
                 info->bus, info->device, info->function);
    } else {
        snprintf(desc, BBS_DESC_STRING_SIZE, "%s %02x:%02x.%x",
                 device_type_str(info->device_type),
                 info->bus, info->device, info->function);
    }

    /* Set description string pointer (segment:offset for real mode) */
    uintptr_t desc_addr = (uintptr_t)desc;
    entry->DescStringSegment = EFI_SEGMENT(desc_addr);
    entry->DescStringOffset = EFI_OFFSET(desc_addr);

    printf("bootdev: BBS[%zu] %s pri=%d\n", idx, desc, entry->BootPriority);

    low_stub->bbs_entry_count++;
}

/*
 * Enumerate block I/O devices and build BBS entries
 */
static int enumerate_block_devices(struct low_stub *low_stub,
                                   const struct boot_device_info *boot_info)
{
    EFI_STATUS status;
    EFI_GUID block_io_guid = EFI_BLOCK_IO_PROTOCOL_GUID;
    EFI_HANDLE *handles = NULL;
    UINTN handle_count = 0;
    int next_priority = 1;  /* Priority 0 reserved for boot device */

    /* Find all block I/O devices */
    status = gBS->LocateHandleBuffer(ByProtocol, &block_io_guid, NULL,
                                     &handle_count, &handles);
    if (EFI_ERROR(status)) {
        printf("bootdev: Failed to locate block devices: %d\n", (int)status);
        return -1;
    }

    printf("bootdev: Found %lu block devices\n", (unsigned long)handle_count);

    for (UINTN i = 0; i < handle_count; i++) {
        EFI_BLOCK_IO_PROTOCOL *block_io;
        struct boot_device_info dev_info;

        status = gBS->HandleProtocol(handles[i], &block_io_guid, (void **)&block_io);
        if (EFI_ERROR(status)) {
            continue;
        }

        /* Skip logical partitions, only want raw devices */
        if (block_io->Media->LogicalPartition) {
            continue;
        }

        /* Get PCI location for this device */
        if (!get_pci_location(handles[i], &dev_info)) {
            continue;
        }

        bool is_boot_device = boot_info->valid && devices_match(&dev_info, boot_info);
        int priority = is_boot_device ? 0 : next_priority++;

        add_bbs_entry(low_stub, &dev_info, priority);
    }

    gBS->FreePool(handles);

    return 0;
}

/*
 * Main entry point: build BBS table for SeaBIOS
 */
int build_bbs_table(struct csmwrap_priv *priv, EFI_HANDLE image_handle)
{
    EFI_STATUS status;
    EFI_GUID loaded_image_guid = EFI_LOADED_IMAGE_PROTOCOL_GUID;
    EFI_LOADED_IMAGE_PROTOCOL *loaded_image = NULL;
    struct boot_device_info boot_info = {0};
    struct low_stub *low_stub = priv->low_stub;

    if (!low_stub) {
        printf("bootdev: low_stub not initialized\n");
        return -1;
    }

    printf("bootdev: Building BBS table...\n");

    /* Get loaded image protocol to find boot device */
    status = gBS->HandleProtocol(image_handle, &loaded_image_guid,
                                  (void **)&loaded_image);
    if (EFI_ERROR(status) || !loaded_image) {
        printf("bootdev: Failed to get loaded image: %d\n", (int)status);
        /* Continue without boot device info - will enumerate all devices */
    } else if (loaded_image->DeviceHandle) {
        /* Get boot device information */
        printf("bootdev: Detecting boot device...\n");
        if (get_pci_location(loaded_image->DeviceHandle, &boot_info)) {
            printf("bootdev: Boot device: PCI %02x:%02x.%x type=%s\n",
                   boot_info.bus, boot_info.device, boot_info.function,
                   device_type_str(boot_info.device_type));
        }
    }

    /* Reset BBS table */
    low_stub->bbs_entry_count = 0;
    memset(low_stub->bbs_entries, 0, sizeof(low_stub->bbs_entries));
    memset(low_stub->bbs_desc_strings, 0, sizeof(low_stub->bbs_desc_strings));

    /* Enumerate all block devices and build BBS entries */
    if (enumerate_block_devices(low_stub, &boot_info) < 0) {
        printf("bootdev: Failed to enumerate block devices\n");
        /* Not fatal - SeaBIOS can still enumerate drives itself */
    }

    /* Set up boot_table to point to our BBS table */
    if (low_stub->bbs_entry_count > 0) {
        low_stub->boot_table.NumberBbsEntries = low_stub->bbs_entry_count;
        low_stub->boot_table.BbsTable = (uintptr_t)low_stub->bbs_entries;
        printf("bootdev: BBS table built with %zu entries\n", low_stub->bbs_entry_count);
    } else {
        printf("bootdev: No BBS entries created\n");
    }

    return 0;
}
