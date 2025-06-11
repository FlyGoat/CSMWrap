#include <csmwrap.h>
#include <io.h>
#include <pci.h>
#include <printf.h>
#include <qsort.h>

#include <uacpi/namespace.h>
#include <uacpi/resources.h>
#include <uacpi/uacpi.h>
#include <uacpi/utilities.h>

typedef uint32_t(*pci_read_t)(struct pci_address *address, uint32_t offset);
typedef void    (*pci_write_t)(struct pci_address *address, uint32_t offset, uint32_t value);

static uint32_t pci_read_pio(struct pci_address *address, uint32_t offset) {
    return pciConfigReadDWord(address->bus, address->slot, address->function, offset);
}

static void pci_write_pio(struct pci_address *address, uint32_t offset, uint32_t value) {
    pciConfigWriteDWord(address->bus, address->slot, address->function, offset, value);
}

// TODO: PCI ECAM

static pci_read_t pci_read = pci_read_pio;
static pci_write_t pci_write = pci_write_pio;

uint32_t pci_read_config_space(struct pci_address *address, uint32_t offset) {
    return pci_read(address, offset & PCI_OFFSET_MASK);
}

void pci_write_config_space(struct pci_address *address, uint32_t offset, uint32_t value) {
    pci_write(address, offset & PCI_OFFSET_MASK, value);
}

#define ROOT_BUSES_MAX 64

static struct pci_bus *root_buses[ROOT_BUSES_MAX];
static size_t root_bus_count = 0;

#define BUS_STRUCT_POOL_COUNT 64

static struct pci_bus *bus_struct_pool = NULL;
static size_t bus_struct_pool_ptr = 0;

static struct pci_bus *allocate_bus(void) {
    if (bus_struct_pool_ptr == BUS_STRUCT_POOL_COUNT) {
        return NULL;
    }
    return &bus_struct_pool[bus_struct_pool_ptr++];
}

#define DEVICE_STRUCT_POOL_COUNT 256

static struct pci_device *device_struct_pool = NULL;
static size_t device_struct_pool_ptr = 0;

static struct pci_device *allocate_device(void) {
    if (device_struct_pool_ptr == DEVICE_STRUCT_POOL_COUNT) {
        return NULL;
    }
    return &device_struct_pool[device_struct_pool_ptr++];
}

#define BAR_STRUCT_POOL_COUNT 512

static struct pci_bar *bar_struct_pool = NULL;
static size_t bar_struct_pool_ptr = 0;

static struct pci_bar *allocate_bar(void) {
    if (bar_struct_pool_ptr == BAR_STRUCT_POOL_COUNT) {
        return NULL;
    }
    return &bar_struct_pool[bar_struct_pool_ptr++];
}

static bool add_root_bus(struct pci_bus *bus) {
    if (root_bus_count == ROOT_BUSES_MAX) {
        return false;
    }

    root_buses[root_bus_count++] = bus;

    return true;
}

static struct pci_range *add_range(struct pci_bus *bus, uint64_t base, uint64_t length, bool prefetchable) {
    // We don't care about ranges >=4G for root buses
    if (bus->root) {
        if (base + length > 0x100000000) {
            if (base >= 0x100000000) {
                return NULL;
            }
            length -= (base + length) - 0x100000000;
        }
    }

    // Low memory ranges are special
    if (base < 0x100000) {
        return NULL;
    }

    if (bus->range_count == PCI_MAX_RANGES_PER_BUS) {
        return NULL;
    }

    bus->ranges[bus->range_count].base = base;
    bus->ranges[bus->range_count].length = length;
    bus->ranges[bus->range_count].prefetchable = prefetchable;

    bus->range_count++;

    return &bus->ranges[bus->range_count - 1];
}

static bool drop_range(struct pci_bus *bus, struct pci_range *range) {
    size_t i = ((uintptr_t)range - (uintptr_t)bus->ranges) / sizeof(struct pci_range);
    memmove(range, &bus->ranges[i + 1], PCI_MAX_RANGES_PER_BUS - i - 1);
    bus->range_count--;
    return true;
}

static bool add_device(struct pci_bus *bus, struct pci_device *device) {
    if (bus->device_count == PCI_MAX_DEVICES_PER_BUS) {
        return false;
    }

    bus->devices[bus->device_count++] = device;

    return true;
}

static bool add_bar(struct pci_bus *bus, struct pci_bar *bar) {
    // Non-bridge BARs >4GB are hopeless
    if (bar->range == NULL && bar->length >= 0x100000000) {
        return true;
    }

    // Likewise for BARs originally below 1MiB
    if (bar->base < 0x100000) {
        return true;
    }

    if (bus->bar_count == PCI_MAX_BARS_PER_BUS) {
        return false;
    }

    bus->bars[bus->bar_count++] = bar;

    return true;
}

static bool drop_bar(struct pci_bus *bus, struct pci_bar *bar) {
    for (size_t i = 0; i < bus->bar_count; i++) {
        if (bus->bars[i] != bar) {
            continue;
        }
        memmove(&bus->bars[i], &bus->bars[i + 1], PCI_MAX_BARS_PER_BUS - i - 1);
        bus->bar_count--;
        break;
    }

    return true;
}

static int compare_bars(struct pci_bar **a, struct pci_bar **b) {
    return (*a)->length > (*b)->length ? -1 : 1;
}

static void sort_bars(struct pci_bus *bus) {
    qsort(bus->bars, bus->bar_count, sizeof(struct pci_bar *), (void *)compare_bars);
    for (size_t i = 0; i < bus->bar_count; i++) {
        if (bus->bars[i]->range == NULL) {
            continue;
        }

        struct pci_bar *bar = bus->bars[i];
        struct pci_device *device = bar->device;
        struct pci_bus *bridge_bus = device->bridge_bus;

        sort_bars(bridge_bus);
    }
}

static void reallocate_bars(struct pci_bus *bus);

static bool framebuffer_relocated = false;

static void reallocate_single_bar(struct pci_bus *bus, struct pci_bar *bar) {
    bool tried_all_prefetchable = false;

again:
    for (size_t i = 0; i < bus->range_count; i++) {
        struct pci_range *range = &bus->ranges[i];

        if (tried_all_prefetchable == false && bar->prefetchable != range->prefetchable) {
            continue;
        }

        if (range->base + range->reloc_ptr + bar->length > range->base + range->length) {
            continue;
        }

        uint64_t orig_base = bar->base;
        bar->base = range->base + range->reloc_ptr;
        range->reloc_ptr += bar->length;

        struct pci_device *device = bar->device;

        struct pci_address address;
        address.segment = device->root_bus->segment;
        address.bus = device->root_bus->bus;
        address.slot = device->slot;
        address.function = device->function;

        printf("reallocating BAR %u of device %04x:%02x:%02x.%02x from 0x%llx to 0x%llx\n",
               bar->bar_number, bus->segment, bus->bus, bar->device->slot, bar->device->function,
               orig_base, bar->base);

        if (framebuffer_relocated == false
         && bar->bar_number != 0xff
         && priv.cb_fb.physical_address >= orig_base
         && priv.cb_fb.physical_address < orig_base + bar->length) {
            printf("BAR contains the EFI framebuffer. Modifying cb_fb.physical_address accordingly...\n");
            printf("  0x%llx => ", priv.cb_fb.physical_address);
            priv.cb_fb.physical_address -= orig_base;
            priv.cb_fb.physical_address += bar->base;
            printf("0x%llx\n", priv.cb_fb.physical_address);
            framebuffer_relocated = true;
        }

        if (bar->bar_number != 0xff) {
            uint64_t new_base = bar->base | (pci_read32(&address, 0x10 + bar->bar_number * 4) & 0xf);

            pci_write32(&address, 0x10 + bar->bar_number * 4, new_base);

            if (bar->is_64) {
                pci_write32(&address, 0x10 + bar->bar_number * 4 + 4, new_base >> 32);
            }
        } else {
            pci_write16(&address, bar->prefetchable ? 0x24 : 0x20,
                ((bar->base >> 16) & 0xfff0) | (pci_read16(&address, 0x20) & 0xf));

            if (bar->prefetchable && bar->is_64) {
                pci_write32(&address, 0x28, bar->base >> 32);
            }

            bar->range->base = bar->base;

            bar->device->reallocated_windows++;

            if (bar->device->reallocated_windows == 2) {
                reallocate_bars(bar->device->bridge_bus);
            }
        }

        return;
    }

    if (bar->prefetchable && tried_all_prefetchable == false) {
        tried_all_prefetchable = true;
        goto again;
    }

    printf("failed to reallocate BAR %u for device %04x:%02x:%02x.%02x\n",
           bar->bar_number, bus->segment, bus->bus, bar->device->slot, bar->device->function);
}

static void reallocate_bars(struct pci_bus *bus) {
    for (size_t i = 0; i < bus->bar_count; i++) {
        reallocate_single_bar(bus, bus->bars[i]);
    }
}

static bool scan_bars(struct pci_device *device) {
    uint8_t max_bars = device->type == PCI_DEVICE_BRIDGE ? 2 : 6;

    struct pci_address address;
    address.segment = device->root_bus->segment;
    address.bus = device->root_bus->bus;
    address.slot = device->slot;
    address.function = device->function;

    if (device->type == PCI_DEVICE_BRIDGE) {
        uint64_t non_prefetchable_base = pci_read16(&address, 0x20);
        uint64_t non_prefetchable_length = pci_read16(&address, 0x22);

        if (non_prefetchable_base != 0) {
            non_prefetchable_base <<= 16;

            non_prefetchable_length <<= 16;
            non_prefetchable_length |= 0xfffff;

            if (non_prefetchable_length < non_prefetchable_base) {
                goto no_non_prefetch_range;
            }

            non_prefetchable_length -= non_prefetchable_base;
            non_prefetchable_length++;

            struct pci_range *range = add_range(device->bridge_bus, non_prefetchable_base, non_prefetchable_length, false);
            if (range == NULL) {
                for (;;);
            }

            struct pci_bar *bar = allocate_bar();
            bar->range = range;
            bar->base = non_prefetchable_base;
            bar->length = non_prefetchable_length;
            bar->bar_number = 0xff;
            bar->device = device;
            bar->prefetchable = false;
            bar->is_64 = false;

            add_bar(device->root_bus, bar);
        }
no_non_prefetch_range:

        uint64_t prefetchable_base = pci_read16(&address, 0x24);
        uint64_t prefetchable_length = pci_read16(&address, 0x26);

        if (prefetchable_base != 0) {
            bool is_64 = (prefetchable_base & 0xf) == 0x1;

            prefetchable_base &= ~((uint64_t)0xf);
            prefetchable_base <<= 16;

            prefetchable_length &= ~((uint64_t)0xf);
            prefetchable_length <<= 16;
            prefetchable_length |= 0xfffff;

            if (!is_64 && prefetchable_length < prefetchable_base) {
                goto no_prefetch_range;
            }

            if (is_64) {
                prefetchable_base |= (uint64_t)pci_read32(&address, 0x28) << 32;
                prefetchable_length |= (uint64_t)pci_read32(&address, 0x2c) << 32;

                if (prefetchable_length < prefetchable_base) {
                    goto no_prefetch_range;
                }
            }

            prefetchable_length -= prefetchable_base;
            prefetchable_length++;

            struct pci_range *range = add_range(device->bridge_bus, prefetchable_base, prefetchable_length, true);
            if (range == NULL) {
                for (;;);
            }

            struct pci_bar *bar = allocate_bar();
            bar->range = range;
            bar->base = prefetchable_base;
            bar->length = prefetchable_length;
            bar->bar_number = 0xff;
            bar->device = device;
            bar->prefetchable = true;
            bar->is_64 = is_64;

            add_bar(device->root_bus, bar);
        }
no_prefetch_range:
    }

    for (uint8_t bar = 0; bar < max_bars; ) {
        uint32_t bar_offset = 0x10 + bar * 4;
        uint32_t bar_value = pci_read32(&address, bar_offset);

        // Memory bar layout is as follows:
        // - bit 0: always 0
        // - bit 1-2: bar type (0 is 32-bit, 1 is reserved, 2 is 64-bit)
        // - bit 3: prefetchable
        // - bit 4-31: base address

        bool is_64bit = false;
        bool prefetchable = false;

        if ((bar_value & (1 << 0)) != 0) {
            bar += 1;
            continue;
        }

        // Check the bar type to figure out whether it's a 64-bit bar
        is_64bit = (bar_value & (2 << 1)) != 0;
        prefetchable = (bar_value & (1 << 3)) != 0;

        // Mask out the flag bits to get the bar address
        uint64_t base = bar_value & 0xFFFFFFF0;

        // If the bar is 64-bit then read the next bar's base address
        // and OR that into our current bar's base address - 64-bit bars
        // are made up of two consecutive bars to form a 64-bit address
        if (bar != max_bars - 1 && is_64bit) {
            uint32_t next_bar = pci_read32(&address, bar_offset + 0x4);
            base |= (uint64_t)next_bar << 32;
        }

        // Disable bus master, memory and IO decoding to prevent the device
        // from mistakenly responding to our PCI config space accesses
        uint8_t cmd = pci_read8(&address, 0x4);
        uint8_t new_cmd = cmd;

        new_cmd &= ~(1 << 0); // IO space decoding
        new_cmd &= ~(1 << 1); // Memory space decoding
        new_cmd &= ~(1 << 2); // Bus master

        pci_write8(&address, 0x4, new_cmd);

        // Discover the bar length
        pci_write32(&address, bar_offset, 0xFFFFFFFF);
        uint32_t response = pci_read32(&address, bar_offset);
        pci_write32(&address, bar_offset, bar_value);
        uint64_t length = response & 0xFFFFFFF0;

        if (bar != max_bars - 1 && is_64bit) {
            uint32_t next_bar = pci_read32(&address, bar_offset + 0x4);
            pci_write32(&address, bar_offset + 0x4, 0xFFFFFFFF);
            uint32_t response = pci_read32(&address, bar_offset + 0x4);
            pci_write32(&address, bar_offset + 0x4, next_bar);
            length |= (uint64_t)response << 32;
        } else {
            length |= 0xffffffff00000000;
        }

        length = ~length + 1;

        // Restore command register
        pci_write8(&address, 0x4, cmd);

        if (base != 0) {
            struct pci_bar *bar_info = allocate_bar();

            bar_info->device = device;
            bar_info->bar_number = bar;
            bar_info->base = base;
            bar_info->length = length;
            bar_info->prefetchable = prefetchable;
            bar_info->is_64 = is_64bit;

            if (!add_bar(device->root_bus, bar_info)) {
                printf("add_bar() failure\n");
            }

            if (prefetchable) {
                device->root_bus->required_prefetchable_size += length;
            } else {
                device->root_bus->required_non_prefetchable_size += length;
            }
        }

        if (is_64bit) {
            bar += 2;
        } else {
            bar += 1;
        }
    }

    return true;
}

static bool scan_bus(struct pci_bus *bus);

static bool scan_function(struct pci_bus *bus, struct pci_address *address) {
    uint8_t subclass = pci_read8(address, 0xA);
    uint8_t class = pci_read8(address, 0xB);

    struct pci_device *device = allocate_device();

    device->root_bus = bus;
    device->slot = address->slot;
    device->function = address->function;

    struct pci_bus *bridge_bus = NULL;

    if (class == 0x6 && subclass == 0x4) {
        bridge_bus = allocate_bus();

        uint8_t secondary_bus = pci_read8(address, 0x19);

        bridge_bus->segment = address->segment;
        bridge_bus->bus = secondary_bus;

        if (!scan_bus(bridge_bus)) {
            printf("scan_bus() failure\n");
        }

        device->type = PCI_DEVICE_BRIDGE;
        device->bridge_bus = bridge_bus;
    } else {
        device->type = PCI_DEVICE_REGULAR;
        device->bridge_bus = NULL;
    }

    if (!scan_bars(device)) {
        printf("scan_bars() failure\n");
    }

    if (bridge_bus != NULL && bridge_bus->range_count == 0) {
        device->bridge_bus = NULL;;
    }

    if (!add_device(bus, device)) {
        printf("add_device() failure\n");
    }

    return true;
}

static bool scan_slot(struct pci_bus *bus, struct pci_address *address) {
    uint16_t vendor_id = pci_read16(address, 0x0);

    // No device on this slot, return
    if (vendor_id == 0xFFFF) {
        return true;
    }

    if (!scan_function(bus, address)) {
        printf("scan_function() failure\n");
    }

    // Check if device is multi-function
    uint8_t header_type = pci_read8(address, 0xE);
    if (!(header_type & 0x80)) {
        return true;
    }

    for (uint8_t func = 1; func < 8; func++) {
        struct pci_address func_addr = *address;
        func_addr.function = func;

        vendor_id = pci_read16(&func_addr, 0x0);
        if (vendor_id == 0xFFFF){
            continue;
        }

        if (!scan_function(bus, &func_addr)) {
            printf("scan_function() failure\n");
        }
    }

    return true;
}

static bool scan_bus(struct pci_bus *bus) {
    for (uint8_t slot = 0; slot < 32; slot++) {
        struct pci_address address;
        address.segment = bus->segment;
        address.bus = bus->bus;
        address.slot = slot;
        address.function = 0;

        if (!scan_slot(bus, &address)) {
            printf("scan_slot() failure\n");
        }
    }

    return true;
}

static void pretty_print_bus(struct pci_bus *bus, int indent) {
    printf("%-*s%s, segment=%d, bus=%d, range_count=%zu, device_count=%zu, bar_count=%zu\n",
        (int)(indent * 2), "", bus->root ? "root bus" : "bridge bus",
        bus->segment, bus->bus, bus->range_count, bus->device_count, bus->bar_count);

    printf("%-*srequired prefetchable size=0x%llx\n", (int)(indent * 2), "", bus->required_prefetchable_size);
    printf("%-*srequired non-prefetchable size=0x%llx\n", (int)(indent * 2), "", bus->required_non_prefetchable_size);

    for (size_t i = 0; i < bus->range_count; i++) {
        struct pci_range *range = &bus->ranges[i];

        printf("%-*srange %zu: base=0x%llx, length=0x%llx [%llx-%llx] (%sprefetchable)\n",
            (int)((indent + 1) * 2), "", i, range->base, range->length, range->base, range->base + range->length - 1,
            range->prefetchable ? "" : "non-");
    }

    for (size_t i = 0; i < bus->device_count; i++) {
        struct pci_device *device = bus->devices[i];

        struct pci_address address;
        address.segment = device->root_bus->segment;
        address.bus = device->root_bus->bus;
        address.slot = device->slot;
        address.function = device->function;

        uint16_t vendor = pci_read16(&address, 0x0);
        uint16_t product = pci_read16(&address, 0x2);

        uint8_t subclass = pci_read8(&address, 0xA);
        uint8_t class = pci_read8(&address, 0xB);

        printf("%-*sdevice %zu: type=%s, address=%04x:%02x:%02x.%02x, vendor=%04x, product=%04x, subclass=%d, class=%d\n",
            (int)((indent + 1) * 2), "", i, device->type == PCI_DEVICE_BRIDGE ? "bridge" : "device",
            bus->segment, bus->bus, device->slot, device->function, vendor, product, subclass, class);

        if (device->bridge_bus != NULL) {
            pretty_print_bus(device->bridge_bus, indent + 2);
        }
    }

    for (size_t j = 0; j < bus->bar_count; j++) {
        struct pci_bar *bar = bus->bars[j];

        printf("%-*sbar%d: device_address=%04x:%02x:%02x.%02x, base=0x%llx, length=0x%llx\n",
            (int)((indent + 1) * 2), "", bar->bar_number, bus->segment, bus->bus, bar->device->slot, bar->device->function, bar->base, bar->length);
        printf("%-*s\t [%llx-%llx] (%sprefetchable, %s-bit)\n",
            (int)((indent + 1) * 2), "", bar->base, bar->base + bar->length - 1, bar->prefetchable ? "" : "non-", bar->is_64 ? "64" : "32");
    }
}

static uacpi_iteration_decision uacpi_discover_root_bus(void *user, uacpi_namespace_node *node, uacpi_u32 node_depth) {
    (void)node_depth;

    uacpi_resources *resources = NULL;
    uacpi_iteration_decision decision = UACPI_ITERATION_DECISION_CONTINUE;
    uacpi_status status = UACPI_STATUS_OK;

    status = uacpi_get_current_resources(node, &resources);
    if (status != UACPI_STATUS_OK) {
        printf("Failed to get node resources: %s\n", uacpi_status_to_string(status));
        goto cleanup;
    }

    struct pci_bus *root_bus = allocate_bus();
    if (root_bus == NULL) {
        printf("allocate_bus() failure\n");
        goto cleanup;
    }

    uint64_t segment = 0, bus_number = 0;

    uacpi_eval_simple_integer(node, "_SEG", &segment);
    uacpi_eval_simple_integer(node, "_BBN", &bus_number);

    root_bus->root = true;
    root_bus->segment = segment;
    root_bus->bus = bus_number;

    uacpi_resource *res = resources->entries;
    while ((void *)res < (void *)resources->entries + resources->length) {
        if (res->type == UACPI_RESOURCE_TYPE_END_TAG) {
            break;
        }

        switch (res->type) {
        case UACPI_RESOURCE_TYPE_IO:
        case UACPI_RESOURCE_TYPE_FIXED_IO:
            // We don't care about IO regions
            break;
        case UACPI_RESOURCE_TYPE_ADDRESS16:
            if (res->address16.common.type != UACPI_RANGE_MEMORY || res->address16.address_length < 0x1000)
                break;
            if (!add_range(root_bus, res->address16.minimum, res->address16.address_length,
                    res->address16.common.attribute.memory.caching != UACPI_NON_CACHEABLE)) {
                printf("add_range() failure\n");
            }
            break;
        case UACPI_RESOURCE_TYPE_ADDRESS32:
            if (res->address32.common.type != UACPI_RANGE_MEMORY || res->address32.address_length < 0x1000)
                break;
            if (!add_range(root_bus, res->address32.minimum, res->address32.address_length,
                    res->address32.common.attribute.memory.caching != UACPI_NON_CACHEABLE)) {
                printf("add_range() failure\n");
            }
            break;
        case UACPI_RESOURCE_TYPE_ADDRESS64:
            if (res->address64.common.type != UACPI_RANGE_MEMORY || res->address64.address_length < 0x1000)
                break;
            if (!add_range(root_bus, res->address64.minimum, res->address64.address_length,
                    res->address64.common.attribute.memory.caching != UACPI_NON_CACHEABLE)) {
                printf("add_range() failure\n");
            }
            break;
        default:
            printf("Unknown PCI root bus resource type %u\n", res->type);
            break;
        }

        res = UACPI_NEXT_RESOURCE(res);
    }

    if (!add_root_bus(root_bus)) {
        goto cleanup;
    }

    goto out;

cleanup:
    decision = UACPI_ITERATION_DECISION_BREAK;

    if (resources != NULL) {
        uacpi_free_resources(resources);
    }

out:
    *(uacpi_status *)user = status;
    return decision;
}

static bool uacpi_discover_root_bridges(void) {
    uacpi_status status;
    uacpi_status iter_status = UACPI_STATUS_OK;

    status = uacpi_find_devices_at(
        uacpi_namespace_get_predefined(UACPI_PREDEFINED_NAMESPACE_SB),
        (const char *[]){"PNP0A03", "PNP0A08", NULL}, uacpi_discover_root_bus, &iter_status);

    if (iter_status != UACPI_STATUS_OK) {
        status = iter_status;
    }

    if (status != UACPI_STATUS_OK) {
        printf("uACPI find devices failed: %s\n", uacpi_status_to_string(status));
        return false;
    }

    return true;
}

static bool efi_discover_root_bridges(EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *root_bridge_io_protocol) {
    printf("TODO handle_root_bridge_io_protocol\n");
    (void)root_bridge_io_protocol;
    return false;
}

bool pci_early_initialize(void) {
    if (gBS->AllocatePool(EfiLoaderData, sizeof(struct pci_bus) * BUS_STRUCT_POOL_COUNT, (void *)&bus_struct_pool) != EFI_SUCCESS) {
        return false;
    }
    memset(bus_struct_pool, 0, sizeof(struct pci_bus) * BUS_STRUCT_POOL_COUNT);

    if (gBS->AllocatePool(EfiLoaderData, sizeof(struct pci_device) * DEVICE_STRUCT_POOL_COUNT, (void *)&device_struct_pool) != EFI_SUCCESS) {
        return false;
    }
    memset(device_struct_pool, 0, sizeof(struct pci_device) * DEVICE_STRUCT_POOL_COUNT);

    if (gBS->AllocatePool(EfiLoaderData, sizeof(struct pci_bar) * BAR_STRUCT_POOL_COUNT, (void *)&bar_struct_pool) != EFI_SUCCESS) {
        return false;
    }
    memset(bar_struct_pool, 0, sizeof(struct pci_bar) * BAR_STRUCT_POOL_COUNT);

    EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL *root_bridge_io_protocol;
    EFI_GUID root_bridge_io_protocol_guid = EFI_PCI_ROOT_BRIDGE_IO_PROTOCOL_GUID;

    if (1){ //gBS->LocateProtocol(&root_bridge_io_protocol_guid, NULL, (void **)&root_bridge_io_protocol) != EFI_SUCCESS) {
        if (!acpi_full_init()) {
            return false;
        }

        if (!uacpi_discover_root_bridges()) {
            return false;
        }
    } else {
        if (!efi_discover_root_bridges(root_bridge_io_protocol)) {
            return false;
        }
    }

    printf("discovered %zu root buses\n", root_bus_count);

    return true;
}

static bool resize_bridge_windows(struct pci_bus *bus) {
again:
    for (size_t i = 0; i < bus->bar_count; i++) {
        if (bus->bars[i]->range == NULL) {
            continue;
        }

        struct pci_bar *bar = bus->bars[i];
        struct pci_device *device = bar->device;
        struct pci_range *range = bar->range;
        struct pci_bus *bridge_bus = device->bridge_bus;

        size_t new_size;
        if (range->prefetchable) {
            new_size = bridge_bus->required_prefetchable_size;
        } else {
            new_size = bridge_bus->required_non_prefetchable_size;
        }

        struct pci_address address;
        address.segment = device->root_bus->segment;
        address.bus = device->root_bus->bus;
        address.slot = device->slot;
        address.function = device->function;

        uint64_t raw_base = pci_read16(&address, 0x20);
        uint64_t raw_limit = pci_read16(&address, 0x22);

        bool is_64 = (raw_base & 0xf) == 0x1;

        printf("new_size=%llx\n", new_size);

        if (new_size == 0) {
            printf("dropping %sprefetchable window of bridge device %04x:%02x:%02x.%02x\n",
                   range->prefetchable ? "" : "non-", bus->segment, bus->bus, device->slot, device->function);
            pci_write16(&address, range->prefetchable ? 0x24 : 0x20, 0x10 | (raw_base & 0xf));
            pci_write16(&address, range->prefetchable ? 0x26 : 0x22, raw_limit & 0xf);
            if (range->prefetchable && is_64) {
                pci_write32(&address, 0x28, 0);
                pci_write32(&address, 0x2c, 0);
            }
            drop_range(bridge_bus, range);
            if (bridge_bus->range_count == 0) {
                device->bridge_bus = NULL;
            }
            drop_bar(bus, bar);
            goto again;
        }

        new_size = ALIGN_UP(new_size, 0x100000);

        printf("resizing %sprefetchable window of bridge device %04x:%02x:%02x.%02x from %llx to %llx\n",
               range->prefetchable ? "" : "non-", bus->segment, bus->bus, device->slot, device->function, bar->length, new_size);

        uint64_t new_limit = new_size - 1;

        pci_write16(&address, range->prefetchable ? 0x26 : 0x22,
            ((new_limit >> 16) & 0xfff0) | (raw_limit & 0x000f));

        if (range->prefetchable && is_64) {
            pci_write32(&address, 0x2c, new_limit >> 32);
        }

        range->length = new_size;
        bar->length = new_size;

        resize_bridge_windows(bridge_bus);
    }

    return true;
}

bool pci_late_initialize(void) {
    for (size_t i = 0; i < root_bus_count; i++) {
        if (!scan_bus(root_buses[i])) {
            printf("scan_bus() failure\n");
        }
    }

    for (size_t i = 0; i < root_bus_count; i++) {
        pretty_print_bus(root_buses[i], 0);
    }

    printf("---------------\n");

    for (size_t i = 0; i < root_bus_count; i++) {
        resize_bridge_windows(root_buses[i]);
    }

    for (size_t i = 0; i < root_bus_count; i++) {
        sort_bars(root_buses[i]);
    }

    for (size_t i = 0; i < root_bus_count; i++) {
        reallocate_bars(root_buses[i]);
    }

    printf("---------------\n");

    for (size_t i = 0; i < root_bus_count; i++) {
        pretty_print_bus(root_buses[i], 0);
    }

    return true;
}
