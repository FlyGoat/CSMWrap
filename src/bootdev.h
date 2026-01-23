#ifndef _BOOTDEV_H
#define _BOOTDEV_H

#include <efi.h>

/* Forward declaration */
struct csmwrap_priv;

/*
 * Boot device detection and BBS table building
 *
 * This module detects the boot device (the drive CSMWrap was loaded from)
 * and builds a BBS (BIOS Boot Specification) table for SeaBIOS with the
 * boot device prioritized first.
 */

/* Boot device information extracted from device path */
struct boot_device_info {
    bool valid;
    uint8_t bus;
    uint8_t device;
    uint8_t function;
    uint8_t pci_class;          /* PCI class code */
    uint8_t pci_subclass;       /* PCI subclass code */
    uint16_t device_type;       /* BBS_HARDDISK, BBS_CDROM, etc. */
    bool is_usb;
    uint16_t sata_port;         /* SATA port number if applicable */
};

/*
 * Detect boot device and build BBS table
 *
 * This function:
 * 1. Parses the device path of the boot device to get PCI location
 * 2. Enumerates all block I/O devices
 * 3. Builds a BBS table with the boot device at highest priority
 *
 * @param priv         CSMWrap private data structure (must have low_stub initialized)
 * @param image_handle EFI image handle (used to get loaded image info)
 * @return 0 on success, -1 on failure
 */
int build_bbs_table(struct csmwrap_priv *priv, EFI_HANDLE image_handle);

#endif /* _BOOTDEV_H */
