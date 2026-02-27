#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>
#include <stdint.h>
#include <efi.h>

#define CONFIG_VGABIOS_PATH_MAX 256

struct csmwrap_config {
    bool serial_debug;
    uint16_t serial_port;
    uint32_t serial_baud;
    CHAR16 vgabios_path[CONFIG_VGABIOS_PATH_MAX];
    bool iommu_disable;
    bool vga_specified;
    uint8_t vga_bus;
    uint8_t vga_device;
    uint8_t vga_function;
};

extern struct csmwrap_config gConfig;

/*
 * Load configuration from csmwrap.ini next to the running EFI executable.
 * root_dir: filesystem root opened via EFI_SIMPLE_FILE_SYSTEM_PROTOCOL
 * file_path: loaded image's FilePath device path (used to find our directory)
 *
 * If the file is missing or unreadable, defaults are silently retained.
 */
void config_load(EFI_FILE_PROTOCOL *root_dir, EFI_DEVICE_PATH_PROTOCOL *file_path);

#endif
