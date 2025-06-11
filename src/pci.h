#ifndef PCI_H
#define PCI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct pci_address {
    uint16_t segment;
    uint8_t bus;
    uint8_t slot;
    uint8_t function;
};

struct pci_range {
    uint64_t base;
    uint64_t length;
    uint64_t reloc_ptr;
    bool prefetchable;
};

enum pci_device_type {
    PCI_DEVICE_REGULAR,
    PCI_DEVICE_BRIDGE,
};

struct pci_device {
    // Type of the device
    enum pci_device_type type;

    // The root bus that this device is on
    struct pci_bus *root_bus;

    // A bus if a device is a bridge.
    struct pci_bus *bridge_bus;

    // Address of the device on the bus
    uint8_t slot;
    uint8_t function;

    int reallocated_windows;
};

struct pci_bar {
    // The PCI device that this bar belongs to
    struct pci_device *device;

    // The bar number in context of the device
    uint8_t bar_number;

    bool is_64;
    bool prefetchable;

    // Base address and size of the bar
    uint64_t base;
    uint64_t length;

    // Range associated with bridge window pseudo-BARs.
    struct pci_range *range;
};

#define PCI_MAX_RANGES_PER_BUS 32
#define PCI_MAX_DEVICES_PER_BUS 256
#define PCI_MAX_BARS_PER_BUS 512

struct pci_bus {
    bool root;

    uint32_t segment;
    uint8_t bus;

    // Sorted list of address ranges this root bus decodes
    size_t range_count;
    struct pci_range ranges[PCI_MAX_RANGES_PER_BUS];

    // List of devices associated with this root bus
    size_t device_count;
    struct pci_device *devices[PCI_MAX_DEVICES_PER_BUS];

    // Sorted list of allocated bars associated with this root bus
    size_t bar_count;
    struct pci_bar *bars[PCI_MAX_BARS_PER_BUS];

    uint64_t required_prefetchable_size;
    uint64_t required_non_prefetchable_size;
};

#define PCI_OFFSET_MASK (~UINT32_C(3))

#define pci_read8(address, offset) ({ \
    /* Figure out which byte we want to read by AND-ing the offset with 0x3 (0b11) */ \
    /* This gives us a value between 0 and 3 (inclusive) */ \
    uint32_t byte_index = (offset) & 0x3; \
    uint32_t dword = pci_read_config_space((address), (offset) & PCI_OFFSET_MASK); \
    /* Shift the read dword right by `byte_index * 8` bits, that moves the byte */ \
    /* we are interested in to the least significant position */ \
    (uint8_t)((dword >> (byte_index * 8)) & 0xFF); \
})

#define pci_read16(address, offset) ({ \
    /* Figure out which word we want to read by AND-ing the offset with 0x2 (0b10) */ \
    /* This gives us a value of 0 or 2 which we then use to select the right word */ \
    uint32_t word_index = (offset) & 0x2; \
    uint32_t dword = pci_read_config_space((address), (offset) & PCI_OFFSET_MASK); \
    /* Shift the read dword right by `word_index * 8` bits, that moves the word */ \
    /* we are interested in to the least significant position */ \
    (uint16_t)((dword >> (word_index * 8)) & 0xFFFF); \
})

// No bit magic required here as that case matches the granularity of pci_read_config_space
#define pci_read32(address, offset) pci_read_config_space((address), (offset))

#define pci_write8(address, offset, value) ({ \
    uint32_t byte_index = (offset) & 0x3; \
    uint32_t dword = pci_read_config_space((address), (offset) & PCI_OFFSET_MASK); \
    /* First, we create a mask which will mask out the bits we are modifying */ \
    /* by shifting 0xFF left by `byte_index * 8` and the inverting it, then */ \
    /* we mask the read dword with that mask and finally we OR in the new values */ \
    /* shifted by `byte_index * 8` which places it at the right spot in the dword */ \
    uint32_t new_dword = (dword & ~(0xFF << (byte_index * 8))) | (((value) & 0xFF) << (byte_index * 8)); \
    pci_write_config_space((address), (offset) & PCI_OFFSET_MASK, new_dword); \
})

#define pci_write16(address, offset, value) ({ \
    uint32_t byte_index = (offset) & 0x2; \
    uint32_t dword = pci_read_config_space((address), (offset) & PCI_OFFSET_MASK); \
    /* This works similarly, except we use 0xFFFF because we work with a word */ \
    /* here instead of a single byte, and the `word_index` can either be 0 or 2 */ \
    uint32_t new_dword = (dword & ~(0xFFFF << (byte_index * 8))) | (((value) & 0xFFFF) << (byte_index * 8)); \
    pci_write_config_space((address), (offset) & PCI_OFFSET_MASK, new_dword); \
})

// And here, again, no bit fiddling required as this matches the granularity of pci_write_config_space
#define pci_write32(address, offset, value) pci_write_config_space((address), (offset), (value))

// Read PCI config space of the given device at given offset.
// Offset will be aligned down to the nearest multiple of 4.
uint32_t pci_read_config_space(struct pci_address *address, uint32_t offset);

// Write PCI config space of the given device at given offset.
// Offset will be aligned down to the nearest multiple of 4.
void pci_write_config_space(struct pci_address *address, uint32_t offset, uint32_t value);

// Discover PCI root buses and devices behind them.
bool pci_early_initialize(void);
bool pci_late_initialize(void);

#endif
