#include <efi.h>

#include <printf.h>
#include "csmwrap.h"

/* This is not in E820.h */
#define EfiAcpiAddressRangeHole     (-1UL)

static const char *
e820_type_name(uint32_t type)
{
    switch (type) {
    case EfiAcpiAddressRangeMemory:      return "RAM";
    case EfiAcpiAddressRangeReserved:    return "RESERVED";
    case EfiAcpiAddressRangeACPI:        return "ACPI";
    case EfiAcpiAddressRangeNVS:         return "NVS";
    default:                             return "UNKNOWN";
    }
}

// Remove an entry from the e820_map.
static void
remove_e820(struct csmwrap_priv *priv, int i)
{
    EFI_E820_ENTRY64 *e820_map = priv->low_stub->e820_map;
    int *e820_count = &priv->low_stub->e820_entries;

    if (i < 0 || i >= *e820_count) {
        DEBUG((DEBUG_ERROR, "e820_map remove index out of range\n"));
        return;
    }

    (*e820_count)--;
    memmove(&e820_map[i], &e820_map[i+1],
            sizeof(EFI_E820_ENTRY64) * (*e820_count - i));
}

// Insert an entry in the e820_map at the given position.
static void
insert_e820(struct csmwrap_priv *priv,
            int i, uint64_t start, uint64_t size, uint64_t type)
{
    EFI_E820_ENTRY64 *e820_map = priv->low_stub->e820_map;
    int *e820_count = &priv->low_stub->e820_entries;

    if (*e820_count >= E820_MAX_ENTRIES) {
        DEBUG((DEBUG_ERROR, "e820_map overflow\n"));
        return;
    }

    memmove(&e820_map[i + 1], &e820_map[i],
            sizeof(EFI_E820_ENTRY64) * (*e820_count - i));

    (*e820_count)++;
    EFI_E820_ENTRY64 *e = &e820_map[i];
    e->BaseAddr = start;
    e->Length = size;
    e->Type = type;
}

// Show the current e820_map.
static void
dump_map(struct csmwrap_priv *priv)
{
    EFI_E820_ENTRY64 *e820_map = priv->low_stub->e820_map;
    int e820_count = priv->low_stub->e820_entries;

    printf("csmwrap e820 map has %d items:\n", e820_count);
    int i;
    for (i = 0; i < e820_count; i++) {
        EFI_E820_ENTRY64 *e = &e820_map[i];
        uint64_t e_end = e->BaseAddr + e->Length;

        printf("  %d: %016llx - %016llx = %d %s\n", i,
               e->BaseAddr, e_end, e->Type, e820_type_name(e->Type));
    }
}

void e820_add(struct csmwrap_priv *priv, uint64_t start,
              uint64_t size, uint64_t type)
{
    EFI_E820_ENTRY64 *e820_map = priv->low_stub->e820_map;
    int *e820_count = &priv->low_stub->e820_entries;

    if (!size)
        return;

    // Find position of new item (splitting existing item if needed).
    uint64_t end = start + size;
    int i;
    for (i = 0; i < *e820_count; i++) {
        EFI_E820_ENTRY64 *e = &e820_map[i];
        uint64_t e_end = e->BaseAddr + e->Length;
        if (start > e_end)
            continue;
        // Found position - check if an existing item needs to be split.
        if (start > e->BaseAddr) {
            if (type == e->Type) {
                // Same type - merge them.
                size += start - e->BaseAddr;
                start = e->BaseAddr;
            } else {
                // Split existing item.
                e->Length = start - e->BaseAddr;
                i++;
                if (e_end > end)
                    insert_e820(priv, i, end, e_end - end, e->Type);
            }
        }
        break;
    }
    // Remove/adjust existing items that are overlapping.
    while (i < *e820_count) {
        EFI_E820_ENTRY64 *e = &e820_map[i];
        if (end < e->BaseAddr)
            // No overlap - done.
            break;
        uint64_t e_end = e->BaseAddr + e->Length;
        if (end >= e_end) {
            // Existing item completely overlapped - remove it.
            remove_e820(priv, i);
            continue;
        }
        // Not completely overlapped - adjust its start.
        e->BaseAddr = end;
        e->Length = e_end - end;
        if (type == e->Type) {
            // Same type - merge them.
            size += e->Length;
            remove_e820(priv, i);
        }
        break;
    }
    // Insert new item.
    if (type != EfiAcpiAddressRangeHole)
        insert_e820(priv, i, start, size, type);
}

// Remove any definitions in a memory range (make a memory hole).
void
e820_remove(struct csmwrap_priv *priv, uint64_t start, uint64_t size)
{
    e820_add(priv, start, size, EfiAcpiAddressRangeHole);
}

/*
 * Convert UEFI memory types to E820 types
 * See https://uefi.org/sites/default/files/resources/ACPI_4_Errata_A.pdf Table 14-6
 */
static uint32_t convert_memory_type(EFI_MEMORY_TYPE type)
{
    switch (type) {
        case EfiConventionalMemory:
        case EfiLoaderCode:
        case EfiLoaderData:
            return EfiAcpiAddressRangeMemory;
        case EfiACPIReclaimMemory:
            return EfiAcpiAddressRangeACPI;
        case EfiACPIMemoryNVS:
            return EfiAcpiAddressRangeNVS;
        case EfiUnusableMemory:
        case EfiReservedMemoryType:
        /* Boot services memory can still be used by broken firmware even past exiting */
        /* boot services. This workaround was originally introduced in commit 3b8eed41da, */
        /* with a FIXME saying it was added in order to fix a Windows 0xA5 BSOD. */
        /* Issues have additionally been identified on Arrow Lake hardware that the same */
        /* workaround also fixes. */
        case EfiBootServicesCode:
        case EfiBootServicesData:
        case EfiRuntimeServicesCode:
        case EfiRuntimeServicesData:
        case EfiMemoryMappedIO:
        case EfiMemoryMappedIOPortSpace:
        case EfiPalCode:
        default:
            return EfiAcpiAddressRangeReserved;
    }
}

/*
 * Build E820 memory map based on UEFI GetMemoryMap
 * Return the number of entries in the E820 map
 */
int build_e820_map(struct csmwrap_priv *priv, EFI_MEMORY_DESCRIPTOR *memory_map, UINTN memory_map_size, UINTN descriptor_size)
{
    EFI_MEMORY_DESCRIPTOR *memory_map_end;
    EFI_MEMORY_DESCRIPTOR *memory_map_ptr;

    memory_map_end = (EFI_MEMORY_DESCRIPTOR *)((uint8_t *)memory_map + memory_map_size);

    /* Process each memory descriptor and convert to E820 format */
    for (memory_map_ptr = memory_map; 
         memory_map_ptr < memory_map_end;
         memory_map_ptr = NextMemoryDescriptor(memory_map_ptr, descriptor_size)) {

        uint64_t start = memory_map_ptr->PhysicalStart;
        uint64_t end = start + (memory_map_ptr->NumberOfPages * EFI_PAGE_SIZE);
        uint32_t type = convert_memory_type(memory_map_ptr->Type);
        
        /* Skip zero-length regions */
        if (start == end)
            continue;

        /* Skip memory types that are not reported in E820 */
        if (type == 0)
            continue;

        e820_add(priv, start, end - start, type);
    }

    /* Remove whole 1MB, we are going to fix it later */
    e820_remove(priv, 0, 0x100000);
    /* Add all low memory as usable */
    e820_add(priv, 0, 0x80000, EfiAcpiAddressRangeMemory);
    /* Reserve EBDA */
    e820_add(priv, EBDA_BASE, 0x20000, EfiAcpiAddressRangeReserved);
    /* Reserve Expansion BIOS */
    e820_add(priv, 0xa0000, 0x100000 - 0xa0000, EfiAcpiAddressRangeReserved);

    if (DEBUG_PRINT_LEVEL & DEBUG_VERBOSE) {
        dump_map(priv);
    }

    return 0;
}
