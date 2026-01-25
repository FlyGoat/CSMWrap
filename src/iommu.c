#include <efi.h>
#include <printf.h>

#include "csmwrap.h"
#include "io.h"
#include "iommu.h"

#include <uacpi/acpi.h>
#include <uacpi/tables.h>

/*
 * IOMMU Disabling for Legacy OS Handoff
 *
 * Disables Intel VT-d and AMD-Vi IOMMUs before legacy OS boot.
 * This is necessary because UEFI-configured IOMMU translation tables
 * become stale after PCI BAR relocation.
 */

/*
 * Intel VT-d DMAR Table Structures
 * Reference: Intel VT-d Architecture Specification
 */

#define ACPI_DMAR_SIGNATURE "DMAR"

#define DMAR_TYPE_DRHD  0  /* DMA Remapping Hardware Unit Definition */

struct acpi_dmar {
    struct acpi_sdt_hdr hdr;
    uint8_t host_address_width;
    uint8_t flags;
    uint8_t reserved[10];
} __attribute__((packed));

struct dmar_header {
    uint16_t type;
    uint16_t length;
} __attribute__((packed));

struct dmar_drhd {
    struct dmar_header header;
    uint8_t flags;
    uint8_t reserved;
    uint16_t segment;
    uint64_t register_base;
} __attribute__((packed));

/*
 * Intel VT-d Register Offsets
 */
#define VTD_GCMD_REG    0x18
#define VTD_GSTS_REG    0x1C

#define VTD_GCMD_TE     (1U << 31)
#define VTD_GSTS_TES    (1U << 31)
#define VTD_GSTS_IRES   (1U << 25)
#define VTD_GSTS_QIES   (1U << 26)

/*
 * Mask to clear one-shot command bits when reading GSTS to write to GCMD.
 * One-shot bits (30, 29, 27, 24) trigger hardware operations when set:
 * - Bit 30: SRTP (Set Root Table Pointer)
 * - Bit 29: SFL (Set Fault Log)
 * - Bit 27: WBF (Write Buffer Flush)
 * - Bit 24: SIRTP (Set Interrupt Remap Table Pointer)
 * Reference: EDK2 IntelSiliconPkg/VTd and Intel VT-d Specification
 */
#define VTD_GSTS_ONESHOT_MASK   0x96FFFFFF

#define VTD_TIMEOUT 100000

/*
 * AMD IOMMU (AMD-Vi) IVRS Table Structures
 * Reference: AMD I/O Virtualization Technology (IOMMU) Specification
 */

#define ACPI_IVRS_SIGNATURE "IVRS"

#define IVRS_TYPE_IVHD_10   0x10
#define IVRS_TYPE_IVHD_11   0x11
#define IVRS_TYPE_IVHD_40   0x40

struct acpi_ivrs {
    struct acpi_sdt_hdr hdr;
    uint32_t iv_info;
    uint64_t reserved;
} __attribute__((packed));

struct ivrs_header {
    uint8_t type;
    uint8_t flags;
    uint16_t length;
    uint16_t device_id;
    uint16_t capability_offset;
    uint64_t iommu_base;
} __attribute__((packed));

/*
 * AMD IOMMU Register Offsets
 */
#define AMD_IOMMU_CTRL_REG  0x18
#define AMD_IOMMU_CTRL_EN   (1ULL << 0)

#define AMD_IOMMU_TIMEOUT 100000

/*
 * Disable a single Intel VT-d IOMMU unit
 */
static bool vtd_disable_unit(uint64_t reg_base) {
    void *base = (void *)(uintptr_t)reg_base;
    uint32_t gsts, gcmd;
    int timeout;

    gsts = readl(base + VTD_GSTS_REG);
    printf("  VT-d unit at 0x%llx: GSTS=0x%08x (TE=%d, IRE=%d, QIE=%d)\n",
           reg_base, gsts,
           !!(gsts & VTD_GSTS_TES),
           !!(gsts & VTD_GSTS_IRES),
           !!(gsts & VTD_GSTS_QIES));

    if (!(gsts & VTD_GSTS_TES)) {
        printf("    Translation already disabled\n");
        return true;
    }

    /* Build GCMD: preserve status bits, clear one-shot bits and TE */
    gcmd = gsts & VTD_GSTS_ONESHOT_MASK;
    gcmd &= ~VTD_GCMD_TE;

    printf("    Disabling translation (GCMD=0x%08x)\n", gcmd);
    writel(base + VTD_GCMD_REG, gcmd);

    /* Wait for TES to clear */
    timeout = VTD_TIMEOUT;
    while (timeout-- > 0) {
        gsts = readl(base + VTD_GSTS_REG);
        if (!(gsts & VTD_GSTS_TES)) {
            printf("    Translation disabled successfully\n");
            return true;
        }
    }

    printf("    WARNING: Timeout waiting for translation to disable\n");
    return false;
}

/*
 * Parse DMAR table and disable all Intel VT-d IOMMUs
 */
static int vtd_disable_all(void) {
    uacpi_table tbl;
    uacpi_status status;
    struct acpi_dmar *dmar;
    uint8_t *ptr, *end;
    int disabled = 0;

    status = uacpi_table_find_by_signature(ACPI_DMAR_SIGNATURE, &tbl);
    if (status != UACPI_STATUS_OK) {
        return 0;  /* No DMAR table, no Intel VT-d */
    }

    dmar = (struct acpi_dmar *)tbl.hdr;
    printf("DMAR: found table, host_address_width=%d, flags=0x%02x\n",
           dmar->host_address_width, dmar->flags);

    ptr = (uint8_t *)dmar + sizeof(struct acpi_dmar);
    end = (uint8_t *)dmar + dmar->hdr.length;

    while (ptr + sizeof(struct dmar_header) <= end) {
        struct dmar_header *hdr = (struct dmar_header *)ptr;

        if (hdr->length < sizeof(struct dmar_header) || ptr + hdr->length > end) {
            printf("DMAR: invalid structure length\n");
            break;
        }

        if (hdr->type == DMAR_TYPE_DRHD) {
            struct dmar_drhd *drhd = (struct dmar_drhd *)ptr;
            printf("DMAR: DRHD segment=%d flags=0x%02x base=0x%llx\n",
                   drhd->segment, drhd->flags, drhd->register_base);

            if (vtd_disable_unit(drhd->register_base)) {
                disabled++;
            }
        }

        ptr += hdr->length;
    }

    uacpi_table_unref(&tbl);
    return disabled;
}

static void writeq(void *addr, uint64_t val) {
    *(volatile uint64_t *)addr = val;
    barrier();
}

static uint64_t readq_iommu(void *addr) {
    uint64_t val = *(volatile uint64_t *)addr;
    barrier();
    return val;
}

/*
 * Disable a single AMD IOMMU unit
 */
static bool amd_iommu_disable_unit(uint64_t iommu_base) {
    void *base = (void *)(uintptr_t)iommu_base;
    uint64_t ctrl;
    int timeout;

    ctrl = readq_iommu(base + AMD_IOMMU_CTRL_REG);
    printf("  AMD IOMMU at 0x%llx: CTRL=0x%016llx (En=%d)\n",
           iommu_base, ctrl, !!(ctrl & AMD_IOMMU_CTRL_EN));

    if (!(ctrl & AMD_IOMMU_CTRL_EN)) {
        printf("    IOMMU already disabled\n");
        return true;
    }

    ctrl &= ~AMD_IOMMU_CTRL_EN;

    printf("    Disabling IOMMU (CTRL=0x%016llx)\n", ctrl);
    writeq(base + AMD_IOMMU_CTRL_REG, ctrl);

    timeout = AMD_IOMMU_TIMEOUT;
    while (timeout-- > 0) {
        ctrl = readq_iommu(base + AMD_IOMMU_CTRL_REG);
        if (!(ctrl & AMD_IOMMU_CTRL_EN)) {
            printf("    IOMMU disabled successfully\n");
            return true;
        }
    }

    printf("    WARNING: Timeout waiting for IOMMU to disable\n");
    return false;
}

/*
 * Parse IVRS table and disable all AMD IOMMUs
 */
static int amd_iommu_disable_all(void) {
    uacpi_table tbl;
    uacpi_status status;
    struct acpi_ivrs *ivrs;
    uint8_t *ptr, *end;
    int disabled = 0;

    status = uacpi_table_find_by_signature(ACPI_IVRS_SIGNATURE, &tbl);
    if (status != UACPI_STATUS_OK) {
        return 0;  /* No IVRS table, no AMD IOMMU */
    }

    ivrs = (struct acpi_ivrs *)tbl.hdr;
    printf("IVRS: found table, iv_info=0x%08x\n", ivrs->iv_info);

    ptr = (uint8_t *)ivrs + sizeof(struct acpi_ivrs);
    end = (uint8_t *)ivrs + ivrs->hdr.length;

    while (ptr + sizeof(struct ivrs_header) <= end) {
        struct ivrs_header *hdr = (struct ivrs_header *)ptr;

        if (hdr->length < sizeof(struct ivrs_header) || ptr + hdr->length > end) {
            printf("IVRS: invalid block length\n");
            break;
        }

        if (hdr->type == IVRS_TYPE_IVHD_10 ||
            hdr->type == IVRS_TYPE_IVHD_11 ||
            hdr->type == IVRS_TYPE_IVHD_40) {
            printf("IVRS: IVHD type=0x%02x device_id=0x%04x base=0x%llx\n",
                   hdr->type, hdr->device_id, hdr->iommu_base);

            if (amd_iommu_disable_unit(hdr->iommu_base)) {
                disabled++;
            }
        }

        ptr += hdr->length;
    }

    uacpi_table_unref(&tbl);
    return disabled;
}

/*
 * Main entry point: disable all IOMMUs
 */
bool iommu_disable(void) {
    int vtd_count = 0;
    int amd_count = 0;

    printf("Disabling IOMMUs for legacy OS compatibility...\n");

    vtd_count = vtd_disable_all();
    if (vtd_count > 0) {
        printf("Disabled %d Intel VT-d IOMMU unit(s)\n", vtd_count);
    }

    amd_count = amd_iommu_disable_all();
    if (amd_count > 0) {
        printf("Disabled %d AMD IOMMU unit(s)\n", amd_count);
    }

    if (vtd_count == 0 && amd_count == 0) {
        printf("No IOMMUs found or all already disabled\n");
        return false;
    }

    return true;
}
