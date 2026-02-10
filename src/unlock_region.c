/*
 * legacy_region_unlock.c
 *
 * Implementation of BIOS region unlocking using the UEFI Legacy Region 2 Protocol
 * with fallback to direct PCI configuration space access for specific chipsets.
 */

#include <stdbool.h>
#include <efi.h>
#include "csmwrap.h"
#include "edk2/LegacyRegion2.h"
#include "io.h"

static EFI_GUID gEfiLegacyRegion2ProtocolGuid = EFI_LEGACY_REGION2_PROTOCOL_GUID;

/*
* Intel chipset PCI configuration register addresses for PAM 
* (Programmable Attribute Map) controls
*/
#define PAM0_REGISTER  0x90    /* Q35 chipset */
#define PAM_LOCK_BIT   0x01    /* Bit indicating PAM registers are locked */
#define PAM_LOCK_REG   0x80    /* Register containing PAM lock bit on newer Intel chipsets */
#define PAM_ENABLE     0x33    /* Enable read+write for both halves of PAM1-PAM6 */


/*
 * AMD MTRRs for Legacy Region
 * This is already here since AMD64
 */
#define AMD_AP_MTRR_VARIABLE_BASE0              0x200
#define AMD_AP_MTRR_VARIABLE_BASE6              0x20C
#define AMD_AP_MTRR_FIX64k_00000                0x250
#define AMD_AP_MTRR_FIX16k_80000                0x258
#define AMD_AP_MTRR_FIX16k_A0000                0x259
#define AMD_AP_MTRR_FIX4k_C0000                 0x268
#define AMD_AP_MTRR_FIX4k_C8000                 0x269
#define AMD_AP_MTRR_FIX4k_D0000                 0x26A
#define AMD_AP_MTRR_FIX4k_D8000                 0x26B
#define AMD_AP_MTRR_FIX4k_E0000                 0x26C
#define AMD_AP_MTRR_FIX4k_E8000                 0x26D
#define AMD_AP_MTRR_FIX4k_F0000                 0x26E
#define AMD_AP_MTRR_FIX4k_F8000                 0x26F

#define AMD_MTRR_FIX64K_WB_DRAM                 0x1E1E1E1E1E1E1E1Eull
#define AMD_MTRR_FIX64K_WT_DRAM                 0x1C1C1C1C1C1C1C1Cull
#define AMD_MTRR_FIX64K_UC_DRAM                 0x1818181818181818ull
#define AMD_MTRR_FIX16K_WB_DRAM                 0x1E1E1E1E1E1E1E1Eull
#define AMD_MTRR_FIX16K_WT_DRAM                 0x1C1C1C1C1C1C1C1Cull
#define AMD_MTRR_FIX16K_UC_DRAM                 0x1818181818181818ull
#define AMD_MTRR_FIX4K_WB_DRAM                  0x1E1E1E1E1E1E1E1Eull
#define AMD_MTRR_FIX4K_WT_DRAM                  0x1C1C1C1C1C1C1C1Cull
#define AMD_MTRR_FIX4K_UC_DRAM                  0x1818181818181818ull

#define MSR_SYS_CFG                         0xC0010010ul
#define SYS_CFG_MTRR_FIX_DRAM_EN            (1 << 18) ///< Core::X86::Msr::SYS_CFG::MtrrFixDramEn.
                                                       ///< MTRR fixed RdDram and WrDram attributes enable.
#define SYS_CFG_MTRR_FIX_DRAM_MOD_EN        (1 << 19) ///< Core::X86::Msr::SYS_CFG::MtrrFixDramModEn.
                                                       ///< MTRR fixed RdDram and WrDram modification enable.
#define SYS_CFG_MTRR_VAR_DRAM_EN            (1 << 20) ///< Core::X86::Msr::SYS_CFG::MtrrVarDramEn.
                                                       ///< MTRR variable DRAM enable.
#define SYS_CFG_MTRR_TOM2_EN                (1 << 21) ///< Core::X86::Msr::SYS_CFG::MtrrTom2En. MTRR
                                                       ///< top of memory 2 enable.
#define SYS_CFG_TOM2_FORCE_MEM_TYPE_WB      (1 << 22) ///< Core::X86::Msr::SYS_CFG::Tom2ForceMemTypeWB.
                                                       ///< top of memory 2 memory type write back.

/* Intel PCI Vendor ID */
#define INTEL_VENDOR_ID 0x8086

/* AMD Vendor ID */
#define AMD_VENDOR_ID   0x1022

/**
 * Unlock BIOS memory region using the Legacy Region 2 Protocol
 *
 * @return EFI_SUCCESS on success, or an error status code on failure
 */
EFI_STATUS unlock_legacy_region_protocol(void)
{
    EFI_LEGACY_REGION2_PROTOCOL *legacy_region = NULL;
    EFI_STATUS status;
    uint32_t granularity;

    /* Look for the Legacy Region 2 Protocol */
    status = gBS->LocateProtocol(
        &gEfiLegacyRegion2ProtocolGuid,
        NULL,
        (void **)&legacy_region
    );

    if (EFI_ERROR(status)) {
        printf("Legacy Region 2 Protocol not found (status: %lx)\n", status);
        return status;
    }

    /*
    * Unlock the entire legacy BIOS region (0xC0000 to 0xFFFFF)
    * Each region covers 64KB
    */

    /* First enable memory reads in the region */
    bool on = TRUE;
    status = legacy_region->Decode(
        legacy_region,
        0xC0000,         /* Start address */
        0x40000,         /* Length (256KB) */
        &granularity,
        &on
    );
    
    if (EFI_ERROR(status)) {
        printf("Failed to enable memory reads in legacy region (status: %lx)\n", status);
        return status;
    }

    /* Then enable memory writes in the region */
    status = legacy_region->UnLock(
        legacy_region,
        0xC0000,         /* Start address */
        0x40000,         /* Length (256KB) */
        &granularity
    );

    if (EFI_ERROR(status)) {
        printf("Failed to enable memory writes in legacy region (status: %lx)\n", status);
        return status;
    }
    
    printf("Successfully unlocked legacy region 0xC0000-0xFFFFF using UEFI protocol\n");
    printf("Granularity: 0x%x bytes\n", granularity);

    return EFI_SUCCESS;
}

/**
 * Unlock BIOS region using direct PCI configuration space access for piix4 chipset
 *
 * @return 0 on success, -1 on failure
 */
int unlock_piix4_pam(void)
{
    printf("Unlocking BIOS region with PIIX4 PAM\n");

    /* Enable read+write for PAM0-PAM6 (0x59-0x96) */
    pciConfigWriteByte(0, 0, 0, 0x59, PAM_ENABLE);  /* PAM0 (0xF0000-0xFFFFF) */
    pciConfigWriteByte(0, 0, 0, 0x5a, PAM_ENABLE);  /* PAM1 (0xC0000-0xC3FFF) */
    pciConfigWriteByte(0, 0, 0, 0x5b, PAM_ENABLE);  /* PAM2 (0xC4000-0xC7FFF) */
    pciConfigWriteByte(0, 0, 0, 0x5c, PAM_ENABLE);  /* PAM3 (0xC8000-0xCBFFF) */
    pciConfigWriteByte(0, 0, 0, 0x5d, PAM_ENABLE);  /* PAM4 (0xCC000-0xCFFFF) */
    pciConfigWriteByte(0, 0, 0, 0x5e, PAM_ENABLE);  /* PAM5 (0xD0000-0xD3FFF) */
    pciConfigWriteByte(0, 0, 0, 0x5f, PAM_ENABLE);  /* PAM6 (0xD4000-0xD7FFF) */

    return 0;
}

/**
 * Unlock BIOS region using direct PCI configuration space access for Q35 chipset
 *
 * @return 0 on success, -1 on failure
 */
int unlock_q35_pam(void)
{
    printf("Unlocking BIOS region with Q35 PAM\n");

    /* Enable read+write for PAM0-PAM6 (0x90-0x96) */
    pciConfigWriteByte(0, 0, 0, 0x90, PAM_ENABLE);  /* PAM0 (0xF0000-0xFFFFF) */
    pciConfigWriteByte(0, 0, 0, 0x91, PAM_ENABLE);  /* PAM1 (0xC0000-0xC3FFF) */
    pciConfigWriteByte(0, 0, 0, 0x92, PAM_ENABLE);  /* PAM2 (0xC4000-0xC7FFF) */
    pciConfigWriteByte(0, 0, 0, 0x93, PAM_ENABLE);  /* PAM3 (0xC8000-0xCBFFF) */
    pciConfigWriteByte(0, 0, 0, 0x94, PAM_ENABLE);  /* PAM4 (0xCC000-0xCFFFF) */
    pciConfigWriteByte(0, 0, 0, 0x95, PAM_ENABLE);  /* PAM5 (0xD0000-0xD3FFF) */
    pciConfigWriteByte(0, 0, 0, 0x96, PAM_ENABLE);  /* PAM6 (0xD4000-0xD7FFF) */

    return 0;
}

/**
 * Unlock BIOS region using direct PCI configuration space access for Intel Skylake+ chipsets
 *
 * @return 0 on success, -1 on failure
 */
int unlock_skylake_pam(void)
{
    printf("Unlocking BIOS region with Intel Skylake+ Generic PAM\n");

    /* Check if PAM is locked */
    if (pciConfigReadByte(0, 0, 0, PAM_LOCK_REG) & PAM_LOCK_BIT) {
        printf("PAM is locked on your platform\n");
        return -1;
    }

    /* Enable read+write for PAM0-PAM6 (0x80-0x86) */
    pciConfigWriteByte(0, 0, 0, 0x80, 0x30);        /* PAM0: bits[5:4]=11 enables read+write; bits[1:0] kept 0 to avoid setting PAM lock */
    pciConfigWriteByte(0, 0, 0, 0x81, PAM_ENABLE);  /* PAM1 */
    pciConfigWriteByte(0, 0, 0, 0x82, PAM_ENABLE);  /* PAM2 */
    pciConfigWriteByte(0, 0, 0, 0x83, PAM_ENABLE);  /* PAM3 */
    pciConfigWriteByte(0, 0, 0, 0x84, PAM_ENABLE);  /* PAM4 */
    pciConfigWriteByte(0, 0, 0, 0x85, PAM_ENABLE);  /* PAM5 */
    pciConfigWriteByte(0, 0, 0, 0x86, PAM_ENABLE);  /* PAM6 */

    return 0;
}

/**
 * Unlock BIOS region using fixed MTRR for AMD chipsets
 *
 * @return 0 on success, -1 on failure
 */
int unlock_amd_mtrr(void)
{
    uint64_t val;
    printf("Unlocking BIOS region with AMD MTRR\n");

    /* TODO: Investigate SMP impact */
    val = rdmsr(MSR_SYS_CFG);
    val |= SYS_CFG_MTRR_FIX_DRAM_MOD_EN;
    wrmsr(MSR_SYS_CFG, val);

    /* Set all to WB */
    wrmsr(AMD_AP_MTRR_FIX64k_00000, AMD_MTRR_FIX64K_WB_DRAM);
    wrmsr(AMD_AP_MTRR_FIX16k_80000, AMD_MTRR_FIX16K_WB_DRAM);
    /* A0000 map to UC IO */
    wrmsr(AMD_AP_MTRR_FIX16k_A0000, 0x0);
    wrmsr(AMD_AP_MTRR_FIX4k_C0000, AMD_MTRR_FIX4K_WB_DRAM);
    wrmsr(AMD_AP_MTRR_FIX4k_C8000, AMD_MTRR_FIX4K_WB_DRAM);
    wrmsr(AMD_AP_MTRR_FIX4k_D0000, AMD_MTRR_FIX4K_WB_DRAM);
    wrmsr(AMD_AP_MTRR_FIX4k_D8000, AMD_MTRR_FIX4K_WB_DRAM);
    wrmsr(AMD_AP_MTRR_FIX4k_E0000, AMD_MTRR_FIX4K_WB_DRAM);
    wrmsr(AMD_AP_MTRR_FIX4k_E8000, AMD_MTRR_FIX4K_WB_DRAM);
    wrmsr(AMD_AP_MTRR_FIX4k_F0000, AMD_MTRR_FIX4K_WB_DRAM);
    wrmsr(AMD_AP_MTRR_FIX4k_F8000, AMD_MTRR_FIX4K_WB_DRAM);

    val = rdmsr(MSR_SYS_CFG);
    val &= ~SYS_CFG_MTRR_FIX_DRAM_MOD_EN;
    val |= SYS_CFG_MTRR_FIX_DRAM_EN;
    wrmsr(MSR_SYS_CFG, val);

    return 0;
}

/**
 * Get information about the legacy region and display it
 *
 * @param legacy_region Legacy Region 2 Protocol instance
 * @return EFI_SUCCESS on success, or an error status code on failure
 */
EFI_STATUS print_legacy_region_info(EFI_LEGACY_REGION2_PROTOCOL *legacy_region)
{
    EFI_STATUS status;
    uint32_t descriptor_count = 0;
    EFI_LEGACY_REGION_DESCRIPTOR *descriptors = NULL;
    
    status = legacy_region->GetInfo(
        legacy_region,
        &descriptor_count,
        &descriptors
    );
    
    if (EFI_ERROR(status)) {
        printf("Failed to get legacy region information (status: %lx)\n", status);
        return status;
    }

    printf("Legacy Region Information:\n");
    printf("Found %u region descriptors\n", descriptor_count);

    for (uint32_t i = 0; i < descriptor_count; i++) {
        printf("Region %u: 0x%08x-0x%08x, Granularity: 0x%x bytes\n",
            i,
            descriptors[i].Start,
            descriptors[i].Start + descriptors[i].Length - 1,
            descriptors[i].Granularity);

        printf("  Attribute: ");
        switch (descriptors[i].Attribute) {
            case LegacyRegionDecoded:
                printf("Read Enabled\n");
                break;
            case LegacyRegionNotDecoded:
                printf("Read Disabled\n");
                break;
            case LegacyRegionWriteEnabled:
                printf("Write Enabled\n");
                break;
            case LegacyRegionWriteDisabled:
                printf("Write Disabled\n");
                break;
            case LegacyRegionBootLocked:
                printf("Boot Locked\n");
                break;
            case LegacyRegionNotLocked:
                printf("Not Locked\n");
                break;
            default:
                printf("Unknown\n");
                break;
        }
    }

    return EFI_SUCCESS;
}

static bool test_bios_region_rw(void) {
    uint32_t *bios_region = (uint32_t *)BIOSROM_START;
    uint32_t *bios_region_end = (uint32_t *)BIOSROM_END;
    uint32_t *ptr = bios_region;

    while (ptr < bios_region_end) {
        clflush(ptr);
        uint32_t val = readl(ptr);

        writel(ptr, ~val);
        clflush(ptr);

        if (readl(ptr) != ~val) {
            printf("Unable to write to BIOS region\n");
            return false;
        }

        writel(ptr, val);
        ptr++;
    }

    return true;
}

/**
 * Main function to unlock the BIOS region
 * Tries to use the UEFI protocol first, then falls back to chipset-specific methods
 *
 * @return 0 on success, non-zero on failure
 */
int unlock_bios_region(void)
{
    EFI_LEGACY_REGION2_PROTOCOL *legacy_region = NULL;
    EFI_STATUS status;

    // No need to do anything if the region is already unlocked and working.
    if (test_bios_region_rw()) {
        return 0;
    }

    /* First, try to use the Legacy Region 2 Protocol */
    status = gBS->LocateProtocol(
        &gEfiLegacyRegion2ProtocolGuid,
        NULL,
        (void **)&legacy_region
    );

    if (!EFI_ERROR(status)) {
        /* If we have the protocol, print region information for debugging */
        print_legacy_region_info(legacy_region);
        
        /* Try to unlock using the protocol */
        status = unlock_legacy_region_protocol();
        if (!EFI_ERROR(status) && test_bios_region_rw()) {
            return 0;  /* Success */
        }

        /* Protocol method failed, fall back to chipset-specific methods */
        printf("Protocol method failed, trying chipset-specific methods\n");
    } else {
        printf("Legacy Region 2 Protocol not found, trying chipset-specific methods\n");
    }

    /* Check for known chipsets and use appropriate method */
    uint32_t host_bridge_id = pciConfigReadDWord(0, 0, 0, 0x0);
    printf("Host Bridge ID: 0x%08x\n", host_bridge_id);
    uint16_t vendor_id = (host_bridge_id & 0xFFFF);
    uint16_t device_id = (host_bridge_id >> 16) & 0xFFFF;

    switch (vendor_id) {
        case INTEL_VENDOR_ID:
            switch (device_id) {
                case 0x1237: /* 440FX (QEMU) */
                case 0x7190: /* 440BX/ZX/DX (VMware) */
                case 0x71A0: /* 440GX */
                case 0x7194: /* 440MX */
                case 0x7180: /* 440LX/EX */
                    status = unlock_piix4_pam();
                    break;
                case 0x29C0: /* Q35 (QEMU) */
                case 0x29E0: /* X38/X48 (VirtualBox) */
                    status = unlock_q35_pam();
                    break;
                default:
                    status = unlock_skylake_pam();
                    break;
            }
            break;
        case AMD_VENDOR_ID:
            /* AMD chipsets */
            status = unlock_amd_mtrr();
            break;
        default:
            status = EFI_UNSUPPORTED;
            printf("Unknown chipset, unable to unlock BIOS region\n");
            break;
    }

    return (status == 0 && test_bios_region_rw()) ? 0 : -1;
}
