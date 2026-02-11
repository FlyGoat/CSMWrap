#include <efi.h>
#include "csmwrap.h"

#include "io.h"

#define PCI_DEVICE_NUMBER_PCH_P2SB                 31
#define PCI_FUNCTION_NUMBER_PCH_P2SB               1

#define	SBREG_BAR		0x10
#define SBREG_BARH      0x14

/* PCH sideband parameters vary by CPU generation - detected via CPUID */
struct pch_info {
    uintptr_t sbreg_bar;
    uint8_t pid_itss;
};

/* Intel CPU model numbers (Family 6) */
#define INTEL_SKYLAKE_L         0x4E
#define INTEL_SKYLAKE           0x5E
#define INTEL_SKYLAKE_X         0x55
#define INTEL_KABYLAKE_L        0x8E
#define INTEL_KABYLAKE          0x9E
#define INTEL_COMETLAKE         0xA5
#define INTEL_COMETLAKE_L       0xA6
#define INTEL_ICELAKE_L         0x7E
#define INTEL_TIGERLAKE_L       0x8C
#define INTEL_TIGERLAKE         0x8D
#define INTEL_ALDERLAKE         0x97
#define INTEL_ALDERLAKE_L       0x9A
#define INTEL_RAPTORLAKE        0xB7
#define INTEL_RAPTORLAKE_P      0xBA
#define INTEL_RAPTORLAKE_S      0xBF
#define INTEL_METEORLAKE        0xAC
#define INTEL_METEORLAKE_L      0xAA
#define INTEL_ARROWLAKE         0xC6
#define INTEL_ARROWLAKE_H       0xC5
#define INTEL_ARROWLAKE_U       0xB5
#define INTEL_PANTHERLAKE_L     0xCC

static bool get_pch_info(struct pch_info *info)
{
    uint32_t eax, ebx, ecx, edx;
    asm volatile("cpuid" : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx) : "a"(1), "c"(0));

    uint8_t family = (eax >> 8) & 0xF;
    uint8_t model = (eax >> 4) & 0xF;
    if (family == 6 || family == 15)
        model |= ((eax >> 16) & 0xF) << 4;

    if (family != 6)
        return false;

    switch (model) {
    /* Meteor Lake / Arrow Lake / Panther Lake: SBREG=0xE0000000 */
    case INTEL_METEORLAKE:
    case INTEL_METEORLAKE_L:
    case INTEL_ARROWLAKE:
    case INTEL_ARROWLAKE_H:
    case INTEL_ARROWLAKE_U:
        info->sbreg_bar = 0xE0000000;
        info->pid_itss = 0xCA;
        return true;
    case INTEL_PANTHERLAKE_L:
        info->sbreg_bar = 0xE0000000;
        info->pid_itss = 0x69;
        return true;
    /* Alder Lake / Raptor Lake Desktop (S-series, PCH-S): SBREG=0xE0000000 */
    case INTEL_ALDERLAKE:
    case INTEL_RAPTORLAKE:
    case INTEL_RAPTORLAKE_S:
        info->sbreg_bar = 0xE0000000;
        info->pid_itss = 0xC4;
        return true;
    /* Alder Lake / Raptor Lake Mobile (P-series, PCH-P): SBREG=0xFD000000 */
    case INTEL_ALDERLAKE_L:
    case INTEL_RAPTORLAKE_P:
        info->sbreg_bar = 0xFD000000;
        info->pid_itss = 0xC4;
        return true;
    /* Skylake through Tiger Lake: SBREG=0xFD000000 */
    case INTEL_SKYLAKE_L:
    case INTEL_SKYLAKE:
    case INTEL_SKYLAKE_X:
    case INTEL_KABYLAKE_L:
    case INTEL_KABYLAKE:
    case INTEL_COMETLAKE:
    case INTEL_COMETLAKE_L:
    case INTEL_ICELAKE_L:
    case INTEL_TIGERLAKE_L:
    case INTEL_TIGERLAKE:
        info->sbreg_bar = 0xFD000000;
        info->pid_itss = 0xC4;
        return true;
    default:
        return false;
    }
}

#define R_PCH_PCR_ITSS_ITSSPRC                0x3300
#define B_PCH_PCR_ITSS_ITSSPRC_8254CGE        (1 << 2)

#define PCH_PCR_ADDRESS(Base, Pid, Offset)    ((void *)(Base | (UINT32) (((Offset) & 0x0F0000) << 8) | ((UINT8)(Pid) << 16) | (UINT16) ((Offset) & 0xFFFF)))

#define R_P2SB_CFG_P2SBC                      0xE0
#define B_P2SB_CFG_P2SBC_HIDE                 (1 << 8)

static int pit_8254cge_workaround(void)
{
    struct pch_info pch;
    uint32_t reg;
    uintptr_t base;
    bool p2sb_hide = false;
    int pch_pci_bus = 0;

    if (!get_pch_info(&pch)) {
        printf("Unknown CPU model, skipping PIT workaround\n");
        return 0;
    }

    reg = pciConfigReadDWord(pch_pci_bus, PCI_DEVICE_NUMBER_PCH_P2SB,
                             PCI_FUNCTION_NUMBER_PCH_P2SB,
                             0x0);

    /* P2SB maybe hidden, try unhide it first */
    if ((reg & 0xFFFF) == 0xffff) {
        reg = pciConfigReadDWord(pch_pci_bus, PCI_DEVICE_NUMBER_PCH_P2SB,
                                 PCI_FUNCTION_NUMBER_PCH_P2SB,
                                 R_P2SB_CFG_P2SBC);
        reg &= ~B_P2SB_CFG_P2SBC_HIDE;
        pciConfigWriteDWord(pch_pci_bus, PCI_DEVICE_NUMBER_PCH_P2SB,
                            PCI_FUNCTION_NUMBER_PCH_P2SB,
                            R_P2SB_CFG_P2SBC, reg);
        p2sb_hide = true;
    }

    reg = pciConfigReadDWord(pch_pci_bus, PCI_DEVICE_NUMBER_PCH_P2SB,
                              PCI_FUNCTION_NUMBER_PCH_P2SB,
                              0x0);

    if ((reg & 0xFFFF) != 0x8086) {
        /* P2SB locked hidden - use CPUID-determined SBREG_BAR */
        base = pch.sbreg_bar;
    } else {
        reg = pciConfigReadDWord(pch_pci_bus, PCI_DEVICE_NUMBER_PCH_P2SB,
                                  PCI_FUNCTION_NUMBER_PCH_P2SB,
                                  SBREG_BAR);
        base = reg & ~0x0F;

        reg = pciConfigReadDWord(pch_pci_bus, PCI_DEVICE_NUMBER_PCH_P2SB,
                                  PCI_FUNCTION_NUMBER_PCH_P2SB,
                                  SBREG_BARH);
#ifdef __LP64__
        base |= ((uint64_t)reg & 0xFFFFFFFF) << 32;
#else
        if (reg) {
            printf("Invalid P2SB BARH\n");
            goto hide_and_return;
        }
#endif
        /* Hide P2SB again */
        if (p2sb_hide) {
            reg = pciConfigReadDWord(pch_pci_bus, PCI_DEVICE_NUMBER_PCH_P2SB,
                                     PCI_FUNCTION_NUMBER_PCH_P2SB,
                                     R_P2SB_CFG_P2SBC);
            reg |= B_P2SB_CFG_P2SBC_HIDE;
            pciConfigWriteDWord(pch_pci_bus, PCI_DEVICE_NUMBER_PCH_P2SB,
                                PCI_FUNCTION_NUMBER_PCH_P2SB,
                                R_P2SB_CFG_P2SBC, reg);
        }
    }

    reg = readl(PCH_PCR_ADDRESS(base, pch.pid_itss, R_PCH_PCR_ITSS_ITSSPRC));
    printf("ITSSPRC = %x, ITSSPRC.8254CGE= %x\n", reg, !!(reg & B_PCH_PCR_ITSS_ITSSPRC_8254CGE));
    /* Disable 8254CGE */
    reg &= ~B_PCH_PCR_ITSS_ITSSPRC_8254CGE;
    writel(PCH_PCR_ADDRESS(base, pch.pid_itss, R_PCH_PCR_ITSS_ITSSPRC), reg);

    return 0;

#ifndef __LP64__
hide_and_return:
    if (p2sb_hide) {
        reg = pciConfigReadDWord(pch_pci_bus, PCI_DEVICE_NUMBER_PCH_P2SB,
                                 PCI_FUNCTION_NUMBER_PCH_P2SB,
                                 R_P2SB_CFG_P2SBC);
        reg |= B_P2SB_CFG_P2SBC_HIDE;
        pciConfigWriteDWord(pch_pci_bus, PCI_DEVICE_NUMBER_PCH_P2SB,
                            PCI_FUNCTION_NUMBER_PCH_P2SB,
                            R_P2SB_CFG_P2SBC, reg);
    }
    return 0;
#endif
}

int apply_intel_platform_workarounds(void)
{
    uint16_t vendor_id;

    vendor_id = pciConfigReadWord(0, 0, 0, 0x0);

    if (vendor_id != 0x8086) {
        return 0;
    }

    pit_8254cge_workaround();

    return 0;
}
