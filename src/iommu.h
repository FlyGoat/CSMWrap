#ifndef IOMMU_H
#define IOMMU_H

#include <stdbool.h>

/*
 * Disable all IOMMUs (Intel VT-d and AMD-Vi) to allow legacy OS booting.
 *
 * This is called after ExitBootServices but before CSM initialization.
 * UEFI may have configured IOMMU translation tables, but after PCI BAR
 * relocation, those tables reference stale addresses. Disabling the IOMMU
 * prevents DMA failures in the legacy OS.
 *
 * Returns true if IOMMUs were found and disabled, false otherwise.
 */
bool iommu_disable(void);

#endif
