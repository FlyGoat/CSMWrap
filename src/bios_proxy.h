/*
 * BIOS Proxy Helper Core Support
 *
 * Provides a dedicated CPU core to handle BIOS calls when the main core
 * is running in V86 mode (under EMM386).
 */

#ifndef _BIOS_PROXY_H
#define _BIOS_PROXY_H

#include <stddef.h>
#include <stdint.h>

/*
 * Initialize the BIOS proxy helper core.
 * Call this after CSM binary is loaded but before Legacy16Boot.
 *
 * @param csm_base   Base address of the loaded CSM binary
 * @param csm_size   Size of the CSM binary in bytes
 * @param rsdp_copy  Pointer to the RSDP copy in CSM region (for MADT patching)
 *                   If NULL, MADT patching is skipped.
 * @return 0 on success, -1 on failure
 */
int bios_proxy_init(void *csm_base, size_t csm_size, void *rsdp_copy);

/*
 * Start the helper core.
 * Call this after ExitBootServices when we have full control of the system,
 * and after the CSM binary has been copied to its final location.
 *
 * @param csm_final_base  The address where the CSM binary was copied to
 * @return 0 on success, -1 on failure
 */
int bios_proxy_start_helper(uintptr_t csm_final_base);

/*
 * Get the APIC ID of the helper core.
 * Returns -1 if no helper core has been selected.
 * Used by mptable generation to exclude the helper from MP tables.
 */
int bios_proxy_get_helper_apic_id(void);

#endif /* _BIOS_PROXY_H */
