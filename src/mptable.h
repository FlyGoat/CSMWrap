/*
 * MP Table Generation from ACPI
 *
 * Generates Intel MultiProcessor Specification tables from ACPI MADT
 * for legacy BIOS compatibility.
 */

#ifndef _MPTABLE_H
#define _MPTABLE_H

#include <stdint.h>
#include <stdbool.h>

struct csmwrap_priv;

/*
 * Initialize and build MP tables from ACPI MADT.
 *
 * @param priv  CSMWrap private data structure
 * @return true on success, false on failure
 */
bool mptable_init(struct csmwrap_priv *priv);

#endif /* _MPTABLE_H */
