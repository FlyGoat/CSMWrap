/*
 * APIC handling for legacy BIOS compatibility
 */

#ifndef _APIC_H
#define _APIC_H

/*
 * Prepare APIC for legacy BIOS operation.
 *
 * Disables LAPIC or configures it for ExtINT passthrough so that
 * legacy 8259 PIC interrupts (especially IRQ0 timer) can reach the CPU.
 *
 * Must be called after ExitBootServices but before CSM initialization.
 */
void apic_prepare_for_legacy(void);

#endif /* _APIC_H */
