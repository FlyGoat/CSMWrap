/*
 * BIOS Proxy Helper Core Support
 *
 * Starts a dedicated CPU core to handle BIOS calls when the main core
 * is running in V86 mode (under EMM386). The helper core stays in
 * protected mode and can execute call32 normally.
 */

#include <efi.h>
#include <csmwrap.h>
#include <io.h>
#include <time.h>
#include <uacpi/uacpi.h>
#include <uacpi/tables.h>
#include <uacpi/acpi.h>

#define HELPER_STACK_SIZE 4096

/*
 * Fixed mailbox address in EBDA (Extended BIOS Data Area).
 * EBDA is 1KB at 0x9FC00-0xA0000. SeaBIOS uses ~0x121 bytes at the start.
 * Mailbox at 0x9FF00 is well clear of SeaBIOS's usage.
 * EBDA is normal RAM, immune to OS MTRR changes on the BIOS region.
 */
#define BIOS_PROXY_MAILBOX_ADDR 0x9FF00

struct bios_proxy_mailbox {
    volatile uint32_t request_pending;  /* offset 0 */
    uint32_t func_ptr;                  /* offset 4 */
    uint32_t arg_eax;                   /* offset 8 */
    uint32_t arg_edx;                   /* offset 12 */
    uint32_t arg_ecx;                   /* offset 16 */
    uint32_t result;                    /* offset 20 */
    uint32_t helper_core_id;            /* offset 24 */
};

/* Separately allocated stack for helper core */
static uint8_t *helper_stack_buffer = NULL;

/* Local APIC register offsets (xAPIC MMIO mode) */
#define LAPIC_ID                0x020
#define LAPIC_ICR_LOW           0x300
#define LAPIC_ICR_HIGH          0x310

/* APIC MSRs */
#define IA32_APIC_BASE_MSR      0x1B
#define APIC_BASE_ADDR_MASK     0xFFFFFFFFFFFFF000ULL  /* Bits 12-51 contain base address */
#define APIC_BASE_EXTD          (1 << 10)              /* x2APIC mode enabled */

/* x2APIC MSRs */
#define X2APIC_ICR              0x830
#define X2APIC_ID               0x802

/* Get the LAPIC base address from IA32_APIC_BASE MSR */
static uintptr_t get_lapic_base(void)
{
    return (uintptr_t)(rdmsr(IA32_APIC_BASE_MSR) & APIC_BASE_ADDR_MASK);
}

/* AP trampoline will be placed here */
#define AP_TRAMPOLINE_ADDR      0x7000
#define AP_TRAMPOLINE_VECTOR    0x07  /* SIPI vector = addr / 0x1000 */

static struct bios_proxy_mailbox *mailbox = NULL;
static int selected_ap_id = -1;

/* Detect if running in x2APIC mode */
static int is_x2apic_mode(void)
{
    uint64_t apic_base = rdmsr(IA32_APIC_BASE_MSR);
    return (apic_base & APIC_BASE_EXTD) != 0;
}

/* Signature before 16-bit helper entry: "PRXY16EP" */
#define HELPER_16_ENTRY_SIGNATURE 0x5045363159585250ULL

/*
 * Find the bios_proxy_helper_16_entry in the CSM binary by scanning for signature.
 * Returns the linear address of the entry point.
 */
static uint32_t find_helper_16_entry(void *csm_base, size_t csm_size, uintptr_t final_base)
{
    /* Signature is 8-byte aligned in romlayout.S */
    uint64_t *base = (uint64_t *)csm_base;
    uint64_t *end = (uint64_t *)((uint8_t *)csm_base + csm_size - 16);

    for (uint64_t *ptr = base; ptr < end; ptr++) {
        if (*ptr == HELPER_16_ENTRY_SIGNATURE) {
            uint32_t offset_in_binary = ((uint8_t *)ptr - (uint8_t *)csm_base) + 8;  /* Skip signature */
            return (uint32_t)final_base + offset_in_binary;
        }
    }
    return 0;
}

/* Trampoline from assembly file */
extern uint8_t ap_trampoline_start[];
extern uint32_t ap_trampoline_size_value;
extern uint32_t ap_trampoline_mailbox_offset;
extern uint32_t ap_trampoline_stack_offset;
extern uint32_t ap_trampoline_target16_offset;
extern uint32_t ap_trampoline_helper_ready_offset;

/*
 * Create AP trampoline code at AP_TRAMPOLINE_ADDR
 * target16_addr is a linear address which will be converted to segment:offset
 */
static void create_ap_trampoline(uint32_t target16_addr, uint32_t mailbox_addr, uint32_t stack_top)
{
    uint8_t *tramp = (uint8_t *)AP_TRAMPOLINE_ADDR;
    uint32_t size = ap_trampoline_size_value;

    /* Convert linear address to segment:offset for far jump
     * SeaBIOS is at 0xF0000 and expects CS=0xF000 (uses %cs: prefix for data access)
     */
    uint16_t target_segment = 0xF000;
    uint16_t target_offset = (uint16_t)(target16_addr - 0xF0000);

    memcpy(tramp, ap_trampoline_start, size);
    *(uint32_t *)(tramp + ap_trampoline_mailbox_offset) = mailbox_addr;
    *(uint32_t *)(tramp + ap_trampoline_stack_offset) = stack_top;
    /* Far pointer: offset first, then segment (little-endian) */
    *(uint16_t *)(tramp + ap_trampoline_target16_offset) = target_offset;
    *(uint16_t *)(tramp + ap_trampoline_target16_offset + 2) = target_segment;
}

/*
 * Wait for ICR delivery to complete (xAPIC mode only)
 */
static void wait_icr_idle_xapic(uintptr_t lapic_base)
{
    volatile uint32_t *icr_low = (volatile uint32_t *)(lapic_base + LAPIC_ICR_LOW);
    int count = 0;
    while (*icr_low & (1 << 12)) {
        asm volatile ("pause");
        if (++count > 1000000) return;
    }
}

/*
 * Send INIT-SIPI sequence (xAPIC MMIO mode)
 */
static void start_ap_xapic(uint32_t apic_id)
{
    uintptr_t lapic_base = get_lapic_base();
    volatile uint32_t *icr_high = (volatile uint32_t *)(lapic_base + LAPIC_ICR_HIGH);
    volatile uint32_t *icr_low = (volatile uint32_t *)(lapic_base + LAPIC_ICR_LOW);

    wait_icr_idle_xapic(lapic_base);
    *icr_high = apic_id << 24;
    *icr_low = 0x4500;  /* INIT */
    delay_us(10000);
    wait_icr_idle_xapic(lapic_base);

    *icr_high = apic_id << 24;
    *icr_low = 0x4600 | AP_TRAMPOLINE_VECTOR;  /* SIPI */
    delay_us(200);
    wait_icr_idle_xapic(lapic_base);

    *icr_high = apic_id << 24;
    *icr_low = 0x4600 | AP_TRAMPOLINE_VECTOR;  /* SIPI (retry) */
    wait_icr_idle_xapic(lapic_base);
}

/*
 * Send INIT-SIPI sequence (x2APIC MSR mode)
 */
static void start_ap_x2apic(uint32_t apic_id)
{
    wrmsr(X2APIC_ICR, ((uint64_t)apic_id << 32) | 0x4500);  /* INIT */
    delay_us(10000);
    wrmsr(X2APIC_ICR, ((uint64_t)apic_id << 32) | 0x4600 | AP_TRAMPOLINE_VECTOR);  /* SIPI */
    delay_us(200);
    wrmsr(X2APIC_ICR, ((uint64_t)apic_id << 32) | 0x4600 | AP_TRAMPOLINE_VECTOR);  /* SIPI (retry) */
}

static void start_ap(uint32_t apic_id)
{
    if (is_x2apic_mode()) {
        start_ap_x2apic(apic_id);
    } else {
        start_ap_xapic(apic_id);
    }
}

/*
 * Find an available AP to use as helper core by parsing the MADT.
 * Returns the highest APIC ID AP so the helper core is least likely
 * to be the one the OS would use first.
 */
static int find_available_ap(void)
{
    uint32_t bsp_id;
    if (is_x2apic_mode()) {
        bsp_id = (uint32_t)rdmsr(X2APIC_ID);
    } else {
        uintptr_t lapic_base = get_lapic_base();
        volatile uint32_t *lapic_id_reg = (volatile uint32_t *)(lapic_base + LAPIC_ID);
        bsp_id = (*lapic_id_reg >> 24) & 0xFF;
    }

    struct uacpi_table madt_table;
    if (uacpi_table_find_by_signature(ACPI_MADT_SIGNATURE, &madt_table) != UACPI_STATUS_OK) {
        return -1;
    }

    struct acpi_madt *madt = (struct acpi_madt *)madt_table.virt_addr;
    uint8_t *entry = (uint8_t *)(madt + 1);
    uint8_t *end = (uint8_t *)madt + madt->hdr.length;

    int highest_ap_id = -1;

    while (entry < end) {
        uint8_t type = entry[0];
        uint8_t len = entry[1];
        if (len < 2) break;

        if (type == ACPI_MADT_ENTRY_TYPE_LAPIC) {
            struct acpi_madt_lapic *lapic = (struct acpi_madt_lapic *)entry;
            if ((lapic->flags & 0x3) && lapic->id != bsp_id) {
                if (lapic->id > highest_ap_id) highest_ap_id = lapic->id;
            }
        } else if (type == ACPI_MADT_ENTRY_TYPE_LOCAL_X2APIC) {
            struct acpi_madt_x2apic *x2apic = (struct acpi_madt_x2apic *)entry;
            /* Only consider APs with xAPIC-addressable IDs (<255) so we can
               deliver INIT-SIPI; ID 0xFF is broadcast in physical dest mode */
            if ((x2apic->flags & 0x3) && x2apic->id != bsp_id && x2apic->id < 0xFF) {
                if ((int)x2apic->id > highest_ap_id) highest_ap_id = x2apic->id;
            }
        }
        entry += len;
    }

    uacpi_table_unref(&madt_table);
    return highest_ap_id;
}

/*
 * Compute ACPI table checksum (sum of all bytes must be 0)
 */
static uint8_t acpi_checksum(void *data, size_t len)
{
    uint8_t sum = 0;
    uint8_t *p = (uint8_t *)data;
    for (size_t i = 0; i < len; i++) {
        sum += p[i];
    }
    return sum;
}

static void acpi_fix_checksum(struct acpi_sdt_hdr *hdr)
{
    hdr->checksum = 0;
    hdr->checksum = -acpi_checksum(hdr, hdr->length);
}

/* Pointers to allocated patched tables */
static void *patched_madt = NULL;
static void *patched_rsdt = NULL;
static void *patched_xsdt = NULL;

/*
 * Create a patched MADT with the helper core entry removed.
 * Returns the new MADT or NULL on failure.
 */
static struct acpi_madt *create_patched_madt(int helper_apic_id)
{
    struct uacpi_table madt_table;
    if (uacpi_table_find_by_signature(ACPI_MADT_SIGNATURE, &madt_table) != UACPI_STATUS_OK) {
        return NULL;
    }

    struct acpi_madt *orig_madt = (struct acpi_madt *)madt_table.virt_addr;
    uint32_t orig_len = orig_madt->hdr.length;

    /* First pass: find entries to remove and calculate new size */
    uint8_t *entry = (uint8_t *)(orig_madt + 1);
    uint8_t *end = (uint8_t *)orig_madt + orig_len;
    uint32_t removed_bytes = 0;
    bool found = false;

    while (entry < end) {
        uint8_t type = entry[0];
        uint8_t len = entry[1];
        if (len < 2) break;

        if (type == ACPI_MADT_ENTRY_TYPE_LAPIC) {
            struct acpi_madt_lapic *lapic = (struct acpi_madt_lapic *)entry;
            if (lapic->id == helper_apic_id) {
                removed_bytes += len;
                found = true;
            }
        } else if (type == ACPI_MADT_ENTRY_TYPE_LOCAL_X2APIC) {
            struct acpi_madt_x2apic *x2apic = (struct acpi_madt_x2apic *)entry;
            if (x2apic->id == (uint32_t)helper_apic_id) {
                removed_bytes += len;
                found = true;
            }
        }
        entry += len;
    }

    if (!found) {
        printf("Warning: helper core APIC ID %d not found in MADT\n", helper_apic_id);
        uacpi_table_unref(&madt_table);
        return NULL;
    }

    /* Allocate new MADT (must be < 4GB for legacy OS) */
    uint32_t new_len = orig_len - removed_bytes;
    EFI_PHYSICAL_ADDRESS new_madt_addr = 0xFFFFFFFF;
    EFI_STATUS status = gBS->AllocatePages(
        AllocateMaxAddress,
        EfiACPIReclaimMemory,
        (new_len + 4095) / 4096,
        &new_madt_addr
    );
    if (EFI_ERROR(status)) {
        printf("Failed to allocate memory for patched MADT\n");
        uacpi_table_unref(&madt_table);
        return NULL;
    }

    struct acpi_madt *new_madt = (struct acpi_madt *)(uintptr_t)new_madt_addr;

    /* Copy MADT header */
    memcpy(new_madt, orig_madt, sizeof(struct acpi_madt));

    /* Copy entries, skipping all matching helper core entries */
    uint8_t *dst = (uint8_t *)(new_madt + 1);
    entry = (uint8_t *)(orig_madt + 1);

    while (entry < end) {
        uint8_t type = entry[0];
        uint8_t len = entry[1];
        if (len < 2) break;

        bool skip = false;
        if (type == ACPI_MADT_ENTRY_TYPE_LAPIC) {
            struct acpi_madt_lapic *lapic = (struct acpi_madt_lapic *)entry;
            if (lapic->id == helper_apic_id) skip = true;
        } else if (type == ACPI_MADT_ENTRY_TYPE_LOCAL_X2APIC) {
            struct acpi_madt_x2apic *x2apic = (struct acpi_madt_x2apic *)entry;
            if (x2apic->id == (uint32_t)helper_apic_id) skip = true;
        }

        if (!skip) {
            memcpy(dst, entry, len);
            dst += len;
        }
        entry += len;
    }

    /* Update header */
    new_madt->hdr.length = new_len;
    acpi_fix_checksum(&new_madt->hdr);

    uacpi_table_unref(&madt_table);
    printf("Created patched MADT at %p (removed APIC ID %d)\n",
           (void *)new_madt, helper_apic_id);
    return new_madt;
}

/*
 * Create patched RSDT with updated MADT pointer.
 */
static struct acpi_rsdt *create_patched_rsdt(struct acpi_rsdp *rsdp, uintptr_t new_madt_addr)
{
    if (!rsdp->rsdt_addr) {
        return NULL;
    }

    struct acpi_rsdt *orig_rsdt = (struct acpi_rsdt *)(uintptr_t)rsdp->rsdt_addr;
    uint32_t len = orig_rsdt->hdr.length;
    size_t num_entries = (len - sizeof(struct acpi_sdt_hdr)) / sizeof(uint32_t);

    /* Allocate new RSDT */
    EFI_PHYSICAL_ADDRESS new_rsdt_addr = 0xFFFFFFFF;
    EFI_STATUS status = gBS->AllocatePages(
        AllocateMaxAddress,
        EfiACPIReclaimMemory,
        (len + 4095) / 4096,
        &new_rsdt_addr
    );
    if (EFI_ERROR(status)) {
        printf("Failed to allocate memory for patched RSDT\n");
        return NULL;
    }

    struct acpi_rsdt *new_rsdt = (struct acpi_rsdt *)(uintptr_t)new_rsdt_addr;
    memcpy(new_rsdt, orig_rsdt, len);

    /* Find and update MADT entry */
    for (size_t i = 0; i < num_entries; i++) {
        struct acpi_sdt_hdr *hdr = (struct acpi_sdt_hdr *)(uintptr_t)new_rsdt->entries[i];
        if (hdr && memcmp(hdr->signature, ACPI_MADT_SIGNATURE, 4) == 0) {
            new_rsdt->entries[i] = (uint32_t)new_madt_addr;
            break;
        }
    }

    acpi_fix_checksum(&new_rsdt->hdr);
    printf("Created patched RSDT at %p\n", (void *)new_rsdt);
    return new_rsdt;
}

/*
 * Create patched XSDT with updated MADT pointer.
 */
static struct acpi_xsdt *create_patched_xsdt(struct acpi_rsdp *rsdp, uintptr_t new_madt_addr)
{
    if (rsdp->revision < 2 || !rsdp->xsdt_addr) {
        return NULL;
    }

    struct acpi_xsdt *orig_xsdt = (struct acpi_xsdt *)(uintptr_t)rsdp->xsdt_addr;
    uint32_t len = orig_xsdt->hdr.length;
    size_t num_entries = (len - sizeof(struct acpi_sdt_hdr)) / sizeof(uint64_t);

    /* Allocate new XSDT */
    EFI_PHYSICAL_ADDRESS new_xsdt_addr = 0xFFFFFFFF;
    EFI_STATUS status = gBS->AllocatePages(
        AllocateMaxAddress,
        EfiACPIReclaimMemory,
        (len + 4095) / 4096,
        &new_xsdt_addr
    );
    if (EFI_ERROR(status)) {
        printf("Failed to allocate memory for patched XSDT\n");
        return NULL;
    }

    struct acpi_xsdt *new_xsdt = (struct acpi_xsdt *)(uintptr_t)new_xsdt_addr;
    memcpy(new_xsdt, orig_xsdt, len);

    /* Find and update MADT entry */
    for (size_t i = 0; i < num_entries; i++) {
        struct acpi_sdt_hdr *hdr = (struct acpi_sdt_hdr *)(uintptr_t)new_xsdt->entries[i];
        if (hdr && memcmp(hdr->signature, ACPI_MADT_SIGNATURE, 4) == 0) {
            new_xsdt->entries[i] = (uint64_t)new_madt_addr;
            break;
        }
    }

    acpi_fix_checksum(&new_xsdt->hdr);
    printf("Created patched XSDT at %p\n", (void *)new_xsdt);
    return new_xsdt;
}

/*
 * Patch ACPI tables to hide the helper core from the OS.
 * Updates the RSDP copy in CSM region to point to patched tables.
 */
static int patch_acpi_hide_helper(void *rsdp_copy, int helper_apic_id)
{
    extern uintptr_t g_rsdp;  /* Original RSDP from acpi.c */

    if (!g_rsdp) {
        printf("No RSDP available for MADT patching\n");
        return -1;
    }

    struct acpi_rsdp *orig_rsdp = (struct acpi_rsdp *)g_rsdp;
    struct acpi_rsdp *copy_rsdp = (struct acpi_rsdp *)rsdp_copy;

    /* Create patched MADT */
    struct acpi_madt *new_madt = create_patched_madt(helper_apic_id);
    if (!new_madt) {
        return -1;
    }
    patched_madt = new_madt;

    /* Create patched RSDT */
    struct acpi_rsdt *new_rsdt = create_patched_rsdt(orig_rsdp, (uintptr_t)new_madt);
    if (new_rsdt) {
        patched_rsdt = new_rsdt;
        copy_rsdp->rsdt_addr = (uint32_t)(uintptr_t)new_rsdt;
    }

    /* Create patched XSDT (if ACPI 2.0+) */
    struct acpi_xsdt *new_xsdt = create_patched_xsdt(orig_rsdp, (uintptr_t)new_madt);
    if (new_xsdt) {
        patched_xsdt = new_xsdt;
        copy_rsdp->xsdt_addr = (uint64_t)(uintptr_t)new_xsdt;
    }

    /* Fix RSDP checksums */
    copy_rsdp->checksum = 0;
    copy_rsdp->checksum = -acpi_checksum(copy_rsdp, 20);  /* First 20 bytes for ACPI 1.0 */

    if (copy_rsdp->revision >= 2) {
        copy_rsdp->extended_checksum = 0;
        copy_rsdp->extended_checksum = -acpi_checksum(copy_rsdp, copy_rsdp->length);
    }

    printf("ACPI tables patched to hide helper core (APIC ID %d)\n", helper_apic_id);
    return 0;
}

static void *saved_csm_base = NULL;
static size_t saved_csm_size = 0;
static void *saved_rsdp_copy = NULL;

/*
 * Initialize the BIOS proxy helper core.
 * Call after CSM binary is loaded but before ExitBootServices.
 *
 * Parameters:
 *   csm_base  - Pointer to the loaded CSM binary
 *   csm_size  - Size of the CSM binary
 *   rsdp_copy - Pointer to the RSDP copy in CSM region (for MADT patching)
 */
int bios_proxy_init(void *csm_base, size_t csm_size, void *rsdp_copy)
{
    printf("Initializing BIOS proxy helper core...\n");

    saved_csm_base = csm_base;
    saved_csm_size = csm_size;
    saved_rsdp_copy = rsdp_copy;

    /* Zero out mailbox at fixed EBDA address */
    mailbox = (struct bios_proxy_mailbox *)BIOS_PROXY_MAILBOX_ADDR;
    memset((void *)mailbox, 0, sizeof(struct bios_proxy_mailbox));
    printf("BIOS proxy mailbox at 0x%x (EBDA)\n", BIOS_PROXY_MAILBOX_ADDR);

    selected_ap_id = find_available_ap();
    if (selected_ap_id < 0) {
        printf("No AP available for BIOS proxy\n");
        return -1;
    }

    /* Patch ACPI tables to hide the helper core from the OS */
    if (rsdp_copy) {
        if (patch_acpi_hide_helper(rsdp_copy, selected_ap_id) < 0) {
            printf("Warning: Failed to patch MADT, OS may see helper core\n");
            /* Continue anyway - helper will still work */
        }
    }

    /* Allocate stack for helper core (must be < 4GB) */
    EFI_PHYSICAL_ADDRESS stack_addr = 0xFFFFFFFF;
    EFI_STATUS status = gBS->AllocatePages(
        AllocateMaxAddress,
        EfiRuntimeServicesData,
        (HELPER_STACK_SIZE + 4095) / 4096,
        &stack_addr
    );
    if (EFI_ERROR(status)) {
        printf("Failed to allocate helper stack\n");
        return -1;
    }
    helper_stack_buffer = (uint8_t *)(uintptr_t)stack_addr;

    printf("BIOS proxy ready (AP %d)\n", selected_ap_id);
    return 0;
}

/*
 * Start the helper core.
 * Call after ExitBootServices.
 */
int bios_proxy_start_helper(uintptr_t csm_final_base)
{
    if (!saved_csm_base || selected_ap_id < 0) {
        return -1;
    }

    uint32_t target16_addr = find_helper_16_entry(saved_csm_base, saved_csm_size, csm_final_base);
    if (!target16_addr) {
        return -1;
    }

    /* Mailbox is at fixed EBDA address, already set in bios_proxy_init */

    if (!helper_stack_buffer) {
        return -1;
    }
    uint32_t stack_top = (uint32_t)(uintptr_t)(helper_stack_buffer + HELPER_STACK_SIZE);

    create_ap_trampoline(target16_addr, BIOS_PROXY_MAILBOX_ADDR, stack_top);

    start_ap(selected_ap_id);

    /* Wait for helper to signal ready */
    volatile uint32_t *helper_ready = (volatile uint32_t *)(uintptr_t)(AP_TRAMPOLINE_ADDR + ap_trampoline_helper_ready_offset);
    for (int timeout = 0; timeout < 100; timeout++) {
        asm volatile ("" ::: "memory");
        if (*helper_ready) {
            return 0;
        }
        delay(10000000);
    }

    return -1;
}

/*
 * Get the APIC ID of the helper core.
 * Returns -1 if no helper core has been selected.
 */
int bios_proxy_get_helper_apic_id(void)
{
    return selected_ap_id;
}
