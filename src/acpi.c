#include <efi.h>
#include <io.h>
#include <pci.h>
#include <printf.h>
#include "csmwrap.h"

#include <uacpi/kernel_api.h>
#include <uacpi/tables.h>
#include <uacpi/uacpi.h>

uintptr_t g_rsdp = 0;

static inline const char *uacpi_log_level_to_string(uacpi_log_level lvl) {
    switch (lvl) {
        case UACPI_LOG_DEBUG:
            return "DEBUG";
        case UACPI_LOG_TRACE:
            return "TRACE";
        case UACPI_LOG_INFO:
            return "INFO";
        case UACPI_LOG_WARN:
            return "WARN";
        case UACPI_LOG_ERROR:
        default:
            return "ERROR";
    }
}

void uacpi_kernel_log(enum uacpi_log_level lvl, const char *text) {
    printf("[uACPI][%s] %s", uacpi_log_level_to_string(lvl), text);
}

void *uacpi_kernel_map(uacpi_phys_addr addr, EFI_UNUSED uacpi_size len) {
    return (void*)((uintptr_t)addr);
}

void uacpi_kernel_unmap(EFI_UNUSED void *ptr, EFI_UNUSED uacpi_size len) {
}

uacpi_status uacpi_kernel_pci_device_open(uacpi_pci_address address, uacpi_handle *out_handle) {
    void *handle;
    if (gBS->AllocatePool(EfiLoaderData, sizeof(struct pci_address), &handle) != EFI_SUCCESS) {
        return UACPI_STATUS_OUT_OF_MEMORY;
    }

    struct pci_address *pci_address = (struct pci_address *)handle;
    pci_address->segment = address.segment;
    pci_address->bus = address.bus;
    pci_address->slot = address.device;
    pci_address->function = address.function;

    *out_handle = handle;
    return UACPI_STATUS_OK;
}

void uacpi_kernel_pci_device_close(uacpi_handle handle) {
    gBS->FreePool(handle);
}

uacpi_status uacpi_kernel_pci_read8(uacpi_handle device, uacpi_size offset, uacpi_u8 *value) {
    *value = pci_read8((struct pci_address *)device, offset);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_pci_read16(uacpi_handle device, uacpi_size offset, uacpi_u16 *value) {
    *value = pci_read16((struct pci_address *)device, offset);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_pci_read32(uacpi_handle device, uacpi_size offset, uacpi_u32 *value) {
    *value = pci_read32((struct pci_address *)device, offset);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_pci_write8(uacpi_handle device, uacpi_size offset, uacpi_u8 value) {
    pci_write8((struct pci_address *)device, offset, value);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_pci_write16(uacpi_handle device, uacpi_size offset, uacpi_u16 value) {
    pci_write16((struct pci_address *)device, offset, value);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_pci_write32(uacpi_handle device, uacpi_size offset, uacpi_u32 value) {
    pci_write32((struct pci_address *)device, offset, value);
    return UACPI_STATUS_OK;
}

struct mapped_io {
    uacpi_io_addr base;
    uacpi_size len;
};

uacpi_status uacpi_kernel_io_map(uacpi_io_addr base, uacpi_size len, uacpi_handle *out_handle) {
    void *handle;
    if (gBS->AllocatePool(EfiLoaderData, sizeof(struct mapped_io), &handle) != EFI_SUCCESS) {
        return UACPI_STATUS_OUT_OF_MEMORY;
    }

    struct mapped_io *io = (struct mapped_io *)handle;
    io->base = base;
    io->len = len;

    *out_handle = handle;
    return UACPI_STATUS_OK;
}

void uacpi_kernel_io_unmap(uacpi_handle handle) {
    gBS->FreePool(handle);
}

uacpi_status uacpi_kernel_io_read8(uacpi_handle handle, uacpi_size offset, uacpi_u8 *out_value) {
    struct mapped_io *io = (struct mapped_io *)handle;
    if (offset >= io->len) {
        return UACPI_STATUS_INVALID_ARGUMENT;
    }

    *out_value = inb(io->base + offset);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_read16(uacpi_handle handle, uacpi_size offset, uacpi_u16 *out_value) {
    struct mapped_io *io = (struct mapped_io *)handle;
    if (offset >= io->len) {
        return UACPI_STATUS_INVALID_ARGUMENT;
    }

    *out_value = inw(io->base + offset);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_read32(uacpi_handle handle, uacpi_size offset, uacpi_u32 *out_value) {
    struct mapped_io *io = (struct mapped_io *)handle;
    if (offset >= io->len) {
        return UACPI_STATUS_INVALID_ARGUMENT;
    }

    *out_value = inl(io->base + offset);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_write8(uacpi_handle handle, uacpi_size offset, uacpi_u8 in_value) {
    struct mapped_io *io = (struct mapped_io *)handle;
    if (offset >= io->len) {
        return UACPI_STATUS_INVALID_ARGUMENT;
    }

    outb(io->base + offset, in_value);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_write16(uacpi_handle handle, uacpi_size offset, uacpi_u16 in_value) {
    struct mapped_io *io = (struct mapped_io *)handle;
    if (offset >= io->len) {
        return UACPI_STATUS_INVALID_ARGUMENT;
    }

    outw(io->base + offset, in_value);
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_io_write32(uacpi_handle handle, uacpi_size offset, uacpi_u32 in_value) {
    struct mapped_io *io = (struct mapped_io *)handle;
    if (offset >= io->len) {
        return UACPI_STATUS_INVALID_ARGUMENT;
    }

    outl(io->base + offset, in_value);
    return UACPI_STATUS_OK;
}

uacpi_handle uacpi_kernel_create_spinlock(void) {
    void *handle;
    if (gBS->AllocatePool(EfiLoaderData, 0x1, &handle) != EFI_SUCCESS) {
        return NULL;
    }

    return handle;
}

void uacpi_kernel_free_spinlock(uacpi_handle handle) {
    gBS->FreePool(handle);
}

uacpi_cpu_flags uacpi_kernel_lock_spinlock(uacpi_handle handle) {
    (void)handle;
    return 0;
}

void uacpi_kernel_unlock_spinlock(uacpi_handle handle, uacpi_cpu_flags cpu_flags) {
    (void)handle;
    (void)cpu_flags;
}

uacpi_handle uacpi_kernel_create_event(void) {
    void *handle;
    if (gBS->AllocatePool(EfiLoaderData, 0x1, &handle) != EFI_SUCCESS) {
        return NULL;
    }

    return handle;
}

void uacpi_kernel_free_event(uacpi_handle handle) {
    gBS->FreePool(handle);
}

uacpi_bool uacpi_kernel_wait_for_event(uacpi_handle handle, uacpi_u16 timeout) {
    (void)handle;
    (void)timeout;
    return UACPI_TRUE;
}

void uacpi_kernel_signal_event(uacpi_handle handle) {
    (void)handle;
}

void uacpi_kernel_reset_event(uacpi_handle handle) {
    (void)handle;
}

static uint64_t tsc_freq;  /* TSC ticks per second, calibrated at init */
static uint64_t tsc_boot;  /* TSC value at calibration time */

/*
 * Calibrate TSC frequency using gBS->Stall() as a reference.
 * Called once during acpi_init(), before any uACPI timing calls.
 */
static void calibrate_tsc(void) {
    uint64_t start = rdtsc();
    gBS->Stall(1000);  /* 1ms */
    uint64_t end = rdtsc();
    tsc_freq = (end - start) * 1000;
    tsc_boot = rdtsc();
}

uacpi_u64 uacpi_kernel_get_nanoseconds_since_boot(void) {
    uint64_t elapsed = rdtsc() - tsc_boot;
    /* Convert to nanoseconds: elapsed * 1e9 / tsc_freq */
    return elapsed / (tsc_freq / 1000000000ULL);
}

void uacpi_kernel_stall(uacpi_u8 usec) {
    gBS->Stall(usec);
}

void uacpi_kernel_sleep(uacpi_u64 msec) {
    gBS->Stall(msec * 1000);
}

uacpi_thread_id uacpi_kernel_get_thread_id(void) {
    return (uacpi_thread_id)1;
}

uacpi_status uacpi_kernel_handle_firmware_request(uacpi_firmware_request *request) {
    (void)request;
    return UACPI_STATUS_UNIMPLEMENTED;
}

uacpi_status uacpi_kernel_install_interrupt_handler(
        uacpi_u32 irq, uacpi_interrupt_handler handler, uacpi_handle ctx,
        uacpi_handle *out_irq_handle) {
    (void)irq;
    (void)handler;
    (void)ctx;
    (void)out_irq_handle;
    return UACPI_STATUS_OK;
}

uacpi_status uacpi_kernel_uninstall_interrupt_handler(uacpi_interrupt_handler handler, uacpi_handle irq_handle) {
    (void)handler;
    (void)irq_handle;
    return UACPI_STATUS_UNIMPLEMENTED;
}

uacpi_status uacpi_kernel_schedule_work(uacpi_work_type work_type, uacpi_work_handler handler, uacpi_handle ctx) {
    (void)work_type;
    (void)handler;
    (void)ctx;
    return UACPI_STATUS_UNIMPLEMENTED;
}

uacpi_status uacpi_kernel_wait_for_work_completion(void) {
    return UACPI_STATUS_UNIMPLEMENTED;
}

void *uacpi_kernel_alloc(uacpi_size size) {
    void *result;
    if (gBS->AllocatePool(EfiLoaderData, size, &result) != EFI_SUCCESS) {
        return NULL;
    }

    return result;
}

void uacpi_kernel_free(void *mem) {
    if (mem != NULL) {
        gBS->FreePool(mem);
    }
}

uacpi_handle uacpi_kernel_create_mutex(void) {
    void *handle;
    if (gBS->AllocatePool(EfiLoaderData, 0x1, &handle) != EFI_SUCCESS) {
        return NULL;
    }

    return handle;
}

void uacpi_kernel_free_mutex(uacpi_handle handle) {
    gBS->FreePool(handle);
}

uacpi_status uacpi_kernel_acquire_mutex(uacpi_handle handle, uacpi_u16 timeout) {
    (void)handle;
    (void)timeout;
    return UACPI_STATUS_OK;
}

void uacpi_kernel_release_mutex(uacpi_handle handle) {
    (void)handle;
}

uacpi_status uacpi_kernel_get_rsdp(uacpi_phys_addr *rsdp) {
    if (!g_rsdp) {
        return UACPI_STATUS_NOT_FOUND;
    }

    *rsdp = g_rsdp;
    return UACPI_STATUS_OK;
}

static void *early_table_buffer;

bool acpi_init(struct csmwrap_priv *priv) {
    UINTN i;
    EFI_GUID acpiGuid = ACPI_TABLE_GUID;
    EFI_GUID acpi2Guid = ACPI_20_TABLE_GUID;
    void *table_target = priv->csm_bin + (priv->csm_efi_table->AcpiRsdPtrPointer - priv->csm_bin_base);

    calibrate_tsc();

    for (i = 0; i < gST->NumberOfTableEntries; i++) {
        EFI_CONFIGURATION_TABLE *table;
        table = gST->ConfigurationTable + i;

        if (!efi_guidcmp(table->VendorGuid, acpi2Guid)) {
            printf("Found ACPI 2.0 RSDT at %x, copied to %x\n", (uintptr_t)table->VendorTable, (uintptr_t)table_target);
            memcpy(table_target, table->VendorTable, sizeof(EFI_ACPI_2_0_ROOT_SYSTEM_DESCRIPTION_POINTER));
            g_rsdp = (uintptr_t)table->VendorTable;
            break;
        }
    }

    if (g_rsdp == 0) {
        for (i = 0; i < gST->NumberOfTableEntries; i++) {
            EFI_CONFIGURATION_TABLE *table;
            table = gST->ConfigurationTable + i;

            if (!efi_guidcmp(table->VendorGuid, acpiGuid)) {
                printf("Found ACPI 1.0 RSDT at %x, copied to %x\n", (uintptr_t)table->VendorTable, (uintptr_t)table_target);
                memcpy(table_target, table->VendorTable, sizeof(EFI_ACPI_1_0_ROOT_SYSTEM_DESCRIPTION_POINTER));
                g_rsdp = (uintptr_t)table->VendorTable;
                break;
            }
        }
    }

    if (g_rsdp) {
        const size_t table_buffer_size = 4096;

        if (gBS->AllocatePool(EfiLoaderData, table_buffer_size, &early_table_buffer) != EFI_SUCCESS) {
            return false;
        }

        enum uacpi_status uacpi_status;
        uacpi_status = uacpi_setup_early_table_access(early_table_buffer, table_buffer_size);
        if (uacpi_status != UACPI_STATUS_OK) {
            printf("uACPI early table setup failed: %s\n", uacpi_status_to_string(uacpi_status));
            return false;
        }

        return true;
    }

    printf("No ACPI RSDT found\n");
    return false;
}

/*
 * Initialize ACPI namespace without running _INI methods.
 * This is sufficient for PCI root bridge discovery via _CRS evaluation.
 * Avoids side effects like changing power button behavior.
 */
bool acpi_namespace_init(void) {
    enum uacpi_status uacpi_status;

    uacpi_status = uacpi_initialize(UACPI_FLAG_NO_ACPI_MODE);
    if (uacpi_status != UACPI_STATUS_OK) {
        printf("uACPI initialization failed: %s\n", uacpi_status_to_string(uacpi_status));
        return false;
    }

    uacpi_status = uacpi_namespace_load();
    if (uacpi_status != UACPI_STATUS_OK) {
        printf("uACPI namespace load failed: %s\n", uacpi_status_to_string(uacpi_status));
        return false;
    }

    /* Note: We intentionally skip uacpi_namespace_initialize() which runs _INI methods */

    return true;
}
