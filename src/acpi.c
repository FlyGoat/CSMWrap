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

// Borrowed from https://github.com/limine-bootloader/limine/blob/v9.x/common/lib/time.c

static int get_jdn(int days, int months, int years) {
    return (1461 * (years + 4800 + (months - 14) / 12)) / 4
        + (367 * (months - 2 - 12 * ((months - 14) / 12))) / 12
        - (3 * ((years + 4900 + (months - 14) / 12) / 100)) / 4
        + days - 32075;
}

#define NS_PER_S UINT64_C(1000000000)

static uint64_t get_unix_epoch(
        uint32_t nanoseconds, uint8_t seconds, uint8_t minutes, uint8_t hours,
        uint8_t days, uint8_t months, uint16_t years) {
    uint64_t jdn_current = get_jdn(days, months, years);
    uint64_t jdn_1970 = get_jdn(1, 1, 1970);
    uint64_t jdn_diff = jdn_current - jdn_1970;

    return (jdn_diff * 60 * 60 * 24 * NS_PER_S)
        + (hours * 3600 * NS_PER_S)
        + (minutes * 60 * NS_PER_S)
        + (seconds * NS_PER_S)
        + nanoseconds;
}

uacpi_u64 uacpi_kernel_get_nanoseconds_since_boot(void) {
    EFI_TIME time;
    if (gRT->GetTime(&time, NULL) != EFI_SUCCESS) {
        return 0;
    }

    uint64_t boot_time = get_unix_epoch(
        gTimeAtBoot.Nanosecond, gTimeAtBoot.Second, gTimeAtBoot.Minute,
        gTimeAtBoot.Hour, gTimeAtBoot.Day, gTimeAtBoot.Month, gTimeAtBoot.Year);
    uint64_t current_time = get_unix_epoch(
        time.Nanosecond, time.Second, time.Minute, time.Hour, time.Day, time.Month, time.Year);

    return current_time - boot_time;
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
