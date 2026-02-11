#include <stddef.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>

#define NANOPRINTF_IMPLEMENTATION
#define NANOPRINTF_USE_FIELD_WIDTH_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_PRECISION_FORMAT_SPECIFIERS 0
#define NANOPRINTF_USE_FLOAT_FORMAT_SPECIFIERS 0
#define NANOPRINTF_USE_LARGE_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_SMALL_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_BINARY_FORMAT_SPECIFIERS 1
#define NANOPRINTF_USE_WRITEBACK_FORMAT_SPECIFIERS 1
#include <nanoprintf.h>

#include <efi.h>
#include <csmwrap.h>
#include <io.h>
#include <flanterm.h>
#include <flanterm_backends/fb.h>

struct flanterm_context *flanterm_ctx = NULL;

#ifndef SERIAL_DEBUG_ENABLED
#   define SERIAL_DEBUG_ENABLED 0
#endif

static void _putchar(int character, void *extra_arg) {
    (void)extra_arg;

    if (character == '\n') {
        _putchar('\r', NULL);
    }

#if SERIAL_DEBUG_ENABLED == 0
    if (flanterm_ctx != NULL) {
        flanterm_write(flanterm_ctx, (const char *)&character, 1);
    }
#else
    if (!gST->ConOut || !gST->ConOut->OutputString) {
        /* No console output available */
        static bool serial_initialised = false;
        if (!serial_initialised) {
            outb(0x3f8 + 3, 0x00);
            outb(0x3f8 + 1, 0x00);
            outb(0x3f8 + 3, 0x80);

            uint16_t divisor = 1;
            outb(0x3f8 + 0, divisor & 0xff);
            outb(0x3f8 + 1, (divisor >> 8) & 0xff);

            outb(0x3f8 + 1, 0x00);
            outb(0x3f8 + 3, 0x03);
            outb(0x3f8 + 2, 0xc7);
            outb(0x3f8 + 4, 0x0b);

            serial_initialised = true;
        }

        while ((inb(0x3f8 + 5) & 0x20) == 0);
        outb(0x3f8, character);

        if (flanterm_ctx != NULL) {
            static bool flanterm_refreshed = false;
            if (!flanterm_refreshed) {
                flanterm_full_refresh(flanterm_ctx);
                flanterm_refreshed = true;
            }
            flanterm_write(flanterm_ctx, (const char *)&character, 1);
        }

        return;
    }

    CHAR16 string[2];
    string[0] = character;
    string[1] = 0;

    gST->ConOut->OutputString(gST->ConOut, string);
#endif
}

int printf(const char *restrict fmt, ...) {
    va_list l;
    va_start(l, fmt);
    int ret = npf_vpprintf(_putchar, NULL, fmt, l);
    va_end(l);
    return ret;
}

int vprintf(const char *restrict fmt, va_list l) {
    return npf_vpprintf(_putchar, NULL, fmt, l);
}

int snprintf(char *buffer, size_t bufsz, const char *restrict fmt, ...) {
    va_list l;
    va_start(l, fmt);
    int ret = npf_vsnprintf(buffer, bufsz, fmt, l);
    va_end(l);
    return ret;
}
