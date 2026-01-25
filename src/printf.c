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

#define SERIAL_DEBUG_ENABLED 0

#if SERIAL_DEBUG_ENABLED == 1
static bool serial_initialised = false;
#endif

static void _putchar(int character, void *extra_arg) {
    (void)extra_arg;

    if (character == '\n') {
        _putchar('\r', NULL);
    }

    if (!gST->ConOut || !gST->ConOut->OutputString) {
        /* No console output available */
#if SERIAL_DEBUG_ENABLED == 1
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
#endif

        return;
    }

    CHAR16 string[2];
    string[0] = character;
    string[1] = 0;

    gST->ConOut->OutputString(gST->ConOut, string);
}

int printf(const char *restrict fmt, ...) {
    va_list l;
    va_start(l, fmt);
    int ret = npf_vpprintf(_putchar, NULL, fmt, l);
    va_end(l);
    return ret;
}

int snprintf(char *buffer, size_t bufsz, const char *restrict fmt, ...) {
    va_list l;
    va_start(l, fmt);
    int ret = npf_vsnprintf(buffer, bufsz, fmt, l);
    va_end(l);
    return ret;
}
