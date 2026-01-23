#include <stdarg.h>
#include <stddef.h>

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

static void _putchar(int character, void *extra_arg) {
    (void)extra_arg;

    if (character == '\n') {
        _putchar('\r', NULL);
    }

    CHAR16 string[2];
    string[0] = character;
    string[1] = 0;

    if (!gST->ConOut || !gST->ConOut->OutputString) {
        /* No console output available */
        return;
    }

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
