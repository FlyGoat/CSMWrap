#ifndef PRINTF_H
#define PRINTF_H

#include <stddef.h>
#include <flanterm.h>

extern struct flanterm_context *flanterm_ctx;

int printf(const char *restrict fmt, ...);
int snprintf(char *buffer, size_t bufsz, const char *restrict fmt, ...);

#endif
