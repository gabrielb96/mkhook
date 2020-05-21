/* Copyright (c) 2020 Gabriel Manoel 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include "string_utils.h"
#include "abort.h"
#include "mem.h"

char *c_strdup(const char *s)
{
    char *temp_buf = strdup(s);

    if (!temp_buf)
            abort_on_error(ENOMEM);

    return temp_buf;
}

size_t c_fmtlen(const char *format, ...)
{
    va_list ap;
    size_t len;

    va_start(ap, format);
    len = c_vfmtlen(format, ap);
    va_end(ap);

    return len;
}

size_t c_vfmtlen(const char *format, va_list ap)
{
    va_list ap_copy;
    char dummy_buffer[1];
    size_t len;

    if (!format)
        return 0;

    va_copy(ap_copy, ap);
    // vsnprintf() returns the number that would have been written
    len = vsnprintf(dummy_buffer, 1, format, ap_copy);
    va_end(ap);

    return len;
}

/*
 * calls c_vsprintf_alloc() internally.
 */
size_t c_sprintf_alloc(char **buf, const char *format, ...)
{
    va_list ap;
    size_t written;

    va_start(ap, format);
    written = c_vsprintf_alloc(buf, format, ap);
    va_end(ap);

    return written;
}

/*
 * Sames as vsprintf, but it allocates a buffer using c_malloc().
 * The caller should free() the buffer when done using it.
 *
 * The c_malloc() function aborts in case of ENOMEM.
 */
size_t c_vsprintf_alloc(char **buf, const char *format, va_list ap)
{
    *buf = c_malloc(c_vfmtlen(format, ap));
    return vsprintf(*buf, format, ap);
}
