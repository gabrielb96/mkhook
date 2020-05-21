/* Copyright (c) 2020 Gabriel Manoel
 *
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

#include <errno.h>

#include "mem.h"
#include "abort.h"

static void *initialize_ptr(void *ptr, size_t size);

static void *initialize_ptr(void *ptr, size_t size)
{
    for (size_t i = 0; i <= size; i++)
        ((char *)ptr)[i] = 0;

    return ptr;
}

/*
 * Aborts on case of failure (ENOMEM), printing an error message to stderr.
 *
 * The returned buffer is initialized to all zeros to avoid memory disclosure.
 */
void *c_malloc(size_t size)
{
    void *buf = malloc(size);

    if (!buf)
        abort_on_error(ENOMEM);

    return initialize_ptr(buf, size);
}

inline void c_free(void *ptr)
{
    free(ptr);
}

/*
 * Like c_malloc, this function aborts in case of ENOMEM.
 */
void *c_calloc(size_t nmemb, size_t size)
{
    void *buf = calloc(nmemb, size);

    if (!buf)
        abort_on_error(ENOMEM);

    return buf;
}
