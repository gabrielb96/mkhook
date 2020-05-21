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

#include <stdint.h>
#include <stddef.h>
#include <sys/mman.h>

#pragma once

typedef uint64_t addr64_t;
typedef uint32_t addr32_t;
typedef addr32_t addr_rel32_t;

// permissions for the perms field of the mmap_region struct
#define PERM_READ   1
#define PERM_WRITE  2
#define PERM_EXEC   4
#define PERM_SHARED 8
#define PERM_PRIVATE 16

struct mmap_region {
    addr64_t base;
    addr64_t end;
    size_t size;
    int perms;
    addr32_t offset;
    // dev;
    // inode;
    char *mapped_file;
};

struct process_image {
    int pid;
    struct mmap_region *regions;
    size_t regions_num;
};

#define bytearray(var) (uint8_t *)&(var)

static int attach_to_process(int pid);
static int detach_from_process(int pid);

static void *fmmap(void *addr, size_t *length, int prot, int flags, const char *pathname, off_t offset);

static void parse_proc_line(const char *line, struct mmap_region *buf);
static void read_mem_regions(struct process_image *process);
static struct process_image *create_proc_image(int pid);
static void destroy_proc_image(struct process_image *image);

static size_t pheader_size(addr32_t offset, const char *file);
static void hexdump(uint8_t *bytes, size_t length, ...);
