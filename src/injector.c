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

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <limits.h>

#include "CHelper/string_utils.h"
#include "injector.h"

static int attach_to_process(int pid)
{
    int err = ptrace(PTRACE_ATTACH, pid, NULL, NULL);

    if (err >= 0)
        waitpid(pid, NULL, 0);

    return err;
}

static int detach_from_process(int pid)
{
    return (ptrace(PTRACE_DETACH, pid, 0, 0) < 0);
}

static void *fmmap(void *addr, size_t *length, int prot, int flags,
                                const char *pathname, off_t offset)
{
    int fd;
    struct stat st;
    void *mmap_addr = NULL;

    fd = open(pathname, O_RDWR);
    if (fd == -1)
        return NULL;

    if (*length == 0) {
        if (fstat(fd, &st) == -1)
            return NULL;
        *length = st.st_size;
    }

    mmap_addr = mmap(addr, *length, prot, flags, fd, offset);
    close(fd);

    return mmap_addr;
}

static void parse_proc_line(const char *line, struct mmap_region *buf)
{
    char *end_addr = NULL;
    char *perms = NULL;
    const char *mapped_file = NULL;

    buf->base = strtoul(line, &end_addr, 16);
    buf->end = strtoul(end_addr+1, &perms, 16);
    buf->size = buf->end - buf->base;

    buf->perms = 0;
    perms++;
    while (*perms != ' ') {
        switch (*perms++) {
            case 'r':
                buf->perms |= PERM_READ;
                break;
            case 'w':
                buf->perms |= PERM_WRITE;
                break;
            case 'x':
                buf->perms |= PERM_EXEC;
                break;
            case 's':
                buf->perms |= PERM_SHARED;
                break;
            case 'p':
                buf->perms |= PERM_PRIVATE;
                break;
            default:
                break;
        }
    }
    buf->offset = strtoul(perms+1, NULL, 16);

    mapped_file = &line[strlen(line)-1];
    if (isdigit(*mapped_file)) {  // last field is the inode so we have a anonymous map
        buf->mapped_file = NULL;
    } else {
        while (*mapped_file != ' ' && *mapped_file != '[')
            mapped_file--;
        if (*mapped_file == ' ')
            mapped_file++;
        buf->mapped_file = strndup(mapped_file, strlen(mapped_file)-1);
    }
}


static void read_mem_regions(struct process_image *process)
{
    char *filename = malloc(PATH_MAX);
    FILE *maps_file = NULL;
    char *line = NULL;
    size_t line_len = 0;
    size_t lines = 0;
    void *temp_buf = NULL;

    snprintf(filename, PATH_MAX, "/proc/%d/maps", process->pid);
    maps_file = fopen(filename, "r");
    if (!maps_file)
        return;

    process->regions = NULL;
    while (getline(&line, &line_len, maps_file) != -1) {
        lines++;
        temp_buf = reallocarray(process->regions, lines, sizeof(*process->regions));
        if (!temp_buf)
            break;
        process->regions = temp_buf;
        parse_proc_line(line, process->regions+(lines-1));
    }

    process->regions_num = lines;
    free(line);
}

static struct process_image *create_proc_image(int pid)
{
    struct process_image *proc_image = malloc(sizeof(*proc_image));

    proc_image->pid = pid;
    read_mem_regions(proc_image);

    return proc_image;
}

static void destroy_proc_image(struct process_image *image)
{
    for (size_t i = 0; i > image->regions_num; i++)
        free(image->regions[i].mapped_file);
    free(image->regions);
    free(image);
}

static size_t pheader_size(addr32_t offset, const char *file)
{
    size_t size = 0;
    char *command_str = NULL;
    FILE *pipe = NULL;
    char *line = NULL;
    size_t line_len = 0;

    // FIXME: port this function to use only C code without popen()
    c_sprintf_alloc(&command_str, "readelf -l %s | grep 0x%016lx -A1 | grep -v LOAD | awk '{print $1}'", file, offset);

    pipe = popen(command_str, "r");
    getline(&line, &line_len, pipe);
    size = strtoul(line, NULL, 16);

    pclose(pipe);
    free(line);
    free(command_str);

    return size;
}

static void hexdump(uint8_t *bytes, size_t length, ...)
{
    addr32_t offset = 0;
    int line_offset = 1;
    //TODO: hexdump() needs to suports different kinds of hexdump format (think of xxd)
    while(offset < length) {
        printf("%02hhx", bytes[offset++]);

        if (line_offset == 16) {
            printf("\n");
            line_offset = 1;
            continue;
        } else if (line_offset == 8) {
            printf("  ");
        } else {
            printf(" ");
        }
        line_offset++;
    }
    if (line_offset != 16)
        printf("\n");
}

int main(int argc, char *argv[])
{
    const char *shellcode = NULL;
    void *shellcode_mmaped = NULL;
    addr_rel32_t address_to_hook;
    int target_pid;
    int shellcode_file_fd = 0;
    struct process_image *process = NULL;
    struct mmap_region *text_segment = NULL;
    addr_rel32_t padding_start;
    addr_rel32_t hook_address;

    size_t shellcode_sz = 0;
    unsigned long original_bytes;
    unsigned char add_rsp_8[4] = "\x48\x83\xc4\x08";    // add  rsp, 0x8
    unsigned char jmpn_function[5] = "\xe9\xfc\xff\xff\xff";  //	jmp near function_address
    int hook_address_jmpto;
    int trampoline_jmp_address;
    int err;

    unsigned char hook_asm[8] = "\xe9\x00\x00\x00\x00\x90\x90\x90";

    if (argc < 4) {
        fprintf(stderr, "usage: ./injector shellcode address_to_hook target_pid\n");
        exit(0);
    }

    shellcode = argv[1];
    address_to_hook = strtoul(argv[2], NULL, 16);
    target_pid = atoi(argv[3]);

    printf("attaching to target %d\n", target_pid);

    err = attach_to_process(target_pid);
    if (err != 0) {
        printf("failed to attach to target (%s)\n", strerror(err));
        exit(EXIT_FAILURE);
    }

    printf("preparing shellcode...\n");
    shellcode_mmaped = fmmap(0, &shellcode_sz, PROT_READ | PROT_WRITE, MAP_PRIVATE, shellcode, 0);
    if (!shellcode_mmaped) {
        fprintf(stderr, "error mapping \"%s\"\n", shellcode);
        exit(1);
    }
    printf("gathering information about the process image\n");
    process = create_proc_image(target_pid);
    if (!process) {
        fprintf(stderr, "failed to open /proc/%d/maps :(\n", target_pid);
        exit(1);
    }

    for (size_t i = 0; i < process->regions_num; i++) {
        if (process->regions[i].perms & PERM_EXEC) {
            text_segment = &process->regions[i];
            break;
        }
    }
    printf(".text segment at 0x%lx with size 0x%lx\n", text_segment->base, text_segment->size);

    padding_start = pheader_size(text_segment->offset, text_segment->mapped_file) + text_segment->base;
    printf("padding start at address 0x%x\n", padding_start);

    original_bytes = ptrace(PTRACE_PEEKTEXT, target_pid, address_to_hook, NULL);
    printf("original bytes = 0x%lx\n", original_bytes);
    hexdump(bytearray(original_bytes), sizeof(original_bytes));

    hook_address = (padding_start+17) - (address_to_hook+5);
    printf("padding_start+17 = 0x%x (%d)\n", padding_start, padding_start);
    printf("address_to_hook+5 = 0x%x (%d)\n", address_to_hook, address_to_hook);
    printf("hook_address = 0x%x (%d)\n", hook_address, hook_address);

    *(addr_rel32_t *)(hook_asm+1) = hook_address;
    hook_asm[7] = (unsigned char)(original_bytes >> 7 * 8);

    printf("writing hook to function...");
    hexdump(hook_asm, sizeof(hook_asm));
    ptrace(PTRACE_POKETEXT, target_pid, address_to_hook, *(unsigned long *)hook_asm);

    trampoline_jmp_address = (address_to_hook+7) - (padding_start+17);
    *(int *)(jmpn_function+1) = trampoline_jmp_address;
    printf("writing trampoline...\n");

    ptrace(PTRACE_POKETEXT, target_pid, padding_start, *(unsigned long *)add_rsp_8);
    ptrace(PTRACE_POKETEXT, target_pid, padding_start+4, original_bytes);
    ptrace(PTRACE_POKETEXT, target_pid, padding_start+4+sizeof(original_bytes), *(unsigned long *)jmpn_function);

    printf("writing shellcode...\n");
    hook_address_jmpto = padding_start - (padding_start+4+sizeof(original_bytes)+5+shellcode_sz);

    // FIXME: if shellcode is a empty file then it will segfault at injector.c::289
    *(int*)(shellcode_mmaped+(shellcode_sz-4)) = hook_address_jmpto;
    printf("here\n");
    hexdump(shellcode_mmaped, shellcode_sz);

    for (size_t i = 0; i < shellcode_sz; i+=sizeof(unsigned long))
        ptrace(PTRACE_POKETEXT, target_pid, padding_start+4+sizeof(original_bytes)+5+i, *(unsigned long *)(shellcode_mmaped+i));

    destroy_proc_image(process);
    close(shellcode_file_fd);
    munmap(shellcode_mmaped, shellcode_sz);

    printf("detaching from target\n");
    detach_from_process(target_pid);

    printf("** It worked!! :)\n...or maybe not ¯\\_(ツ)_/¯\n");
}
