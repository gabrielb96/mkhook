#include <stdio.h>
#include <unistd.h>

void func_A(const char *msg, int magic);
void func_B(int magic);

void func_A(const char *msg, int magic)
{
    puts(msg);
    printf("magic is 0x%x\n", magic);
}

void func_B(int magic)
{
    func_A("called from func_B", magic);
}

int main(void)
{
    int magicA = 0;
    int magicB = 0x3fff;

    printf("Hello from PID %d\n", getpid());
    while (magicA < 0x3fff || magicB > 0) {
        func_A("called from main", magicA++);
        func_B(magicB--);
        sleep(1);
    }

    return 0;
}
