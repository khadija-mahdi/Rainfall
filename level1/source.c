#include <stdio.h>
#include <stdlib.h>

void run(void)
{
    fwrite("Good... Wait what?\n", 1, 19, stdout);
    system("/bin/sh");
    return;
}

void main(void)

{
    /*
        sub $0x50, %esp      // Reserve 80 bytes on the stack for locals (including buffer + padding)
        lea 0x10(%esp), %eax // Compute address of buffer: starts 16 bytes into that space
        This means buffer size = 80 - 16 = 64 bytes
    */
    char local_50[64];
    gets(local_50);
    return;
}