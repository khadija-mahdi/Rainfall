#include <stdio.h>
#include <stdlib.h>

void v(unsigned int a0)
{
    char buffer[520];
    fgets(&buffer, 0x200, stdin);
    unsigned int m = printf(&buffer);
    a0 = m;
    if (a0 != 64)
        return;
    fwrite("Wait what?!\n", 1, 12, stdout);
    system("/bin/sh");
    return;
}

void main()
{
    char buffer; 

    v(&buffer);
    return;
}