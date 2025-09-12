#include <stdio.h>
#include <stdlib.h>

void v(unsigned int a0)
{
    char v0[520];
    fgets(&v0, 0x200, stdin);
    unsigned int m = printf(&v0);
    a0 = m;
    if (a0 != 64)
        return;
    fwrite("Wait what?!\n", 1, 12, stdout);
    system("/bin/sh");
    return;
}

void main()
{
    char v0; 

    v(&v0);
    return;
}