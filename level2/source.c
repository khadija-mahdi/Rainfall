#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

char* p()
{
    char buffer[64];
    fflush(stdout);
    gets(buffer);

    if (((uintptr_t)__builtin_return_address(0) & 0xb0000000) != 0xb0000000) {
        puts(buffer);
        return strdup(buffer);
    }

    printf("%p\n", __builtin_return_address(0));
    exit(1);
}

int main()
{
    p();
    return 0;
}
