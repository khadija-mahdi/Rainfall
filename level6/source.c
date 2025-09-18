#include <stdio.h>
#include <stdlib.h>
#include <string.h>

 n()
{
    system("/bin/cat /home/user/level7/.pass");
    return ;
}

 m()
{
    puts("Nope");
    return;
}

int main(int argc, char** argv, char** envp)
{
    char* buffer = malloc(64);
    int (** buffer_1)() = malloc(4);
    *buffer_1 = m;
    strcpy(buffer, argv[1]);
    return (*buffer_1)();
}