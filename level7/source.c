#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char c[68];

typedef struct
{
    int id;
    char *data;
} node_t;

void m()
{
    time_t tVar1;
    tVar1 = time(0);
    printf("%s - %ld\n", c, tVar1);
}

int main(int argc, char *argv[])
{
    node_t *node1;
    node_t *node2;
    FILE *stream;

    if (argc < 3)
    {
        printf("Usage: %s <arg1> <arg2>\n", argv[0]);
        return 1;
    }

    node1 = (node_t *)malloc(sizeof(node_t));
    node1->id = 1;
    node1->data = malloc(8);

    node2 = (node_t *)malloc(sizeof(node_t));
    node2->id = 2;
    node2->data = malloc(8);

    strcpy(node1->data, argv[1]);
    strcpy(node2->data, argv[2]);
    stream = fopen("/home/user/level8/.pass", "r");
    fgets(c, 68, stream);
    puts("~~");
    return 0;
}