#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main() {
    char buf[128];
    char *auth = NULL;
    char *service = NULL;

    while (1) {
        printf("%p, %p \n", auth, service);

        if (!fgets(buf, 128, stdin))
            break;

        if (!strncmp(buf, "auth ", 5)) {
            char *payload = buf + 5;
            auth = malloc(4);
            *(int *)auth = 0; 

            if (strlen(payload) <= 30) {
                strcpy(auth, payload); 
            }
        }

        if (!strncmp(buf, "reset", 5)) {
            free(auth); 
            free(service);
        }

        if (!strncmp(buf, "service", 7)) {
            char *payload = buf + 7;
            service = strdup(payload);
        }

        if (!strncmp(buf, "login", 5)) {
            if (auth && *((int *)(auth + 32)))
                system("/bin/sh");
            else
                fwrite("Password:\n", 1, 10, stdout);
        }
    }

    return 0;
}
