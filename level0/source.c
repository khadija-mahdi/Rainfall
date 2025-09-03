#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main(int argc, char *argv[]) {

    int val = atoi(argv[1]);

    if (val == 423) {
        int options = 0;

        
        gid_t egid = getegid();
        uid_t euid = geteuid();

        setresgid(egid, egid, egid);

        setresuid(euid, euid, euid);

        char *args[] = { "/bin/sh", NULL };
        execv("/bin/sh", args);

    } else {
        fwrite("NO !\n", 1, 5, stdout);
    }

    return 0;
}
