// Pre-built static i386 version: http://vi-server.org/pub/no_new_privs

#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/prctl.h>

int main(int argc, char* argv[])
{
    if (argc == 1 || !strcmp(argv[1], "--help")) {
        printf("Usage: no_new_privs program arguments...\n");
        printf("    It disables filesystem-based privilege elevation for started programs.\n");
        printf("    ping, passwd, su, sudo and others will not work\n");
        return 1;
    }

    #ifndef PR_SET_NO_NEW_PRIVS
    #define PR_SET_NO_NEW_PRIVS 38
    #endif
    
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
        perror("prctl(PR_SET_NO_NEW_PRIVS)");
        return 2;
    }

    execvp(argv[1], argv+1);
    perror("execvp");
    return 127;
}
