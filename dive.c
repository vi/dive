// dived -- Client for seamless program starter inside unshared namespaces
// License=MIT ; Created by Vitaly "_Vi" Shukela in 2012

#define _GNU_SOURCE

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>

#include "send_fd.h"
#include "safer.h"

pid_t theirpid;

/*
void sigint(int arg) {
    kill(-theirpid, SIGINT);
}*/

#define MAXFD 1024

int main(int argc, char* argv[], char* envp[]) {
    int fd;
    struct sockaddr_un addr;
    int ret;

    if(argc<3) {
        printf("Usage: dive socket_path program [arguments]\n");
        printf("Start program in remote 'dived' redirecting fds from here\n");
        printf("       If you want normal \"bash\", use sommand line like that:\n");
        printf("       dive /path/to/socket socat -,raw,echo=0 exec:bash,pty,setsid,stderr\n");
        return 4;
    }
   
    /*
    {
        struct sigaction sa = {{sigint}};
        sigaction(SIGINT, &sa, NULL);
    }
    */

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, argv[1], sizeof(addr.sun_path) - 1);

    argc-=2;
    argv+=2;


    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if(fd==-1) {
        perror("socket AF_UNIX");
        return 1;
    }

    
    ret = connect(fd, (struct sockaddr*)&addr, sizeof addr);
    if(ret==-1) {
        perror("connect");
        return 2;
    }
    
    /* Receive PID */
    safer_read(fd, (char*)&theirpid, sizeof(theirpid));

    //ptrace(PTRACE_ATTACH, theirpid, 0, 0);
    //ptrace(PTRACE_CONT, theirpid, 0, 0);

    /* Send current directory */
    DIR *curdir = opendir(".");
    int curdir_fd = dirfd(curdir);
    send_fd(fd, curdir_fd);
    closedir(curdir);

    /* Send and close all file descriptors */
    int i, u;
    for(i=0; i<MAXFD; ++i) {
        struct stat st;
        ret = fstat(i, &st);
        if(ret!=-1 && i!=fd) {
            safer_write(fd, (char*)&i, sizeof(i));
            send_fd(fd, i);
            if (i!=2) {
                close(i);
            }
        }
    }
    i=-1;
    safer_write(fd, (char*)&i, sizeof(i));

    /* Send argv */
    int totallen=0;
    for(i=0; i<argc; ++i) {
        totallen+=strlen(argv[i])+1;
    }

    char *buf2 = (char*)malloc(totallen);
    u=0;
    for(i=0; i<argc; ++i) {
        int l = strlen(argv[i]);
        memcpy(buf2+u, argv[i], l+1);
        u+=l+1;
    }

    safer_write(fd, (char*)&argc, sizeof(argc));
    safer_write(fd, (char*)&totallen, sizeof(totallen));
    safer_write(fd, buf2, totallen);
    free(buf2);


    /* Send environment variables */
    int envc;
    totallen=0;
    for(envc=0; envp[envc] ;++envc) {
        totallen+=strlen(envp[envc])+1;
    }

    buf2 = (char*)malloc(totallen);
    u=0;
    for(i=0; i<envc; ++i) {
        int l = strlen(envp[i]);
        memcpy(buf2+u, envp[i], l+1);
        u+=l+1;
    }
    safer_write(fd, (char*)&envc, sizeof(envc));
    safer_write(fd, (char*)&totallen, sizeof(totallen));
    safer_write(fd, buf2, totallen);
    free(buf2);


    /* Server is leaving our client socket as "marker" 
     *
     * We will get EOF here when all processes started there exit
     */
    int exitcode;
    ret = safer_read(fd, (char*)&exitcode, sizeof(exitcode));
    if (ret!=sizeof(exitcode)) {
        fprintf(stderr, "dive: Something failed with the server\n");
        return 127;
    }
    
    if (exitcode==127) {
        fprintf(stderr, "dive: Probably can't execute command\n");
    }

    return exitcode;
}
