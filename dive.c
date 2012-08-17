// dived -- Client for seamless program starter inside unshared namespaces
// License=MIT ; Created by Vitaly "_Vi" Shukela in 2012

#define _GNU_SOURCE

#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>   // for umask
#include <sys/un.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <stdlib.h>
#include <unistd.h>
#include <dirent.h>
#include <signal.h>
#include <sys/stat.h>
#include  <fcntl.h>

#include "send_fd.h"
#include "safer.h"

pid_t theirpid;

/*
void sigint(int arg) {
    kill(-theirpid, SIGINT);
}*/

#define MAXFD 1024

#define VERSION 800
#define VERSION2 "v0.8"

int main(int argc, char* argv[], char* envp[]) {
    int fd;
    struct sockaddr_un addr;
    int ret;
    long int version;

    if(argc<2 || !strcmp(argv[1], "-?") || !strcmp(argv[1], "--help") || !strcmp(argv[1], "--version")) {
        printf("Dive client %s (proto %d) https://github.com/vi/dive/\n", VERSION2, VERSION);
        printf("Usage: dive {socket_path|@abstract_address} [program arguments]\n");
        printf("Start program in remote 'dived' and 'invite' it here by redirecting fds\n");
        printf("       If don't have normal \"bash\" behaviour by default, there's workaround commands like that:\n");
        printf("         dive /path/to/socket reptyr -L bash\n");
        printf("         dive /path/to/socket socat -,raw,echo=0 exec:bash,pty,setsid,stderr\n");
        printf("       If calling shell loses terminal ownership, there are workarounds:\n");
        printf("         \"exec bash\" after using dive (to regain the terminal)\n");
        printf("         reptyr -L dive /path/to/socket bash\n");
        printf("    Environment variables:\n");
        printf("    DIVE_CURDIR   - use this current directory instead of \".\"\n");
        printf("    DIVE_ROOTDIR  - use this root directory instead of \"/\"\n");
        printf("    DIVE_TERMINAL - use this instead of \"@0\" (can be path to file or @fd)\n");
        printf("    Note that DIVE_* variables are filtered out by dived.\n");
        return 4;
    }
   
    /*
    {
        struct sigaction sa = {{sigint}};
        sigaction(SIGINT, &sa, NULL);
    }
    */

    const char* curdir_path  = ".";
    const char* rootdir_path = "/";
    const char* terminal_path = "@0";
    if (getenv("DIVE_CURDIR"))   curdir_path   = getenv("DIVE_CURDIR");
    if (getenv("DIVE_ROOTDIR"))  rootdir_path  = getenv("DIVE_ROOTDIR");
    if (getenv("DIVE_TERMINAL")) terminal_path = getenv("DIVE_TERMINAL");


    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, argv[1], sizeof(addr.sun_path) - 1);
    if (addr.sun_path[0]=='@') {
        addr.sun_path[0]=0; /* Abstract socket */
    }

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
    
    
    /* Receive version */
    safer_read(fd, (char*)&version, sizeof(version));
    if (version != VERSION) {
        fprintf(stderr, "Incompatible versions of dive and dived\n");
        return 3;
    }
    
    /* Receive PID */
    safer_read(fd, (char*)&theirpid, sizeof(theirpid));

    //ptrace(PTRACE_ATTACH, theirpid, 0, 0);
    //ptrace(PTRACE_CONT, theirpid, 0, 0);

    /* Send terminal FD */
    int terminal = -1;
    if(terminal_path[0]=='@') {
        terminal = atoi(terminal_path+1);
    } else {
        terminal = open(terminal_path, O_RDONLY, 0777);
    }
    if (send_fd(fd, terminal) == -1) {
        safer_write(fd, "X", 1); /* Dummy instead of terminal */
    }

    if(terminal_path[0]!='@') {
        close(terminal);
    }
    
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


    /* Send umask */
    mode_t umask_ = umask(0);
    umask(umask_);
    safer_write(fd, (char*)&umask_, sizeof(umask_));
    
    /* Send root directory */
    DIR* rootdir = opendir(rootdir_path);
    int rootdir_fd = dirfd(rootdir);
    send_fd(fd, rootdir_fd);
    closedir(rootdir);
    
    /* Send current directory */
    DIR *curdir = opendir(curdir_path);
    int curdir_fd = dirfd(curdir);
    send_fd(fd, curdir_fd);
    closedir(curdir);


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
