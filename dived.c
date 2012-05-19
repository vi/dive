// dived -- Server for seamless program starter inside unshared namespaces
// License=MIT ; Created by Vitaly "_Vi" Shukela in 2012

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pwd.h>
#include <grp.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>

#include "recv_fd.h"
#include "safer.h"

#define MAXFD 1024

int saved_fdnums[MAXFD];

void sigchild(int arg) {
    int status;
    wait(&status);
}

int main(int argc, char* argv[]) {
    int sock;
    struct sockaddr_un addr;
    int ret;

    if(argc<2) {
        printf("Usage: dived socket_path [-d] [-D] [-F] [-P] [-S] [-p pidfile]\n");
        printf("Listen UNIX socket and start programs, redirecting fds.\n");
        printf("          -d   detach\n");
        printf("          -D   call daemon(0,0) in children\n");
        printf("          -F   no fork, serve once (debugging)\n");
        printf("          -P   no setuid/setgid/etc\n");
        printf("          -S   no sedsid/ioctl TIOCSCTTY\n");
        printf("          -p   save PID to this file\n");
        return 4;
    }

    {
        struct sigaction sa = {{sigchild}};
        sigaction(SIGCHLD, &sa, NULL);
    }

    unlink(argv[1]);

    int nochilddaemon=1;
    int nodaemon=1;
    int nofork=0;
    int noprivs=0;
    int nosetsid=0;
    char* pidfile=NULL;

    {
        int i;
        for(i=2; i<argc; ++i) {
            if(!strcmp(argv[i], "-d")) {
                nodaemon=0;
            }else
            if(!strcmp(argv[i], "-D")) {
                nochilddaemon=0;
            }else
            if(!strcmp(argv[i], "-F")) {
                nofork=1;
            }else
            if(!strcmp(argv[i], "-P")) {
                noprivs=1;
            }else
            if(!strcmp(argv[i], "-S")) {
                nosetsid=1;
            }else
            if(!strcmp(argv[i], "-p")) {
                pidfile=argv[i+1];
                ++i;
            }else
            {
                fprintf(stderr, "Unknown argument %s\n", argv[i]);
                return 4;
            }
        }
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, argv[1], sizeof(addr.sun_path) - 1);


    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock==-1) {
        perror("socket AF_UNIX");
        return 1;
    }

    ret = bind(sock, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
    if (ret == -1) {
        perror("bind");
        return 2;
    }
    
    ret = listen(sock, 10);
    if (ret == -1) {
        perror("listen");
        return 3;
    }


    if(!nodaemon) daemon(0, 0);

    /* Save pidfile */
    if (pidfile){
        FILE* f = fopen(pidfile, "w");
        fprintf(f, "%d\n", getpid());
        fclose(f);
    }


    for(;;) {
        struct sockaddr_un addr2;
        socklen_t addrlen = sizeof(addr2);
        int fd;

retry_accept:
        fd = accept(sock, (struct sockaddr*)&addr2, &addrlen);

        if(fd == -1) {
            if(errno == EINTR || errno == EAGAIN) goto retry_accept;
            perror("accept");
            return 5;
        }

        int childpid = 0;
        if(!nofork) {
            childpid = fork();
        }

        if(!childpid) {
            close(sock);
            struct ucred cred;
            socklen_t len = sizeof(struct ucred);
            getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len);


            //printf("pid=%ld, euid=%ld, egid=%ld\n", (long) cred.pid, (long) cred.uid, (long) cred.gid);
            
            if(!nochilddaemon) daemon(0,0);
            
            /* Send pid */
            pid_t mypid = getpid();
            safer_write(fd, (char*)&mypid, sizeof(mypid));

            /* Receive and apply current directory */
            int curdir = recv_fd(fd);
            fchdir(curdir);
            close(curdir);


            /* Receive and apply file descriptors */
            memset(saved_fdnums, 0, sizeof saved_fdnums);
            for(;;) {
                int i;
                safer_read(fd, (char*)&i, sizeof(i));
                if(i==-1) {
                    break;
                }
                if(i<-1 || i>=MAXFD) {
                    fprintf(stderr, "dived: Wrong file descriptor number %d\n", i);
                    return 7;
                }
                int f = recv_fd(fd);
                if(i==fd) {
                    /* Move away our socket desciptor */
                    int tmp = dup(fd);
                    close(fd);
                    dup2(f, i);
                    fd = tmp;
                } else {
                    if(f!=i) {
                        dup2(f, i);
                        close(f);
                    }
                }
                if(i<MAXFD) saved_fdnums[i]=1;
            }

            if (!nosetsid) {
                ret = setsid();
                
                #ifndef TIOCSCTTY
                #define TIOCSCTTY 0x540E
                #endif
                ioctl (0, TIOCSCTTY, 1);
            }



            /* Change into the user which is calling us */
            if(!noprivs) {
                char *username = "";

                struct passwd *pw = getpwuid(cred.uid);
                if(pw) {
                    username = pw->pw_name;
                }

                initgroups(username, cred.gid);
                setgid(cred.gid);
                setuid(cred.uid);
            }

            /* Not caring much about security since that point */


            int pid2 = fork();

            if (!pid2) {

                /* Receive argv */
                int numargs, totallen;
                safer_read(fd, (char*)&numargs, sizeof(numargs));
                safer_read(fd, (char*)&totallen, sizeof(totallen));

                char* args=(char*)malloc(totallen);
                safer_read(fd, args, totallen);
                char** argv=malloc((numargs+1)*sizeof(char*));
                int i, u;
                argv[0]=args;
                u=0;
                for(i=0; i<totallen; ++i) {
                    if (!args[i]) {
                        ++u;
                        argv[u]=args+i+1;
                    }
                }
                argv[numargs]=NULL;

                
                /* Receive environment */
                safer_read(fd, (char*)&numargs, sizeof(numargs));
                safer_read(fd, (char*)&totallen, sizeof(totallen));
                char* env=(char*)malloc(totallen);
                safer_read(fd, env, totallen);
                char** envp=malloc((numargs+1)*sizeof(char*));
                envp[0]=env;
                u=0;
                for(i=0; i<totallen; ++i) {
                    if (!env[i]) {
                        ++u;
                        envp[u]=env+i+1;
                    }
                }
                envp[numargs]=NULL;

                close(fd);
                execvpe(argv[0], argv, envp);
                exit(127);
            }

            /* Release client's fds */
            int i;
            for(i=0; i<MAXFD; ++i) {
                if(saved_fdnums[i]) close(i);
            }

            int status;
            waitpid(pid2, &status, 0);

            int exitcode = WEXITSTATUS(status);
            safer_write(fd, (char*)&exitcode, sizeof(exitcode));
            
            exit(1);
        } else {
            close(fd);
        }

    }
    
    return 0;
}
