// dived -- Server for seamless program starter inside unshared namespaces
// License=MIT ; Created by Vitaly "_Vi" Shukela in 2012

#define _GNU_SOURCE

#include <stdlib.h>
#include <stdio.h>
#include <sys/stat.h>   // for umask
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

#define VERSION 400
#define VERSION2 "v0.4"

int saved_fdnums[MAXFD];

void sigchild(int arg) {
    int status;
    wait(&status);
}

int main(int argc, char* argv[], char* envp[]) {
    int sock;
    struct sockaddr_un addr;
    int ret;

    if(argc<2 || !strcmp(argv[1], "-?") || !strcmp(argv[1], "--help") || !strcmp(argv[1], "--version")) {
        printf("Dive server %s (proto %d) https://github.com/vi/dive/\n", VERSION2, VERSION);
        printf("Listen UNIX socket and start programs for each connected client, redirecting fds to client.\n");
        printf("Usage: dived socket_path [-d] [-D] [-F] [-P] [-S] [-p pidfile] [-u user] "
               "[-C mode] [-U user:group] [-- prepended commandline parts]\n");
        printf("          -d --detach           detach\n");
        printf("          -D --children-daemon  call daemon(0,0) in children\n");
        printf("          -F --no-fork          no fork, serve once (debugging)\n");
        printf("          -P --no-setuid        no setuid/setgid/etc\n");
        printf("          -u --user             setuid to this user instead of the client\n");
        printf("          -S --no-setsid        no sedsid/ioctl TIOCSCTTY\n");
        printf("          -p --pidfile          save PID to this file\n");
        printf("          -C --chmod            chmod the socket to this mode (like '0777')\n");
        printf("          -U --chown            chown the socket to this user:group\n");
        printf("          -E --no-environment   Don't let client set environment variables\n");
        printf("          -A --no-argv          Don't let client set command line\n");
        printf("          -H --no-chdir         Don't let client set current directory\n");
        printf("          -O --no-fds           Don't let client set file descriptors\n");
        printf("          -M --no-umask         Don't let client set umask\n");
        printf("          --                    prepend this to each command line ('--' is mandatory)\n");
        printf("              Note that the program being strarted using \"--\" should be\n");
        printf("              as secure as suid programs, but it doesn't know\n");
        printf("              real uid/gid.\n");
        return 4;
    }

    {
        struct sigaction sa = {{sigchild}};
        sigaction(SIGCHLD, &sa, NULL);
    }

    unlink(argv[1]);

    char* socket_path = argv[1];
    int nochilddaemon=1;
    int nodaemon=1;
    int nofork=0;
    int noprivs=0;
    int nosetsid=0;
    char* forceuser=NULL;
    char* pidfile=NULL;
    char* chmod_=NULL;
    char* chown_=NULL;
    char** forced_argv = NULL;
    int forced_argv_count = 0;
    int client_umask = 1;
    int client_chdir = 1;
    int client_fds = 1;
    int client_environment = 1;
    int client_argv = 1;

    {
        int i;
        for(i=2; i<argc; ++i) {
            if(!strcmp(argv[i], "-d") || !strcmp(argv[i], "--detach")) {
                nodaemon=0;
            }else
            if(!strcmp(argv[i], "-D") || !strcmp(argv[i], "--children-daemon")) {
                nochilddaemon=0;
            }else
            if(!strcmp(argv[i], "-F") || !strcmp(argv[i], "--no-fork")) {
                nofork=1;
            }else
            if(!strcmp(argv[i], "-P") || !strcmp(argv[i], "--no-setuid")) {
                noprivs=1;
            }else
            if(!strcmp(argv[i], "-S") || !strcmp(argv[i], "--no-setsid")) {
                nosetsid=1;
            }else
            if(!strcmp(argv[i], "-u") || !strcmp(argv[i], "--user")) {
                forceuser=argv[i+1];
                ++i;
            }else
            if(!strcmp(argv[i], "-p") || !strcmp(argv[i], "--pidfile")) {
                pidfile=argv[i+1];
                ++i;
            }else
            if(!strcmp(argv[i], "-C") || !strcmp(argv[i], "--chmod")) {
                chmod_=argv[i+1];
                ++i;
            }else
            if(!strcmp(argv[i], "-U") || !strcmp(argv[i], "--chown")) {
                chown_=argv[i+1];
                ++i;
            }else
            if(!strcmp(argv[i], "-E") || !strcmp(argv[i], "--no-environment")) {
                client_environment = 0;
            }else
            if(!strcmp(argv[i], "-A") || !strcmp(argv[i], "--no-argv")) {
                client_argv = 0;
            }else
            if(!strcmp(argv[i], "-H") || !strcmp(argv[i], "--no-chdir")) {
                client_chdir = 0;
            }else
            if(!strcmp(argv[i], "-O") || !strcmp(argv[i], "--no-fds")) {
                client_fds = 0;
            }else
            if(!strcmp(argv[i], "-M") || !strcmp(argv[i], "--no-umask")) {
                client_umask = 0;
            }else
            if(!strcmp(argv[i], "--")) {
                forced_argv = &argv[i+1];
                forced_argv_count = argc - (i+1);
                break;
            }else
            {
                fprintf(stderr, "Unknown argument %s\n", argv[i]);
                return 4;
            }
        }
    }

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

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
    
    if (chown_) {
        char *usern = strtok(chown_, ":");
        char *groupn = strtok(NULL, ":");
        if (!groupn) {
            fprintf(stderr, "chown parameter should be in format \"user:group\"\n");
            return 12;
        }
        uid_t targetuid;
        gid_t targetgid;
        
        char* endnum;
        targetuid = strtol(usern, &endnum, 10);
        if (errno || endnum == usern || *endnum) {
            /* not a number */
            struct passwd *userp = getpwnam(usern);
            if (!userp) {
                fprintf(stderr, "User %s not found (and not a number)\n", usern);
                return 12;
            }
            targetuid = userp->pw_uid;
        }
        
        targetgid = strtol(groupn, &endnum, 10);
        if (errno || endnum == groupn || *endnum) {
            struct group *groupp = getgrnam(groupn);
            if (!groupp) {
                fprintf(stderr, "Group %s not found (and not a number)\n", groupn);
                return 13;
            }
            targetgid = groupp->gr_gid;
        }
        
        if (chown(socket_path, targetuid, targetgid) == -1) {
            perror("chown");
            return 14;
        }
    }
    
    if (chmod_) {
        long mask_decoded = strtol(chmod_, NULL, 8);
        if (chmod(socket_path, mask_decoded) == -1) {
            perror("chmod");
            return 15;
        }
    }


    if(!nodaemon) daemon(1, 0);

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
            
            long int version = VERSION;
            safer_write(fd, (char*)&version, sizeof(version));
            
            /* Send pid */
            pid_t mypid = getpid();
            safer_write(fd, (char*)&mypid, sizeof(mypid));

            /* Receive and apply umask */
            mode_t umask_;
            safer_read(fd, (char*)&umask_, sizeof(umask_));
            if (client_umask) umask(umask_);
            
            /* Receive and apply current directory */
            int curdir = recv_fd(fd);
            if (client_chdir) fchdir(curdir);
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
                if(!client_fds)continue;
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



            /* Change into the appropriate user*/
            if(!noprivs) {
                struct passwd *pw;                
                uid_t targetuid = cred.uid;
                gid_t targetgid = cred.gid;
                
                if (forceuser) {
                    pw = getpwnam(forceuser);
                    if (pw) {
                        targetuid = pw->pw_uid;
                        targetgid = pw->pw_gid;
                    }
                } else {
                    /* By default it is user at the other end of the connection */
                    pw = getpwuid(cred.uid);
                }
                
                char *username = "";

                if(pw) {
                    username = pw->pw_name;
                }

                initgroups(username, targetgid);
                setgid(targetgid);
                setuid(targetuid);
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
                if(!client_argv) { numargs=0; totallen=0; }
                char** argv=malloc((numargs+forced_argv_count+1)*sizeof(char*));
                int i, u;
                for(u=0; u<forced_argv_count; ++u) {
                    argv[u] = forced_argv[u];
                }
                u=forced_argv_count; /* explicit > implicit */
                argv[u]=args;
                for(i=0; i<totallen; ++i) {
                    if (!args[i]) {
                        ++u;
                        argv[u]=args+i+1;
                    }
                }
                argv[forced_argv_count + numargs]=NULL;

                
                /* Receive environment */
                safer_read(fd, (char*)&numargs, sizeof(numargs));
                safer_read(fd, (char*)&totallen, sizeof(totallen));
                char* env=(char*)malloc(totallen);
                safer_read(fd, env, totallen);
                char** envp_;
                if (client_environment) {
                    envp_=malloc((numargs+1)*sizeof(char*));
                    envp_[0]=env;
                    u=0;
                    for(i=0; i<totallen; ++i) {
                        if (!env[i]) {
                            ++u;
                            envp_[u]=env+i+1;
                        }
                    }
                    envp_[numargs]=NULL;
                } else {
                    envp_ = envp;
                }

                close(fd);
                execvpe(argv[0], argv, envp_);
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
