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

struct dived_options {
    char* socket_path;
    int nochilddaemon;
    int nodaemon;
    int nofork;
    int noprivs;
    int nosetsid;
    char* forceuser;
    char* pidfile;
    char* chmod_;
    char* chown_;
    char** forced_argv;
    int forced_argv_count;
    int client_umask;
    int client_chdir;
    int client_fds;
    int client_environment;
    int client_argv;
    char* chroot_;
    char** envp;
} options;

int serve(struct dived_options* opts) {
    int sock;
    struct sockaddr_un addr;
    int ret;
    
    unlink(opts->socket_path);
    
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, opts->socket_path, sizeof(addr.sun_path) - 1);

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
    
    if (opts->chown_) {
        char *usern = strtok(opts->chown_, ":");
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
        
        if (chown(opts->socket_path, targetuid, targetgid) == -1) {
            perror("chown");
            return 14;
        }
    }
    
    if (opts->chmod_) {
        long mask_decoded = strtol(opts->chmod_, NULL, 8);
        if (chmod(opts->socket_path, mask_decoded) == -1) {
            perror("chmod");
            return 15;
        }
    }


    if(!opts->nodaemon) daemon(1, 0);
        
    if (opts->chroot_) {
        chroot(opts->chroot_);
    }

    /* Save pidfile */
    if (opts->pidfile){
        FILE* f = fopen(opts->pidfile, "w");
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
        if(!opts->nofork) {
            childpid = fork();
        }

        if(!childpid) {
            close(sock);
            struct ucred cred;
            socklen_t len = sizeof(struct ucred);
            getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len);


            //printf("pid=%ld, euid=%ld, egid=%ld\n", (long) cred.pid, (long) cred.uid, (long) cred.gid);
            
            if(!opts->nochilddaemon) daemon(0,0);
            
            long int version = VERSION;
            safer_write(fd, (char*)&version, sizeof(version));
            
            /* Send pid */
            pid_t mypid = getpid();
            safer_write(fd, (char*)&mypid, sizeof(mypid));

            /* Receive and apply umask */
            mode_t umask_;
            safer_read(fd, (char*)&umask_, sizeof(umask_));
            if (opts->client_umask) umask(umask_);
            
            /* Receive and apply current directory */
            int curdir = recv_fd(fd);
            if (opts->client_chdir) fchdir(curdir);
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
                if(!opts->client_fds)continue;
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

            if (!opts->nosetsid) {
                ret = setsid();
                
                #ifndef TIOCSCTTY
                #define TIOCSCTTY 0x540E
                #endif
                ioctl (0, TIOCSCTTY, 1);
            }



            /* Change into the appropriate user*/
            if(!opts->noprivs) {
                struct passwd *pw;                
                uid_t targetuid = cred.uid;
                gid_t targetgid = cred.gid;
                
                if (opts->forceuser) {
                    pw = getpwnam(opts->forceuser);
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

                int forced_argv_count = opts->forced_argv_count;
                char* args=(char*)malloc(totallen);
                safer_read(fd, args, totallen);
                if(!opts->client_argv) { numargs=0; totallen=0; }
                char** argv=malloc((numargs+forced_argv_count+1)*sizeof(char*));
                int i, u;
                for(u=0; u<forced_argv_count; ++u) {
                    argv[u] = opts->forced_argv[u];
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
                if (opts->client_environment) {
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
                    envp_ = opts->envp;
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

int main(int argc, char* argv[], char* envp[]) {
    if(argc<2 || !strcmp(argv[1], "-?") || !strcmp(argv[1], "--help") || !strcmp(argv[1], "--version")) {
        printf("Dive server %s (proto %d) https://github.com/vi/dive/\n", VERSION2, VERSION);
        printf("Listen UNIX socket and start programs for each connected client, redirecting fds to client.\n");
        printf("Usage: dived socket_path [-d] [-D] [-F] [-P] [-S] [-p pidfile] [-u user] "
               "[-C mode] [-U user:group] [-R directory] [-- prepended commandline parts]\n");
        printf("          -d --detach           detach\n");
        printf("          -D --children-daemon  call daemon(0,0) in children\n");
        printf("          -F --no-fork          no fork, serve once (debugging)\n");
        printf("          -P --no-setuid        no setuid/setgid/etc\n");
        printf("          -u --user             setuid to this user instead of the client\n");
        printf("          -S --no-setsid        no sedsid/ioctl TIOCSCTTY\n");
        printf("          -R --chroot           chroot to this directory \n");
        printf("              Note that current directory stays on unchrooted filesystem \n");
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

    struct dived_options *opts = &options;
    
    opts->socket_path = argv[1];
    opts->nochilddaemon=1;
    opts->nodaemon=1;
    opts->nofork=0;
    opts->noprivs=0;
    opts->nosetsid=0;
    opts->forceuser=NULL;
    opts->pidfile=NULL;
    opts->chmod_=NULL;
    opts->chown_=NULL;
    opts->forced_argv = NULL;
    opts->forced_argv_count = 0;
    opts->client_umask = 1;
    opts->client_chdir = 1;
    opts->client_fds = 1;
    opts->client_argv = 1;
    opts->client_environment = 1;
    opts->chroot_ = NULL;
    opts->envp = envp;

    {
        int i;
        for(i=2; i<argc; ++i) {
            if(!strcmp(argv[i], "-d") || !strcmp(argv[i], "--detach")) {
                opts->nodaemon=0;
            }else
            if(!strcmp(argv[i], "-D") || !strcmp(argv[i], "--children-daemon")) {
                opts->nochilddaemon=0;
            }else
            if(!strcmp(argv[i], "-F") || !strcmp(argv[i], "--no-fork")) {
                opts->nofork=1;
            }else
            if(!strcmp(argv[i], "-P") || !strcmp(argv[i], "--no-setuid")) {
                opts->noprivs=1;
            }else
            if(!strcmp(argv[i], "-S") || !strcmp(argv[i], "--no-setsid")) {
                opts->nosetsid=1;
            }else
            if(!strcmp(argv[i], "-u") || !strcmp(argv[i], "--user")) {
                opts->forceuser=argv[i+1];
                ++i;
            }else
            if(!strcmp(argv[i], "-p") || !strcmp(argv[i], "--pidfile")) {
                opts->pidfile=argv[i+1];
                ++i;
            }else
            if(!strcmp(argv[i], "-C") || !strcmp(argv[i], "--chmod")) {
                opts->chmod_=argv[i+1];
                ++i;
            }else
            if(!strcmp(argv[i], "-U") || !strcmp(argv[i], "--chown")) {
                opts->chown_=argv[i+1];
                ++i;
            }else
            if(!strcmp(argv[i], "-R") || !strcmp(argv[i], "--chroot")) {
                opts->chroot_=argv[i+1];
                ++i;
            }else
            if(!strcmp(argv[i], "-E") || !strcmp(argv[i], "--no-environment")) {
                opts->client_environment = 0;
            }else
            if(!strcmp(argv[i], "-A") || !strcmp(argv[i], "--no-argv")) {
                opts->client_argv = 0;
            }else
            if(!strcmp(argv[i], "-H") || !strcmp(argv[i], "--no-chdir")) {
                opts->client_chdir = 0;
            }else
            if(!strcmp(argv[i], "-O") || !strcmp(argv[i], "--no-fds")) {
                opts->client_fds = 0;
            }else
            if(!strcmp(argv[i], "-M") || !strcmp(argv[i], "--no-umask")) {
                opts->client_umask = 0;
            }else
            if(!strcmp(argv[i], "--")) {
                opts->forced_argv = &argv[i+1];
                opts->forced_argv_count = argc - (i+1);
                break;
            }else
            {
                fprintf(stderr, "Unknown argument %s\n", argv[i]);
                return 4;
            }
        }
    }

    return serve(opts);
}
