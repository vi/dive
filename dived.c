// dived -- Server for seamless program starter inside unshared namespaces
// License=MIT ; Created by Vitaly "_Vi" Shukela in 2012

#define _GNU_SOURCE

#include <sched.h> // clone
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
#include <dirent.h>

#include <string.h>
#include <unistd.h>

#include "recv_fd.h"
#include "safer.h"

#define MAXFD 1024

#define VERSION 800
#define VERSION2 "v1.0"

int saved_fdnums[MAXFD];

extern char **environ;

void sigchild(int arg) {
    int status;
    wait(&status);
}

struct dived_options {
    int sock;
    char* socket_path;
    int nochilddaemon;
    int nodaemon;
    int nofork;
    int noprivs;
    int nosetsid;
    int nocsctty;
    char* forceuser;
    char* effective_user;
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
    int inetd;
    int client_chroot;
    int root_to_current;
    char* authentication_program;
} options;



int serve_client(int fd, struct dived_options *opts) {
    int ret;

    if (opts->chroot_) {
        int ret = chroot(opts->chroot_);
        if (ret==-1) {
            perror("chroot");
            return 23;
        }
    }
    
    struct ucred cred;
    socklen_t len = sizeof(struct ucred);
    struct passwd *client_cred = NULL;
    if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len) == -1) {
        perror("getsockopt SOL_SOCKET SO_PEERCRED");
        if (!opts->noprivs) {
            return 23;
        }
    } else {
        client_cred = getpwuid(cred.uid);
    }
    {
        char buffer[64];
        sprintf(buffer, "%d", cred.uid); setenv("DIVE_UID", buffer, 1);
        sprintf(buffer, "%d", cred.gid); setenv("DIVE_GID", buffer, 1);
        sprintf(buffer, "%d", cred.pid); setenv("DIVE_PID", buffer, 1);
        if (client_cred) {
            setenv("DIVE_USER", client_cred->pw_name, 1);
        } else {
            setenv("DIVE_USER", "", 1);
        }
    }

    //printf("pid=%ld, euid=%ld, egid=%ld\n", (long) cred.pid, (long) cred.uid, (long) cred.gid);
    
    if(!opts->nochilddaemon) {
        int ret = daemon(0,0);
        if (ret==-1) {
            perror("daemon");
            // considering this error as non-important and not exiting
        }
    }
    
    long int version = VERSION;
    safer_write(fd, (char*)&version, sizeof(version));
    
    /* Send pid */
    pid_t mypid = getpid();
    safer_write(fd, (char*)&mypid, sizeof(mypid));

    /* Receive file descriptor to be controlling terminal */
    int terminal_fd = recv_fd(fd);

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

    if (opts->authentication_program) {
        if (system(opts->authentication_program)) {
            return 1;
        }
    }

    /* Receive and apply umask */
    mode_t umask_;
    safer_read(fd, (char*)&umask_, sizeof(umask_));
    if (opts->client_umask) umask(umask_);
    
    /* Receive and apply root directory */
    int rootdir = recv_fd(fd);
    if (opts->client_chroot) {
        DIR* curdir = NULL;
        if (!opts->client_chdir) {
            if (opts->root_to_current) {
                curdir = opendir("/");
            } else {
                curdir = opendir("."); 
            }
        }
        
        int ret = fchdir(rootdir);
        if (ret==-1) {
            perror("fchdir");
            /* Inability to do client-managed chroot is not a security error, so continuing */
        } else {
            ret = chroot(".");
            if (ret==-1) {
                perror("chroot");
            }
        }
        close(rootdir);
        
        if (!opts->client_chdir) {
            ret = fchdir(dirfd(curdir));
            if (ret==-1) {
                perror("fchdir");
            }
            closedir(curdir);
        }        
    }
    close(rootdir);
    
    /* Receive and apply current directory */
    int curdir = recv_fd(fd);
    if (!opts->root_to_current) {
        if (opts->client_chdir) {
            int ret = fchdir(curdir);
            if (ret==-1) {
                perror("fchdir");
                /* Not considering preservance of current directory instead 
                    of client-choosed one as a security issue, continuing */
            }
        }
    } else {
        if (!opts->client_chroot) {
            int ret = chdir("/");
            if (ret==-1) {
               perror("chdir");
               return 23; 
            }
        }
    }
    close(curdir);


    if (!opts->nosetsid) {
        setpgid(0, getppid());
        ret = setsid();
    }
    if (!opts->nocsctty) {
        if (terminal_fd != -1) {
            #ifndef TIOCSCTTY
            #define TIOCSCTTY 0x540E
            #endif
            ioctl (terminal_fd, TIOCSCTTY, 1);
        }
    }

    close(terminal_fd);



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
            pw = client_cred;
        }
        
        uid_t effective_user = targetuid;
        gid_t effective_group = targetgid;
        
        if (opts->effective_user) {
            struct passwd *pw_e;
            pw_e = getpwnam(opts->effective_user);
            if (pw_e) {
                effective_user = pw_e->pw_uid;
                effective_group = pw_e->pw_gid;
            } else {
                effective_user = atoi(opts->effective_user);
            }
        }
        
        
        char *username = "";

        if(pw) {
            username = pw->pw_name;
        }

        initgroups(username, targetgid);
        if (!opts->effective_user) {
            if(setgid(targetgid) == -1) { perror("setgid"); return -1; }
            if(setuid(targetuid) == -1) { perror("setuid"); return -1; }
        } else {
            if(setregid(targetgid, effective_group) == -1) { perror("setregid"); return -1; }
            if(setreuid(targetuid, effective_user) == -1) { perror("setregid"); return -1; }
        }
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
            envp_=malloc((numargs+4+1)*sizeof(char*));
            int was_zero = 1;
            u=0;
            for(i=0; i<totallen; ++i) {
                if (was_zero) {
                    was_zero = 0;
                    if(!strncmp(env+i, "DIVE_", 5)) continue;
                    envp_[u]=env+i;
                    ++u;
                    if(u>=numargs) break;
                } 
                if (!env[i]) {
                    was_zero = 1;
                }
            }
            char *buffer_uid = (char*)malloc(64);
            char *buffer_gid = (char*)malloc(64);
            char *buffer_pid = (char*)malloc(64);
            char *buffer_user = (char*)malloc(1024);
            snprintf(buffer_uid, 64, "DIVE_UID=%d", cred.uid);
            snprintf(buffer_gid, 64, "DIVE_GID=%d", cred.gid);
            snprintf(buffer_pid, 64, "DIVE_PID=%d", cred.pid);
            if (client_cred) {
                snprintf(buffer_user, 1024, "DIVE_USER=%s", client_cred->pw_name);
            } else {
                snprintf(buffer_user, 1024, "DIVE_USER=");
            }
            
            envp_[u+0]=buffer_uid;
            envp_[u+1]=buffer_gid;
            envp_[u+2]=buffer_pid;
            envp_[u+3]=buffer_user;
            envp_[u+4]=NULL;
        } else {
            envp_ = environ;
        }

        close(fd);
        #ifndef __MUSL__
        execvpe(argv[0], argv, envp_);
        #else
        execve(argv[0], argv, envp_);
        #endif
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
    return 0;
}




int serve(struct dived_options* opts) {
    int sock = opts->sock;

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
            serve_client(fd, opts);
            
            exit(1);
        } else {
            close(fd);
        }

    }
    return 0;
}




int main(int argc, char* argv[], char* envp[]) {
    if(argc<2 || !strcmp(argv[1], "-?") || !strcmp(argv[1], "--help") || !strcmp(argv[1], "--version")) {
        printf("Dive server %s (proto %d) nocreep https://github.com/vi/dive/\n", VERSION2, VERSION);
        printf("Listen UNIX socket and start programs for each connected client, redirecting fds to client.\n");
        printf("Usage: dived {socket_path|@abstract_address|-i} [-d] [-D] [-F] [-P] [-S] [-p pidfile] [-u user] [-e effective_user] "
               "[-C mode] [-U user:group] [-R directory] [-r [-W]] [-s smth1,smth2,...] [-a \"program\"] "
               "[-- prepended commandline parts]\n");
        printf("          -d --detach           detach\n");
        printf("          -i --inetd            serve once, interpred stdin as client socket\n");
        printf("          -D --children-daemon  call daemon(0,0) in children\n");
        printf("          -F --no-fork          no fork, serve once (debugging)\n");
        printf("          -P --no-setuid        no setuid/setgid/etc\n");
        printf("          -u --user             setuid to this user instead of the client\n");
        printf("          -e --effective-user   seteuid to this user instead of the client\n");
        printf("          -a --authenticate     start this program for authentication\n");
        printf("              The program is started using \"system\" after file descriptors are received\n");
        printf("              from client, but before everything else (root, current dir, environment) is received.\n");
        printf("              Nonzero exit code => rejected client.\n");
        printf("          -S --no-setsid        no setsid\n");
        printf("          -T --no-csctty        no ioctl TIOCSCTTY\n");
        printf("          -R --chroot           chroot to this directory \n");
        printf("              Note that current directory stays on unchrooted filesystem; use -W option to prevent.\n");
        printf("          -r --client-chroot    Allow arbitrary chroot from client\n");
        printf("          -W --root-to-current  Set server's root directory as current directory\n");
        printf("                                (implies -H; useful with -r)\n");
        printf("          -p --pidfile          save PID to this file\n");
        printf("          -C --chmod            chmod the socket to this mode (like '0777')\n");
        printf("          -U --chown            chown the socket to this user:group\n");
        printf("          -E --no-environment   Don't let client set environment variables\n");
        printf("          -A --no-argv          Don't let client set command line\n");
        printf("          -H --no-chdir         Don't let client set current directory\n");
        printf("          -O --no-fds           Don't let client set file descriptors\n");
        printf("          -M --no-umask         Don't let client set umask\n");
        printf("          --                    prepend this to each command line ('--' is mandatory)\n");
        printf("              Note that the program beingnocsctty strarted using \"--\" should be\n");
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
    opts->nocsctty=0;
    opts->forceuser=NULL;
    opts->effective_user=NULL;
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
    opts->inetd = 0;
    opts->client_chroot = 0;
    opts->root_to_current = 0;
    opts->authentication_program = NULL;
    if(!strcmp(argv[1], "-i") || !strcmp(argv[1], "--inetd")) { opts->inetd = 1; }
    if(!strcmp(argv[1], "-J") || !strcmp(argv[1], "--just-execute")) { 
        fprintf(stderr, "--just-execute option is not supported in 'nocreep' edition\n");
        return 1;
    }

    {
        int i;
        for(i=2; i<argc; ++i) {
            if(!strcmp(argv[i], "-d") || !strcmp(argv[i], "--detach")) {
                opts->nodaemon=0;
            }else
            if(!strcmp(argv[i], "-i") || !strcmp(argv[i], "--inetd")) {
                opts->inetd=1;
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
            if(!strcmp(argv[i], "-T") || !strcmp(argv[i], "--no-csctty")) {
                opts->nocsctty=1;
            }else
            if(!strcmp(argv[i], "-u") || !strcmp(argv[i], "--user")) {
                opts->forceuser=argv[i+1];
                ++i;
            }else
            if(!strcmp(argv[i], "-e") || !strcmp(argv[i], "--effective-user")) {
                opts->effective_user=argv[i+1];
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
            if(!strcmp(argv[i], "-s") || !strcmp(argv[i], "--unshare")) {
                fprintf(stderr, "Unsharing namespaces is not supported in 'nocreep' edition of dived\n");
                return 1;
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
            if(!strcmp(argv[i], "-r") || !strcmp(argv[i], "--client-chroot")) {
                opts->client_chroot = 1;
            }else
            if(!strcmp(argv[i], "-W") || !strcmp(argv[i], "--root-to-current")) {
                opts->root_to_current = 1;
            }else
            if(!strcmp(argv[i], "-a") || !strcmp(argv[i], "--authenticate")) {
                opts->authentication_program = argv[i+1];
                ++i;
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
    
    if (opts->inetd) {
        return serve_client(0, opts);
    }
    
    struct sockaddr_un addr;
    int ret;
    int sock;
    
    if(opts->socket_path[0]!='@') {
        unlink(opts->socket_path);
    }
    
    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, opts->socket_path, sizeof(addr.sun_path) - 1);
    if (addr.sun_path[0]=='@') {
        addr.sun_path[0]=0; /* Abstract socket */
    }

    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sock==-1) {
        perror("socket AF_UNIX");
        return 1;
    }
    opts->sock = sock;

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
        errno=0;
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
        
        errno=0;
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
        
    /* Save pidfile */
    if (opts->pidfile){
        FILE* f = fopen(opts->pidfile, "w");
        fprintf(f, "%d\n", getpid());
        fclose(f);
    }
        
    return serve(opts);
}
