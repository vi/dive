// dived -- Server for seamless program starter inside unshared namespaces
// License=MIT ; Created by Vitaly "_Vi" Shukela in 2012

#include "config.h"

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
#include <fcntl.h>
#include <sys/select.h>

#ifndef SIGNALFD_WORKAROUND
#include <sys/signalfd.h>
#endif

#include <string.h>
#include <unistd.h>

#ifndef NO_RLIMIT
#include <sys/resource.h>
#endif


#ifndef NO_CAPABILITIES   
    #include <sys/capability.h>
    #ifndef SECUREBITS_WORKAROUND
        #include <linux/securebits.h>
    #else
        // build supporting this feature even if system does not support it yet
        #include "hacks/securebits.h"
    #endif
#endif

#ifdef CLONE_PARAMETERS_WORKAROUND
    #include "hacks/clone_parameters.h"
#endif // CLONE_PARAMETERS_WORKAROUND


#include <sys/prctl.h>

#include "recv_fd.h"
#include "safer.h"

/* Maximum FD number */
#define MAXFD 1024

/* Maximum number of groups specified by --groups */
#define MAXGROUPS 128

#define VERSION 1100
#define VERSION2 "v1.8.2"

#define CLONE_STACK_SIZE  (1024*16)
// For use with "--unshare"

// list of FDs that should be closed for non-client process
int saved_fdnums[MAXFD];

extern char **environ;

void sigchild(int arg) {
    int status;
    wait(&status);
}

#define MAX_SETNS_FILES 8
#define MAX_WRITECONTENT_FILES 8
#define MAX_PIDFILES 12
#define MAX_RLIMIT_SETS 30

struct rlimit_setter {
    int resource;
    struct rlimit limits;
};

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
    char* forcegroups;
    char* effective_user;
    char* pidfiles[MAX_PIDFILES];
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
    char* chdir_;
    char* setns_files[MAX_SETNS_FILES];
    char** envp;
    char* unshare_;
    int inetd;
    int client_chroot;
    int root_to_current;
    char* authentication_program;
    char* retain_capabilities;
    char* remove_capabilities;
    char* ambient_capabilities;
    char* set_capabilities;
    int no_new_privs;
    int just_execute;
    int lock_securebits;
    int signal_processing;
    int fork_and_wait_for_exit_code;
    struct rlimit_setter rlimits[MAX_RLIMIT_SETS];
    char* pivotroot_newroot;
    char* pivotroot_putold;
    char* writecontent_files[MAX_WRITECONTENT_FILES];
    char* writecontent_data[MAX_WRITECONTENT_FILES];
    
    int maximum_fd_count;
    int maximum_argv_count;
    int maximum_argv_size;
    int maximum_envp_count;
    int maximum_envp_size;
} options;

#ifndef NO_PIVOTROOT
#ifndef PIVOTROOT_WORKAROUND
int pivot_root(const char* newroot, const char* putold);
#else
int pivot_root(const char* newroot, const char* putold) {
    return syscall(SYS_pivot_root, newroot, putold, 0, 0);
}
#endif
#endif // NO_PIVOTROOT

struct serve_client_context {
    int fd;
    struct ucred cred;
    struct passwd *client_cred;
    int terminal_fd;
    const char* username;
    uid_t effective_user;
    gid_t effective_group;
    uid_t targetuid;
    gid_t targetgid;
    
    /* When we receive and apply (dup2) file descriptors, it can happen that we need to replace the fd itself.
     * In this postpone applying it until we close "fd" */
    int debt_instead_of_fd;

    int exit_code_or_signal_processing_enabled;
    int initialisation_finished_event[2];
    int signal_fd;
    int pid2;
    char** argv;
    char** envp_;
    int dive_signal_fd;
};


int serve_client_setns(struct dived_options *opts, struct serve_client_context *ctx) {
    #ifndef NO_SETNS
    { 
        int i;
        for (i=0; i<MAX_SETNS_FILES; ++i) {
            if (opts->setns_files[i]) {
                int nsfd = open(opts->setns_files[i], O_RDONLY);
                if(nsfd==-1) {
                    perror("open");
                    return 23;
                }
                if(setns(nsfd, 0) == -1) {
                    perror("setns");
                    return 23;
                }
                close(nsfd);
            }
        }
    }
    #endif
    return 0;
}

int serve_client_write_content(struct dived_options *opts, struct serve_client_context *ctx) {
    int i;
    for (i=0; i<MAX_WRITECONTENT_FILES; ++i) {
        if (opts->writecontent_files[i]) {
            const char* n = opts->writecontent_files[i];
            const char* c = opts->writecontent_data[i];
            size_t cl = strlen(c);

            int fd = open(n, O_WRONLY|O_TRUNC|O_CREAT, 0777);
            if (fd == -1) {
                perror("open");
                return 23;
            }
            int ret = safer_write(fd, c, cl);
            if (ret == -1) {
                close(fd);
                perror("write");
                return 23;
            }
            close(fd);
            if (ret < cl) {
                fprintf(stderr, "Can't write content file in full. Aborting.\n");
                return 23;
            }
        }
    }
    return 0;
}

int serve_client_opt_chdir_chroot(struct dived_options *opts, struct serve_client_context *ctx) {
    DIR* chdir_here_after_chroot = NULL;
    if (opts->chdir_ && !opts->chroot_) {
        int ret = chdir(opts->chdir_);
        if (ret==-1) {
            perror("chdir");
            return 23;
        }
    }
    // save away current directory before it is mangled by chroot
    if (opts->chdir_ && opts->chroot_) {
        chdir_here_after_chroot = opendir(opts->chdir_);
        if (!chdir_here_after_chroot) {
            perror("opendir for later chdir");
            return 23;
        }
    }
    if (opts->chroot_) {
        int ret = chroot(opts->chroot_);
        if (ret==-1) {
            perror("chroot");
            return 23;
        }
    }
    if (chdir_here_after_chroot) {
        int ret = fchdir(dirfd(chdir_here_after_chroot));
        if (ret==-1) {
            perror("fchdir");
            return 23;
        }
        closedir(chdir_here_after_chroot);
    }
    
    #ifndef NO_PIVOTROOT
    if (opts->pivotroot_newroot) {
        int ret = pivot_root(opts->pivotroot_newroot, opts->pivotroot_putold);
        if (ret==-1) {
            perror("pivot_root");
            return 23;
        }
    }
    #endif // NO_PIVOTROOT
    return 0;
}

int serve_client_getcred(struct dived_options *opts, struct serve_client_context *ctx) {
    socklen_t len = sizeof(struct ucred);
    
    if (!opts->just_execute) {
    
    if (getsockopt(ctx->fd, SOL_SOCKET, SO_PEERCRED, &ctx->cred, &len) == -1) {
        perror("getsockopt SOL_SOCKET SO_PEERCRED");
        if (!opts->noprivs) {
            return 23;
        }
    } else {
        ctx->client_cred = getpwuid(ctx->cred.uid);
    }
    
    } else {
        // --just-execute
        ctx->cred.uid = getuid();
        ctx->cred.gid = getgid();
        ctx->cred.pid = getpid();
    }
    return 0;
}

int serve_client_set_dive_envvars(struct dived_options *opts, struct serve_client_context *ctx) {
    {
        char buffer[64];
        sprintf(buffer, "%d", ctx->cred.uid); setenv("DIVE_UID", buffer, 1);
        sprintf(buffer, "%d", ctx->cred.gid); setenv("DIVE_GID", buffer, 1);
        sprintf(buffer, "%d", ctx->cred.pid); setenv("DIVE_PID", buffer, 1);
        if (ctx->client_cred) {
            setenv("DIVE_USER", ctx->client_cred->pw_name, 1);
        } else {
            setenv("DIVE_USER", "", 1);
        }
    }
    //printf("pid=%ld, euid=%ld, egid=%ld\n", (long) ctx->cred.pid, (long) ctx->cred.uid, (long) ctx->cred.gid);
    return 0;
}

int serve_client_daemon(struct dived_options *opts, struct serve_client_context *ctx) {
    if(!opts->nochilddaemon) {
        int ret = daemon(0,0);
        if (ret==-1) {
            perror("daemon");
            // considering this error as non-important and not exiting
        }
    }
    return 0;
}
    
int serve_client_recv_fds_flags(struct dived_options *opts, struct serve_client_context *ctx) {

    long int version = VERSION;
    safer_write(ctx->fd, (char*)&version, sizeof(version));
    
    /* Send pid */
    pid_t mypid = getpid();
    safer_write(ctx->fd, (char*)&mypid, sizeof(mypid));

    /* Receive file descriptor to be controlling terminal */
    ctx->terminal_fd = recv_fd(ctx->fd);
    
    
    /* Receive flag whether client wants us to stay and wait for exit code */
    int waiting_requested;
    safer_read(ctx->fd, (char*)&waiting_requested, sizeof(waiting_requested));
    
    if (!waiting_requested) ctx->exit_code_or_signal_processing_enabled=0;
        
    /* Send whether we will wait for the client */
    safer_write(ctx->fd, (char*)&ctx->exit_code_or_signal_processing_enabled, sizeof(ctx->exit_code_or_signal_processing_enabled));

    /* Receive and apply file descriptors */
    int received_fd_count = 0;
    memset(saved_fdnums, 0, sizeof saved_fdnums);
    for(;;) {
        int i;
        safer_read(ctx->fd, (char*)&i, sizeof(i));
        if(i==-1) {
            break;
        }                    
        if(i<-1 || i>=MAXFD) {
            fprintf(stderr, "dived: Wrong file descriptor number %d\n", i);
            return 7;
        }
        int f = recv_fd(ctx->fd);                
        if (!opts->client_fds) {
            close(f);
            continue;
        }
        if (received_fd_count == opts->maximum_fd_count) {
            fprintf(stderr, "dived: Too many FDs, ignoring %d\n", i);
            close(f);
            continue;
        }
        ++received_fd_count;
        if(i==ctx->fd) {
            ctx->debt_instead_of_fd=f;
        } else if (i==ctx->debt_instead_of_fd) {
            // Now "debt_instead_of_fd wants" to become "fd" and
            // "i" wants to become "debt_instead_of_fd"
            
            // reroute the debt to new FD.
            // Unfortunately this may be "kicked down the street"
            // again and again as more FDs are received
            int newfd = dup(ctx->debt_instead_of_fd);
            if (newfd == -1) { perror("dup"); return 1; }
            ctx->debt_instead_of_fd = newfd;
            
            // this also closes "i" aka the former debt_instead_of_fd
            if (dup2(f, i) == i) {
                saved_fdnums[i]=1;
            } else {
                perror("dup2");
            }
            close(f);
        } else {
            if(f!=i) {
                if(dup2(f, i)==i) {
                    saved_fdnums[i]=1;
                } else {
                    perror("dup2");
                }
                close(f);
            } else {
                saved_fdnums[i]=1;
            }
        }
    }
    return 0;
}

int serve_client_auth_prog(struct dived_options *opts, struct serve_client_context *ctx) {
    if (opts->authentication_program) {
        if (system(opts->authentication_program)) {
            return 1;
        }
    }
    return 0;
}

int serve_client_umask(struct dived_options *opts, struct serve_client_context *ctx) {
    /* Receive and apply umask */
    mode_t umask_;
    safer_read(ctx->fd, (char*)&umask_, sizeof(umask_));
    if (opts->client_umask) umask(umask_);
    
    return 0;
}
    
int serve_client_rootdir(struct dived_options *opts, struct serve_client_context *ctx) {
    /* Receive and apply root directory */
    int rootdir = recv_fd(ctx->fd);
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
    } else {
        close(rootdir);
    }
    return 0;
}
    
int serve_client_curdir(struct dived_options *opts, struct serve_client_context *ctx) {
    /* Receive and apply current directory */
    int curdir = recv_fd(ctx->fd);
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
    return 0;
}

int serve_client_setsid(struct dived_options *opts, struct serve_client_context *ctx) {
    if (!opts->nosetsid) {
        setpgid(0, getppid());
        setsid();
    }
    return 0;
}
int serve_client_csctty(struct dived_options *opts, struct serve_client_context *ctx) {
    if (!opts->nocsctty) {
        if (ctx->terminal_fd != -1) {
            #ifndef TIOCSCTTY
            #define TIOCSCTTY 0x540E
            #endif
            ioctl (ctx->terminal_fd, TIOCSCTTY, 1);
        }
    }

    close(ctx->terminal_fd);
    return 0;
}


int serve_client_securebits(struct dived_options *opts, struct serve_client_context *ctx) {
    #ifndef NO_CAPABILITIES   
    if (opts->set_capabilities || opts->lock_securebits) {
        if (!opts->lock_securebits) {
            prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS, 0, 0);
        } else {
            if(prctl(PR_SET_SECUREBITS, 
                        SECBIT_KEEP_CAPS |
                        SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED |
                        SECBIT_NOROOT | SECBIT_NOROOT_LOCKED
                        , 0, 0) == -1) {
                perror("prctl(PR_SET_SECUREBITS)");
                return -1;
            }
        }
    }
    #endif
    return 0;
}

int serve_client_rlimit(struct dived_options *opts, struct serve_client_context *ctx) {
    /* Set resource limits, if needed */
    #ifndef NO_RLIMIT
    if(opts->rlimits[0].resource!=-1) {
        int j;
        for(j=0; j<MAX_RLIMIT_SETS; ++j) {
            struct rlimit_setter *r = &opts->rlimits[j];
            if(r->resource==-1)break;
            
            if(setrlimit(r->resource, &r->limits) == -1) {
                perror("setrlimit");
                return -1;
            }
        }
    }
    #endif
    return 0;
}
    
int serve_client_decide_user(struct dived_options *opts, struct serve_client_context *ctx) {
    /* Decide what user shall we change to */
    struct passwd *pw = NULL;
    ctx->targetuid = ctx->cred.uid;
    ctx->targetgid = ctx->cred.gid;

    
    if (opts->forceuser) {
        if (!opts->forcegroups) {
            pw = getpwnam(opts->forceuser);
            if (pw) {
                ctx->targetuid = pw->pw_uid;
                ctx->targetgid = pw->pw_gid;
            } else {
                ctx->targetuid = -1;
                fprintf(stderr, "Failed to getpwnam the specified user\n");
                fprintf(stderr, "If you want to set uid by number then also specify --groups \n");
                return 112;
            }
        } else {
            ctx->targetuid = -1;
            sscanf(opts->forceuser, "%d", &ctx->targetuid);
            
            
            if (ctx->targetuid == -1) {
                struct passwd *userp = getpwnam(opts->forceuser);
                if (!userp) {
                    fprintf(stderr, "User %s not found (and is not a numeric uid)\n", opts->forceuser);
                    return 13;
                }
                ctx->targetuid = userp->pw_uid;
            }
            
            ctx->targetgid = -1;
            sscanf(opts->forcegroups, "%u", &ctx->targetgid);
            
            
            if (ctx->targetgid == -1) {
                char first_group_name_without_comma[256];
                snprintf(first_group_name_without_comma, sizeof first_group_name_without_comma, "%s", opts->forcegroups);
                if (strchr(first_group_name_without_comma, ',')) {
                    *strchr(first_group_name_without_comma, ',') = 0;
                }
                    
                struct group *groupp = getgrnam(first_group_name_without_comma);
                if (!groupp) {
                    fprintf(stderr, "Group %s not found (and is not a numeric gid)\n", first_group_name_without_comma);
                    return 13;
                }
                ctx->targetgid = groupp->gr_gid;
            }
        }
    } else {
        /* By default it is user at the other end of the connection */
        pw = ctx->client_cred;
    }
    
    ctx->effective_user = ctx->targetuid;
    ctx->effective_group = ctx->targetgid;
    
    if (opts->effective_user) {
        struct passwd *pw_e;
        pw_e = getpwnam(opts->effective_user);
        if (pw_e) {
            ctx->effective_user = pw_e->pw_uid;
            ctx->effective_group = pw_e->pw_gid;
        } else {
            ctx->effective_user=-1;
            sscanf(opts->effective_user, "%d", &ctx->effective_user);
        }
    }
    
    if(pw) {
        ctx->username = pw->pw_name;
    }
    return 0;
}
        
int serve_client_cap_bset(struct dived_options *opts, struct serve_client_context *ctx) {
    #ifndef NO_CAPABILITIES
    if (opts->remove_capabilities || opts->retain_capabilities) {      
        int also_remove_CAP_SETPCAP = 0;      
        
        if (opts->remove_capabilities ) {
            
            char* q = strtok(opts->remove_capabilities, ",");
            for(; q; q=strtok(NULL, ",")) {                
                cap_value_t c=-1;
                cap_from_name(q, &c);
                if(c==-1) {
                    perror("cap_from_name");
                    return -1;
                }
                if (c == CAP_SETPCAP) {
                    also_remove_CAP_SETPCAP = 1;
                    continue;
                }
                if(prctl(PR_CAPBSET_DROP, c, 0, 0, 0)==-1) {                
                    perror("prctl(PR_CAPBSET_DROP)");
                    return -1;
                }
            }
        } else {
            // retain capabilities
            
            #define MAXCAPS 256
            
            unsigned char retain_set[MAXCAPS] = {0};
            
            char* q = strtok(opts->retain_capabilities, ",");
            for(; q; q=strtok(NULL, ",")) {                
                cap_value_t c=-1;
                cap_from_name(q, &c);
                if(c==-1) {
                    perror("cap_from_name");
                    return -1;
                }
                if (c<MAXCAPS) {
                    retain_set[c] = 1;
                }
            }
            
            cap_value_t i;
            
            for(i=0; i<MAXCAPS; ++i) {
                if(!retain_set[i]) {
                    if(i!=CAP_SETPCAP) {
                        if(prctl(PR_CAPBSET_DROP, i, 0, 0, 0)==-1) {   
                            if(errno==EINVAL) {
                                continue;
                            }
                            perror("prctl(PR_CAPBSET_DROP)");
                            return -1;
                        }
                    } else {
                        also_remove_CAP_SETPCAP = 1;
                    }
                } 
            }
        }
        if (also_remove_CAP_SETPCAP) {
            if(prctl(PR_CAPBSET_DROP, CAP_SETPCAP, 0, 0, 0)==-1) {                
                perror("prctl(PR_CAPBSET_DROP)");
                return -1;
            }
        }
    }
    #endif
    return 0;
}
        
int serve_client_groups(struct dived_options *opts, struct serve_client_context *ctx) {
    if (!opts->forcegroups) {
        if (ctx->targetuid != getuid() || ctx->targetgid != getgid()) {
            if (initgroups(ctx->username, ctx->targetgid) == -1) {
                perror("initgroups");
                return -1;
            }
        }
    } else {
        gid_t groups[MAXGROUPS];
        size_t group_count = 0;
        
        char *saveptr_commas;
        char* q = strtok_r(opts->forcegroups, ",", &saveptr_commas);
        for(; q && group_count < MAXGROUPS; q=strtok_r(NULL, ",", &saveptr_commas)) {
            unsigned int gid = -1;
            sscanf(q, "%u", &gid);
            if (gid == -1) {
                struct group *groupp = getgrnam(q);
                if (!groupp) {
                    fprintf(stderr, "Group %s not found (and is not a numeric uid)\n", q);
                    return 13;
                }
                gid = groupp->gr_gid;
            }
            groups[group_count] = gid;
            ++group_count;
        }
        if (setgroups(group_count, groups) == -1) {
            perror("setgroups");
            return -1;
        }
    }
    return 0;
}

int serve_client_setuid(struct dived_options *opts, struct serve_client_context *ctx) {
    if (!opts->effective_user) {
        if(setgid(ctx->targetgid) == -1) { perror("setgid"); return -1; }
        if(setuid(ctx->targetuid) == -1) { perror("setuid"); return -1; }
    } else {
        if(setregid(ctx->targetgid, ctx->effective_group) == -1) { perror("setregid"); return -1; }
        if(setreuid(ctx->targetuid, ctx->effective_user) == -1) { perror("setregid"); return -1; }
    }
    return 0;
}
    
int serve_client_setcap(struct dived_options *opts, struct serve_client_context *ctx) {
    #ifndef NO_CAPABILITIES
    if (opts->set_capabilities) {            
        cap_t c = cap_from_text(opts->set_capabilities);
        if (c==NULL) {
            perror("cap_from_text");
            return -1;
        }
        if (cap_set_proc(c) == -1) {
            perror("caps_set_proc");
            return -1;
        }
        cap_free(c);
    }
    #endif
    return 0;
}

int serve_client_ambient_caps(struct dived_options *opts, struct serve_client_context *ctx) {
    #ifndef NO_CAPABILITIES
    if (opts->ambient_capabilities) {
        char* q = strtok(opts->ambient_capabilities, ",");
        for(; q; q=strtok(NULL, ",")) {
            cap_value_t c=-1;
            cap_from_name(q, &c);
            if(c==-1) {
                perror("cap_from_name");
                return -1;
            }
#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#define PR_CAP_AMBIENT_RAISE 2
#endif
            if(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, c, 0, 0)==-1) {
                perror("prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE)");
                return -1;
            }
        }
    }
    #endif
    return 0;
}
    
int serve_client_no_new_privs(struct dived_options *opts, struct serve_client_context *ctx) {
    if (opts->no_new_privs) {
        #ifndef PR_SET_NO_NEW_PRIVS
        #define PR_SET_NO_NEW_PRIVS 38
        #endif
        
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == -1) {
            perror("prctl(PR_SET_NO_NEW_PRIVS)");
            return -1;
        }
    }
    return 0;
}


int serve_client_initfinevent(struct dived_options *opts, struct serve_client_context *ctx) {
    int ret;
    ret = pipe2(ctx->initialisation_finished_event, O_CLOEXEC);
    if (ret == -1) {
        ctx->initialisation_finished_event[0]=-1;
        ctx->initialisation_finished_event[1]=-1;
    }
    return 0;
}

int serve_client_signalsetup(struct dived_options *opts, struct serve_client_context *ctx) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    #ifndef SIGNALFD_WORKAROUND
    ctx->signal_fd = signalfd(-1, &mask, 0/*SFD_NONBLOCK*/);
    #endif
    sigprocmask(SIG_BLOCK, &mask, NULL);
    return 0;
}


int serve_client_maybe_fork(struct dived_options *opts, struct serve_client_context *ctx) {
    if (ctx->exit_code_or_signal_processing_enabled) {
        ctx->pid2 = fork();

        if (ctx->pid2 == -1) {
            perror("fork");
            return -1;
        }
    }
    
    if (!ctx->pid2) {
        if (ctx->signal_fd != -1) close(ctx->signal_fd);
    }
    return 0;
}

int serve_client_recv_argv(struct dived_options *opts, struct serve_client_context *ctx) {
    /* Receive argv */
    int numargs, totallen;
    int i, u;
    int forced_argv_count = opts->forced_argv_count;


    safer_read(ctx->fd, (char*)&numargs, sizeof(numargs));
    safer_read(ctx->fd, (char*)&totallen, sizeof(totallen));
        
    if (numargs < 0 || numargs > opts->maximum_argv_count ||
        totallen < 0 || totallen > opts->maximum_argv_size) {
        fprintf(stderr, "dived: Exceed maximum argv count or size\n");
        return -1;
    }

    char* args=(char*)malloc(totallen);
    if (!args) {
        perror("malloc");
        return -1;
    }
    safer_read(ctx->fd, args, totallen);
    if(!opts->client_argv) { numargs=0; totallen=0; }
    ctx->argv = (char**) malloc((numargs+forced_argv_count+1)*sizeof(char*));
    if (!ctx->argv) {
        perror("malloc");
        return -1;
    }

    for(u=0; u<forced_argv_count; ++u) {
        ctx->argv[u] = opts->forced_argv[u];
    }
    u=forced_argv_count; /* explicit > implicit */
    ctx->argv[u]=args;
    for(i=0; i<totallen; ++i) {
        if (!args[i]) {
            ++u;
            if ( u-forced_argv_count > numargs) {
                fprintf(stderr, "dived: Malformed argv\n");
                return -1;
            }
            ctx->argv[u]=args+i+1;
        }
    }
    ctx->argv[forced_argv_count + numargs]=NULL;
    return 0;
}
        
int serve_client_recv_evnvars(struct dived_options *opts, struct serve_client_context *ctx) {
    /* Receive environment */
    int numargs, totallen;
    int i, u;

    safer_read(ctx->fd, (char*)&numargs, sizeof(numargs));
    safer_read(ctx->fd, (char*)&totallen, sizeof(totallen));
    
    if (numargs < 0 || numargs > opts->maximum_envp_count ||
        totallen < 0 || totallen > opts->maximum_envp_size) {
        fprintf(stderr, "dived: Exceed maximum environment count or size\n");
        return -1;
    }
    
    char* env=(char*)malloc(totallen);
    if (!env) {
        perror("malloc");
        return -1;
    }
    safer_read(ctx->fd, env, totallen);
    if (opts->client_environment) {
        ctx->envp_ = (char**) malloc((numargs+4+1)*sizeof(char*));
        
        if (!ctx->envp_) {
            perror("malloc");
            return -1;
        }
        
        int was_zero = 1;
        u=0;
        for(i=0; i<totallen; ++i) {
            if (was_zero) {
                was_zero = 0;
                if(!strncmp(env+i, "DIVE_", 5)) continue;
                ctx->envp_[u]=env+i;
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
        
        if (!buffer_uid || !buffer_gid || !buffer_pid || !buffer_user) {
            perror("malloc");
            // if some buffers are actually allocated, the memory is obviously freed by itself
            return -1;
        }
        
        snprintf(buffer_uid, 64, "DIVE_UID=%d", ctx->cred.uid);
        snprintf(buffer_gid, 64, "DIVE_GID=%d", ctx->cred.gid);
        snprintf(buffer_pid, 64, "DIVE_PID=%d", ctx->cred.pid);
        if (ctx->client_cred) {
            snprintf(buffer_user, 1024, "DIVE_USER=%s", ctx->client_cred->pw_name);
        } else {
            snprintf(buffer_user, 1024, "DIVE_USER=");
        }
        
        ctx->envp_[u+0]=buffer_uid;
        ctx->envp_[u+1]=buffer_gid;
        ctx->envp_[u+2]=buffer_pid;
        ctx->envp_[u+3]=buffer_user;
        ctx->envp_[u+4]=NULL;
    } else {
        ctx->envp_ = environ;
    }
    return 0;
}

int serve_client_exec(struct dived_options *opts, struct serve_client_context *ctx) {
    close(ctx->fd);
    if (ctx->debt_instead_of_fd != -1) {
        dup2(ctx->debt_instead_of_fd, ctx->fd);
        close(ctx->debt_instead_of_fd);
    }
    
    close (ctx->initialisation_finished_event[1]);
    
    #ifndef NO_EXECVPE
    execvpe(ctx->argv[0], ctx->argv, ctx->envp_);
    #else
    execve(ctx->argv[0], ctx->argv, ctx->envp_);
    #endif
    exit(127);
    return 127;
}
        

int serve_client_release_fds(struct dived_options *opts, struct serve_client_context *ctx) {
    /* Release client's fds */
    int i;

    for(i=0; i<MAXFD; ++i) {
        if(saved_fdnums[i] && i!=ctx->initialisation_finished_event[0]) close(i);
    }
    
    if (ctx->debt_instead_of_fd != -1) {
        close(ctx->debt_instead_of_fd);
    }
    
    close (ctx->initialisation_finished_event[1]);
    return 0;
}

int serve_client_wait_init_event(struct dived_options *opts, struct serve_client_context *ctx) {
    int ret;
    if (ctx->initialisation_finished_event[0] != -1) {
        // will not complete
        ret = read(ctx->initialisation_finished_event[0], &ctx->initialisation_finished_event[1], 1); 
        // ret should be 0
        (void)ret;
    } else {
        //workaround
        struct timeval to = { 0, 200000};
        ret = select(0,NULL,NULL,NULL, &to);
        (void)ret;
    }
    close(ctx->initialisation_finished_event[0]);
    return 0;
}

int serve_client_send_pid(struct dived_options *opts, struct serve_client_context *ctx) {
    /* Send executed pid */
    safer_write(ctx->fd, (char*)&ctx->pid2, sizeof(ctx->pid2));
    return 0;
}
    
int serve_client_process_signals(struct dived_options *opts, struct serve_client_context *ctx) {
    int ret;
    {
        int signal_processing_actual = opts->signal_processing;
        if (ctx->signal_fd == -1) signal_processing_actual=0;
        safer_write(ctx->fd, (char*)&signal_processing_actual, sizeof(signal_processing_actual));
    }
    
    int dive_signal_fd = recv_fd(ctx->fd);
    
    int status;
    if (opts->signal_processing && dive_signal_fd != -1 && ctx->signal_fd != -1) {
        #ifndef SIGNALFD_WORKAROUND
        fcntl(dive_signal_fd, F_SETFL, O_NONBLOCK);
        
        int maxfd = (ctx->signal_fd > dive_signal_fd) ? ctx->signal_fd  : dive_signal_fd;
        
        int ret;
        for(;;) {
            fd_set rfds;
            
            FD_ZERO(&rfds);
            FD_SET(ctx->signal_fd, &rfds);
            FD_SET(dive_signal_fd, &rfds);
               

            ret = select(maxfd+1, &rfds, NULL, NULL, NULL);
            
            if (ret == -1) {
                if (errno==EINTR || errno==EAGAIN) continue;
                break;
            }
            
            if (FD_ISSET(dive_signal_fd, &rfds)) {
                struct signalfd_siginfo si;
                if (read(dive_signal_fd, &si, sizeof si)>0) {
                    kill(ctx->pid2, si.ssi_signo);
                }                
            }
            
            
            if (FD_ISSET(ctx->signal_fd, &rfds)) {
                struct signalfd_siginfo si;
                if (read(ctx->signal_fd, &si, sizeof si)>0) {
                    if (si.ssi_pid == ctx->pid2 && si.ssi_signo == SIGCHLD) {
                        status = si.ssi_status;
                        safer_write(ctx->fd, (char*)&si.ssi_status, 4);
                        return 0;
                    }
                }
                
            }
        }
        #endif // SIGNALFD_WORKAROUND
    } else {
        close(dive_signal_fd);
        
        
        #ifndef SIGNALFD_WORKAROUND
        struct signalfd_siginfo si;
        ret = read(ctx->signal_fd, &si, sizeof si);
        if (ret != -1 && si.ssi_pid == ctx->pid2 && si.ssi_signo == SIGCHLD) {
            status = si.ssi_status;
            safer_write(ctx->fd, (char*)&si.ssi_status, 4);
            return 0;
        }
        /* fallback */
        close(ctx->signal_fd);
        #endif // SIGNALFD_WORKAROUND
        
        waitpid(ctx->pid2, &status, 0);
        int exitcode = WEXITSTATUS(status);
        safer_write(ctx->fd, (char*)&exitcode, sizeof(exitcode));
        return 0;
    }
    return 1;
}

int serve_client(int fd, struct dived_options *opts) {
    int ret;
    struct serve_client_context ctx;

    ctx.fd = fd;
    ctx.client_cred = NULL;
    ctx.terminal_fd = -1;
    ctx.debt_instead_of_fd = -1;
    ctx.exit_code_or_signal_processing_enabled = opts->fork_and_wait_for_exit_code && !opts->just_execute;
    ctx.signal_fd = -1;
    ctx.pid2 = 0;
    ctx.username = "";

    ret=serve_client_setns            (opts, &ctx);  if (ret!=0) return ret;
    ret=serve_client_write_content    (opts, &ctx);  if (ret!=0) return ret;
    ret=serve_client_opt_chdir_chroot (opts, &ctx);  if (ret!=0) return ret;

    ret=serve_client_getcred          (opts, &ctx);  if (ret!=0) return ret;
    ret=serve_client_set_dive_envvars (opts, &ctx);  if (ret!=0) return ret;

    ret=serve_client_daemon           (opts, &ctx);  if (ret!=0) return ret;
    
    if (!opts->just_execute) {
        ret=serve_client_recv_fds_flags   (opts, &ctx);  if (ret!=0) return ret;
    }

    ret=serve_client_auth_prog        (opts, &ctx);  if (ret!=0) return ret;

    if (!opts->just_execute) {
        ret=serve_client_umask            (opts, &ctx);  if (ret!=0) return ret;
        ret=serve_client_rootdir          (opts, &ctx);  if (ret!=0) return ret;
        ret=serve_client_curdir           (opts, &ctx);  if (ret!=0) return ret;
    }

    ret=serve_client_setsid           (opts, &ctx);  if (ret!=0) return ret;
    ret=serve_client_csctty           (opts, &ctx);  if (ret!=0) return ret;

    ret=serve_client_securebits       (opts, &ctx);  if (ret!=0) return ret;
    ret=serve_client_rlimit           (opts, &ctx);  if (ret!=0) return ret;

    if(!opts->noprivs) {
        ret=serve_client_decide_user      (opts, &ctx);  if (ret!=0) return ret;
        ret=serve_client_cap_bset         (opts, &ctx);  if (ret!=0) return ret;
        ret=serve_client_groups           (opts, &ctx);  if (ret!=0) return ret;
        ret=serve_client_setuid           (opts, &ctx);  if (ret!=0) return ret;
    }


    ret=serve_client_setcap           (opts, &ctx);  if (ret!=0) return ret;
    ret=serve_client_ambient_caps     (opts, &ctx);  if (ret!=0) return ret;
    ret=serve_client_no_new_privs     (opts, &ctx);  if (ret!=0) return ret;
    
    /* Not caring much about security since that point */
    
    ret=serve_client_initfinevent     (opts, &ctx);  if (ret!=0) return ret;
    if (!opts->just_execute) {
        ret=serve_client_signalsetup      (opts, &ctx);  if (ret!=0) return ret;
        ret=serve_client_maybe_fork       (opts, &ctx);  if (ret!=0) return ret;
    }
    if (!ctx.pid2) {
        if (! opts->just_execute) {
            ret=serve_client_recv_argv    (opts, &ctx);  if (ret!=0) return ret;
            ret=serve_client_recv_evnvars (opts, &ctx);  if (ret!=0) return ret;
            ret=serve_client_exec         (opts, &ctx);  if (ret!=0) return ret;
            exit(127);
        } else {
            close(fd);
            execvp(opts->forced_argv[0], opts->forced_argv);
            perror("execvp");
            exit(127);
        }
    }

    // if forked, parent process is a signal and exit code processor:
    
    ret=serve_client_release_fds      (opts, &ctx);  if (ret!=0) return ret;
    ret=serve_client_wait_init_event  (opts, &ctx);  if (ret!=0) return ret;
    ret=serve_client_send_pid         (opts, &ctx);  if (ret!=0) return ret;
    ret=serve_client_process_signals  (opts, &ctx);  if (ret!=0) return ret;
    return 0;
}



void serve_sigchild(int something) {
    // Note: there are multiple SIGCHLD handlers thought the dived code
    // this is is for case when -J or -F or --inetd options are not in use.
    
    // Here also orphaned processes get rebased when "--unshare pid" is in use.

    int status;
    for (;;) {
        int ret = waitpid(-1, &status, WNOHANG);
        if (ret==0 || ret == -1) break;
    }
    (void)status;
}

int serve(struct dived_options* opts) {
    if (opts->inetd) {
        return serve_client(0, opts);
    } 
    if (opts->just_execute) {
        return serve_client(-1, opts);
    }
    
    {
        struct sigaction sa = {{&serve_sigchild}};
        int ret = sigaction(SIGCHLD, &sa, NULL);
        if (ret == -1) {
            perror("sigaction");
        }
    }
    
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
            if (childpid == -1) {
                perror("fork");
                close(fd);
                goto retry_accept;
            }
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
        printf("Dive server %s (proto %d) https://github.com/vi/dive/\n", VERSION2, VERSION);
        printf("Listen UNIX socket and start programs for each connected client, redirecting fds to client.\n");        
        printf("Usage: dived {socket_path|@abstract_address|-i|-J} [-p pidfile] [-u user] [-e effective_user] "
               "[-C mode] [-U user:group] [{-R directory | -V newroot putold}] [-r [-W]] [-s smth1,smth2,...] [-a \"program\"] "
               "[{-B cap_smth1,cap_smth2|-b cap_smth1,cap_smth2}] [-m cap_smth1,...] [-X] [-c 'cap_smth+eip cap_smth2+i'] "
               "[-N /proc/.../ns/net [-N ...]] [-l res_name1=hard1,4=0,res_name2=hard2:soft2,...] [-t filename content]"
               "[various other argumentless options] [-- prepended commandline parts]\n");
        printf("          -d --detach           detach\n");
        printf("          -i --inetd            serve once, interpred stdin as client socket\n");
        printf("          -J --just-execute     don't mess with sockets at all, just execute the program.\n");
        printf("                                Other options does apply.\n");
        printf("          -j --just-execute2    Alias of -J -S -T -P\n");
        printf("          -D --children-daemon  call daemon(0,0) in children\n");
        printf("          -F --no-fork          no fork, serve once\n");
        printf("                                this is for debugging or for starting init process in PID unshare\n");
        printf("          -P --no-setuid        no setuid/setgid/etc\n");
        printf("          -u --user             setuid to this user instead of the client\n");
        printf("          -g --groups           setgid/setgroups to this comma-separated groups. The first one is primary.\n");
        printf("          -e --effective-user   seteuid to this user instead of the client\n");
        printf("          -B --retain-capabilities Remove all capabilities from bounding set\n");
        printf("                                   except of specified ones\n");
        printf("          -b --remove-capabilities Remove capabilities from bounding set\n");
        printf("          -m --ambient-capabilities Set these capabilities as ambient\n");
        printf("          -c --set-capabilities cap_set_proc the argument (like 'cap_smth+eip cap_smth2+i')\n"); 
        printf("          -X --no-new-privs     set PR_SET_NO_NEW_PRIVS\n");
        printf("          -L --lock-securebits  set and lock SECBIT_NO_SETUID_FIXUP and SECBIT_NOROOT\n");
        printf("          -a --authenticate     start this program for authentication\n");
        printf("              The program is started using \"system\" after file descriptors are received\n");
        printf("              from client, but before everything else (root, current dir, environment) is received.\n");
        printf("              Nonzero exit code => rejected client.\n");
        printf("          -l --rlimit           Set resource limits (comma-separated key=val list)\n");
        printf("                                  as,cpu,fsize,data,stack,core,locks,sigpending,msgqueue,nice,rtprio,rttime,nofile,nproc,memlock\n");
        printf("          -S --no-setsid        no setsid\n");
        printf("          -T --no-csctty        no ioctl TIOCSCTTY\n");
        printf("          -N --setns file       open this file and do setns(2); can be specified multiple times.\n");
        printf("          -R --chroot           chroot to this directory \n");
        printf("          -h --chdir            chdir to this directory (prior to chroot)\n");
        printf("              Note that current directory stays on unchrooted filesystem; use -W option to prevent.\n");
        printf("          -V --pivot-root       pivot_root to this directory, putting old root to the second argument\n");
        printf("          -r --client-chroot    Allow arbitrary chroot from client\n");
        printf("          -W --root-to-current  Set server's root directory as current directory\n");
        printf("                                (implies -H; useful with -r)\n");
        printf("          -s --unshare          Unshare specified namespaces (comma-separated list); also detaches\n");
        printf("                                ipc,net,fs,pid,uts,user,cgroup\n");
        printf("          -t  --write-content   write specified string to specified file after namespaces setup, \n");
        printf("                                (can be specified multiple times)\n");
        printf("          -tt --setup-uidgidmap Automatically write /proc/self/{uidmap,setgroup,gidmap}\n");
        printf("          -p --pidfile          save PID to this file; can be specified multiple times\n");
        printf("                                can also be used to append to cgroup's tasks. Happens early.\n");
        printf("          -C --chmod            chmod the socket to this mode (like '0777')\n");
        printf("          -U --chown            chown the socket to this user:group\n");
        printf("          -E --no-environment   Don't let client set environment variables\n");
        printf("          -A --no-argv          Don't let client set [part of] command line\n");
        printf("          -H --no-chdir         Don't let client set current directory\n");
        printf("          -O --no-fds           Don't let client set file descriptors\n");
        printf("          -M --no-umask         Don't let client set umask\n");
        printf("          -n --signals          Transfer all signals from dive\n");
        printf("          -w --no-wait          Don't fork and wait for exit code\n");
        printf("          --                    prepend this to each command line ('--' is mandatory)\n");
        printf("              Note that the program being started using \"--\" with '-e' or '-u' or '-P' options should be\n");
        printf("              as secure as suid programs, unless additional options like -E, -M, -O, -H or -A are in use.\n");
        return 4;
    }

// Unused short letters:
// GIKQYZfkoqvxyz

    {
        struct sigaction sa = {{sigchild}};
        sigaction(SIGCHLD, &sa, NULL);
    }

    struct dived_options *opts = &options;

    memset(opts, 0, sizeof(struct dived_options));
    
    opts->socket_path = argv[1];
    opts->nochilddaemon=1;
    opts->nodaemon=1;
    opts->client_umask = 1;
    opts->client_chdir = 1;
    opts->client_fds = 1;
    opts->client_argv = 1;
    opts->client_environment = 1;
    opts->envp = envp;
    opts->fork_and_wait_for_exit_code = 1;
    {int i; for(i=0; i<MAX_RLIMIT_SETS; ++i) { opts->rlimits[i].resource = -1; } }
    
    opts->maximum_fd_count=MAXFD-16;
    opts->maximum_argv_count=1000000;
    opts->maximum_argv_size=10000000;
    opts->maximum_envp_count=1000000;
    opts->maximum_envp_size=10000000;
    

    if(!strcmp(argv[1], "-i") || !strcmp(argv[1], "--inetd")) { opts->inetd = 1; }
    if(!strcmp(argv[1], "-J") || !strcmp(argv[1], "--just-execute")) { opts->just_execute = 1; }
    if(!strcmp(argv[1], "-j") || !strcmp(argv[1], "--just-execute2")) {
        opts->just_execute = 1;
        opts->nosetsid = 1;
        opts->nocsctty = 1;
        opts->noprivs = 1;
    }

    if(argv[1][0] == '-') {
        if (!opts->inetd  && !opts->just_execute) {
            fprintf(stderr, "Warning: suspicious socket name '%s'\n", argv[1]);
            fprintf(stderr, "Only --just-execute, --just-execute2 (-j/-J) or --inetd (-i) may be the first option\n");
        }
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
            if(!strcmp(argv[i], "-g") || !strcmp(argv[i], "--groups")) {
                opts->forcegroups=argv[i+1];
                ++i;
            }else
            if(!strcmp(argv[i], "-e") || !strcmp(argv[i], "--effective-user")) {
                opts->effective_user=argv[i+1];
                ++i;
            }else
            if(!strcmp(argv[i], "-p") || !strcmp(argv[i], "--pidfile")) {
                int j;
                for (j=0; j<MAX_PIDFILES && opts->pidfiles[j]!=NULL; ++j);
                if (j == MAX_PIDFILES) {
                    fprintf(stderr, "Exceed maximum number of --pidfile arguments\n");
                    return 4;
                }
                if (argv[i+1] == NULL) {
                    fprintf(stderr, "--pidfile requires an argument\n");
                    return 4;
                }
                opts->pidfiles[j]=argv[i+1];
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
            if(!strcmp(argv[i], "-h") || !strcmp(argv[i], "--chdir")) {
                opts->chdir_=argv[i+1];
                ++i;
            }else
            if(!strcmp(argv[i], "-R") || !strcmp(argv[i], "--chroot")) {
                opts->chroot_=argv[i+1];
                ++i;
            }else
            if(!strcmp(argv[i], "-V") || !strcmp(argv[i], "--pivot-root")) {
                opts->pivotroot_newroot=argv[i+1];
                ++i;
                if(opts->pivotroot_newroot == NULL) {
                    fprintf(stderr, "--pivot-root should be followed by two arguments\n");
                    return 4;
                }
                opts->pivotroot_putold=argv[i+1];
                ++i;
                if(opts->pivotroot_putold == NULL) {
                    fprintf(stderr, "--pivot-root should be followed by two arguments\n");
                    return 4;
                }
            }else
            if(!strcmp(argv[i], "-N") || !strcmp(argv[i], "--setns")) {
                int j;
                #ifdef NO_SETNS
                    fprintf(stderr, "setns is not enabled in this build of dived\n");
                    return 4;
                #endif
                for (j=0; j<MAX_SETNS_FILES && opts->setns_files[j]!=NULL; ++j);
                if (j == MAX_SETNS_FILES) {
                    fprintf(stderr, "Exceed maximum number of --setns arguments\n");
                    return 4;
                }
                if (argv[i+1] == NULL) {
                    fprintf(stderr, "--set-ns requires an argument\n");
                    return 4;
                }
                opts->setns_files[j]=argv[i+1];
                ++i;
            }else
            if(!strcmp(argv[i], "-t") || !strcmp(argv[i], "--write-content")) {
                int j;
                for (j=0; j<MAX_WRITECONTENT_FILES && opts->writecontent_files[j]!=NULL; ++j);
                if (j == MAX_WRITECONTENT_FILES) {
                    fprintf(stderr, "Exceed maximum number of --write-content argument pairs\n");
                    return 4;
                }
                if (argv[i+1] == NULL || argv[i+2] == NULL) {
                    fprintf(stderr, "--write-content requires two arguments\n");
                    return 4;
                }
                opts->writecontent_files[j]=argv[i+1];
                opts->writecontent_data[j]=argv[i+2];
                ++i;
                ++i;
            }else
            if(!strcmp(argv[i], "-tt") || !strcmp(argv[i], "--setup-uidgidmap")) {
                int j;
                for (j=0; j<MAX_WRITECONTENT_FILES && opts->writecontent_files[j]!=NULL; ++j);
                if (j >= MAX_WRITECONTENT_FILES-2) {
                    fprintf(stderr, "Exceed maximum number of --write-content argument pairs\n");
                    return 4;
                }
                opts->writecontent_data[j+0] = malloc(128);
                opts->writecontent_data[j+2] = malloc(128);

                if (!opts->writecontent_data[j+0] || !opts->writecontent_data[j+2]) {
                    perror("malloc");
                    return 4;
                }


                opts->writecontent_files[j+0] = "/proc/self/uid_map";
                snprintf(opts->writecontent_data[j+0], 128, "0 %lld 1", (long long)getuid());
                opts->writecontent_files[j+1] = "/proc/self/setgroups";
                opts->writecontent_data [j+1] = "deny";
                opts->writecontent_files[j+2] = "/proc/self/gid_map";
                snprintf(opts->writecontent_data[j+2], 128, "0 %lld 1", (long long)getgid());
            }else
            if(!strcmp(argv[i], "-s") || !strcmp(argv[i], "--unshare")) {
                opts->unshare_=argv[i+1];
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
            if(!strcmp(argv[i], "-l") || !strcmp(argv[i], "--rlimit")) {
                int j;
                #ifdef NO_RLIMIT
                    fprintf(stderr, "--rlimit is not enabled in this build of dived\n");
                    return 4;
                #endif
                j=0;
                char *saveptr_commas="";
                char* q = strtok_r(argv[i+1], ",", &saveptr_commas);
                for(; q; q=strtok_r(NULL, ",", &saveptr_commas)) {
                    if (j==MAX_RLIMIT_SETS) {
                        fprintf(stderr, "Exceed maximum number of --rlimit arguments\n");
                        return 4;
                    }             
                    struct rlimit_setter *r = &opts->rlimits[j];
                    
                    char *saveptr_equalsign;
                    char *saveptr_colon;
                    
                    char *resource = strtok_r(q, "=", &saveptr_equalsign);
                    char *limits = strtok_r(NULL, "=", &saveptr_equalsign);
                    
                    if (resource==NULL || limits==NULL) {
                        fprintf(stderr, "Invalid --rlimit parameter %s\n",q);
                        fprintf(stderr, "Should be rlimit_name_or_number=hard_limit[:soft_limit]");
                        return 4;
                    }
                    
                    char *limit_hard = strtok_r(limits, ":", &saveptr_colon);
                    char *limit_soft = strtok_r(NULL, ":", &saveptr_colon);
                    
                    if(limit_hard==NULL) {
                        fprintf(stderr, "Invalid --rlimit value \"%s\"\n", q);
                        return 4;
                    } else {
                        if(sscanf(limit_hard, "%ld", &r->limits.rlim_max) != 1) {
                            fprintf(stderr, "\"%s\" is not a number in --rlimit %s\n", limit_hard, q);
                            return 4;
                        }
                    }
                    if (limit_soft==NULL) {
                        r->limits.rlim_cur = r->limits.rlim_max;
                    } else {
                        if(sscanf(limit_soft, "%ld", &r->limits.rlim_cur) != 1) {
                            fprintf(stderr, "\"%s\" is not a number in --rlimit %s\n", limit_soft, q);
                            return 4;
                        }                        
                    }
                    
                    if(sscanf(resource, "%d", &r->resource)!=1) {
                        if      (!strcasecmp(resource, "as"))         r->resource=RLIMIT_AS;
                        else if (!strcasecmp(resource, "cpu"))        r->resource=RLIMIT_CPU;
                        else if (!strcasecmp(resource, "fsize"))      r->resource=RLIMIT_FSIZE;
                        else if (!strcasecmp(resource, "data"))       r->resource=RLIMIT_DATA;
                        else if (!strcasecmp(resource, "stack"))      r->resource=RLIMIT_STACK;
                        else if (!strcasecmp(resource, "core"))       r->resource=RLIMIT_CORE;
                        else if (!strcasecmp(resource, "locks"))      r->resource=RLIMIT_LOCKS;
                        else if (!strcasecmp(resource, "sigpending")) r->resource=RLIMIT_SIGPENDING;
                        else if (!strcasecmp(resource, "msgqueue"))   r->resource=RLIMIT_MSGQUEUE;
                        else if (!strcasecmp(resource, "nice"))       r->resource=RLIMIT_NICE;
                        else if (!strcasecmp(resource, "nofile"))     r->resource=RLIMIT_NOFILE;
                        else if (!strcasecmp(resource, "nproc"))      r->resource=RLIMIT_NPROC;
                        else if (!strcasecmp(resource, "memlock"))    r->resource=RLIMIT_MEMLOCK;
#ifndef RLIMIT_RTPRIO
#define RLIMIT_RTPRIO		14
#endif
                        else if (!strcasecmp(resource, "rtprio"))     r->resource=RLIMIT_RTPRIO;
#ifndef RLIMIT_RTTIME
#define RLIMIT_RTTIME		15
#endif
                        else if (!strcasecmp(resource, "rttime"))     r->resource=RLIMIT_RTTIME;
                        else {
                            fprintf(stderr, "Unknown --rlimit resource %s\n", resource);
                            fprintf(stderr, "You can also specify a numeric value\n");
                            return 4;
                        }
                    }
                 
                    ++j;
                }
                
                
                ++i;
            }else
            if(!strcmp(argv[i], "-B") || !strcmp(argv[i], "--retain-capabilities")) {
                opts->retain_capabilities = argv[i+1];
                ++i;
            }else
            if(!strcmp(argv[i], "-b") || !strcmp(argv[i], "--remove-capabilities")) {
                opts->remove_capabilities = argv[i+1];
                ++i;
            }else
            if(!strcmp(argv[i], "-m") || !strcmp(argv[i], "--ambient-capabilities")) {
                opts->ambient_capabilities = argv[i+1];
                ++i;
            }else
            if(!strcmp(argv[i], "-X") || !strcmp(argv[i], "--no-new-privs")) {
                opts->no_new_privs = 1;
            }else
            if(!strcmp(argv[i], "-c") || !strcmp(argv[i], "--set-capabilities")) {
                opts->set_capabilities = argv[i+1];
                ++i;
            }else
            if(!strcmp(argv[i], "-L") || !strcmp(argv[i], "--lock-securebits")) {
                opts->lock_securebits = 1;
            }else
            if(!strcmp(argv[i], "-n") || !strcmp(argv[i], "--signals")) {
                opts->signal_processing = 1;
            }else
            if(!strcmp(argv[i], "-w") || !strcmp(argv[i], "--no-wait")) {
                opts->fork_and_wait_for_exit_code = 0;
            }else
            if(!strcmp(argv[i], "--")) {
                opts->forced_argv = &argv[i+1];
                opts->forced_argv_count = argc - (i+1);
                break;
            }else
            if(!strcmp(argv[i], "-j") || !strcmp(argv[i], "--just-execute2")) {
                fprintf(stderr, "Option --just-execute2 must be the first\n");
                return 4;
            }else
            if(!strcmp(argv[i], "-J") || !strcmp(argv[i], "--just-execute")) {
                fprintf(stderr, "Option --just-execute must be the first\n");
                return 4;
            }else
            if(!strcmp(argv[i], "-i") || !strcmp(argv[i], "--inetd")) {
                fprintf(stderr, "Option --inetd must be the first\n");
                return 4;
            }else
            {
                fprintf(stderr, "Unknown argument %s\n", argv[i]);
                return 4;
            }
        }
    }
    
    if (opts->noprivs) {
        if (opts->forceuser || opts->forcegroups || opts->effective_user) {
            fprintf(stderr, "--user, --group and --effective_user options are not effective with --no-setuid\n");
            if (!strcmp(argv[1], "-j") || !strcmp(argv[1], "--just-execute2")) {
                fprintf(stderr, "Maybe use '-J -S -T' instead of '-j'?\n");
            }
            return 4;
        }
    }
    if (!getenv("DIVED_NOSANITYCHECK") && !opts->just_execute) { // little check for really insecure setup
        if (opts->forced_argv_count>0 && opts->forced_argv[0][0]!='/' && opts->client_environment) {
            fprintf(stderr, "Please either use absolute program path after -- or use --no-environment option.\n");
            fprintf(stderr, "In current mode remote client can override PATH and chose any program.\n");
            fprintf(stderr, "Set DIVED_NOSANITYCHECK to force insecure mode.\n");
            return 4;
        }
        if (!opts->forceuser && opts->forcegroups) {
            fprintf(stderr, "--groups won't work without --user\n");
            return 4;
        }
    
        int permissive_chmod = 0;
        int no_privs = 0;
        int overridden_effective = 0;
        
        if (opts->chmod_) {
            long mask_decoded = strtol(opts->chmod_, NULL, 8);
            if (mask_decoded&0002) permissive_chmod = 1;
        }
        if (opts->effective_user) overridden_effective = 1;
        if (opts->noprivs) no_privs = 1;
        
        if (opts->client_environment && permissive_chmod && opts->forced_argv_count &&
            (overridden_effective || no_privs || (
                opts->forceuser && (!strcmp(opts->forceuser, "root") || !strcmp(opts->forceuser, "0"))
                ))){
            fprintf(stderr, "Warning: Allowing permissive remote starting of specific program and also allowing");
            fprintf(stderr, "setting environment variables is probably a security issue.\n");
            fprintf(stderr, "Consider using --no-environment option (or set DIVED_NOSANITYCHECK to prevent this message).\n");
        }
    }
    
    if (opts->just_execute && opts->inetd) {
        fprintf(stderr, "--just-execute and --inetd are incompatible\n");
        return 15;
    }
    
    if (!opts->fork_and_wait_for_exit_code && opts->signal_processing) {
        fprintf(stderr, "--no-wait and --signals are incompatible\n");
        return 15;
    }
    
    #ifdef NO_CAPABILITIES       
    if (opts->set_capabilities || opts->retain_capabilities || opts->remove_capabilities || opts->ambient_capabilities) {
        fprintf(stderr, "Capabilities are not enabled for this build\n");
        return 17;
    }
    #endif
    
    if (opts->remove_capabilities && opts->retain_capabilities) {
        fprintf(stderr, "--remove-capabilities and --retain-capabilities are incompatible\n");
        return 18;
    }
    
    if (opts->chroot_ && opts->pivotroot_newroot) {
        fprintf(stderr, "--chroot and --pivot-root are incompatible\n");
        return 4;
    }
    #ifdef NO_PIVOTROOT
    if (opts->pivotroot_newroot) {
        fprintf(stderr, "--pivot-root is not enabled for this build of dived\n");
        return 17;
    }
    #endif
    
    if (opts->just_execute && opts->forced_argv_count == 0) {        
        fprintf(stderr, "You must include argv after -- with --just-execute\n");
        return 4;
    }
    
    if (!opts->inetd && !opts->just_execute) {
    
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
                fprintf(stderr, "User %s not found (and not a numeric uid)\n", usern);
                return 12;
            }
            targetuid = userp->pw_uid;
        }
        
        errno=0;
        targetgid = strtol(groupn, &endnum, 10);
        if (errno || endnum == groupn || *endnum) {
            struct group *groupp = getgrnam(groupn);
            if (!groupp) {
                fprintf(stderr, "Group %s not found (and not a numeric gid)\n", groupn);
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
    
    } // not --just-execute and not --inetd
    
    if(!opts->nodaemon) {
        int ret = daemon(1, 0);
        if (ret == -1) {
            perror("daemon");
            return 16;
        }
    }
    
    /* Save pidfile */
    if (!opts->unshare_){
        int j;
        for (j=0; j<MAX_PIDFILES; ++j) {
            if (opts->pidfiles[j] == NULL) continue;
            FILE* f = fopen(opts->pidfiles[j], "w");
            fprintf(f, "%d\n", getpid());
            fclose(f);
        }
    }
        
    if (!opts->unshare_) {
        return serve(opts);
    } else {
        int flags=0;
        char* q = strtok(opts->unshare_, ",");
        for(; q; q=strtok(NULL, ",")) {
            if      (!strcmp(q,"ipc")) flags|=CLONE_NEWIPC;
            else if (!strcmp(q,"net")) flags|=CLONE_NEWNET;
            else if (!strcmp(q,"fs" ))  flags|=CLONE_NEWNS;
            else if (!strcmp(q,"mnt" )) flags|=CLONE_NEWNS;
            else if (!strcmp(q,"pid")) flags|=CLONE_NEWPID;
            else if (!strcmp(q,"uts")) flags|=CLONE_NEWUTS;
            else if (!strcmp(q,"user")) flags|=CLONE_NEWUSER;
#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP         0x02000000
#endif
            else if (!strcmp(q,"cgroup")) flags|=CLONE_NEWCGROUP;
            else {
                fprintf(stderr, "Unknown unshare flag '%s'\n", q);
                return 21;
            }
        }
        
        #ifndef NO_UNSHARE
        if (! ((flags & CLONE_NEWUSER) ||  (flags & CLONE_NEWPID)) ) {
            /* Simpler mode: just use unshare(2) */
            int ret = unshare(flags);
            if (ret == -1) {
                perror("unshare");
                return -1;
            }
            return serve(opts);
        }
        #endif
        
        char* stack = (char*) malloc(CLONE_STACK_SIZE);
        if (!stack) {
            perror("malloc");
            return -1;
        }
        char* stack_pointer = stack;
        
        #ifndef CPU_STACK_GROWS_UP
        #define CPU_STACK_GROWS_UP FALSE
        #endif
        
        #ifndef FALSE
        #define FALSE (0)
        #endif
        
        #ifndef TRUE
        #define TRUE (1)
        #endif
        
        int signal_fd = -1;
        
        if (opts->nodaemon) {
            sigset_t mask;
            sigemptyset(&mask);
            sigaddset(&mask, SIGCHLD);
            #ifndef SIGNALFD_WORKAROUND
            signal_fd = signalfd(-1, &mask, 0/*SFD_NONBLOCK*/);
            #endif
            sigprocmask(SIG_BLOCK, &mask, NULL);
        }
        
        stack_pointer += (CPU_STACK_GROWS_UP) ? 0 : CLONE_STACK_SIZE;
        int cpid = clone( (int(*)(void*)) serve, stack_pointer, CLONE_VM|flags, opts);
        if (cpid == -1) {
            perror("clone");
            return 19;
        }
        
        {
            int j;
            for (j=0; j<MAX_PIDFILES; ++j) {
                if (opts->pidfiles[j] == NULL) continue;
                FILE* f = fopen(opts->pidfiles[j], "w");
                fprintf(f, "%d\n", getpid());
                fclose(f);
            }
        }
        
        if (opts->nodaemon) {  
            #ifndef SIGNALFD_WORKAROUND
            if (signal_fd!=-1) for(;;) {
                struct signalfd_siginfo si;
                int ret = read(signal_fd, &si, sizeof si);
                if (ret!=-1 && si.ssi_pid == cpid && si.ssi_signo == SIGCHLD) {
                    return si.ssi_status;
                }
                if (ret==-1) break;
            }
            #endif // SIGNALFD_WORKAROUND
            
            /* Fall-back to unreliable method */
            
            int status=0;
            int spinlimit=100;
            for(;;) {
                int ret = waitpid(0, &status, 0);
                fprintf(stderr, "ret=%d errno=%d status=%08x\n", ret, errno, status);
                if (ret == cpid && WIFEXITED(status)) {
                    return WEXITSTATUS(status);
                }
                if (ret == -1) {
                    if (spinlimit) {
                       --spinlimit; 
                    } else {
                        sleep(1);
                    }
                }
            }
        }
        
        return 0; 
    }
}
