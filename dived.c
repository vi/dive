#define _GNU_SOURCE

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pwd.h>
#include "recv_fd.h"

int main(int argc, char* argv[]) {
    int sock;
    struct sockaddr_un addr;

    unlink("qqq");

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "qqq", sizeof(addr.sun_path) - 1);


    sock = socket(AF_UNIX, SOCK_STREAM, 0);
    bind(sock, (struct sockaddr *) &addr, sizeof(struct sockaddr_un));
    listen(sock, 10);


    daemon();
    for(;;) {
        struct sockaddr_un addr2;
        socklen_t addrlen = sizeof(addr2);
        int fd = accept(sock, (struct sockaddr*)&addr2, &addrlen);

        int childpid = fork();

        if(!childpid) {
            close(sock);
            struct ucred cred;
            socklen_t len = sizeof(struct ucred);
            getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cred, &len);


            //printf("pid=%ld, euid=%ld, egid=%ld\n", (long) cred.pid, (long) cred.uid, (long) cred.gid);
            
            int sin = recv_fd(fd);
            int sout = recv_fd(fd);
            int serr = recv_fd(fd);
            
            dup2(sin, 0);
            dup2(sout, 1);
            dup2(serr, 2);

            close(sin);
            close(sout);
            close(serr);

            //setsid();
            //setpgid(0,0);

            char *username = "";
            struct passwd *pw = getpwuid(cred.uid);
            if(pw) {
                username = pw->pw_name;
            }

            initgroups(username, cred.gid);
            setgid(cred.gid);
            setuid(cred.uid);

            char buf[256];
            snprintf(buf, 256, "%d", getpid());
            send(fd, buf, 256, 0);
            

            execl("/bin/bash", "bash", NULL);
        } else {
            close(fd);
        }

    }
    
    return 0;
}
