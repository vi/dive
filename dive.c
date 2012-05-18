#define _GNU_SOURCE

#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <sys/ptrace.h>

#include "send_fd.h"


int main(int argc, char* argv[]) {
    int fd;
    struct sockaddr_un addr;
    int ret;

    memset(&addr, 0, sizeof(struct sockaddr_un));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, "qqq", sizeof(addr.sun_path) - 1);


    fd = socket(AF_UNIX, SOCK_STREAM, 0);

    
    connect(fd, (struct sockaddr*)&addr, sizeof addr);

    send_fd(fd, 0);
    send_fd(fd, 1);
    send_fd(fd, 2);

    close(0);
    close(1);
    close(2);

    char buf[256];
    recv(fd, buf, 256, 0);
    pid_t theirpid;
    sscanf(buf, "%d", &theirpid);
    //ptrace(PTRACE_ATTACH, theirpid, 0, 0);
    //ptrace(PTRACE_CONT, theirpid, 0, 0);

    
rerecv:
    ret = recv(fd, buf, 1, 0);
    if(ret==-1){
        if (errno==EINTR || errno==EAGAIN) {
            goto rerecv;
        }
    }
    
    return 0;
}
