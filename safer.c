#include <unistd.h>
#include <errno.h>

int safer_write(int f, char* b, int n) {
    int acc = 0;
    while(n) {
        int r = write(f, b, n);        
        if(!r) return acc;
        if(r==-1) {
            if (errno==EINTR || errno==EAGAIN) continue;
            return -1;
        }
        n-=r;
        b+=r;
        acc+=r;
    }
    return acc;
}

int safer_read(int f, char* b, int n) {
    int acc = 0;
    while(n) {
        int r = read(f, b, n);        
        if(!r) return acc;
        if(r==-1) {
            if (errno==EINTR || errno==EAGAIN) continue;
            return -1;
        }
        n-=r;
        b+=r;
        acc+=r;
    }
    return acc;
}
