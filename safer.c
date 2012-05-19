#include <unistd.h>
#include <errno.h>

int safer_write(int f, char* b, int n) {
    while(n) {
        int r = write(f, b, n);        
        if(!r) return 0;
        if(r==-1) {
            if (errno==EINTR || errno==EAGAIN) continue;
            return -1;
        }
        n-=r;
        b+=r;
    }
}

int safer_read(int f, char* b, int n) {
    while(n) {
        int r = read(f, b, n);        
        if(!r) return 0;
        if(r==-1) {
            if (errno==EINTR || errno==EAGAIN) continue;
            return -1;
        }
        n-=r;
        b+=r;
    }
}
