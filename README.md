Start processes in other network/mount/whatever namespace, as created by `unshare` or `lxc-start`.

Works by sending file descriptors over UNIX socket. 

Exampe:

    # # Start dived in unshared network namespace
    # unshare -n  -- dived /var/run/qqq.socket -d
    # dive /var/run/qqq.socket ip addr
    1218: lo: <LOOPBACK> mtu 16436 qdisc noop state DOWN 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    # dive /var/run/qqq.socket bash
    # # Now we are inside that unshare
    # ip link set lo up
    # exit
    exit
    # # outside unshare again
    # dive /var/run/qqq.socket bash
    # ip addr
    1218: lo: <LOOPBACK,UP,LOWER_UP> mtu 16436 qdisc noqueue state UNKNOWN 
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 scope host lo
    # # our network configuration persisted


Features:
    
* Absence of any filesystem permission tricks (chmod +s)
* Secure preserving of user id and groups (requires root access)
* Preserving of current directory
* Preserving of all file descriptors (not only stdin/stdout/stderr)
* Setting session ID and controlling terminal, for clean bash without "no job control" (requires root access)
* Preserving of environment variables

Notes:

* For clean interactive shell access dived need to be started as root (for setsid/TIOCSCTTY)
* * Without TIOCSCTTY, use `socat -,raw,echo=0 exec:bash,pty,setsid,stderr` (there's hind in `dive`'s usage message) as the program to start to have nicer bash
* Current directory can be "smuggled" into unshare where that part of filesystem is not mounted
 

