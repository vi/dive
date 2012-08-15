Start processes in other network/mount/whatever namespace, as created by `unshare` or `lxc-start`. Also allow users execute programs in other user account or in chroot in controlled way (like sudo, but without setuid-bit in filesystem).

Works by sending file descriptors over UNIX socket. 

**Exampe**

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

**Multi-user example**

Let users start programs with network access disabled.

    # umask 0000
    # unshare -n -- dived /var/run/qqq2.socket -d
    
    $ dive /var/run/qqq2.socket bash
    $ ping 127.0.0.1
    connect: Network is unreachable
    $ id
    $ uid=1000(vi) gid=1000(vi) groups=1000(vi),20(dialout),21(fax),...

**"Poor man's sudo" example 1**

Grant Alice access to Bob.

    root# dived /var/run/alice2bob -d -C 700 -U alice:alice -u bob
    
    alice$ HOME=/home/bob USER=bob dive /var/run/alice2bob bash
    bob$ id
    uid=1037(bob) gid=1045(bob) groups=1045(bob),1033(ololo)
    bob$ exit
    alice$
    malice$ dive /var/run/alice2bob bash
    connect: Permission denied
    
    
**Poor man's suid-bit-less sudo example 2**

Allow certain users execute certain programs (script in some directory) as root. Use client's command line arguments and filehandles, but not environment variables, current directory or controlling tty.

    root# dived  /var/run/suidless_sudo --detach --user root --no-csctty --chmod 777 --no-environment  --no-chdir --no-umask -- /root/scripts/suidless_sudo
    root# cat /root/scripts/suidless_sudo
    #!/usr/bin/perl -w
      use strict;
      die("No script specified") if $#ARGV == -1;
      my $script = $ARGV[0];
      my $user = $ENV{"DIVE_USER"};
      die ("No user") unless $user;
      die ("Forbidden") unless $user eq "alice";
      die ("Bad script name $script") unless ($script =~ /^([a-zA-Z0-9_]{1,64})$/);
      exec "/root/scripts/allowed_scripts/$1"
    
    alice$ dive /var/run/suidless_sudo ../../../bin/bash
    Bad script name  at /root/scripts/suidless_sudo line 8.
    alice$ dive /var/run/suidless_sudo reboot
    Reboot started
    
    bob$ dive /var/run/suidless_sudo reboot
    Forbidden at /root/scripts/suidless_sudo line 7.
    bob$ DIVE_USER=alice dive /var/run/suidless_sudo reboot
    Forbidden at /root/scripts/suidless_sudo line 7.
    
    

    
**Usage**

    Usage: dived {socket_path|-i} [-d] [-D] [-F] [-P] [-S] 
    [-p pidfile] [-u user] [-C mode] [-U user:group] [-R directory] 
    [-s smth1,smth2,...] [-- prepended commandline parts]
              -d --detach           detach
              -i --inetd            serve once, interpred stdin as client socket
              -D --children-daemon  call daemon(0,0) in children
              -F --no-fork          no fork, serve once (debugging)
              -P --no-setuid        no setuid/setgid/etc
              -u --user             setuid to this user instead of the client
              -S --no-setsid        no setsid
              -T --no-csctty        no ioctl TIOCSCTTY
              -R --chroot           chroot to this directory 
                  Note that current directory stays on unchrooted filesystem 
              -s --unshare          Unshare this (comma-separated list); also detaches
                                    ipc,net,fs,pid,uts
              -p --pidfile          save PID to this file
              -C --chmod            chmod the socket to this mode (like '0777')
              -U --chown            chown the socket to this user:group
              -E --no-environment   Don't let client set environment variables
              -A --no-argv          Don't let client set command line
              -H --no-chdir         Don't let client set current directory
              -O --no-fds           Don't let client set file descriptors
              -M --no-umask         Don't let client set umask
              --                    prepend this to each command line ('--' is mandatory)
                  Note that the program beingnocsctty strarted using "--" should be
                  as secure as suid programs, but it doesn't know
                  real uid/gid.

                      
        Usage: dive socket_path [program arguments]
    
**Features**
    
* Absence of any filesystem permission tricks (no "chmod +s" required)
* Secure preserving of user id and groups (requires root access)
* Preserving of current directory
* Preserving of all file descriptors (not only stdin/stdout/stderr)
* Setting session ID and controlling terminal, for clean bash without "no job control" (requires root access)
* Preserving of environment variables
* Preserving of exit code
* Selective disabling of "preserving" parts above (from v0.5)
* Chroot / CLONE_NEW... / forced command line (from v0.5)
* Setting of DIVE_USER and other variables according to client credentials

**Notes**

* For clean interactive shell access dived need to be started as root (for setsid/TIOCSCTTY)
    * Without TIOCSCTTY, use `socat -,raw,echo=0 exec:bash,pty,setsid,stderr` (there's hind in `dive`'s usage message) as the program to start to have nicer bash
    * With TIOCSCTTY it steams controlling terminal from the previous process (leaving it "homeless"), so "exec dive socket bash" is preferred.
* Current directory can be "smuggled" into unshare where that part of filesystem is not mounted
 

 There are pre-built i386 binaries for [dive](http://vi-server.org/pub/dive) and [dived](http://vi-server.org/pub/dived).
