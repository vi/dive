Start processes in other network/mount/whatever namespace, as created by `unshare` or `lxc-start` 
(as long as there is a shared filesytem between the host and container and you use recent enough Linux kernel). 
Also allow users execute programs in other user account or in chroot in controlled way 
(like sudo, but without setuid-bit in filesystem).

Works by sending file descriptors over UNIX socket. 

<strong>See various usage examples and pre-built dive[d] versions at the [github page](http://vi.github.com/dive/).</strong>
    
**Usage**

```
Dive server v1.1 (proto 800) https://github.com/vi/dive/
Listen UNIX socket and start programs for each connected client, redirecting fds to client.
Usage: dived {socket_path|@abstract_address|-i|-J} [-d] [-D] [-F] [-P] [-S] [-p pidfile] [-u user] [-e effective_user] [-C mode] [-U user:group] [-R directory] [-r [-W]] [-s smth1,smth2,...] [-a "program"] [{-B cap_smth1,cap_smth2|-b cap_smth1,cap_smth2}] [-X] [-c 'cap_smth+eip cap_smth2+i'] [-- prepended commandline parts]
          -d --detach           detach
          -i --inetd            serve once, interpred stdin as client socket
          -J --just-execute     don't mess with sockets at all, just execute the program.
                                Other options does apply.
          -D --children-daemon  call daemon(0,0) in children
          -F --no-fork          no fork, serve once (debugging)
          -P --no-setuid        no setuid/setgid/etc
          -u --user             setuid to this user instead of the client
          -e --effective-user   seteuid to this user instead of the client
          -B --retain-capabilities Remove all capabilities from bounding set
                                   except of specified ones
          -b --remove-capabilities Remove capabilities from bounding set
          -c --set-capabilities cap_set_proc this
          -X --no-new-privs     set PR_SET_NO_NEW_PRIVS
          -a --authenticate     start this program for authentication
              The program is started using "system" after file descriptors are received
              from client, but before everything else (root, current dir, environment) is received.
              Nonzero exit code => rejected client.
          -S --no-setsid        no setsid
          -T --no-csctty        no ioctl TIOCSCTTY
          -R --chroot           chroot to this directory 
              Note that current directory stays on unchrooted filesystem; use -W option to prevent.
          -r --client-chroot    Allow arbitrary chroot from client
          -W --root-to-current  Set server's root directory as current directory
                                (implies -H; useful with -r)
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
```

    Usage: dive socket_path [program arguments]
    
**Features**
    
* Absence of any filesystem permission tricks (no "chmod +s" required)
* Secure preserving of user id and groups (requires root access)
* Preserving of current directory
* Preserving of all file descriptors (not only stdin/stdout/stderr)
* Setting session ID and controlling terminal, for clean bash without "no job control" (requires root access)
* Preserving of environment variables
* Preserving of exit code
* Selective disabling of "preserving" parts above 
* Chroot / CLONE_NEW... / forced command line
* Setting of DIVE_USER and other variables according to client credentials
* Allowing clients to set it's own root directory ("-r" option)
* Setting of PR_SET_NO_NEW_PRIVS to turn off filesystem-based permission elevations
* Setting Linux capabilities
* "Just execute" feature to use capabilities, chroot, PR_SET_NO_NEW_PRIVS
 setup; "authenticate", pidfile and so on without any "remote startup" thought
 socket at all

For less feature-creep version see "nocreep" branch


**Notes**

* For clean interactive shell access dived need to be started as root (for setsid/TIOCSCTTY)
    * Without TIOCSCTTY, use `socat -,raw,echo=0 exec:bash,pty,setsid,stderr` (there's hind in `dive`'s usage message) as the program to start to have nicer bash
    * With TIOCSCTTY it steams controlling terminal from the previous process (leaving it "homeless"), so "exec dive socket bash" is preferred (or workaround with [reptyr](https://github.com/nelhage/reptyr) >= v0.4 is needed).
* Current directory can be "smuggled" into the chroot or unshare where that part of filesystem is not mounted (can be prevented using -W or -H options)
* dived sets up groups for user, but it does not provide fully fledged PAM-like login. For example, resource limits are just inherited, not set up using `/etc/security/limits.conf`.
 

 There are pre-built i386 binaries for [dive](http://vi-server.org/pub/dive) and [dived](http://vi-server.org/pub/dived). There are also [musl-gcc](http://www.musl-libc.org/)-built binaries for [dive](http://vi-server.org/pub/dive_musl) and [dived](http://vi-server.org/pub/dived_musl) (without capabilities support). There are static uClibc ARMel binaries: [dive](http://vi-server.org/pub/dive_armel), [dived](http://vi-server.org/pub/dived_armel) (also without libcap).
