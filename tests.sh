#!/bin/bash

true ${DIVE_NAME:="dive"}
true ${DIVED_NAME:="dived"}

export DIVE_NAME
export DIVED_NAME

STATUS=0

unset V
unset E
true ${UID:="`id -u`"}

VERBOSE=0

function t() {
    # call the specified argv, capture output and exit code, compare to $V and $E respectively
    
    if [ "$VERBOSE" == "0" ]; then
        VAL=`"$@" < /dev/null 2> /dev/null`
    else
        VAL=`"$@" < /dev/null`
    fi
    C=$?
    if [[ "$C" != "0" && "$E" == "fail" ]]; then C=fail; fi
    if [ "$C" != "$E"  ]; then
        if [ -z "$MF" ]; then # "May fail"
            echo "FAIL code=$C"
            STATUS=1
        else
            echo "fail soft; code=$C"
        fi
        return 1
    fi
    
    if [[ "$V" != "nocheck" && "$VAL" != "$V" ]]; then
        if [ -z "$MF" ]; then
            printf "FAIL\nexpected: %s\nactual:   %s\n" "$V" "$VAL"
            STATUS=1
        else
            echo "fail soft; val=$VAL"
        fi
        STATUS=1
        return 1
    fi
    
    echo " OK "
}

function terminate_dived() {
    test -e test_dived.pid && pkill -F test_dived.pid
    rm -f test_dived test_dived.pid
}

function prepare_dived() {
    terminate_dived
    ./$DIVED_NAME test_dived --detach --pidfile test_dived.pid "$@"
} 

function announce() {
    printf "%-50s" "$*"
}

trap 'terminate_dived' EXIT




if [ -z "$TESTS_NO_USER" ]; then


announce    Dummy dived call
E=4 V='nocheck' t ./$DIVED_NAME

announce    Dummy dive  call
E=4 V='nocheck' t ./$DIVE_NAME

announce    dived -J simple test
E=0 V='' t ./$DIVED_NAME -J -- /bin/true

announce    dived -J return code
E=44 V='' t ./$DIVED_NAME -J -- /bin/sh -c "exit 44"

announce    dived -J print
E=0 V='qqq' t ./$DIVED_NAME -J -- /bin/echo qqq

announce    dive and dived echo
prepare_dived
E=0 V='qqq' t ./$DIVE_NAME test_dived /bin/echo qqq


announce    dive and dived echo '(dived -n)'
prepare_dived --signals
E=0 V='qqq' t ./$DIVE_NAME test_dived /bin/echo qqq

announce    dive and dived return code
prepare_dived
E=44 V='' t ./$DIVE_NAME test_dived /bin/sh -c "exit 44"


announce    dive and dived return code '(dived -n)'
prepare_dived --signals
E=44 V='' t ./$DIVE_NAME test_dived /bin/sh -c "exit 44"

announce    Preserve environment
prepare_dived
E=0 V='31336' t ./$DIVE_NAME test_dived /bin/sh -c 'echo $V'

announce    No preserve environment if -E
prepare_dived -E
E=0 V='' t ./$DIVE_NAME test_dived /bin/sh -c 'echo $V'

announce    No preserve DIVE_* environment
prepare_dived
E=0 V='' DIVE_QQQ=12345 t ./$DIVE_NAME test_dived /bin/sh -c 'echo $DIVE_QQQ'

announce    DIVE_USER
prepare_dived
E=0 V=`id -un` t ./$DIVE_NAME test_dived /bin/sh -c 'echo $DIVE_USER'

announce    DIVE_USER -E
prepare_dived --no-environment
E=0 V=`id -un` t ./$DIVE_NAME test_dived /bin/sh -c 'echo $DIVE_USER'

announce    DIVE_UID
prepare_dived
E=0 V=$UID t ./$DIVE_NAME test_dived /bin/sh -c 'echo $DIVE_UID'

announce    DIVE_PID
prepare_dived
E=137 V="" t ./$DIVE_NAME test_dived /bin/sh -c '/bin/kill -9 $DIVE_PID'

announce    High fd redirection
prepare_dived
E=0 V="qwerty" t ./$DIVE_NAME test_dived /bin/bash -c 'cat <&100' 100<<< "qwerty"

announce    dived -O option
prepare_dived --no-fds
E=fail V=""       t ./$DIVE_NAME test_dived /bin/bash -c 'cat <&100' 100<<< "qwerty"

announce    Current directory preservation
prepare_dived
mkdir -p testdir
(cd testdir; E=0 V="`pwd`" t ../$DIVE_NAME ../test_dived /bin/pwd)
rmdir testdir

announce    No current directory preservation if dived -H
prepare_dived --no-chdir
mkdir -p testdir
(cd testdir; E=0 V="`cd ..; pwd`" t ../$DIVE_NAME ../test_dived /bin/pwd)
rmdir testdir

announce    Prepended args test
prepare_dived -- /bin/echo qqq
E=0 V='qqq www' t ./$DIVE_NAME test_dived www

announce    Prepended args test with dived -A
prepare_dived  --no-argv -- /bin/echo qqq
E=0 V='qqq'     t ./$DIVE_NAME test_dived www

announce    Umask preservance
prepare_dived
(umask 0354; E=0 V='0354' t ./$DIVE_NAME test_dived    /bin/bash -c 'umask')

announce    No umask preservance if dived -M
prepare_dived --no-umask
UMASK=`umask`
(umask 0354; E=0 V=$UMASK t ./$DIVE_NAME test_dived    /bin/bash -c 'umask')

announce    No stray FDs
prepare_dived
E=0 V=`/bin/ls -1 /proc/self/fd/` t ./$DIVE_NAME test_dived    /bin/ls -1 /proc/self/fd/

announce    No stray FDs '(dived -n)'
prepare_dived --signals
E=0 V=`/bin/ls -1 /proc/self/fd/` t ./$DIVE_NAME test_dived    /bin/ls -1 /proc/self/fd/


announce    dived -X option supported
E=0 MF=1 V='' t ./$DIVED_NAME --just-execute --no-new-privs -- /bin/true

announce    ping works
E=0 MF=1 V='nocheck' t /bin/ping -c 1 127.0.0.1

announce    ping fails when from dived -X
E=fail MF=1 V='nocheck' t ./$DIVED_NAME --just-execute --no-new-privs -- /bin/ping -c 1 127.0.0.1


announce    signal delivery without --signals
prepare_dived
E=0 V='qqq' t ./$DIVE_NAME test_dived /bin/bash -c 'trap "echo qqq" USR1; kill -USR1 $DIVE_PID; sleep 0.2'


announce    signal delivery with --signals
prepare_dived --signals
E=0 V='qqq' t ./$DIVE_NAME test_dived /bin/bash -c 'trap "echo qqq" USR1; kill -USR1 $DIVE_PID; sleep 0.2'

announce    simple --authenticate test
prepare_dived --authenticate 'printf qqq'
E=0 V="qqqwww" t ./$DIVE_NAME test_dived /bin/echo "www"


announce    failed authentication test
prepare_dived --authenticate /bin/false
E=fail V=''    t ./$DIVE_NAME test_dived /bin/echo "qqq"

announce    no pwd, env or umask is preserved for auth prog
export QQQ=3443
V=`pwd; echo $QQQ; umask;`
prepare_dived --authenticate 'pwd; echo $QQQ; umask;'
E=0 V="$V" 
mkdir -p testdir
(cd testdir; umask 0354; E=0 V="$V" QQQ=1234 t ../$DIVE_NAME ../test_dived /bin/true)
rmdir testdir

announce   signals are not delivered to auth prog
prepare_dived --signals --authenticate 'trap "printf qqq" USR1; printf rrr; sleep 0.2; printf www'
E=fail MF=1 V="rrrwww" t /bin/bash -c './$DIVE_NAME test_dived /bin/bash -c "sleep 0.3; printf yyy"& sleep 0.1; kill -USR1 $!; wait $!'



announce    DIVE_WAITMODE=0 works
prepare_dived
E=0 V='wwwqqq' t /bin/bash -c 'DIVE_WAITMODE=0 ./$DIVE_NAME test_dived /bin/bash -c "sleep 0.3; printf www"; printf qqq'

announce    DIVE_WAITMODE=1 works
prepare_dived
E=0 V='qqqwww' t /bin/bash -c 'DIVE_WAITMODE=1 ./$DIVE_NAME test_dived /bin/bash -c "sleep 0.3; printf www"; printf qqq'

announce    DIVE_WAITMODE=2 works
prepare_dived
E=0 V='wwwqqq' t /bin/bash -c 'DIVE_WAITMODE=2 ./$DIVE_NAME test_dived /bin/bash -c "sleep 0.3; printf www"; printf qqq'

announce    DIVE_WAITMODE=0 with dived -w works
prepare_dived --no-wait
E=0 V='wwwqqq' t /bin/bash -c 'DIVE_WAITMODE=0 ./$DIVE_NAME test_dived /bin/bash -c "sleep 0.3; printf www"; printf qqq'

announce    DIVE_WAITMODE=1 with dived -w works
prepare_dived --no-wait
E=0 V='qqqwww' t /bin/bash -c 'DIVE_WAITMODE=1 ./$DIVE_NAME test_dived /bin/bash -c "sleep 0.3; printf www"; printf qqq'

announce    DIVE_WAITMODE=2 with dived -w works
prepare_dived --no-wait
E=0 V='wwwqqq' t /bin/bash -c 'DIVE_WAITMODE=2 ./$DIVE_NAME test_dived /bin/bash -c "sleep 0.3; printf www"; printf qqq'

terminate_dived
    
announce 'Can we test with inetd? (inetd and socat works)'
inetd -i <(echo 'test_dived stream unix nowait vi  /bin/echo echo qqq')&
INETD_PID=$!
sleep 0.1
E=0 V='qqq' t socat unix-connect:test_dived  -
kill $INETD_PID

terminate_dived

announce 'Testing --inetd mode'
inetd -i <(echo "test_dived stream unix nowait vi  ./$DIVED_NAME dived -i -T -P")&
INETD_PID=$!
sleep 0.1
E=0 V='qqq' t ./$DIVE_NAME test_dived /bin/echo qqq
kill $INETD_PID

fi # TESTS_NO_USER


if [ -z "$TESTS_NO_ROOT" ]; then


if [ "$UID" != "0" ]; then
    echo "The rest tests require root access"
    exit $STATUS 
fi

NOBODY_UID=`cat /etc/passwd | grep '^nobody:' | cut -d: -f3`
echo "NOBODY_UID=$NOBODY_UID"

announce can we change to other user?
E=0 V=$NOBODY_UID t su nobody -c 'id -u'


VERBOSE=1

terminate_dived

announce dived --chown option
prepare_dived  --chown $NOBODY_UID:0
E=0 V=$NOBODY_UID t stat test_dived -c '%u'

announce dived --chown name option 
prepare_dived  --chown nobody:0
E=0 V=$NOBODY_UID t stat test_dived -c '%u'

announce dived --chmod option 
prepare_dived  --chmod 765
E=0 V=765 t stat test_dived -c '%a'

announce dived --chown option actual
prepare_dived  --chown $NOBODY_UID:0
E=0 V=qqq t su nobody -c './$DIVE_NAME test_dived /bin/echo qqq' 

announce dived --chown name option actual
prepare_dived  --chown nobody:0
E=0 V=qqq t su nobody -c './$DIVE_NAME test_dived /bin/echo qqq' 

announce dived --chmod option actual
prepare_dived  --chmod 777
E=0 V=qqq t su nobody -c './$DIVE_NAME test_dived /bin/echo qqq' 


announce dived preserve user by default
prepare_dived  --chown $NOBODY_UID:0
E=0 V=$NOBODY_UID t su nobody -c './$DIVE_NAME test_dived /usr/bin/id -u' 


announce dived sets up groups
prepare_dived  --chown $NOBODY_UID:0
E=0 V=`su nobody bash -c id` t su nobody -c './$DIVE_NAME test_dived /usr/bin/id'

announce dived -P does not touch things
prepare_dived  --chown $NOBODY_UID:0 --no-setuid
E=0 V=`id` t su nobody -c './$DIVE_NAME test_dived /usr/bin/id'

announce dived -u works
prepare_dived  --chown $NOBODY_UID:0 --user root
E=0 V=`id` t su nobody -c './$DIVE_NAME test_dived /usr/bin/id'

announce dived -u works 2
prepare_dived  --chown $NOBODY_UID:0 --user nobody
E=0 V=`su nobody bash -c id` t su nobody -c './$DIVE_NAME test_dived /usr/bin/id'

announce dived -e works
prepare_dived  --chown $NOBODY_UID:0 --effective-user root
E=0 V="uid=$NOBODY_UID(nobody) euid=0(root) " t \
    su nobody -c './$DIVE_NAME test_dived /usr/bin/id | tr " " "\n" | grep "^euid\|^uid" | tr "\n" " "'

announce dived -u -e works
prepare_dived  --chown $NOBODY_UID:0 --effective-user root --user nobody
E=0 V="uid=$NOBODY_UID(nobody) euid=0(root) " t \
    su nobody -c './$DIVE_NAME test_dived /usr/bin/id | tr " " "\n" | grep "^euid\|^uid" | tr "\n" " "'

announce dived -u -e works 2
prepare_dived  --chown $NOBODY_UID:0 --effective-user nobody --user root
E=0 V="uid=0(root) euid=$NOBODY_UID(nobody) " t \
    su nobody -c './$DIVE_NAME test_dived /usr/bin/id | tr " " "\n" | grep "^euid\|^uid" | tr "\n" " "'

announce "Removing capabilities from bounding set (-B)"
E=0 V="0000000" t ./$DIVED_NAME -J --retain-capabilities '' -- /bin/sh -c "cat /proc/self/status | grep CapBnd | cut -c 18-"

announce "Removing capabilities from bounding set (-b)"
E=0 V="0000000" t ./$DIVED_NAME -J \
    --remove-capabilities '0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28' \
    -- bash -c "cat /proc/self/status | grep CapBnd | cut -c 18-"
    
announce "Adding an inherited capability"
E=0 V="0000800" t ./$DIVED_NAME -J \
    --set-capabilities '11+i' \
    -- bash -c "cat /proc/self/status | grep CapInh | cut -c 18-"

announce "--lock-securebits"
E=0 V="0000000" t ./$DIVED_NAME -J \
    --lock-securebits \
    -- bash -c "cat /proc/self/status | grep CapPrm | cut -c 18-"
    
announce   unsharing pid namespace
prepare_dived  --unshare pid --no-wait --no-fork
DIVE_WAITMODE=2 E=0 V="1" t ./$DIVE_NAME test_dived  /bin/sh -c 'echo $$'
    
fi # TESTS_NO_ROOT
    
exit $STATUS 
