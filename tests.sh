#!/bin/bash

STATUS=0

true ${UID:="`id -u`"}

function t() {
    # call the specified argv, capture output and exit code, compare to $V and $E respectively
    
    VAL=`"$@" < /dev/null 2> /dev/null`
    C=$?
    if [ "$C" != "$E" ]; then
        echo "FAIL code=$C"
        STATUS=1
        return 1
    fi
    
    if [[ "$V" != "nocheck" && "$VAL" != "$V" ]]; then
        echo "FAIL val=$VAL"
        STATUS=1
        return 1
    fi
    
    echo " OK "
}

function pt() {
    # Privileged test

    if [ "$UID" != "0" ]; then
        echo "REQUIRES ROOT"
        return 0
    fi
    t "$@"
}

function prepare_dived() {
    test -e test_dived.pid && pkill -F test_dived.pid
    rm -f test_dived
    ./dived test_dived --detach --pidfile test_dived.pid "$@"
} 

function announce() {
    printf "%-50s" "$*"
}

trap 'pkill -F test_dived.pid; rm -f test_dived test_dived.pid' EXIT







announce    Dummy dived call
E=4 V='nocheck' t ./dived

announce    Dummy dive  call
E=4 V='nocheck' t ./dive

announce    dived -J simple test
E=0 V='' t ./dived -J -- /bin/true

announce    dived -J return code
E=44 V='' t ./dived -J -- /bin/sh -c "exit 44"

announce    dived -J print
E=0 V='qqq' t ./dived -J -- /bin/echo qqq

announce    dive and dived echo
prepare_dived
E=0 V='qqq' t ./dive test_dived /bin/echo qqq


announce    dive and dived echo '(dived -n)'
prepare_dived --signals
E=0 V='qqq' t ./dive test_dived /bin/echo qqq

announce    dive and dived return code
prepare_dived
E=44 V='' t ./dive test_dived /bin/sh -c "exit 44"


announce    dive and dived return code '(dived -n)'
prepare_dived --signals
E=44 V='' t ./dive test_dived /bin/sh -c "exit 44"

announce    Preserve environment
prepare_dived
E=0 V='31336' t ./dive test_dived /bin/sh -c 'echo $V'

announce    No preserve environment if -E
prepare_dived -E
E=0 V='' t ./dive test_dived /bin/sh -c 'echo $V'

announce    No preserve DIVE_* environment
prepare_dived
E=0 V='' DIVE_QQQ=12345 t ./dive test_dived /bin/sh -c 'echo $DIVE_QQQ'

announce    DIVE_USER
prepare_dived
E=0 V=$USER t ./dive test_dived /bin/sh -c 'echo $DIVE_USER'

announce    DIVE_USER -E
prepare_dived --no-environment
E=0 V=$USER t ./dive test_dived /bin/sh -c 'echo $DIVE_USER'

announce    DIVE_UID
prepare_dived
E=0 V=$UID t ./dive test_dived /bin/sh -c 'echo $DIVE_UID'

announce    DIVE_PID
prepare_dived
E=137 V="" t ./dive test_dived /bin/sh -c '/bin/kill -9 $DIVE_PID'

announce    High fd redirection
prepare_dived
E=0 V="qwerty" t ./dive test_dived /bin/bash -c 'cat <&100' 100<<< "qwerty"

announce    dived -O option
prepare_dived --no-fds
E=1 V=""       t ./dive test_dived /bin/bash -c 'cat <&100' 100<<< "qwerty"

announce    Current directory preservation
prepare_dived
mkdir -p testdir
(cd testdir; E=0 V="`pwd`" t ../dive ../test_dived /bin/pwd)
rmdir testdir

announce    No current directory preservation if dived -H
prepare_dived --no-chdir
mkdir -p testdir
(cd testdir; E=0 V="`cd ..; pwd`" t ../dive ../test_dived /bin/pwd)
rmdir testdir

announce    Prepended args test
prepare_dived -- /bin/echo qqq
E=0 V='qqq www' t ./dive test_dived www

announce    Prepended args test with dived -A
prepare_dived  --no-argv -- /bin/echo qqq
E=0 V='qqq'     t ./dive test_dived www

announce    Umask preservance
prepare_dived
(umask 0354; E=0 V='0354' t ./dive test_dived    /bin/bash -c 'umask')

announce    No umask preservance if dived -M
prepare_dived --no-umask
UMASK=`umask`
(umask 0354; E=0 V=$UMASK t ./dive test_dived    /bin/bash -c 'umask')

announce    No stray FDs
prepare_dived
E=0 V=`/bin/ls -1 /proc/self/fd/` t ./dive test_dived    /bin/ls -1 /proc/self/fd/

announce    No stray FDs '(dived -n)'
prepare_dived --signals
E=0 V=`/bin/ls -1 /proc/self/fd/` t ./dive test_dived    /bin/ls -1 /proc/self/fd/




exit $STATUS 