#!/bin/bash
VERSION=`cat dived.c | grep 'define VERSION2 ' | awk '{print $3}' | grep -o '[0-9]*\.[0-9]*\.[0-9]*'`

changelog_version=`grep urgency= debian/changelog  | head -n 1 | awk '{print $2}' | cut -d- -f 1 | tr -d '(' `

if [ "$VERSION" != "$changelog_version" ]; then
    echo "Warning: debian/changelog's version does not match current version"
fi

rm -Rf dist/dive-$VERSION

mkdir -p dist/dive-$VERSION

cp -a \
    *.c \
    recv_fd.h \
    safer.h \
    send_fd.h \
    Makefile \
    *.sh \
    .gitignore \
    askpassword \
    *.1 \
    README.md \
    debian \
    configure \
    hacks \
    \
    dist/dive-$VERSION/ 

(cd dist/dive-$VERSION && tar -czf ../dive_$VERSION.orig.tar.gz *)
