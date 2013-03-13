#!/bin/bash
VERSION=`cat dived.c | grep 'define VERSION2 ' | awk '{print $3}' | grep -o '[0-9]*\.[0-9]'`

mkdir -p \
    release/usr/bin \
    release/DEBIAN  \
    release/usr/share/man/man1/  \
    release/usr/share/doc/dive/

cat > release/DEBIAN/control << EOF
Package: dive
Priority: extra
Section: utils
Installed-Size: 32
Maintainer: Vitaly "_Vi" Shukela <vi0oss@gmail.com>
Architecture: i386
Version: $VERSION.0-1
Provides: dive
Recommends: reptyr(>=0.4)
Depends: libcap2, libc6 (>= 2.11)
Homepage: http://vi.github.com/dive/
Description: Start programs in unshare/lxc namespaces easily and more.
 Starting programs in various ways like socat using sockets in various ways.
 Allows simple "remote" startup of programs inside LXC containers,
 simple starting LXC-like containers on low level, managing capabilities
 and securebits and more.
EOF

cat > release/usr/share/doc/dive/copyright << \EOF
Format: http://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: dive
Upstream-Contact: Vitaly "_Vi" Shukela <vi0oss@gmail.com>
Source: https://github.com/vi/dive

Files: dive.c dived.c
Copyright: 2012-2013 Vitaly Shukela
License: MIT

Files: recv_fd.c send_fd.c
Copyright: 2006 - 2012 C. Thomas Stover

License: MIT
 Permission to use, copy, modify, distribute, and sell this software and its
 documentation for any purpose is hereby granted without fee, provided that
 the above copyright notice appear in all copies and that both that
 copyright notice and this permission notice appear in supporting
 documentation, and that the name of M.I.T. not be used in advertising or
 publicity pertaining to distribution of the software without specific,
 written prior permission.  M.I.T. makes no representations about the
 suitability of this software for any purpose.  It is provided "as is"
 without express or implied warranty.
EOF

gzip -9 >  release/usr/share/doc/dive/changelog.Debian.gz << \EOF
dive (1.2.0-1) experimental; urgency=low

  * Now with a proper deb package

 -- Vitaly Shukela <vi0oss@gmail.com>  Tue, 12 Mar 2013 02:50:00 +0300

EOF

install -s -m 755 dive dived release/usr/bin/
cat dive.1 | gzip -9 > release/usr/share/man/man1/dive.1.gz
cat dived.1 | gzip -9 > release/usr/share/man/man1/dived.1.gz

dpkg-deb -b release dive_$VERSION.0-1_i386.deb 

rm -Rf release
