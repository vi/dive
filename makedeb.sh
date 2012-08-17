#!/bin/bash
VERSION=`cat dived.c | grep 'define VERSION2 ' | awk '{print $3}' | grep -o '[0-9]*\.[0-9]'`

mkdir -p release/usr/bin release/DEBIAN

cat > release/DEBIAN/control << EOF
Package: dive
Priority: extra
Installed-Size: 32
Maintainer: Vitaly "_Vi" Shukela <vi0oss@gmail.com>
Architecture: i386
Version: $VERSION.0-1
Provides: dive
Recommends: reptyr(>=0.4)
Description: Start programs in unshare/lxc namespaces easily and more. 
EOF

install -s -m 755 dive dived release/usr/bin/

dpkg-deb -b release dive_$VERSION.0-1_i386.deb 

rm -Rf release
