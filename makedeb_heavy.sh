#!/bin/bash
VERSION=`cat dived.c | grep 'define VERSION2 ' | awk '{print $3}' | grep -o '[0-9]*\.[0-9]*\.[0-9]*'`

set -e

cd dist/dive-"$VERSION"
debuild
