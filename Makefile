-include config.mak
-include config.mak2

all: dived dive
	
dived: recv_fd.h recv_fd.c dived.c safer.o config.h
	${CC} ${CFLAGS} ${CPPFLAGS} -Wall -g -lcap recv_fd.c dived.c safer.o ${LDFLAGS} -o dived

dive: send_fd.h send_fd.c dive.c safer.o config.h
	${CC} ${CFLAGS} ${CPPFLAGS} -Wall -g send_fd.c dive.c safer.o ${LDFLAGS} -o dive

config.h:
	./configure


# install to DESTDIR/usr/ whenn called from debuild, 
# but still install to /usr/local when called by just "make install"
DESTDIR=/usr/local
prefix_=${DESTDIR}/usr
prefix=$(shell echo "${prefix_}" | sed 's!local/usr!local!')

install:
	mkdir -p ${prefix}/bin/ ${prefix}/share/man/man1/
	install -m 755 dive ${prefix}/bin/
	install -m 755 dived ${prefix}/bin/
	gzip -9 < dive.1 > ${prefix}/share/man/man1/dive.1.gz
	gzip -9 < dived.1 > ${prefix}/share/man/man1/dived.1.gz
	
deb:
	@echo 'Use "make deb_heavy" for proper Debian package building sequence'
	@echo 'Use "make deb_light" for lightweight i386 Debian package building sequence'
	
deb_light: dived dive
	fakeroot ./makedeb.sh
	
deb_heavy: dist
	sh -c "cd dist/dive-* && debuild"

musl: recv_fd.h recv_fd.c dived.c safer.c
	musl-gcc ${CFLAGS} -DNO_CAPABILITIES -DNO_EXECVPE -Wall recv_fd.c dived.c safer.c -o dived_musl
	musl-gcc ${CFLAGS}                                -Wall send_fd.c dive.c safer.c -o dive_musl

test: dived dive
	bash tests.sh
	
.PHONY: dist
dist:
	./makedist.sh

clean:
	rm -f dive dived *.o config.h

