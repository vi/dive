-include config.mak
-include config.mak2

EXTRALIBS=
ifeq ($(NO_CAPABILITIES),1)
       
else
	EXTRALIBS+=-lcap
endif

IS_CONFIGURED=$(shell test -e config.h && echo 1 || echo 0)

ifeq (${IS_CONFIGURED},1)
	MAIN_TARGETS=dived dive
else
	MAIN_TARGETS=config.h
	# and we'll restart "make" after config.mak2 is available
endif

all: ${MAIN_TARGETS}
	
dived: recv_fd.h recv_fd.c dived.c safer.o config.h
	${CC} ${CFLAGS} ${CPPFLAGS} -Wall -g recv_fd.c dived.c safer.o ${LDFLAGS} ${EXTRALIBS} -o dived

dive: send_fd.h send_fd.c dive.c safer.o config.h
	${CC} ${CFLAGS} ${CPPFLAGS} -Wall -g send_fd.c dive.c safer.o ${LDFLAGS} -o dive

config.h:
	./configure
	${MAKE}
	@echo "Compilation finished. If you see output indicating errors past this, just restart \"make\""


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
	./makedeb_heavy.sh


test: dived dive
	bash tests.sh
	
.PHONY: dist
dist:
	./makedist.sh

clean:
	rm -f dive dived *.o config.h config.mak2
