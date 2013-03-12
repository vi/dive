all: dived dive
	
dived: recv_fd.h recv_fd.c dived.c safer.o
	${CC} ${CFLAGS} -Wall -g -lcap recv_fd.c dived.c safer.o ${LDFLAGS} -o dived

dive: send_fd.h send_fd.c dive.c safer.o
	${CC} ${CFLAGS} -Wall -g send_fd.c dive.c safer.o ${LDFLAGS} -o dive

prefix=/usr/local

install:
	install -m 755 dive ${prefix}/bin/
	install -m 755 dived ${prefix}/bin/
	install -m 644 dive.1 ${prefix}/share/man/man1/
	install -m 644 dived.1 ${prefix}/share/man/man1/
	
deb: dived dive
	fakeroot ./makedeb.sh
	

musl: recv_fd.h recv_fd.c dived.c safer.c
	musl-gcc ${CFLAGS} -DNO_CAPABILITIES -DNO_EXECVPE -Wall recv_fd.c dived.c safer.c -o dived_musl
	musl-gcc ${CFLAGS}                                -Wall send_fd.c dive.c safer.c -o dive_musl

test: dived dive
	bash tests.sh