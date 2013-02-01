all: dived dive
	
dived: recv_fd.h recv_fd.c dived.c safer.o
	${CC} -Wall -g recv_fd.c dived.c safer.o -o dived

dive: send_fd.h send_fd.c dive.c safer.o
	${CC} -Wall -g send_fd.c dive.c safer.o -o dive

prefix=/usr/local

install:
	install -m 755 dive ${prefix}/bin/
	install -m 755 dived ${prefix}/bin/
	
deb: dived dive
	fakeroot ./makedeb.sh
	

musl: recv_fd.h recv_fd.c dived.c safer.c
	musl-gcc -D__MUSL__ -Wall recv_fd.c dived.c safer.c -o dived_musl
	musl-gcc -D__MUSL__ -Wall send_fd.c dive.c safer.c -o dive_musl
