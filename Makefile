all: dived dive
	
dived: recv_fd.h recv_fd.c dived.c
	${CC} recv_fd.c dived.c -o dived

dive: send_fd.h send_fd.c dive.c
	${CC} send_fd.c dive.c -o dive
	
