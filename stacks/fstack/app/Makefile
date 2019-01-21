LIBS+= -L../../../release/lib64 -Wl,--whole-archive,-lnStackAPI,--no-whole-archive
TARGET="fstack"
all:
	cc -O -gdwarf-2 -Wl,--rpath,../../../release/lib64 -I../../../src/nSocket/include  -o ${TARGET}_multi_sock_epoll multi_sock_tcp_epoll.c ${LIBS}
	cc -O -gdwarf-2 -Wl,--rpath,../../../release/lib64 -I../../../src/nSocket/include  -o ${TARGET}_server_no_epoll fstack_server.c ${LIBS}
	cc -O -gdwarf-2 -Wl,--rpath,../../../release/lib64 -I../../../src/nSocket/include  -o ${TARGET}_single_sock_server single_sock_tcp_epoll.c ${LIBS}
.PHONY: clean
clean:
	rm -f *.o ${TARGET}_multi_sock_epoll ${TARGET}_single_sock_server ${TARGET}_server_no_epoll
