.PHONY: rebuild

CC=gcc
CFLAGS=-g -D_GNU_SOURCE -Wall
CLIBS=

CORE=vinitiator.c queue.c fabrics.c block.c rng.c
TRANSPORT=tcp.c
ifeq ($(USE_RDMA),yes)
	TRANSPORT+=rdma.c
	CLIBS+= -lrdmacm -libverbs
endif

rebuild: clean initiator

initiator: prepare
	$(CC) $(CORE) $(TRANSPORT) $(CFLAGS) $(CLIBS) -o vinitiator

prepare:
	ln -s ../include/virtio_of.h .

clean:
	$(shell unlink virtio_of.h 2> /dev/null)
	rm -f vinitiator
