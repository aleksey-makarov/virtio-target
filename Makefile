.PHONY: rebuild iniparser initiator

CC=gcc
CFLAGS=-Iinclude -Iiniparser/src/ iniparser/libiniparser.a -g -D_GNU_SOURCE -DDEBUG -Wall
CLIBS=-lpthread -lgcrypt

CORE=object.c device.c driver.c target.c thread.c fabrics.c main.c
BLOCK=block/virtio_block.c block/posix.c
RNG=rng/virtio_rng.c rng/simulator.c
CRYPTO=crypto/virtio_crypto.c crypto/gcrypt.c crypto/rsakey.c crypto/der.c
TRANSPORT=tcp.c
ifeq ($(USE_RDMA),yes)
	TRANSPORT+=rdma.c
	CLIBS+= -lrdmacm -libverbs
endif

rebuild: clean target initiator

target: iniparser
	$(CC) $(CORE) $(TRANSPORT) $(BLOCK) $(RNG) $(CRYPTO) $(CFLAGS) $(CLIBS) -o vtgt

iniparser:
	make -C iniparser libiniparser.a

initiator:
	make -C initiator USE_RDMA=$(USE_RDMA)

clean:
	rm -f vtgt
	make -C initiator clean
