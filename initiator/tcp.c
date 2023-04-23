#include <stddef.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <linux/virtio_ring.h>

#include "queue.h"
#include "vinitiator.h"

struct vi_tcp_queue {
	int sockfd;
};

static int vi_tcp_send_cmd(void *_queue, struct virtio_of_command *vofcmd, int ndesc, struct virtio_of_vring_desc *descs, struct iovec *_iovs)
{
	struct vi_tcp_queue *queue = (struct vi_tcp_queue *)_queue;
	struct virtio_of_vring_desc *desc;
	struct iovec *iovs;
	int niov, index = 0, i;
	int ret;

	if (!ndesc) {
		return write(queue->sockfd, vofcmd, sizeof(struct virtio_of_command));
	}

	niov = 2;	/* [0] for vofcmd, [1] for descs */
	for (i = 0; i < ndesc; i++) {
		desc = descs + i;
		if (!(le16toh(desc->flags) & VRING_DESC_F_WRITE)) {
			niov++;
		}
	}

	iovs = calloc(sizeof(struct iovec), niov);
	ASSERT(iovs);
	index = 0;
	iovs[index].iov_base = vofcmd;
	iovs[index].iov_len = sizeof(struct virtio_of_command);

	index = 1;
	iovs[index].iov_base = descs;
	iovs[index].iov_len = sizeof(struct virtio_of_vring_desc) * ndesc;

	for (i = 0; i < ndesc; i++) {
		desc = descs + i;
		if (!(le16toh(desc->flags) & VRING_DESC_F_WRITE)) {
			index++;
			iovs[index].iov_base = _iovs[i].iov_base;
			iovs[index].iov_len = _iovs[i].iov_len;
		}
	}

	ret = writev(queue->sockfd, iovs, niov);
	free(iovs);

	return ret;
}

static ssize_t vi_tcp_recv_one(int fd, void *buf, size_t count)
{
        unsigned char *dst = buf;
        int bytes = count;
        int ret = 0;

        do {
                ret = read(fd, dst, bytes);
                if (ret < 0) {
                        return ret;
                }

                dst += ret;
                bytes -= ret;
        } while (bytes);

        return count;
}

static int vi_tcp_recv_comp(void *_queue, struct virtio_of_completion *vofcomp, int ndesc, struct virtio_of_vring_desc *_descs, struct iovec *_iovs)
{
	struct vi_tcp_queue *queue = (struct vi_tcp_queue *)_queue;
	struct virtio_of_vring_desc *descs, *desc, *_desc;
	int niov, i, j;
	int length;
	__le16 id;

	length = sizeof(struct virtio_of_completion);
	ASSERT(vi_tcp_recv_one(queue->sockfd, vofcomp, length) == length);
	if (!ndesc) {
		return length;
	}

	ASSERT(le16toh(vofcomp->status) == VIRTIO_OF_SUCCESS);

	for (niov = 0, i = 0; i < ndesc; i++) {
		_desc = _descs + i;
		if (le16toh(_desc->flags) & VRING_DESC_F_WRITE) {
			niov++;
		}
	}
	ASSERT(le16toh(vofcomp->ndesc) == niov);

	if (!niov) {
		return 0;
	}

	descs = calloc(sizeof(struct virtio_of_vring_desc), niov);
	ASSERT(descs);
	length = sizeof(struct virtio_of_vring_desc) * niov;
	ASSERT(vi_tcp_recv_one(queue->sockfd, descs, length) == length);

	for (i = 0; i < niov; i++) {
		desc = descs + i;
		id = le16toh(desc->id);

		for (j = 0; j < ndesc; j++) {
			if (le16toh(_descs[j].id) == id) {
				break;
			}
		}

		ASSERT(j < ndesc);
		ASSERT(le16toh(_descs[j].flags) & VRING_DESC_F_WRITE);
		ASSERT(le32toh(desc->length) <= _iovs[j].iov_len);

		length = le32toh(desc->length);
		ASSERT(vi_tcp_recv_one(queue->sockfd, _iovs[j].iov_base, length) == length);
	}

	return 0;
}

static void *vi_tcp_create_queue(const char *taddr, int tport)
{
	struct vi_tcp_queue *queue;
	int sockfd;
	struct sockaddr_in addr;

	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	ASSERT(sockfd != -1);

	memset(&addr, 0x00, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(taddr);
	addr.sin_port = htons(tport);
	ASSERT(!connect(sockfd, (const struct sockaddr *)&addr, sizeof(addr)));

	queue = calloc(sizeof(struct vi_tcp_queue), 1);
	ASSERT(queue);
	queue->sockfd = sockfd;

	return queue;
}

static struct vi_queue vi_queue_tcp = {
	.transport = "tcp",
	.oftype = virtio_of_connection_tcp,
	.create_queue = vi_tcp_create_queue,
	.send_cmd = vi_tcp_send_cmd,
	.recv_comp = vi_tcp_recv_comp,
};

static void __attribute__((constructor)) vi_queue_tcp_init(void)
{
	vi_queue_register(&vi_queue_tcp);
}
