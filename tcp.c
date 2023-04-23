#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <netinet/tcp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <linux/virtio_ring.h>

#include "transport.h"
#include "fabrics.h"
#include "utils.h"
#include "log.h"

static struct virtiot_transport virtiot_tcp;
static int virtiot_tcp_send(struct virtiot_queue *vtq);

struct virtiot_tcp_queue {
	struct virtiot_queue vtq;
	int sockfd;
	int epollfd;

	struct virtiot_tcp_request *vttcpreq, *vttcpresp;
	struct list_head requests;
	struct list_head responses;
};

enum virtiot_tcp_stage {
	virtiot_tcp_recv_cmd,
	virtiot_tcp_recv_desc,
	virtiot_tcp_recv_vring,
	virtiot_tcp_send_comp,
	virtiot_tcp_send_desc,
	virtiot_tcp_send_vring
};

struct virtiot_tcp_request {
	struct virtiot_request vtreq;
	struct list_head entry;
	unsigned char stage;
	__u16 cur_desc;
	__u32 cur_off;
};

static inline struct virtiot_tcp_queue *to_tcp_queue(struct virtiot_queue *vtq)
{
	return container_of(vtq, struct virtiot_tcp_queue, vtq);
}

static inline struct virtiot_tcp_request *to_tcp_request(struct virtiot_request *vtreq)
{
	return container_of(vtreq, struct virtiot_tcp_request, vtreq);
}

static inline bool virtiot_tcp_output_pending(struct virtiot_tcp_queue *vttcpq)
{
	if (vttcpq->vttcpresp || !list_empty(&vttcpq->responses)) {
		return true;
	}

	return false;
}

static void virtiot_tcp_fill_desc(struct virtio_of_vring_desc *vofdesc, __u64 addr, __u32 length)
{
	vofdesc->addr = htole64(addr);
	vofdesc->length = htole32(length);
}

static void virtiot_tcp_complete_req(struct virtiot_request *vtreq)
{
	struct virtiot_tcp_request *vttcpreq = to_tcp_request(vtreq);
	struct virtiot_tcp_queue *vttcpq = to_tcp_queue(vtreq->vtq);

	assert(vttcpreq->stage == virtiot_tcp_send_comp);
	list_add_tail(&vttcpreq->entry, &vttcpq->responses);
	virtiot_tcp_send(vtreq->vtq);
}

static struct virtiot_tcp_request *virtiot_tcp_alloc_req(struct virtiot_queue *vtq)
{
	struct virtiot_tcp_request *vttcpreq;
	struct virtiot_request *vtreq;
	int size;

	size = sizeof(struct virtiot_tcp_request) + sizeof(struct virtio_of_command)
		+ sizeof(struct virtio_of_completion);
	vttcpreq = calloc(size, 1);
	INIT_LIST_HEAD(&vttcpreq->entry);
	vtreq = &(vttcpreq->vtreq);
	vtreq->vtq = vtq;
	vtreq->complete = virtiot_tcp_complete_req;
	vtreq->fill_desc = virtiot_tcp_fill_desc;
	vtreq->vofcmd = (struct virtio_of_command *)(vttcpreq + 1);
	vtreq->vofcomp = (struct virtio_of_completion *)(vtreq->vofcmd + 1);

	return vttcpreq;
}

static void virtiot_tcp_alloc_ndesc(struct virtiot_tcp_request *vttcpreq, __u16 ndesc)
{
	vttcpreq->vtreq.ndesc = ndesc;
	vttcpreq->vtreq.vofdescs = calloc(sizeof(struct virtio_of_vring_desc), ndesc);
	vttcpreq->vtreq.addr = calloc(sizeof(unsigned char *), ndesc);
}

static void virtiot_tcp_free_req(struct virtiot_tcp_request *vttcpreq)
{
	virtiot_request_free_desc(&vttcpreq->vtreq);
	free(vttcpreq->vtreq.vofdescs);
	free(vttcpreq->vtreq.addr);
	free(vttcpreq);
}

static int virtiot_tcp_send_buf(struct virtiot_tcp_queue *vttcpq, struct virtiot_tcp_request *vttcpreq, unsigned char *addr, int towrite)
{
	int ret;

	if (!towrite) {
		return 0;
	}

	ret = write(vttcpq->sockfd, addr, towrite);
	if (!ret) {
		return -EPIPE;
	} else if (ret == -1) {
		return -errno;
	}

	vttcpreq->cur_off += ret;
	if (towrite == ret) {
		vttcpreq->cur_off = 0;
	}

	return ret;
}

static int virtiot_tcp_send(struct virtiot_queue *vtq)
{
	struct virtiot_tcp_queue *vttcpq = to_tcp_queue(vtq);
	struct virtiot_tcp_request *vttcpresp;
	struct virtio_of_vring_desc *vofdesc;
	unsigned char *addr;
	int towrite, ret;

send_one:
	vttcpresp = vttcpq->vttcpresp;
	if (!vttcpresp) {
		if (list_empty(&vttcpq->responses)) {
			return 0;
		}

		vttcpresp = list_first_entry(&vttcpq->responses, struct virtiot_tcp_request, entry);
		list_del(&vttcpresp->entry);
		vttcpq->vttcpresp = vttcpresp;
//log_debug("fd[%d] handle vring: command_id 0x%x\n", vttcpq->sockfd, le16toh(vttcpresp->vtreq.vofcmd->common.command_id));
	}

	switch (vttcpresp->stage) {
	case virtiot_tcp_send_comp:
		towrite = sizeof(struct virtio_of_completion) - vttcpresp->cur_off;
		addr = (unsigned char *)vttcpresp->vtreq.vofcomp + vttcpresp->cur_off;
		ret = virtiot_tcp_send_buf(vttcpq, vttcpresp, addr, towrite);
		if (ret == towrite) {
			if (vttcpresp->vtreq.ndesc) {
				vttcpresp->stage = virtiot_tcp_send_desc;
				goto send_one;
			} else {
				goto send_done;
			}
		}

		return ret;

	case virtiot_tcp_send_desc:
		vofdesc = vttcpresp->vtreq.vofdescs + vttcpresp->cur_desc;
		if (le16toh(vofdesc->flags) & VRING_DESC_F_WRITE) {
			towrite = sizeof(struct virtio_of_vring_desc) - vttcpresp->cur_off;
		} else {
			towrite = 0;
		}
		addr = (unsigned char *)&vttcpresp->vtreq.vofdescs[vttcpresp->cur_desc] + vttcpresp->cur_off;
		ret = virtiot_tcp_send_buf(vttcpq, vttcpresp, addr, towrite);
		if (ret == towrite) {
			//if (towrite)
			//	log_debug("desc[%d] towrite %d\n", vttcpresp->cur_desc, towrite);
			vttcpresp->cur_desc++;
			if (vttcpresp->cur_desc == vttcpresp->vtreq.ndesc) {
				vttcpresp->stage = virtiot_tcp_send_vring;
				vttcpresp->cur_desc = 0;
			}

			goto send_one;
		}

		return ret;

	case virtiot_tcp_send_vring:
		vofdesc = vttcpresp->vtreq.vofdescs + vttcpresp->cur_desc;
		if (le16toh(vofdesc->flags) & VRING_DESC_F_WRITE) {
			towrite = le32toh(vofdesc->length) - vttcpresp->cur_off;
		} else {
			towrite = 0;
		}
		addr = vttcpresp->vtreq.addr[vttcpresp->cur_desc] + vttcpresp->cur_off;
		ret = virtiot_tcp_send_buf(vttcpq, vttcpresp, addr, towrite);
		if (ret == towrite) {
			//if (towrite)
			//	log_debug("vring[%d] towrite %d\n", vttcpresp->cur_desc, towrite);
			vttcpresp->cur_desc++;
			if (vttcpresp->cur_desc == vttcpresp->vtreq.ndesc) {
				goto send_done;
			}
		}

		return ret;

	default:
		assert(0);
	}

send_done:
	virtiot_tcp_free_req(vttcpresp);
	vttcpq->vttcpresp = NULL;
	goto send_one;
}

static int virtiot_tcp_recv_buf(struct virtiot_tcp_queue *vttcpq, struct virtiot_tcp_request *vttcpreq, unsigned char *addr, int toread)
{
	int ret;

	if (!toread) {
		return 0;
	}

	ret = read(vttcpq->sockfd, addr, toread);
	if (!ret) {
		return -EPIPE;
	} else if (ret == -1) {
		return -errno;
	}

	vttcpreq->cur_off += ret;
	if (toread == ret) {
		vttcpreq->cur_off = 0;
	}

	return ret;
}

static int virtiot_tcp_recv(struct virtiot_queue *vtq)
{
	struct virtiot_tcp_queue *vttcpq = to_tcp_queue(vtq);
	struct virtiot_tcp_request *vttcpreq, *tmpreq;
	struct virtio_of_vring_desc *vofdesc;
	unsigned char *addr;
	int toread, ret, ndesc;

recv_one:
	if (!vttcpq->vttcpreq) {
		vttcpq->vttcpreq = virtiot_tcp_alloc_req(vtq);
	}

	vttcpreq = vttcpq->vttcpreq;

	switch (vttcpreq->stage) {
	case virtiot_tcp_recv_cmd:
		toread = sizeof(struct virtio_of_command) - vttcpreq->cur_off;
		addr = (unsigned char *)vttcpreq->vtreq.vofcmd + vttcpreq->cur_off;
		ret = virtiot_tcp_recv_buf(vttcpq, vttcpreq, addr, toread);
//log_debug("virtiot_tcp_recv_cmd: ret %d, toread %d\n", ret, toread);
		if (ret == toread) {
			ndesc = virtiot_fabrics_ndesc(vttcpreq->vtreq.vofcmd);
//log_debug("virtiot_tcp_recv_cmd: command_id 0x%x, ndesc %d\n", le16toh(vttcpreq->vtreq.vofcmd->common.command_id), ndesc);
			if (ndesc < 0) {
				return ndesc;
			} else if (ndesc == 0) {
				vttcpreq->stage = virtiot_tcp_send_comp;
				goto handle_one;	/* no more additional descs */
			} else {
				vttcpreq->stage = virtiot_tcp_recv_desc;
				virtiot_tcp_alloc_ndesc(vttcpreq, ndesc);
				goto recv_one;
			}
		}

		goto handle_commands;

	case virtiot_tcp_recv_desc:
		toread = sizeof(struct virtio_of_vring_desc) * vttcpreq->vtreq.ndesc - vttcpreq->cur_off;
		addr = (unsigned char *)vttcpreq->vtreq.vofdescs + vttcpreq->cur_off;
		ret = virtiot_tcp_recv_buf(vttcpq, vttcpreq, addr, toread);
//log_debug("virtiot_tcp_recv_desc: ret %d, toread %d\n", ret, toread);
		if (ret == toread) {
			virtiot_request_alloc_desc(&vttcpreq->vtreq);
			vttcpreq->stage = virtiot_tcp_recv_vring;
			goto recv_one;
		}

		goto handle_commands;

	case virtiot_tcp_recv_vring:
		vofdesc = vttcpreq->vtreq.vofdescs + vttcpreq->cur_desc;
		if (le16toh(vofdesc->flags) & VRING_DESC_F_WRITE) {
			toread = 0;
		} else {
			toread = le32toh(vofdesc->length) - vttcpreq->cur_off;
		}
		addr = vttcpreq->vtreq.addr[vttcpreq->cur_desc] + vttcpreq->cur_off;
		ret = virtiot_tcp_recv_buf(vttcpq, vttcpreq, addr, toread);
		if (ret == toread) {
	//log_debug("desc[%d] ndesc %d, addr 0x%lx, length %d, id 0x%x, flags 0x%x, ret %d, toread %d\n", vttcpreq->cur_desc, vttcpreq->vtreq.ndesc, le64toh(vofdesc->addr), le32toh(vofdesc->length), le16toh(vofdesc->id), le16toh(vofdesc->flags), ret, toread);
			vttcpreq->cur_desc++;
			if (vttcpreq->cur_desc == vttcpreq->vtreq.ndesc) {
				vttcpreq->stage = virtiot_tcp_send_comp;
				goto handle_one;	/* we have alread read all */
			} else {
				goto recv_one;
			}
		}

		goto handle_commands;

	default:
		assert(0);
	}

handle_one:
	vttcpq->vttcpreq = NULL;
	assert(vttcpreq->cur_desc == vttcpreq->vtreq.ndesc);
	vttcpreq->cur_desc = 0;
	list_add_tail(&vttcpreq->entry, &vttcpq->requests);
	goto recv_one;

handle_commands:
	if ((ret < 0) && (ret != -EAGAIN)) {
		return ret;
	}

	list_for_each_entry_safe(vttcpreq, tmpreq, &vttcpq->requests, entry) {
		list_del(&vttcpreq->entry);
		virtiot_fabrics_handle_command(&vttcpreq->vtreq);
//log_debug("fd[%d] handle vring: command_id 0x%x\n", vttcpq->sockfd, le16toh(vttcpreq->vtreq.vofcmd->common.command_id));
	}

	return 0;
}

static int virtiot_tcp_process(struct virtiot_queue *vtq)
{
	struct virtiot_tcp_queue *vttcpq = to_tcp_queue(vtq);
	struct epoll_event event;
	__poll_t events = EPOLLIN | EPOLLET;
	int nevents;
	int ret;

	while (true) {
		nevents = epoll_wait(vttcpq->epollfd, &event, 1, 0);
		if (!nevents) {
			break;
		}

		if (unlikely(nevents < 0)) {
			assert(errno == EINTR);
			break;
		}

		if (unlikely((event.events & (EPOLLHUP | EPOLLERR)))) {
			return -EPIPE;
		}

		if (event.events & EPOLLIN) {
			ret = virtiot_tcp_recv(vtq);
			if (ret < 0) {
				return ret;
			}
		}

		if (event.events & EPOLLOUT) {
			ret = virtiot_tcp_send(vtq);
			if (ret < 0) {
				return ret;
			}
		}
	}

	if (virtiot_tcp_output_pending(vttcpq)) {
		events |= EPOLLOUT;
	}

	virtiot_mod_event(vttcpq->epollfd, vttcpq->sockfd, events, vttcpq);

	return 0;
}

static struct virtiot_queue *virtiot_tcp_listen(const char *address, int port)
{
	struct virtiot_tcp_queue *vttcpq;
	struct virtiot_queue *vtq;
	struct sockaddr_in listenaddr;
	int listenfd = -1;
	int reuse = 1;

	vttcpq = calloc(sizeof(struct virtiot_tcp_queue), 1);
	assert(vttcpq);

	listenfd = socket(AF_INET, SOCK_STREAM, 0);
	if (listenfd == -1)
		goto freevtq;

	virtiot_set_nonblock(listenfd);
	setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse));

	/* TODO resolve address */
	listenaddr.sin_family = AF_INET;
	listenaddr.sin_addr.s_addr = inet_addr(address);
	listenaddr.sin_port = htons(port);
	if (bind(listenfd, (struct sockaddr *)&listenaddr, sizeof(listenaddr)))
		goto closefd;

	if (listen(listenfd, 128))
		goto closefd;

	vttcpq->epollfd = -1;	/* the listenfd has POLLIN event only */
	vtq = &vttcpq->vtq;
	vtq->transport = &virtiot_tcp;
	vtq->fd = listenfd;
	vtq->state = virtiot_queue_listen;

	return vtq;

closefd:
	close(listenfd);

freevtq:
	free(vttcpq);

	return NULL;
}

static struct virtiot_queue *virtiot_tcp_accept(struct virtiot_queue *listener)
{
	struct virtiot_tcp_queue *vttcpq;
	struct virtiot_queue *vtq;
	struct sockaddr_in cliaddr;
	socklen_t addrlen = sizeof(cliaddr);
	struct linger sl = { .l_onoff = 1, .l_linger = 1 };
	int fd, opt = 1;
	int epollfd;

	fd = accept(listener->fd, (struct sockaddr *)&cliaddr, &addrlen);
	if (fd == -1) {
		log_error("accept failed: %m");
		return NULL;
	}

	assert(!virtiot_set_nonblock(fd));
	setsockopt(fd, SOL_TCP, TCP_NODELAY, &opt, sizeof(opt));
#if 0
	setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &opt, sizeof(opt));
	setsockopt(fd, SOL_TCP, TCP_KEEPIDLE, &opt, sizeof(opt));
	setsockopt(fd, SOL_TCP, TCP_KEEPINTVL, &opt, sizeof(opt));
	setsockopt(fd, SOL_TCP, TCP_KEEPCNT, &opt, sizeof(opt));
#endif
	setsockopt(fd, SOL_SOCKET, SO_LINGER, &sl, sizeof(sl));

	epollfd = epoll_create1(0);
	if (epollfd == -1) {
		log_error("epoll_create1 failed: %m");
		close(fd);
		return NULL;
	}

	vttcpq = calloc(sizeof(struct virtiot_tcp_queue), 1);
	assert(vttcpq);

	//assert(!virtiot_set_nonblock(epollfd));
	virtiot_add_event(epollfd, fd, vttcpq);
	vttcpq->epollfd = epollfd;
	vttcpq->sockfd = fd;
	INIT_LIST_HEAD(&vttcpq->requests);
	INIT_LIST_HEAD(&vttcpq->responses);
	vtq = &vttcpq->vtq;
	vtq->queue_id = 0xffff;
	vtq->fd = epollfd;
	vtq->transport = listener->transport;
	vtq->state = virtiot_queue_init;

	return vtq;
}

static void virtiot_tcp_close(struct virtiot_queue *vtq)
{
	struct virtiot_tcp_queue *vttcpq = to_tcp_queue(vtq);

	log_debug("fd[%d]\n", vttcpq->sockfd);
	vtq->state = virtiot_queue_close;
	if (vttcpq->epollfd >= 0) {
		virtiot_del_event(vttcpq->epollfd, vttcpq->sockfd);
		close(vttcpq->sockfd);
	}
	close(vtq->fd);

	free(vttcpq->vttcpreq);
	vttcpq->vttcpreq = NULL;
#if 0
	list_for_each_entry_safe(req, tmpreq, &vtq->requests, entry) {
		list_del(&req->entry);
		virtiot_free_request(req);
	}

	free(vtq->resp);
	vtq->resp = NULL;
	list_for_each_entry_safe(resp, tmpresp, &vtq->responses, entry) {
		list_del(&resp->entry);
		virtiot_free_response(resp);
	}
#endif

	free(vttcpq);
}

static struct virtiot_transport virtiot_tcp = {
	.vtobj = {
		.id = "tcp",
		.type = virtiot_object_transport
	},
	.oftype = virtio_of_connection_tcp,
	.listen = virtiot_tcp_listen,
	.accept = virtiot_tcp_accept,
	.close = virtiot_tcp_close,
	.process = virtiot_tcp_process,
};

static void __attribute__((constructor)) virtiot_transport_tcp_init(void)
{
	virtiot_transport_register(&virtiot_tcp);
}
