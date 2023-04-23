#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <linux/virtio_ring.h>
#include <rdma/rdma_cma.h>

#include "virtio_of.h"
#include "target.h"
#include "fabrics.h"
#include "utils.h"
#include "log.h"

static struct virtiot_transport virtiot_rdma;

struct virtiot_rdma_request {
	struct virtiot_request vtreq;
	struct ibv_mr **mr;
	struct virtio_of_completion vofcomp;
	struct virtio_of_command vofcmd;
	struct virtio_of_vring_desc vofdesc[0];
};

struct virtiot_rdma_queue {
	struct virtiot_queue vtq;
	struct rdma_cm_id *cm_id;
	struct ibv_comp_channel *comp_channel;
	struct rdma_event_channel *event_channel;
	struct ibv_cq *cq;
	struct virtiot_rdma_request *vtrdmaconn;
	struct ibv_mr *conn_mr;
	__u16 depth;
	__u16 ndesc;
	struct virtiot_rdma_request *vtrdmareq;
	struct ibv_mr *req_mr;
	int epollfd;
	int evfd;
	bool disconnected;
};

static inline struct virtiot_rdma_request *to_rdma_request(struct virtiot_request *vtreq)
{
	return container_of(vtreq, struct virtiot_rdma_request, vtreq);
}

static inline struct virtiot_rdma_queue *to_rdma_queue(struct virtiot_queue *vtq)
{
	return container_of(vtq, struct virtiot_rdma_queue, vtq);
}

static int virtiot_rdma_recv(struct virtiot_rdma_queue *vtrdmaq, struct virtiot_rdma_request *vtrdmareq, __u32 length, __u32 lkey)
{
	struct ibv_sge sge;
	struct ibv_recv_wr recv_wr, *bad_wr;
	int ret;

	sge.addr = (uint64_t)&vtrdmareq->vofcmd;
	sge.length = length;
	sge.lkey = lkey;

	recv_wr.wr_id = (uint64_t)vtrdmareq;
	recv_wr.sg_list = &sge;
	recv_wr.num_sge = 1;
	recv_wr.next = NULL;
//log_debug("addr %p, length %d, key %d, wr_id %p\n", (void *)sge.addr, sge.length, sge.lkey, (void *)recv_wr.wr_id);

	ret = ibv_post_recv(vtrdmaq->cm_id->qp, &recv_wr, &bad_wr);
	if (ret) {
		log_error("ibv_post_recv failed: %d\n", ret);
	}

	return ret;
}

static int virtiot_rdma_send(struct virtiot_rdma_queue *vtrdmaq, struct virtiot_rdma_request *vtrdmareq, __u32 lkey)
{
	struct ibv_send_wr send_wr, *bad_wr;
	struct ibv_sge sge;

	sge.addr = (uint64_t)&vtrdmareq->vofcomp;
	sge.length = le32toh(sizeof(struct virtio_of_completion));
	sge.lkey = lkey;
//log_debug("vofcomp status %d, ndesc %d, value %d\n", le16toh(vtrdmareq->vofcomp.status), le16toh(vtrdmareq->vofcomp.ndesc), le32toh(vtrdmareq->vofcomp.value.u32));

	send_wr.sg_list = &sge;
	send_wr.num_sge = 1;
	send_wr.wr_id = (uint64_t)vtrdmareq;
	send_wr.opcode = IBV_WR_SEND;
	send_wr.send_flags = IBV_SEND_SIGNALED;
	send_wr.next = NULL;
//log_debug("addr %p, length %d, key %d, wr_id %p\n", (void *)sge.addr, sge.length, sge.lkey, (void *)send_wr.wr_id);
	if (ibv_post_send(vtrdmaq->cm_id->qp, &send_wr, &bad_wr)) {
		log_error("ibv_post_send error, opcode IBV_WR_SEND\n");
		return -errno;
	}

	return 0;
}

static int virtiot_rdma_rw(struct virtiot_rdma_queue *vtrdmaq, struct virtiot_rdma_request *vtrdmareq, __u16 idx, struct virtio_of_vring_desc *vofdesc)
{
	struct ibv_send_wr send_wr, *bad_wr;
	struct ibv_sge sge;
	enum ibv_wr_opcode opcode = IBV_WR_RDMA_READ;

	if (le16toh(vofdesc->flags) & VRING_DESC_F_WRITE) {
		opcode = IBV_WR_RDMA_WRITE;
	}

	sge.addr = (uint64_t)vtrdmareq->vtreq.addr[idx];
	sge.length = le32toh(vofdesc->length);
	sge.lkey = vtrdmareq->mr[idx]->lkey;

	send_wr.sg_list = &sge;
	send_wr.num_sge = 1;
	send_wr.opcode = opcode;
	send_wr.send_flags = IBV_SEND_SIGNALED;
	send_wr.wr.rdma.remote_addr = (uint64_t)le64toh(vofdesc->addr);
	send_wr.wr.rdma.rkey = le32toh(vofdesc->key);
	send_wr.wr_id = (uint64_t)vtrdmareq;
	send_wr.next = NULL;
//log_debug("idx %d, addr %p, length %d, key %d, wr_id %p, remote_addr %p, rkey 0x%x\n", idx, (void *)sge.addr, sge.length, sge.lkey, (void *)send_wr.wr_id, (void *)send_wr.wr.rdma.remote_addr, send_wr.wr.rdma.rkey);
	if (ibv_post_send(vtrdmaq->cm_id->qp, &send_wr, &bad_wr)) {
		log_error("ibv_post_send error, opcode 0x%x\n", opcode);
		return -errno;
	}

	return 0;
}

static void virtiot_rdma_free_buf(struct virtiot_rdma_queue *vtrdmaq)
{
	if (vtrdmaq->conn_mr) {
		ibv_dereg_mr(vtrdmaq->conn_mr);
		vtrdmaq->conn_mr = NULL;
	}
	free(vtrdmaq->vtrdmaconn);
	vtrdmaq->vtrdmaconn = NULL;

	if (vtrdmaq->req_mr) {
		ibv_dereg_mr(vtrdmaq->req_mr);
		vtrdmaq->req_mr = NULL;
	}

	free(vtrdmaq->vtrdmareq);
	vtrdmaq->vtrdmareq = NULL;

	vtrdmaq->depth = 0;
	vtrdmaq->ndesc = 0;
}

static void virtiot_rdma_fill_desc(struct virtio_of_vring_desc *vofdesc, __u64 addr, __u32 length)
{
}

static struct virtiot_rdma_request *virtiot_rdma_alloc_req(struct virtiot_rdma_queue *vtrdmaq, struct ibv_mr **mr, __u16 depth, __u16 ndesc, void (*complete)(struct virtiot_request *))
{
	struct virtiot_rdma_request *vtrdmareq, *tmpreq;
	struct virtiot_request *vtreq;
	struct ibv_mr *__mr;
	int access = IBV_ACCESS_LOCAL_WRITE;
	int length;
	int i;

	length = sizeof(struct virtiot_rdma_request);
	length += sizeof(struct virtio_of_vring_desc) * ndesc;
	vtrdmareq = calloc(length, depth);
	assert(vtrdmareq);
//log_debug("depth %d, ndesc %d, length %d\n", depth, ndesc, length);

	__mr = ibv_reg_mr(vtrdmaq->cm_id->pd, vtrdmareq, length * depth, access);
	if (!__mr) {
		log_error("ibv_reg_mr failed: %m\n");
		goto error;
	}

	for (i = 0; i < depth; i++) {
		tmpreq = (struct virtiot_rdma_request *)((__u8 *)vtrdmareq + length * i);
		vtreq = &tmpreq->vtreq;
		vtreq->vtq = &vtrdmaq->vtq;
		vtreq->fill_desc = virtiot_rdma_fill_desc;
		vtreq->complete = complete;
		vtreq->vofcmd = &tmpreq->vofcmd;
		vtreq->vofcomp = &tmpreq->vofcomp;
		vtreq->vofdescs = &tmpreq->vofdesc[0];
		vtreq->addr = calloc(sizeof(unsigned char *), ndesc);

		if (virtiot_rdma_recv(vtrdmaq, tmpreq, length, __mr->lkey)) {
			goto error;
		}
	}

	vtrdmaq->depth = depth;
	vtrdmaq->ndesc = ndesc;
	*mr = __mr;

	return vtrdmareq;

error:
	if (__mr) {
		ibv_dereg_mr(__mr);
	}
	free(vtrdmareq);

	return NULL;
}

static void virtiot_rdma_reset_req(struct virtiot_request *vtreq)
{
	struct virtiot_rdma_request *vtrdmareq = to_rdma_request(vtreq);
	__u16 idx;

	for (idx = 0; idx < vtreq->ndesc; idx++) {
		ibv_dereg_mr(vtrdmareq->mr[idx]);
	}

	free(vtrdmareq->mr);
	vtrdmareq->mr = NULL;
	virtiot_request_free_desc(vtreq);
	vtreq->ndesc = 0;
	vtreq->read_ndesc = 0;
	vtreq->done_ndesc = 0;
}

static void virtiot_rdma_complete_req(struct virtiot_request *vtreq)
{
	struct virtiot_rdma_request *vtrdmareq = to_rdma_request(vtreq);
	struct virtiot_rdma_queue *vtrdmaq = to_rdma_queue(vtreq->vtq);
	int idx;

	//log_debug("\n");
	if (vtreq->done_ndesc == vtreq->ndesc) {
		virtiot_rdma_send(vtrdmaq, vtrdmareq, vtrdmaq->req_mr->lkey);
		return;
	}

	for (idx = 0; idx < vtreq->ndesc; idx++) {
		struct virtio_of_vring_desc *vofdesc;
		vofdesc = vtreq->vofdescs + idx;
		if (!(le16toh(vofdesc->flags) & VRING_DESC_F_WRITE)) {
			continue;
		}

		virtiot_rdma_rw(vtrdmaq, vtrdmareq, idx, vofdesc);
	}
}

static void virtiot_rdma_complete_conn(struct virtiot_request *vtreq)
{
	struct virtiot_rdma_request *vtrdmareq = to_rdma_request(vtreq);
	struct virtiot_rdma_queue *vtrdmaq = to_rdma_queue(vtreq->vtq);
	struct virtiot_device *vtdev;
	__u16 queue_id, depth, ndesc;

	//log_debug("\n");
	assert(vtrdmareq == vtrdmaq->vtrdmaconn);

	if (vtrdmareq->vtreq.vtq->vtgt) {
		queue_id = vtrdmaq->vtq.queue_id;
		if (queue_id == 0xffff) {
			depth = 32;
			ndesc = 1;
		} else {
			vtdev = vtreq->vtq->vtgt->vtdev;
			depth = vtdev->get_depth(vtdev, queue_id);
			ndesc = vtdev->get_max_segs(vtdev, queue_id);
		}
		vtrdmaq->vtrdmareq = virtiot_rdma_alloc_req(vtrdmaq, &vtrdmaq->req_mr, depth, ndesc, virtiot_rdma_complete_req);
		if (!vtrdmaq->vtrdmareq) {
			vtrdmareq->vofcomp.status = htole16(VIRTIO_OF_ENOMEM);
			//TODO mark qp error and shutdown
		}
	}

	virtiot_rdma_send(vtrdmaq, vtrdmareq, vtrdmaq->conn_mr->lkey);
}

static int virtiot_rdma_alloc_conn_req(struct virtiot_rdma_queue *vtrdmaq)
{
	vtrdmaq->vtrdmaconn = virtiot_rdma_alloc_req(vtrdmaq, &vtrdmaq->conn_mr, 1, 1, virtiot_rdma_complete_conn);
	if (!vtrdmaq->vtrdmaconn) {
		return -errno;
	}

	return 0;
}

static int virtiot_rdma_recv_conn(struct virtiot_rdma_queue *vtrdmaq)
{
	struct virtiot_rdma_request *vtrdmareq = vtrdmaq->vtrdmaconn;
	struct virtiot_request *vtreq = &vtrdmareq->vtreq;
	struct virtio_of_vring_desc *vofdesc;
	int length, access;
	int ret;

	if (vtrdmaq->vtq.state == virtiot_queue_init) {
//log_debug("\n");
		if (vtreq->ndesc != 1) {
			return -EPROTO;
		}

		vofdesc = vtreq->vofdescs;
		length = le32toh(vofdesc->length);
		if (length != sizeof(struct virtio_of_connect)) {
			log_error("unexpected connect body\n");
			return -EPROTO;
		}

		if (le16toh(vofdesc->flags) & VRING_DESC_F_WRITE) {
			log_error("unexpected connect flags in desc\n");
			return -EPROTO;
		}

		virtiot_request_alloc_desc(vtreq);
		vtrdmareq->mr = calloc(sizeof(struct ibv_mr *), 1);
		access = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
		vtrdmareq->mr[0] = ibv_reg_mr(vtrdmaq->cm_id->pd, vtreq->addr[0], length, access);

		ret = virtiot_rdma_rw(vtrdmaq, vtrdmareq, 0, vofdesc);
		if (ret) {
			return ret;
		}

		vtrdmaq->vtq.state = virtiot_queue_connect;
	} else if (vtrdmaq->vtq.state == virtiot_queue_connect) {
//log_debug("\n");
		vtrdmaq->vtq.state = virtiot_queue_established;
	}

	return 0;
}

static int virtiot_rdma_read_conn(struct virtiot_rdma_queue *vtrdmaq)
{
	struct virtiot_rdma_request *vtrdmareq = vtrdmaq->vtrdmaconn;
	struct virtiot_request *vtreq = &vtrdmareq->vtreq;

	assert(!vtreq->done_ndesc);

	return virtiot_fabrics_handle_command(vtreq);
}

static int virtiot_rdma_handle_recv(struct virtiot_rdma_queue *vtrdmaq, struct virtiot_rdma_request *vtrdmareq, int length)
{
	struct virtiot_request *vtreq = &vtrdmareq->vtreq;
	struct virtio_of_command *vofcmd = vtreq->vofcmd;
	int exptlen;
	int ndesc;
	int idx;
	int ret;

	if (length < sizeof(struct virtio_of_command)) {
		return -EPROTO;
	}

	ndesc = virtiot_fabrics_ndesc(vofcmd);
	if (ndesc < 0) {
		return ndesc;
	}

	vtreq->ndesc = ndesc;
	exptlen = sizeof(struct virtio_of_command);
	exptlen += sizeof(struct virtio_of_vring_desc) * ndesc;
	if (exptlen != length) {
		log_error("unexpected length\n");
		return -EPROTO;
	}

	if (vtrdmareq == vtrdmaq->vtrdmaconn) {
		log_debug("CONNECT COMMAND\n");

		return virtiot_rdma_recv_conn(vtrdmaq);
	}

	if (!ndesc) {
		return virtiot_fabrics_handle_command(&vtrdmareq->vtreq);
	}

	virtiot_request_alloc_desc(vtreq);
	vtrdmareq->mr = calloc(sizeof(struct ibv_mr *), ndesc);
	for (idx = 0; idx < vtreq->ndesc; idx++) {
		vtrdmareq->mr[idx] = ibv_reg_mr(vtrdmaq->cm_id->pd, vtreq->addr[idx], le32toh(vtreq->vofdescs[idx].length), IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
		assert(vtrdmareq->mr[idx]);
	}

//log_debug("vtreq->ndesc %d, vtreq->read_ndesc %d, vtreq->done_ndesc %d\n", vtreq->ndesc, vtreq->read_ndesc, vtreq->done_ndesc);
	if (!vtreq->read_ndesc) {
		return virtiot_fabrics_handle_command(&vtrdmareq->vtreq);
	}

	for (idx = 0; idx < vtreq->ndesc; idx++) {
		struct virtio_of_vring_desc *vofdesc;
		vofdesc = vtreq->vofdescs + idx;
		if (le16toh(vofdesc->flags) & VRING_DESC_F_WRITE) {
			continue;
		}

		ret = virtiot_rdma_rw(vtrdmaq, vtrdmareq, idx, vofdesc);
		if (ret) {
			return ret;
		}
	}

	return 0;
}

static int virtiot_rdma_handle_read(struct virtiot_rdma_queue *vtrdmaq, struct virtiot_rdma_request *vtrdmareq, int length)
{
	struct virtiot_request *vtreq = &vtrdmareq->vtreq;

	if (vtrdmareq == vtrdmaq->vtrdmaconn) {
		log_debug("CONNECT COMMAND\n");
		return virtiot_rdma_read_conn(vtrdmaq);
	}

	vtreq = &vtrdmareq->vtreq;
	vtreq->done_ndesc++;

//log_debug("vtreq->ndesc %d, vtreq->read_ndesc %d, vtreq->done_ndesc %d, length %d\n", vtreq->ndesc, vtreq->read_ndesc, vtreq->done_ndesc, length);
	if (vtreq->done_ndesc == vtreq->read_ndesc) {
		return virtiot_fabrics_handle_command(vtreq);
	}

	return 0;
}

static int virtiot_rdma_handle_write(struct virtiot_rdma_queue *vtrdmaq, struct virtiot_rdma_request *vtrdmareq, int length)
{
	struct virtiot_request *vtreq = &vtrdmareq->vtreq;

	if (vtrdmareq == vtrdmaq->vtrdmaconn) {
		log_debug("CONNECT COMMAND\n");
		return virtiot_rdma_read_conn(vtrdmaq);
	}

	vtreq = &vtrdmareq->vtreq;
	vtreq->done_ndesc++;

//log_debug("vtreq->ndesc %d, vtreq->read_ndesc %d, vtreq->done_ndesc %d, length %d\n", vtreq->ndesc, vtreq->read_ndesc, vtreq->done_ndesc, length);
	if (vtreq->done_ndesc == vtreq->ndesc) {
		return virtiot_rdma_send(vtrdmaq, vtrdmareq, vtrdmaq->req_mr->lkey);
	}

	return 0;
}

static int virtiot_rdma_handle_send(struct virtiot_rdma_queue *vtrdmaq, struct virtiot_rdma_request *vtrdmareq, int length)
{
	struct virtiot_request *vtreq = &vtrdmareq->vtreq;

	if (vtrdmareq == vtrdmaq->vtrdmaconn) {
		log_debug("CONNECT COMMAND\n");
		return 0;
	}

	virtiot_rdma_reset_req(vtreq);
	length = sizeof(struct virtiot_rdma_request);
	length += sizeof(struct virtio_of_vring_desc) * vtrdmaq->ndesc;

	return virtiot_rdma_recv(vtrdmaq, vtrdmareq, length, vtrdmaq->req_mr->lkey);
}

static int virtiot_rdma_handle_cq(struct virtiot_rdma_queue *vtrdmaq)
{
	struct virtiot_rdma_request *vtrdmareq;
	struct ibv_cq *ev_cq = NULL;
	void *ev_ctx = NULL;
	struct ibv_wc wc;
	int ret;

	if (ibv_get_cq_event(vtrdmaq->comp_channel, &ev_cq, &ev_ctx) < 0) {
		if (errno != EAGAIN) {
			log_warn("ibv_get_cq_event failed: %m\n");
		}
		return -errno;
	} else if (ibv_req_notify_cq(ev_cq, 0)) {
		log_warn("ibv_req_notify_cq failed: %m\n");
		return -errno;
	}

poll_cq:
	ret = ibv_poll_cq(vtrdmaq->cq, 1, &wc);
	if (ret < 0) {
		log_warn("ibv_poll_cq failed: %m\n");
		return -errno;
	} else if (ret == 0) {
		return 0;
	}

	ibv_ack_cq_events(vtrdmaq->cq, 1);

//log_debug("CQ handle status: %s[0x%x], wr_id: %p, opcode: 0x%x, byte_len: %d\n", ibv_wc_status_str(wc.status), wc.status, (void *)wc.wr_id, wc.opcode, wc.byte_len);
	if (wc.status != IBV_WC_SUCCESS) {
		log_error("CQ handle error status: %s[0x%x], opcode : 0x%x\n", ibv_wc_status_str(wc.status), wc.status, wc.opcode);
		return -EIO;
	}

	vtrdmareq = (struct virtiot_rdma_request *)wc.wr_id;
	switch (wc.opcode) {
	case IBV_WC_RECV:
		ret = virtiot_rdma_handle_recv(vtrdmaq, vtrdmareq, wc.byte_len);
		if (ret < 0) {
			return ret;
		}
		break;

	case IBV_WC_RDMA_READ:
		ret = virtiot_rdma_handle_read(vtrdmaq, vtrdmareq, wc.byte_len);
		if (ret < 0) {
			return ret;
		}
		break;

	case IBV_WC_RDMA_WRITE:
		ret = virtiot_rdma_handle_write(vtrdmaq, vtrdmareq, wc.byte_len);
		if (ret < 0) {
			return ret;
		}
		break;

	case IBV_WC_SEND:
		ret = virtiot_rdma_handle_send(vtrdmaq, vtrdmareq, wc.byte_len);
		if (ret < 0) {
			return ret;
		}
		break;

	default:
		log_error("unexpected opcode 0x%x", wc.opcode);
		return -EIO;
	}

	goto poll_cq;
}

static int virtiot_rdma_process(struct virtiot_queue *vtq)
{
	struct virtiot_rdma_queue *vtrdmaq = to_rdma_queue(vtq);
	int ret;

	if (vtrdmaq->disconnected) {
		return -EPIPE;
	}

	while (true) {
		ret = virtiot_rdma_handle_cq(vtrdmaq);
		if (ret) {
			if (ret == -EAGAIN) {
				return 0;
			}
			return ret;
		}
	}

	return 0;
}

static struct virtiot_queue *virtiot_rdma_listen(const char *address, int port)
{
	struct virtiot_rdma_queue *vtrdmaq;
	struct virtiot_queue *vtq = NULL;
	struct rdma_addrinfo hints = { 0 }, *addrinfo;
	struct rdma_event_channel *listen_channel = NULL;
	struct rdma_cm_id *listen_id = NULL;
	char _port[6];	/* strlen("65535") */
	int ret;

	snprintf(_port, 6, "%d", port);
	hints.ai_flags = RAI_PASSIVE;
	hints.ai_port_space = RDMA_PS_TCP;
	ret = rdma_getaddrinfo(address, _port, &hints, &addrinfo);
	if (ret) {
		log_error("rdma_getaddrinfo: %d\n", ret);
		return NULL;
	}

	listen_channel = rdma_create_event_channel();
	if (!listen_channel) {
		log_error("rdma_create_event_channel: %m\n");
		goto free_addrinfo;
	}

	if (rdma_create_id(listen_channel, &listen_id, NULL, RDMA_PS_TCP)) {
		log_error("rdma_create_id: %m\n");
		goto destroy_channel;
	}

	if (rdma_bind_addr(listen_id, (struct sockaddr *)addrinfo->ai_src_addr)) {
		log_error("rdma_bind_addr: %m\n");
		goto destroy_id;
	}

	ret = rdma_listen(listen_id, 128);
	if (ret) {
		log_error("rdma_listen: %d\n", ret);
		goto destroy_id;
	}

	vtrdmaq = calloc(sizeof(struct virtiot_rdma_queue), 1);
	assert(vtrdmaq);
	listen_id->context = vtrdmaq;

	vtrdmaq->cm_id = listen_id;
	vtrdmaq->event_channel = listen_channel;
	vtrdmaq->epollfd = -1;
	vtrdmaq->evfd = -1;

	vtq = &vtrdmaq->vtq;
	vtq->transport = &virtiot_rdma;
	vtq->queue_id = 0xffff;
	vtq->fd = listen_channel->fd;
	virtiot_set_nonblock(listen_channel->fd);
	vtq->state = virtiot_queue_listen;
//log_debug("listener vtq %p, cm_id %p, fd %d, channel %p\n", vtrdmaq, listen_id, vtq->fd, listen_channel);

	goto free_addrinfo;

destroy_id:
	rdma_destroy_id(listen_id);

destroy_channel:
	rdma_destroy_event_channel(listen_channel);

free_addrinfo:
	rdma_freeaddrinfo(addrinfo);

	return vtq;
}

#if 0
static int virtiot_rdma_alloc_buf(struct virtiot_rdma_queue *vtrdmaq, __u16 depth, __u16 ndesc)
{
	void *addr;
	int access = IBV_ACCESS_LOCAL_WRITE;
	int length;
	__u16 i;

	vtrdmaq->depth = depth;
	vtrdmaq->ndesc = ndesc;

	length = sizeof(struct virtio_of_command) + sizeof(struct virtio_of_vring_desc) * ndesc;
	vtrdmaq->vofcmd = (struct virtio_of_command *)calloc(length, depth);
	assert(vtrdmaq->vofcmd);
	vtrdmaq->cmd_mr = ibv_reg_mr(vtrdmaq->cm_id->pd, vtrdmaq->vofcmd, length, access);
	if (!vtrdmaq->cmd_mr) {
		log_error("ibv_reg_mr commands failed: %m\n");
		goto error;
	}

	for (i = 0; i < depth; i++) {
		addr = (__u8 *)vtrdmaq->vofcmd + length * i;
		virtiot_rdma_post_recv(vtrdmaq, addr);
	}

	length = sizeof(struct virtio_of_completion);
	vtrdmaq->vofcomp = (struct virtio_of_command *)calloc(length, depth);
	assert(vtrdmaq->vofcomp);
	vtrdmaq->comp_mr = ibv_reg_mr(vtrdmaq->cm_id->pd, vtrdmaq->vofcomp, length, access);
	if (!vtrdmaq->comp_mr) {
		log_error("ibv_reg_mr completion failed: %m\n");
		goto error;
	}

	return 0;

error:
	virtiot_rdma_free_buf(vtrdmaq);

	return -errno;
}
#endif

static struct virtiot_queue *virtiot_rdma_connect_request(struct rdma_cm_id *cm_id)
{
	struct virtiot_rdma_queue *vtrdmaq;
	struct virtiot_queue *vtq;
	struct ibv_qp_init_attr init_attr;
	struct ibv_comp_channel *comp_channel = NULL;
	struct ibv_cq *cq = NULL;
	struct ibv_pd *pd = NULL;
	struct rdma_conn_param conn_param;
	int epollfd = -1, evfd = -1;
	int ret;

	epollfd = epoll_create1(0);
	if (epollfd == -1) {
		log_error("epoll_create1 failed: %m");
		goto error;
	}

	evfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (evfd == -1) {
		log_error("eventfd failed: %m");
		goto error;
	}

	pd = ibv_alloc_pd(cm_id->verbs);
	if (!pd) {
		log_error("ibv_alloc_pd failed: %m\n");
		goto error;
	}

	comp_channel = ibv_create_comp_channel(cm_id->verbs);
	if (!comp_channel) {
		log_error("ibv_create_comp_channel failed: %m\n");
		goto error;
	}

	cq = ibv_create_cq(cm_id->verbs, VIRTIO_TARGET_VRING_SIZE, NULL, comp_channel, 0);
	if (!cq) {
		log_error("ibv_create_cq failed: %m\n");
		goto error;
	}

	ibv_req_notify_cq(cq, 0);

	memset(&init_attr, 0x00, sizeof(init_attr));
	init_attr.cap.max_send_wr = VIRTIO_TARGET_VRING_SIZE;
	init_attr.cap.max_recv_wr = VIRTIO_TARGET_VRING_SIZE;
	init_attr.cap.max_send_sge = 1;
	init_attr.cap.max_recv_sge = 1;
	init_attr.qp_type = IBV_QPT_RC;
	init_attr.send_cq = cq;
	init_attr.recv_cq = cq;
	ret = rdma_create_qp(cm_id, pd, &init_attr);
	if (ret) {
		log_error("ibv_create_qp failed: %m\n");
		goto error;
	}

	vtrdmaq = calloc(sizeof(struct virtiot_rdma_queue), 1);
	assert(vtrdmaq);
	cm_id->context = vtrdmaq;
	assert(!virtiot_set_nonblock(comp_channel->fd));

	vtrdmaq->cm_id = cm_id;
	vtrdmaq->comp_channel = comp_channel;
	vtrdmaq->cq = cq;
	vtrdmaq->epollfd = epollfd;
	vtrdmaq->evfd = evfd;
	virtiot_add_event(epollfd, comp_channel->fd, vtrdmaq);
	virtiot_add_event(epollfd, evfd, vtrdmaq);

	vtq = &vtrdmaq->vtq;
	vtq->queue_id = 0xffff;
	vtq->transport = &virtiot_rdma;
	vtq->state = virtiot_queue_init;
	vtq->fd = epollfd;

	/* see struct virtio_of_command_connect */
	if (virtiot_rdma_alloc_conn_req(vtrdmaq) < 0) {
		goto error;
	}

	memset(&conn_param, 0x00, sizeof(conn_param));
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;
	conn_param.retry_count = 5;
	ret = rdma_accept(cm_id, &conn_param);
	if (ret) {
		log_error("rdma_accept failed: %m");
		goto free_buf;
	}

	return vtq;

free_buf:
	virtiot_rdma_free_buf(vtrdmaq);

error:
	if (pd) {
		ibv_dealloc_pd(pd);
	}

	if (comp_channel) {
		ibv_destroy_comp_channel(comp_channel);
	}

	if (cq) {
		ibv_destroy_cq(cq);
	}

	if (cm_id->qp) {
		rdma_destroy_qp(cm_id);
	}

	if (evfd >= 0) {
		close(evfd);
	}

	if (epollfd >= 0) {
		close(epollfd);
	}

	return NULL;
}

static void virtiot_rdma_disconnect(struct rdma_cm_id *cm_id)
{
	struct virtiot_rdma_queue *vtrdmaq = cm_id->context;
	uint64_t u = 1;

	vtrdmaq->disconnected = true;
	write(vtrdmaq->evfd, &u, sizeof(u));
}

static struct virtiot_queue *virtiot_rdma_accept(struct virtiot_queue *listener)
{
	struct virtiot_rdma_queue * vtrdmalistener = to_rdma_queue(listener);
	struct rdma_cm_event *ev;
	struct virtiot_queue *vtq = NULL;
	int ret;

	ret = rdma_get_cm_event(vtrdmalistener->cm_id->channel, &ev);
	if (ret) {
		if (errno != EAGAIN) {
			log_error("listener rdma_get_cm_event failed: %d", errno);
		}

		return NULL;
	}

	log_debug("listener cm event: %s, id %p\n", rdma_event_str(ev->event), ev->id);
	switch (ev->event) {
	case RDMA_CM_EVENT_CONNECT_REQUEST:
		vtq = virtiot_rdma_connect_request(ev->id);
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		break;

	case RDMA_CM_EVENT_DISCONNECTED:
		virtiot_rdma_disconnect(ev->id);
		break;

	default:
		log_warn("listener unexpected cm event: %s\n", rdma_event_str(ev->event));
	}

	rdma_ack_cm_event(ev);

	return vtq;
}

static void virtiot_rdma_close(struct virtiot_queue *vtq)
{
	struct virtiot_rdma_queue *vtrdmaq = to_rdma_queue(vtq);

	log_debug("\n");
	if (vtrdmaq->epollfd == -1) {
		rdma_destroy_event_channel(vtrdmaq->event_channel);
		rdma_destroy_id(vtrdmaq->cm_id);
	} else {
		virtiot_del_event(vtrdmaq->epollfd, vtrdmaq->comp_channel->fd);
		virtiot_del_event(vtrdmaq->epollfd, vtrdmaq->evfd);
		virtiot_rdma_free_buf(vtrdmaq);
		while (!virtiot_rdma_handle_cq(vtrdmaq));
		ibv_destroy_cq(vtrdmaq->cq);
		ibv_destroy_comp_channel(vtrdmaq->comp_channel);
		rdma_disconnect(vtrdmaq->cm_id);
		rdma_destroy_qp(vtrdmaq->cm_id);
		ibv_dealloc_pd(vtrdmaq->cm_id->pd);
		rdma_destroy_id(vtrdmaq->cm_id);
		close(vtrdmaq->evfd);
		close(vtrdmaq->epollfd);
	}

	free(vtrdmaq);
}

static struct virtiot_transport virtiot_rdma = {
	.vtobj = {
		.id = "rdma",
		.type = virtiot_object_transport
	},
	.oftype = virtio_of_connection_rdma,
	.listen = virtiot_rdma_listen,
	.accept = virtiot_rdma_accept,
	.close = virtiot_rdma_close,
	.process = virtiot_rdma_process,
};

static void __attribute__((constructor)) virtiot_rdma_init(void)
{
	virtiot_transport_register(&virtiot_rdma);
}
