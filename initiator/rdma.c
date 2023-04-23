#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <linux/virtio_ring.h>
#include <rdma/rdma_cma.h>
#include <stdio.h>

#include "queue.h"
#include "vinitiator.h"

#define VI_RDMA_DEPTH		128
#define VI_RDMA_MAX_SEGS	128

struct vi_rdma_request {
	unsigned char inuse;
	int ndesc;
	struct ibv_mr *bufmr[VI_RDMA_MAX_SEGS];

	struct virtio_of_command vofcmd; /* keep *contiguous* with vofdesc */
	struct virtio_of_vring_desc vofdesc[VI_RDMA_MAX_SEGS];
};

struct vi_rdma_queue {
	struct rdma_cm_id *cm_id;
	struct ibv_comp_channel *comp_channel;
	struct ibv_cq *cq;
	int epollfd;
	struct ibv_mr *compmr;
	struct virtio_of_completion vofcomp[VI_RDMA_DEPTH];
	struct ibv_mr *reqmr;
	struct vi_rdma_request req[VI_RDMA_DEPTH];
};

static struct vi_rdma_request *vi_rdma_get_req(struct vi_rdma_queue *queue)
{
	struct vi_rdma_request *req;
	int i;

	for (i = 0; i < VI_RDMA_DEPTH; i++) {
		req = &queue->req[i];
		if (req->inuse) {
			continue;
		}

		req->inuse = 1;
		return req;
	}

	ASSERT(!"No empty request");
}

static void vi_rdma_put_req(struct vi_rdma_queue *queue, int command_id)
{
	struct vi_rdma_request *req;
	int i;

	for (i = 0; i < VI_RDMA_DEPTH; i++) {
		req = &queue->req[i];
		if (!req->inuse) {
			continue;
		}

		if (le16toh(req->vofcmd.common.command_id) == 0xffff) {
			/* this is connect command */
			goto put;
		}

		if (le16toh(req->vofcmd.common.command_id) == command_id) {
			goto put;
		}
	}

	ASSERT(!"could not find request");

put:
	ASSERT(req->inuse);

	for (i = 0; i < req->ndesc; i++) {
		ASSERT(!ibv_dereg_mr(req->bufmr[i]));
	}

	req->inuse = 0;
}

static int vi_rdma_send_cmd(void *_queue, struct virtio_of_command *vofcmd, int ndesc, struct virtio_of_vring_desc *descs, struct iovec *_iovs)
{
	struct vi_rdma_queue *queue = _queue;
	struct vi_rdma_request *req;
	struct virtio_of_vring_desc *desc;
	struct ibv_send_wr send_wr, *send_bad_wr;
	struct ibv_sge sge;
	void *iov_base;
	int iov_len;
	int access = IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE;
	int length = sizeof(struct virtio_of_command);
	int i;

	ASSERT(ndesc <= VI_RDMA_MAX_SEGS);
	req = vi_rdma_get_req(queue);
	req->ndesc = ndesc;
	memcpy(&req->vofcmd, vofcmd, sizeof(struct virtio_of_command));
	if (!ndesc) {
		goto post_send;
	}

	memcpy(req->vofdesc, descs, sizeof(struct virtio_of_vring_desc) * ndesc);
	length += sizeof(struct virtio_of_vring_desc) * ndesc;
	for (i = 0; i < ndesc; i++) {
		iov_base = _iovs[i].iov_base;
		iov_len = _iovs[i].iov_len;
		req->bufmr[i] = ibv_reg_mr(queue->cm_id->pd, iov_base, iov_len, access);
		ASSERT(req->bufmr[i]);
		desc = &req->vofdesc[i];
		desc->addr = htole64((uint64_t)iov_base);
		desc->length = htole32(iov_len);
		desc->key = htole32(req->bufmr[i]->rkey);
	}

post_send:
	sge.addr = (uint64_t)&req->vofcmd;
	sge.length = length;
	sge.lkey = queue->reqmr->lkey;

	send_wr.sg_list = &sge;
	send_wr.num_sge = 1;
	send_wr.wr_id = (uint64_t)req;
	send_wr.opcode = IBV_WR_SEND;
	send_wr.send_flags = 0;
	send_wr.next = NULL;
	ASSERT(!ibv_post_send(queue->cm_id->qp, &send_wr, &send_bad_wr));

	return 0;
}

static void vi_rdma_recv_one(struct vi_rdma_queue *queue, struct virtio_of_completion *vofcomp)
{
	struct ibv_recv_wr recv_wr, *recv_bad_wr;
	struct ibv_sge sge;

	sge.addr = (uint64_t)vofcomp;
	sge.length = sizeof(struct virtio_of_completion);
	sge.lkey = queue->compmr->lkey;

	recv_wr.wr_id = sge.addr;
	recv_wr.sg_list = &sge;
	recv_wr.num_sge = 1;
	recv_wr.next = NULL;
	ASSERT(!ibv_post_recv(queue->cm_id->qp, &recv_wr, &recv_bad_wr));
}

static int vi_rdma_recv_comp(void *_queue, struct virtio_of_completion *_vofcomp, int ndesc, struct virtio_of_vring_desc *descs, struct iovec *_iovs)
{
	struct vi_rdma_queue *queue = _queue;
	struct virtio_of_completion *vofcomp;
	struct ibv_wc wc;
	struct ibv_cq *ev_cq = NULL;
	void *ev_ctx = NULL;
	struct epoll_event event;
	int command_id;
	int ret;

again:
	vi_add_event(queue->epollfd, queue->comp_channel->fd, queue);
	ret = epoll_wait(queue->epollfd, &event, 1, 1000);
	if (ret < 0) {
		ASSERT(errno == EINTR);
		return -errno;
	}

	ASSERT(ret == 1);
	vi_del_event(queue->epollfd, queue->comp_channel->fd);

	if (ibv_get_cq_event(queue->comp_channel, &ev_cq, &ev_ctx) < 0) {
		ASSERT(errno == EAGAIN);
	}

	ASSERT(!ibv_req_notify_cq(ev_cq, 0));
	ret = ibv_poll_cq(queue->cq, 1, &wc);
	ASSERT(ret >= 0);
	if (!ret) {
		goto again;
	}

	ibv_ack_cq_events(queue->cq, 1);

	//printf("CQ handle status: %s[0x%x], wr_id: %p, opcode: 0x%x, byte_len: %d\n", ibv_wc_status_str(wc.status), wc.status, (void *)wc.wr_id, wc.opcode, wc.byte_len);
	ASSERT(!wc.status);
	switch (wc.opcode) {
	case IBV_WC_RECV:
		ASSERT(wc.byte_len == sizeof(struct virtio_of_completion));
		vofcomp = (struct virtio_of_completion *)wc.wr_id;
		vi_rdma_recv_one(queue, vofcomp);

		command_id = le16toh(vofcomp->command_id);
		vi_rdma_put_req(queue, command_id);
		memcpy(_vofcomp, vofcomp, sizeof(struct virtio_of_completion));
		break;
	default:
		ASSERT(!"unexpected wr opcode");
	}


	return 0;
}

static int vi_rdma_connect(struct vi_rdma_queue *queue)
{
	struct rdma_cm_id *cm_id = queue->cm_id;
	struct ibv_pd *pd;
	struct ibv_comp_channel *comp_channel;
	struct ibv_cq *cq;
	struct ibv_qp_init_attr init_attr;
	struct rdma_conn_param conn_param;

	pd = ibv_alloc_pd(cm_id->verbs);
	ASSERT(pd);

	comp_channel = ibv_create_comp_channel(cm_id->verbs);
	ASSERT(comp_channel);

	cq = ibv_create_cq(cm_id->verbs, 1, NULL, comp_channel, 0);
	ASSERT(cq);
	ibv_req_notify_cq(cq, 0);

	/* only one WR/SGE during connecting */
	memset(&init_attr, 0x00, sizeof(init_attr));
	init_attr.cap.max_send_wr = VI_RDMA_DEPTH;
	init_attr.cap.max_recv_wr = VI_RDMA_DEPTH;
	init_attr.cap.max_send_sge = 1;
	init_attr.cap.max_recv_sge = 1;
	init_attr.qp_type = IBV_QPT_RC;
	init_attr.send_cq = cq;
	init_attr.recv_cq = cq;
	ASSERT(!rdma_create_qp(cm_id, pd, &init_attr));

	memset(&conn_param, 0x00, sizeof(conn_param));
	conn_param.responder_resources = 1;
	conn_param.initiator_depth = 1;
	conn_param.retry_count = 2;
	conn_param.rnr_retry_count = 2;
	ASSERT(!rdma_connect(cm_id, &conn_param));

	queue->comp_channel = comp_channel;
	queue->cq = cq;

	return 0;
}

static void vi_rdma_established(struct vi_rdma_queue *queue)
{
	int length = sizeof(struct virtio_of_completion) * VI_RDMA_DEPTH;
	int access = IBV_ACCESS_LOCAL_WRITE;
	int i;

	queue->compmr = ibv_reg_mr(queue->cm_id->pd, queue->vofcomp, length, access);
	ASSERT(queue->compmr);
	for (i = 0; i < VI_RDMA_DEPTH; i++) {
		vi_rdma_recv_one(queue, &queue->vofcomp[i]);
	}

	length = sizeof(struct vi_rdma_request) * VI_RDMA_DEPTH;
	queue->reqmr = ibv_reg_mr(queue->cm_id->pd, queue->req, length, access);
	ASSERT(queue->reqmr);
}

static int vi_rdma_handle_cm_event(struct vi_rdma_queue *queue)
{
	struct rdma_event_channel *cm_channel = queue->cm_id->channel;
	struct epoll_event event;
	struct rdma_cm_event *ev;
	enum rdma_cm_event_type ev_type;
	int ret;

	/* to keep the intiator side simple, wait CM event at most 1s */
	vi_add_event(queue->epollfd, cm_channel->fd, queue);
	ret = epoll_wait(queue->epollfd, &event, 1, 1000);
	if (ret < 0) {
		ASSERT(errno == EINTR);
		return 0;
	}

	ASSERT(ret == 1);
	vi_del_event(queue->epollfd, cm_channel->fd);

	ASSERT(!rdma_get_cm_event(cm_channel, &ev));
	ev_type = ev->event;
	//printf("ret %d, client cm event: %s\n", ret, rdma_event_str(ev_type));
	ASSERT(ev->id == queue->cm_id);

	switch (ev_type) {
	case RDMA_CM_EVENT_ADDR_RESOLVED:
		ASSERT(!rdma_resolve_route(ev->id, 100));
		break;

	case RDMA_CM_EVENT_ROUTE_RESOLVED:
		vi_rdma_connect(queue);
		break;

	case RDMA_CM_EVENT_ESTABLISHED:
		vi_rdma_established(queue);
		break;

	default:
		printf("unexpected cm event: %s\n", rdma_event_str(ev_type));
		ASSERT(0);
	};

	rdma_ack_cm_event(ev);
	return ev_type;
}

static void vi_rdma_wait_established(struct vi_rdma_queue *queue)
{
	enum rdma_cm_event_type ev_type;

	while (1) {
		ev_type = vi_rdma_handle_cm_event(queue);
		if (ev_type == RDMA_CM_EVENT_ESTABLISHED) {
			break;
		}
	}
}

static void *vi_rdma_create_queue(const char *taddr, int tport)
{
	struct vi_rdma_queue *queue;
	struct rdma_cm_id *cm_id;
	struct rdma_addrinfo hints = { 0 }, *addrinfo = NULL;
	struct rdma_event_channel *cm_channel = NULL;
	char _port[6];  /* strlen("65535") */
	int epollfd;

	queue = calloc(sizeof(struct vi_rdma_queue), 1);
	ASSERT(queue);

	epollfd = epoll_create1(0);
	ASSERT(epollfd >= 0);

	cm_channel = rdma_create_event_channel();
	ASSERT(cm_channel);
	vi_set_nonblock(cm_channel->fd);
	ASSERT(!rdma_create_id(cm_channel, &cm_id, NULL, RDMA_PS_TCP));

	queue->cm_id = cm_id;
	queue->epollfd = epollfd;

	snprintf(_port, 6, "%d", tport);
	memset(&hints, 0, sizeof(hints));
	hints.ai_port_space = RDMA_PS_TCP;
	ASSERT(!rdma_getaddrinfo(taddr, _port, &hints, &addrinfo));
	ASSERT(!rdma_resolve_addr(cm_id, NULL, (struct sockaddr *)addrinfo->ai_dst_addr, 100));

	vi_rdma_wait_established(queue);

	return queue;
}

static struct vi_queue vi_queue_rdma = {
	.transport = "rdma",
	.oftype = virtio_of_connection_rdma,
	.create_queue = vi_rdma_create_queue,
	.send_cmd = vi_rdma_send_cmd,
	.recv_comp = vi_rdma_recv_comp,
};

static void __attribute__((constructor)) vi_queue_rdma_init(void)
{
	vi_queue_register(&vi_queue_rdma);
}
