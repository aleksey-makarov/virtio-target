/*
 * Copyright 2023 zhenwei pi
 *
 * Authors:
 *   zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef VIRTIO_TARGET_TRANSPORT_H
#define VIRTIO_TARGET_TRANSPORT_H

#include <stdlib.h>
#include <linux/virtio_ring.h>

#include "object.h"
#include "virtio_of.h"
#include "utils.h"

enum virtiot_queue_state {
	virtiot_queue_init,
	virtiot_queue_listen,
	virtiot_queue_connect,
	virtiot_queue_established,
	virtiot_queue_close,
};

struct virtiot_request {
	struct virtiot_queue *vtq;
	void (*fill_desc)(struct virtio_of_vring_desc *vofdesc, __u64 addr, __u32 length);
	void (*complete)(struct virtiot_request *vtreq);
	struct virtio_of_command *vofcmd;
	struct virtio_of_completion *vofcomp;
	__u16 ndesc;	/* total vofdescs */
	__u16 read_ndesc;	/* number of vofdescs to read */
	__u16 done_ndesc;	/* number of vofdescs already read/wrote */
	struct virtio_of_vring_desc *vofdescs;
	unsigned char **addr;
};

static inline void virtiot_request_free_desc(struct virtiot_request *vtreq)
{
	__u16 idx;

	for (idx = 0; idx < vtreq->ndesc; idx++) {
		free(vtreq->addr[idx]);
	}
}

static inline int virtiot_request_alloc_desc(struct virtiot_request *vtreq)
{
	struct virtio_of_vring_desc *vofdesc;
	__u32 length;
	__u16 idx;

	for (idx = 0; idx < vtreq->ndesc; idx++) {
		vofdesc = vtreq->vofdescs + idx;
		length = le32toh(vofdesc->length);
		if (!length) {
			virtiot_request_free_desc(vtreq);
			return -EINVAL;
		}

		if (PAGE_ALIGNED(length)) {
			vtreq->addr[idx] = valloc(length);
			memset(vtreq->addr[idx], 0x00, length);
		} else {
			vtreq->addr[idx] = calloc(1, length);
		}

		if (!(le16toh(vofdesc->flags) & VRING_DESC_F_WRITE)) {
			vtreq->read_ndesc++;
		}
	}

	return 0;
}

struct virtiot_queue {
	struct virtiot_transport *transport;
	struct virtiot_target *vtgt;
	__u16 queue_id;	/* queue index of a device, ctrl queue is 0xffff */
	int fd;
	unsigned int ref;	/*TODO*/
	enum virtiot_queue_state state;
};

struct virtiot_transport {
	struct virtiot_object vtobj;
	enum virtio_of_connection_type oftype;

	struct virtiot_queue *(*listen)(const char *address, int port);
	struct virtiot_queue *(*accept)(struct virtiot_queue *listener);
	void (*close)(struct virtiot_queue *vtq);
	int (*process)(struct virtiot_queue *vtq);
	void (*pin_cpu)(struct virtiot_queue *vtq);
};

static inline int virtiot_transport_register(struct virtiot_transport *transport)
{
	return virtiot_object_add(&transport->vtobj);
}

static inline void virtiot_transport_unregister(struct virtiot_transport *transport)
{
	virtiot_object_del(&transport->vtobj);
}

static inline struct virtiot_transport *virtiot_transport_lookup(const char *id)
{
	struct virtiot_object *vtobj;

	vtobj = virtiot_object_lookup(id, virtiot_object_transport);
	if (!vtobj) {
		return NULL;
	}

	assert(vtobj->type == virtiot_object_transport);

	return container_of(vtobj, struct virtiot_transport, vtobj);
}

#endif
