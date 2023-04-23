/*
 * Copyright 2023 zhenwei pi
 *
 * Authors:
 *   zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef VIRTIO_INITIATOR_QUEUE_H
#define VIRTIO_INITIATOR_QUEUE_H

#include <sys/uio.h>

#include "virtio_of.h"

struct vi_queue {
	char *transport;
	enum virtio_of_connection_type oftype;
	void *(*create_queue)(const char *taddr, int tport);
	void (*destroy_queue)(void *queue);
	int (*send_cmd)(void *queue, struct virtio_of_command *vofcmd, int ndesc, struct virtio_of_vring_desc *descs, struct iovec *iovs);
	int (*recv_comp)(void *queue, struct virtio_of_completion *vofcomp, int ndesc, struct virtio_of_vring_desc *descs, struct iovec *iovs);
};

void vi_queue_register(struct vi_queue *viq);
struct vi_queue *vi_queue_lookup(const char *transport);
void vi_queue_connect_queue(struct vi_queue *viq, void *queue, int *target_id, int queue_id, char *tvqn, char *ivqn);
unsigned int vi_queue_get_vendor_id(struct vi_queue *viq, void *queue);
unsigned int vi_queue_get_device_id(struct vi_queue *viq, void *queue);
unsigned int vi_queue_get_num_queues(struct vi_queue *viq, void *queue);
unsigned int vi_queue_get_queue_size(struct vi_queue *viq, void *queue, __u16 queue_id);
__u64 vi_queue_get_config(struct vi_queue *viq, void *queue, __u16 offset, __u8 bytes);

#endif
