/*
 * Copyright 2023 zhenwei pi
 *
 * Authors:
 *   zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef VIRTIO_TARGET_DEVICE_H
#define VIRTIO_TARGET_DEVICE_H

#include "object.h"
#include "transport.h"

#define VIRTIO_TARGET_VENDOR		0x56544754 /* ascii code "VTGT" */
#define VIRTIO_TARGET_VRING_SIZE	1024

struct virtiot_device {
	struct virtiot_object vtobj;

	/* device attributes */
	__u32 vendor_id;	/* initiator read only */
	__u32 device_id;	/* initiator read only */
	__u32 generation;
	unsigned int config_size;
	unsigned char *config;	/* LE format */
	__u64 dev_feature;	/* initiator read only */
	__u64 drv_feature;
	__u32 status;

	/* device lifecycles */
	void (*destroy)(struct virtiot_device *vtdev);

	/* device operations */
	int (*handle_vring)(struct virtiot_device *vtdev, struct virtiot_request *vtreq);
	int (*set_queues)(struct virtiot_device *vtdev, __u16 queues);
	__u16 (*get_queues)(struct virtiot_device *vtdev);
	__u16 (*get_queue_size)(struct virtiot_device *vtdev, __u16 queue_id);
	__u16 (*get_max_segs)(struct virtiot_device *vtdev, __u16 queue_id);
	__u16 (*get_depth)(struct virtiot_device *vtdev, __u16 queue_id);
#if 0
	void (*set_status)(__u32 status);
	__u16 (*get_status)(void);
#endif
};

struct virtiot_model {
	struct virtiot_object vtobj;
	struct virtiot_device *(*create)(const char *id, const char *backend);
};

int virtiot_model_register(struct virtiot_model *model);
void virtiot_model_unregister(struct virtiot_model *model);
struct virtiot_model *virtiot_model_lookup(const char *id);

#endif
