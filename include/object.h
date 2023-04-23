/*
 * Copyright 2023 zhenwei pi
 *
 * Authors:
 *   zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef VIRTIO_TARGET_OBJECT_H
#define VIRTIO_TARGET_OBJECT_H

#include "list.h"

/* object types */
enum virtiot_object_type {
	virtiot_object_device,	/* device instance of a *model* */
	virtiot_object_driver,	/* device backend driver of an *instance* */
	virtiot_object_model,	/* device model, Ex virtio-blk */
	virtiot_object_target,
	virtiot_object_transport,
	virtiot_object_max	/* always keep this as the last one */
};

struct virtiot_object {
	const char *id;
	enum virtiot_object_type type;
	struct list_head entry;
};

int virtiot_object_add(struct virtiot_object *obj);
void virtiot_object_del(struct virtiot_object *obj);
struct virtiot_object *virtiot_object_lookup(const char *id, enum virtiot_object_type type);
/* iterate all the objects until *fn return none-zero */
void virtiot_object_iterate(enum virtiot_object_type type, int (*fn)(struct virtiot_object *vtobj, void *opaque), void *opaque);

#endif
