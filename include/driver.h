/*
 * Copyright 2023 zhenwei pi
 *
 * Authors:
 *   zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef VIRTIO_TARGET_DRIVER_H
#define VIRTIO_TARGET_DRIVER_H

#include "object.h"

struct virtiot_driver {
	struct virtiot_object vtobj;
};

int virtiot_driver_register(struct virtiot_driver *driver);
void virtiot_driver_unregister(struct virtiot_driver *driver);
struct virtiot_driver *virtiot_driver_lookup(const char *backend);

#define virtiot_driver_find(backend, type, field)	\
		container_of(virtiot_driver_lookup(backend), type, field)

#endif
