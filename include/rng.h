/*
 * Copyright 2023 zhenwei pi
 *
 * Authors:
 *   zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef VIRTIO_TARGET_RNG_H
#define VIRTIO_TARGET_RNG_H

#include "driver.h"
#include "transport.h"

struct virtiot_rng_driver {
	struct virtiot_driver vtdrv;

	void *(*open)(const char *backend);
	void (*close)(void *context);
	int (*read)(void *context, struct virtiot_request *vtreq);
};

#endif
