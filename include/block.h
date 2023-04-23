/*
 * Copyright 2023 zhenwei pi
 *
 * Authors:
 *   zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef VIRTIO_TARGET_BLOCK_H
#define VIRTIO_TARGET_BLOCK_H

#include "driver.h"
#include "transport.h"

struct virtiot_block_driver {
	struct virtiot_driver vtdrv;

	void *(*open)(const char *backend);
	void (*close)(void *context);
	__u64 (*get_capacity)(void *context);
	int (*read)(void *context, off_t offset, struct virtiot_request *vtreq);
	int (*write)(void *context, off_t offset, struct virtiot_request *vtreq);
};

#endif
