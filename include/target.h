/*
 * Copyright 2023 zhenwei pi
 *
 * Authors:
 *   zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef VIRTIO_TARGET_TARGET_H
#define VIRTIO_TARGET_TARGET_H

#include "device.h"
#include "transport.h"

struct virtiot_target {
	struct virtiot_object vtobj;
	struct virtiot_device *vtdev;
	const char *tvqn;

	int target_id;
	const char *ivqn;
	struct virtiot_queue *vtctrlq;
	struct virtiot_queue **vtqueues;
};

void virtiot_target_init(unsigned int targets);
struct virtiot_target *virtiot_target_lookup_by_index(unsigned int index);
struct virtiot_target *virtiot_target_established(struct virtiot_target *vtgt);
void virtiot_target_map_queue(struct virtiot_target *vtgt, struct virtiot_queue *vtq, __u16 queue_id);
struct virtiot_target *virtiot_target_create(const char *id, const char *model, const char *tvqn, const char *driver);
void virtiot_target_del(struct virtiot_target *vtgt);
struct virtiot_target *virtiot_target_lookup_by_id(const char *id);
struct virtiot_target *virtiot_target_lookup_by_tvqn(const char *tvqn);
void virtiot_target_destroy(struct virtiot_target *vtgt, int epollfd);

#endif
