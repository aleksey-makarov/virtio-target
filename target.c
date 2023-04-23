/*
 * Copyright 2023 zhenwei pi
 *
 * Authors:
 *   zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include "target.h"
#include "log.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

/*
 * two types of virtiot_target are used:
 * - listen targets: linked in objects.
 * - established targets: stored in virtiot_targets[],
 *       virtiot_target.virtiot_target.entry is empty.
 */
static inline bool virtiot_target_listen(struct virtiot_target *vtgt)
{
	return !list_empty(&vtgt->vtobj.entry);
}

static unsigned int virtiot_target_nr;
static struct virtiot_target **virtiot_targets;

void virtiot_target_init(unsigned int targets)
{
	assert(!virtiot_target_nr);
	virtiot_target_nr = targets;
	virtiot_targets = calloc(sizeof(struct virtiot_target *), targets);
}

struct virtiot_target *virtiot_target_lookup_by_index(unsigned int index)
{
	if (index >= virtiot_target_nr) {
		return NULL;
	}

	return virtiot_targets[index];
}

struct virtiot_target *virtiot_target_established(struct virtiot_target *vtgt)
{
	struct virtiot_target *new;
	__u16 num_queues = 1;
	int i;

	for (i = 0; i < virtiot_target_nr; i++) {
		if (!virtiot_targets[i]) {
			new = virtiot_targets[i];
			break;
		}
	}

	if (i == virtiot_target_nr) {
		return NULL;
	}

	new = calloc(sizeof(struct virtiot_target), 1);
	if (!new) {
		return NULL;
	}

	if (vtgt->vtdev->get_queues) {
		num_queues = vtgt->vtdev->get_queues(vtgt->vtdev);
	}

	new->vtqueues = calloc(sizeof(struct virtiot_queue*), num_queues);
	assert(new->vtqueues);
	INIT_LIST_HEAD(&new->vtobj.entry);
	new->vtdev = vtgt->vtdev;
	new->tvqn = vtgt->tvqn;
	new->target_id = i;
	virtiot_targets[i] = new;

	return new;
}

void virtiot_target_map_queue(struct virtiot_target *vtgt, struct virtiot_queue *vtq, __u16 queue_id)
{
	assert(!vtq->vtgt);
	vtq->vtgt = vtgt;
	vtq->queue_id = queue_id;
	vtgt->vtqueues[queue_id] = vtq;
}

struct virtiot_target_tvqn_param {
	const char *tvqn;
	struct virtiot_target *vtgt;
};

static int virtiot_target_iterate_tvqn(struct virtiot_object *vtobj, void *opaque)
{
	struct virtiot_target_tvqn_param *vttp = opaque;
	struct virtiot_target *vtgt;

	if (vtobj->type != virtiot_object_target) {
		return 0;
	}

	vtgt = container_of(vtobj, struct virtiot_target, vtobj);
	if (!strcmp(vtgt->tvqn, vttp->tvqn)) {
		vttp->vtgt = vtgt;
		return 1;
	}

	return 0;
}

struct virtiot_target *virtiot_target_lookup_by_tvqn(const char *tvqn)
{
	struct virtiot_target_tvqn_param vttp;

	vttp.tvqn = tvqn;
	vttp.vtgt = NULL;
	virtiot_object_iterate(virtiot_object_target, virtiot_target_iterate_tvqn, &vttp);

	return vttp.vtgt;
}

struct virtiot_target *virtiot_target_lookup_by_id(const char *id)
{
	struct virtiot_object *vtobj;

	vtobj = virtiot_object_lookup(id, virtiot_object_target);
	if (!vtobj) {
		return NULL;
	}

	assert(vtobj->type == virtiot_object_target);

	return container_of(vtobj, struct virtiot_target, vtobj);
}

struct virtiot_target *virtiot_target_create(const char *id, const char *model, const char *tvqn, const char *backend)
{
	struct virtiot_model *vtmodel;
	struct virtiot_device *vtdev;
	struct virtiot_target *vtgt;
	struct virtiot_object *vtobj;

	vtgt = virtiot_target_lookup_by_id(id);
	if (vtgt) {
		log_error("id[%s] exists\n", id);
		return NULL;
	}

	vtmodel = virtiot_model_lookup(model);
	if (!vtmodel) {
		log_error("model [%s] not support\n", model);
		return NULL;
	}

	vtdev = vtmodel->create(id, backend);
	if (!vtdev) {
		return NULL;
	}

	vtgt = calloc(sizeof(struct virtiot_target), 1);
	assert(vtgt);

	vtgt->target_id = -1;
	vtgt->vtdev = vtdev;
	vtgt->tvqn = strdup(tvqn);

	vtobj = &vtgt->vtobj;
	vtobj->id = strdup(id);
	vtobj->type = virtiot_object_target;
	virtiot_object_add(vtobj);

	return vtgt;
}

void virtiot_target_destroy(struct virtiot_target *vtgt, int epollfd)
{
	struct virtiot_transport *transport = vtgt->vtctrlq->transport;
	struct virtiot_device *vtdev;
	struct virtiot_queue *vtq;
	__u16 num_queues = 1, i;

	if (virtiot_target_listen(vtgt)) {
		vtdev = vtgt->vtdev;
		vtdev->destroy(vtdev);
		virtiot_object_del(&vtgt->vtobj);
		free((void *)vtgt->vtobj.id);
		free((void *)vtgt->tvqn);
	} else {
		if (vtgt->vtdev->get_queues) {
			num_queues = vtgt->vtdev->get_queues(vtgt->vtdev);
		}

		for (i = 0; i < num_queues; i++) {
			vtq = vtgt->vtqueues[i];
			if (!vtq)
				continue;

			virtiot_del_event(epollfd, vtq->fd);
			transport->close(vtq);
		}

		vtq = vtgt->vtctrlq;
		virtiot_del_event(epollfd, vtq->fd);
		transport->close(vtq);
		virtiot_targets[vtgt->target_id] = NULL;
	}

	free(vtgt);
}
