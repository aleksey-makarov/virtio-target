/*
 * Copyright 2023 zhenwei pi
 *
 * Authors:
 *   zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include "device.h"
#include "log.h"

#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdlib.h>

int virtiot_model_register(struct virtiot_model *model)
{
	struct virtiot_object *vtobj = &model->vtobj;

	if (!vtobj->id || !vtobj->type) {
		return -EINVAL;
	}

	assert(model->create);

	return virtiot_object_add(vtobj);
}

void virtiot_model_unregister(struct virtiot_model *model)
{
	virtiot_object_del(&model->vtobj);
}

struct virtiot_model *virtiot_model_lookup(const char *id)
{
	struct virtiot_object *vtobj;

	vtobj = virtiot_object_lookup(id, virtiot_object_model);
	if (!vtobj) {
		return NULL;
	}

	assert(vtobj->type == virtiot_object_model);

	return container_of(vtobj, struct virtiot_model, vtobj);
}
