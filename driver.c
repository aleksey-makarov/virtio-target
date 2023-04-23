/*
 * Copyright 2023 zhenwei pi
 *
 * Authors:
 *   zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include "driver.h"
#include "utils.h"
#include "log.h"

int virtiot_driver_register(struct virtiot_driver *driver)
{
	struct virtiot_object *vtobj = &driver->vtobj;

	if (!vtobj->id || !vtobj->type) {
		return -EINVAL;
	}

	return virtiot_object_add(vtobj);
}

void virtiot_driver_unregister(struct virtiot_driver *driver)
{
	virtiot_object_del(&driver->vtobj);
}

struct virtiot_driver *virtiot_driver_lookup(const char *backend)
{
	struct virtiot_object *vtobj;
	char *driver;

	driver = virtiot_parse_string(backend, "driver");
	assert(driver);

	vtobj = virtiot_object_lookup(driver, virtiot_object_driver);
	free(driver);
	assert(vtobj);
	assert(vtobj->type == virtiot_object_driver);

	return container_of(vtobj, struct virtiot_driver, vtobj);
}
