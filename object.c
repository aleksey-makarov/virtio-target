/*
 * Copyright 2023 zhenwei pi
 *
 * Authors:
 *   zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#include <assert.h>
#include <string.h>

#include "object.h"
#include "log.h"

static struct list_head object_lists[virtiot_object_max];
static pthread_mutex_t object_list_locks[virtiot_object_max];
static bool initialized;

static void virtiot_object_init_once(void)
{
	int i;

	if (initialized) {
		return;
	}

	for (i = 0; i < virtiot_object_max; i++) {
		INIT_LIST_HEAD(&object_lists[i]);
	}

	for (i = 0; i < virtiot_object_max; i++) {
		pthread_mutex_init(&object_list_locks[i], NULL);
	}

	initialized = true;
}

static struct virtiot_object *virtiot_object_lookup_locked(const char *id, struct list_head *list)
{
	struct virtiot_object *vtobj;

	list_for_each_entry(vtobj, list, entry) {
		if (!strcmp(vtobj->id, id)) {
			return vtobj;
		}
	}

	return NULL;
}

static const char *virtiot_object_string[] = {
	"device",
	"driver",
	"model",
	"target",
	"transport"
};

int virtiot_object_add(struct virtiot_object *vtobj)
{
	struct list_head *list;
	pthread_mutex_t *lock;

	assert(vtobj->id);
	assert(vtobj->type < virtiot_object_max);
	virtiot_object_init_once();
	list = &object_lists[vtobj->type];
	lock = &object_list_locks[vtobj->type];

	pthread_mutex_lock(lock);
	if (virtiot_object_lookup_locked(vtobj->id, list)) {
		pthread_mutex_unlock(lock);
		log_warn("vtobj[%p] id:%s, type:%s already exist\n", vtobj, vtobj->id, virtiot_object_string[vtobj->type]);
		return -EEXIST;
	}

	list_add_tail(&vtobj->entry, list);
	pthread_mutex_unlock(lock);
	log_debug("vtobj[%p] id:%s, type:%s\n", vtobj, vtobj->id, virtiot_object_string[vtobj->type]);

	return 0;
}

void virtiot_object_del(struct virtiot_object *vtobj)
{
	pthread_mutex_t *lock;

	assert(vtobj->type < virtiot_object_max);
	virtiot_object_init_once();
	lock = &object_list_locks[vtobj->type];
	virtiot_object_init_once();

	pthread_mutex_lock(lock);
	list_del(&vtobj->entry);
	pthread_mutex_unlock(lock);
	log_debug("vtobj[%p] id:%s, type:%s\n", vtobj, vtobj->id, virtiot_object_string[vtobj->type]);
}

struct virtiot_object *virtiot_object_lookup(const char *id, enum virtiot_object_type type)
{
	struct virtiot_object *vtobj;
	struct list_head *list;
	pthread_mutex_t *lock;

	assert(type < virtiot_object_max);
	virtiot_object_init_once();
	list = &object_lists[type];
	lock = &object_list_locks[type];

	pthread_mutex_lock(lock);
	vtobj = virtiot_object_lookup_locked(id, list);
	pthread_mutex_unlock(lock);

	return vtobj;
}

void virtiot_object_iterate(enum virtiot_object_type type, int (*fn)(struct virtiot_object *vtobj, void *opaque), void *opaque)
{
	struct virtiot_object *vtobj;
	struct list_head *list;
	pthread_mutex_t *lock;

	assert(type < virtiot_object_max);
	virtiot_object_init_once();
	list = &object_lists[type];
	lock = &object_list_locks[type];

	pthread_mutex_lock(lock);
	list_for_each_entry(vtobj, list, entry) {
		if (fn(vtobj, opaque)) {
			break;
		}
	}
	pthread_mutex_unlock(lock);
}
