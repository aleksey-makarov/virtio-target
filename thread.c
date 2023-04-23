#include "thread.h"

#include <pthread.h>
#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>

struct virtiot_thread_ctx {
	pthread_t thread;
	unsigned int index;
} __attribute__ ((aligned (64)));

static unsigned int virtiot_thread_nr;
static struct virtiot_thread_ctx *virtiot_threads;

static void virtiot_thread_setname(unsigned int index)
{
	char name[16] = {0};

	snprintf(name, sizeof(name) - 1, "thread-%d", index);
	pthread_setname_np(pthread_self(), name);
}

static void *virtiot_thread_routine(void *arg)
{
	struct virtiot_thread_ctx *vtthd = arg;

	virtiot_thread_setname(vtthd - virtiot_threads);

	while (true)
		sleep(1);

	return NULL;
}

void virtiot_thread_init(int threads)
{
	struct virtiot_thread_ctx *vtthd;
	unsigned int i;

	assert(threads && !virtiot_thread_nr && !virtiot_threads);

	virtiot_thread_nr = threads;
	virtiot_threads = calloc(sizeof(struct virtiot_thread_ctx), threads);

	for (i = 0; i < threads; i++) {
		vtthd = virtiot_threads + i;
		assert(!pthread_create(&vtthd->thread, NULL, virtiot_thread_routine, vtthd));
	}
}
