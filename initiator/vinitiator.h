/*
 * Copyright 2023 zhenwei pi
 *
 * Authors:
 *   zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef VIRTIO_INITIATOR_H
#define VIRTIO_INITIATOR_H

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>

#include "queue.h"

#define ASSERT(x)									\
	do {										\
		if (!(x)) {								\
			printf("[%s:%s:%d] [%m] ", __FILE__, __func__, __LINE__);	\
			printf("ASSERT ON: " #x "\n");					\
			exit(0);							\
		}									\
	} while (0)

#define ARRAY_SIZE(x)	(sizeof(x) / sizeof(x[0]))

static inline void vi_set_nonblock(int fd)
{
        int flags = fcntl(fd, F_GETFL, 0);

        ASSERT(!fcntl(fd, F_SETFL, flags | O_NONBLOCK));
}

static inline void vi_add_event(int epollfd, int fd, void *ctx)
{
        struct epoll_event event = {0};

        /* don't add EPOLLOUT by default */
        event.events = EPOLLIN | EPOLLET;
        event.data.ptr = ctx;
        ASSERT(!epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event));
}

static inline void vi_del_event(int epollfd, int fd)
{
        struct epoll_event event = {0};

        ASSERT(!epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, &event));
}

struct vi_device {
	unsigned int id;
	char *name;
	void (*show_config)(struct vi_queue *viq, void *queue);
	int (*read)(struct vi_queue *viq, void *queue, int niov, struct iovec *iovs, off_t offset);
	int (*write)(struct vi_queue *viq, void *queue, int niov, struct iovec *iovs, off_t offset);
	int (*get_serial)(struct vi_queue *viq, void *queue, int niov, struct iovec *iovs);
};

void vi_device_register(struct vi_device *videv);

#endif
