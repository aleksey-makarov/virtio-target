/*
 * Copyright 2023 zhenwei pi
 *
 * Authors:
 *   zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef VIRTIO_TARGET_UTILS_H
#define VIRTIO_TARGET_UTILS_H

#include <assert.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

/* likely & unlikely */
#define likely(x)	__builtin_expect(!!(x), 1)
#define unlikely(x)	__builtin_expect(!!(x), 0)

/* array helpers */
#define ARRAY_SIZE(x)	(sizeof(x) / sizeof(x[0]))

/* page helpers */
#define PAGE_SIZE	4096
#define PAGE_ALIGNED(x)	(!(x & (PAGE_SIZE - 1)))

/* compare helpers */
#define MIN(x,y)	({		\
		typeof(x) _x = (x);	\
		typeof(y) _y = (y);	\
		(void) (&_x == &_y);	\
		_x < _y ? _x : _y; })

#define MAX(x,y)	({		\
		typeof(x) _x = (x);	\
		typeof(y) _y = (y);	\
		(void) (&_x == &_y);	\
		_x > _y ? _x : _y; })

#define MIN_T(type, a, b)	MIN(((type) a), ((type) b))
#define MAX_T(type, a, b)	MAX(((type) a), ((type) b))

/* user should free the returned string if not NULL */
static inline char *virtiot_parse_string(const char *str, const char *needle)
{
	char *s, *e;

	s = strstr(str, needle);
	if (!s) {
		return NULL;
	}

	s += strlen(needle);
	if (*s++ != '=') {
		return NULL;
	}

	e = strchr(s, ',');
	if (!e) {
		e = s + strlen(s);
	}

	return strndup(s, e - s);
}

static inline int virtiot_parse_long(const char *str, const char *needle, long *val)
{
	char *found;

	found = virtiot_parse_string(str, needle);
	if (!found) {
		return -1;
	}

	*val = atol(found);
	free(found);

	return 0;
}

static inline int virtiot_set_nonblock(int fd)
{
	int flags = fcntl(fd, F_GETFL, 0);

	return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}

static inline void virtiot_add_event(int epollfd, int fd, void *ctx)
{
        struct epoll_event event = {0};

	/* don't add EPOLLOUT by default */
        event.events = EPOLLIN | EPOLLET;
        event.data.ptr = ctx;
        assert(!epoll_ctl(epollfd, EPOLL_CTL_ADD, fd, &event));
}

static inline void virtiot_del_event(int epollfd, int fd)
{
        struct epoll_event event = {0};

        assert(!epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, &event));
}

static inline void virtiot_mod_event(int epollfd, int fd, __poll_t events, void *ctx)
{
        struct epoll_event event = {0};

        event.events = events;
        event.data.ptr = ctx;
        assert(!epoll_ctl(epollfd, EPOLL_CTL_MOD, fd, &event));
}

#endif
