/*
 * Copyright 2023 zhenwei pi
 *
 * Authors:
 *   zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef VIRTIO_TARGET_TYPES_H
#define VIRTIO_TARGET_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <bits/types.h>
#include <linux/types.h>
#include <errno.h>

/* NULL */
#ifndef NULL
#define NULL    ((void *)0)
#endif

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#ifndef container_of
#define container_of(ptr, type, member) ({			\
		const typeof(((type *)0)->member) * __mptr = (ptr);	\
		(type *)((char *)__mptr - offsetof(type, member)); })
#endif

#endif
