/*
 * Copyright 2023 zhenwei pi
 *
 * Authors:
 *   zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */
#ifndef VIRTIO_TARGET_LOG_H
#define VIRTIO_TARGET_LOG_H

#include <pthread.h>
#include <stdio.h>
#include <time.h>

#define log_impl(tag, fmt, args...)						\
	do {									\
		time_t t = time(NULL);						\
		char name[17] = {0};						\
		pthread_getname_np(pthread_self(), name, sizeof(name) - 1);	\
		fprintf(stdout, "%16s %24.24s[%s]%s %d " fmt, name, ctime(&t),	\
				tag, __func__, __LINE__, ##args);		\
	} while (0)

#define log_error(fmt, args...)	log_impl("error", fmt, ##args)

#define log_warn(fmt, args...)	log_impl("warn", fmt, ##args)

#ifdef DEBUG
#define log_debug(fmt, args...)	log_impl("debug", fmt, ##args)

#define log_trace()		log_impl("trace", "\n")
#else
#define log_debug(fmt, args...)	do {} while (0)

#define log_trace()		do {} while (0)
#endif

#endif
