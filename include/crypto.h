/*
 * Copyright 2023 zhenwei pi
 *
 * Authors:
 *   zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef VIRTIO_TARGET_CRYPTO_H
#define VIRTIO_TARGET_CRYPTO_H

#include "driver.h"
#include "transport.h"
#include "virtio_crypto.h"

struct virtiot_crypto_driver {
	struct virtiot_driver vtdrv;

	void *(*open)(const char *backend);
	void (*close)(void *context);
	/* ret >= 0 on success(session id), ret < 0 on failure */
	int (*create_session)(void *context, struct virtio_crypto_akcipher_create_session_req *req, void *key, __u32 keylen);
	int (*destroy_session)(void *context, __u64 id);
	int (*ak_encrypt)(void *context, __u64 id, const void *in, size_t src_len, void *out, size_t dst_len);
	int (*ak_decrypt)(void *context, __u64 id, const void *in, size_t src_len, void *out, size_t dst_len);
	int (*ak_sign)(void *context, __u64 id, const void *in, size_t src_len, void *out, size_t dst_len);
	int (*ak_verify)(void *context, __u64 id, const void *in1, size_t src_len1, void *in2, size_t src_len2);
};

#endif
