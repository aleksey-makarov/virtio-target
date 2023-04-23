/*
 * Copyright 2023 zhenwei pi
 *
 * Authors:
 *   zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef VIRTIO_TARGET_FABRICS_H
#define VIRTIO_TARGET_FABRICS_H

#include <string.h>

#include "transport.h"

static inline bool virtiot_fabrics_is_vring(struct virtio_of_command *vofcmd)
{
	__u16 opcode = le16toh(vofcmd->common.opcode);

	if (opcode == virtio_of_op_vring) {
		return true;
	}

	return false;
}

static inline int virtiot_status_to_errno(__u16 status)
{
	if (status < VIRTIO_OF_EQUIRK)
		return -status;

	return -VIRTIO_OF_EQUIRK;
}

static inline __u16 virtiot_errno_to_status(int err)
{
	return err < 0 ? -err: err;
}

static inline int virtiot_fabrics_completion(struct virtio_of_completion *vofcomp, __u16 status, __u16 command_id)
{
	memset(vofcomp, 0x00, sizeof(struct virtio_of_completion));
	vofcomp->status = htole16(status);
	vofcomp->command_id = htole16(command_id);

	return virtiot_status_to_errno(status);
}

int virtiot_fabrics_handle_command(struct virtiot_request *vtreq);
int virtiot_fabrics_ndesc(struct virtio_of_command *vofcmd);

#endif
