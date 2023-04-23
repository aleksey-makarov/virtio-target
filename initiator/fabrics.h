/*
 * Copyright 2023 zhenwei pi
 *
 * Authors:
 *   zhenwei pi <pizhenwei@bytedance.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#ifndef VIRTIO_INITIATOR_FABRICS_H
#define VIRTIO_INITIATOR_FABRICS_H

#include "virtio_of.h"

void vi_fabric_connect(struct virtio_of_command *vofcmd, struct virtio_of_connect *vofconnect, struct virtio_of_vring_desc *vofdesc, int target_id, int queue_id, char *tvqn, char *ivqn, unsigned char oftype);
void vi_fabric_get_device_id(struct virtio_of_command *vofcmd);
void vi_fabric_get_vendor_id(struct virtio_of_command *vofcmd);
void vi_fabric_get_num_queues(struct virtio_of_command *vofcmd);
void vi_fabric_get_queue_size(struct virtio_of_command *vofcmd, __u16 queue_id);
void vi_fabric_get_config(struct virtio_of_command *vofcmd, __u16 offset, __u8 bytes);
void vi_fabric_vring(struct virtio_of_command *vofcmd, __u16 cmmmand_id, __u32 length, __u16 ndesc);

#endif
