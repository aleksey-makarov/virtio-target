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
#include <endian.h>
#include <string.h>

#include "types.h"
#include "fabrics.h"
#include "target.h"
#include "transport.h"
#include "log.h"
#include "virtio_of.h"
#include "utils.h"

static struct virtiot_fabrics_code_table
{
	enum virtio_of_opcode opcode;
	const char *string;
} virtiot_fabrics_code_tables[] = {
	{ virtio_of_op_connect, "connect" },
	{ virtio_of_op_discconnect, "disconnect" },
	{ virtio_of_op_keepalive, "keepalive" },
	{ virtio_of_op_get_feature, "get-feature" },
	{ virtio_of_op_set_feature, "set-feature" },
	{ virtio_of_op_get_vendor_id, "get-vendor-id" },
	{ virtio_of_op_get_device_id, "get-device-id" },
	{ virtio_of_op_get_generation, "get-generation" },
	{ virtio_of_op_get_status, "get-status" },
	{ virtio_of_op_set_status, "set-status" },
	{ virtio_of_op_get_device_feature, "get-device-feature" },
	{ virtio_of_op_set_driver_feature, "set-device-feature" },
	{ virtio_of_op_get_num_queues, "get-num-queues" },
	{ virtio_of_op_get_queue_size, "get-queue-size" },
	{ virtio_of_op_set_queue_size, "set-queue-size" },
	{ virtio_of_op_get_config, "get-config" },
	{ virtio_of_op_set_config, "set-config" },
	{ virtio_of_op_get_config_changed, "get-config-changed" },
	{ virtio_of_op_vring, "vring" }
};

static const char *virtiot_fabrics_opcode_string(enum virtio_of_opcode opcode)
{
	int idx;

	for (idx = 0; idx < ARRAY_SIZE(virtiot_fabrics_code_tables); idx++) {
		if (opcode == virtiot_fabrics_code_tables[idx].opcode) {
			return virtiot_fabrics_code_tables[idx].string;
		}
	}

	return "unknown";
}

static void virtiot_fabrics_dump_connect(struct virtio_of_command_connect *connect)
{
	log_debug("CONNECT CMD: opcode 0x%x, target_id 0x%x, queue_id 0x%x, ndesc %d, oftype %d\n", le16toh(connect->opcode), le16toh(connect->target_id), le16toh(connect->queue_id), le16toh(connect->ndesc), connect->oftype);
}

int virtiot_fabrics_ndesc(struct virtio_of_command *vofcmd)
{
	struct virtio_of_command_connect *connect;
	struct virtio_of_command_vring *vring;
	int opcode = le16toh(vofcmd->common.opcode);

//log_debug("handle opcode %s\n", virtiot_fabrics_opcode_string(opcode));
	switch (opcode) {
	case virtio_of_op_connect:
		connect = &vofcmd->connect;
		if (le16toh(connect->ndesc) != 1) {
			virtiot_fabrics_dump_connect(connect);
			return -EPROTO;
		}
		return 1;

	case virtio_of_op_discconnect:
	case virtio_of_op_get_vendor_id:
	case virtio_of_op_get_device_id:
	case virtio_of_op_get_generation:
	case virtio_of_op_get_status:
	case virtio_of_op_set_status:
	case virtio_of_op_get_device_feature:
	case virtio_of_op_set_driver_feature:
	case virtio_of_op_get_num_queues:
	case virtio_of_op_get_queue_size:
	case virtio_of_op_set_queue_size:
	case virtio_of_op_get_config:
	case virtio_of_op_set_config:
	case virtio_of_op_get_config_changed:
		return 0;

	case virtio_of_op_vring:
		vring = &vofcmd->vring;
		return le16toh(vring->ndesc);

	default:
		log_error("unknown opcode[0x%x]\n", opcode);
		return -EPROTO;
	}
}

static int virtiot_fabrics_connect(struct virtiot_request *vtreq)
{
	struct virtio_of_command_connect *connect = &vtreq->vofcmd->connect;
	struct virtio_of_completion *comp = vtreq->vofcomp;
	struct virtio_of_vring_desc *desc;
	struct virtio_of_connect *connctbody;
	struct virtiot_target *vtgt, *new;
	__u16 command_id, target_id, queue_id;
	__u16 num_queues = 1;
	int ret;

	if (connect->oftype != vtreq->vtq->transport->oftype) {
		ret = virtiot_fabrics_completion(comp, VIRTIO_OF_EPROTO, 0);
		goto out;
	}

	if (vtreq->ndesc != 1) {
		ret = virtiot_fabrics_completion(comp, VIRTIO_OF_EPROTO, 0);
		goto out;
	}

	desc = vtreq->vofdescs;
	if (le32toh(desc->length) != sizeof(*connctbody)) {
		ret = virtiot_fabrics_completion(comp, VIRTIO_OF_EPROTO, 0);
		goto out;
	}

	command_id = le16toh(connect->command_id);
	target_id = le16toh(connect->target_id);
	queue_id = le32toh(connect->queue_id);
	connctbody = (struct virtio_of_connect*)vtreq->addr[0];
	//log_debug("target_id 0x%x, queue_id %d\n", target_id, queue_id);

	if (target_id == 0xffff) {
		vtgt = virtiot_target_lookup_by_tvqn((const char *)connctbody->tvqn);
		if (!vtgt) {
			log_error("no tvqn[%s]\n", (const char *)connctbody->tvqn);
			ret = virtiot_fabrics_completion(comp, VIRTIO_OF_ENODEV, 0);
			goto out;
		}

		new = virtiot_target_established(vtgt);
		if (!new) {
			log_error("no tvqn[%s]\n", (const char *)connctbody->tvqn);
			comp->status = htole16(VIRTIO_OF_ENOMEM);
			ret = virtiot_fabrics_completion(comp, VIRTIO_OF_EPROTO, 0);
			goto out;
		}

		new->ivqn = strndup((const char *)connctbody->ivqn, sizeof(connctbody->ivqn));
		assert(!vtreq->vtq->vtgt);
		vtreq->vtq->vtgt = new;
		new->vtctrlq = vtreq->vtq;
		log_debug("established target_id[%d]: initiator[%s] <-> target[%s]\n", new->target_id, new->ivqn, new->tvqn);
		ret = virtiot_fabrics_completion(comp, VIRTIO_OF_SUCCESS, command_id);
		comp->value.u16 = htole16(new->target_id);
		goto out;
	} else {
		vtgt = virtiot_target_lookup_by_index(target_id);
		if (!vtgt) {
			log_error("no tvqn[%s]\n", (const char *)connctbody->tvqn);
			ret = virtiot_fabrics_completion(comp, VIRTIO_OF_ENODEV, 0);
			goto out;
		}

		if (strcmp(vtgt->tvqn, (const char *)connctbody->tvqn)) {
			log_error("target[%d] has tvqn[%s], mismatched [%s]\n",
					target_id, vtgt->tvqn, (const char *)connctbody->tvqn);
			ret = virtiot_fabrics_completion(comp, VIRTIO_OF_EPROTO, 0);
			goto out;
		}

		if (strcmp(vtgt->ivqn, (const char *)connctbody->ivqn)) {
			log_error("target[%d] has ivqn[%s], mismatched [%s]\n",
					target_id, vtgt->ivqn, (const char *)connctbody->ivqn);
			ret = virtiot_fabrics_completion(comp, VIRTIO_OF_EPROTO, 0);
			goto out;
		}

		if (vtgt->vtdev->get_queues) {
			num_queues = vtgt->vtdev->get_queues(vtgt->vtdev);
		}

		if (queue_id >= num_queues) {
			log_error("target[%d] has %d queues, but queue_id[%d]\n",
					target_id, num_queues, queue_id);
			ret = virtiot_fabrics_completion(comp, VIRTIO_OF_ECHRNG, 0);
			goto out;
		}

		if (vtgt->vtqueues[queue_id]) {
			log_error("target[%d] queue[%d] already in use\n",
					target_id, queue_id);
			ret = virtiot_fabrics_completion(comp, VIRTIO_OF_EBUSY, 0);
			goto out;
		}

		virtiot_target_map_queue(vtgt, vtreq->vtq, queue_id);
		log_debug("target_id[%d]: queue id[%d], initiator[%s] <-> target[%s] established\n",
				vtgt->target_id, queue_id, vtgt->ivqn, vtgt->tvqn);
		ret = virtiot_fabrics_completion(comp, VIRTIO_OF_SUCCESS, command_id);
	}

out:
	return ret;
}

static int virtiot_fabrics_get_vendor_id(struct virtiot_request *vtreq)
{
	struct virtio_of_command_common *common = &vtreq->vofcmd->common;
	struct virtio_of_completion *comp = vtreq->vofcomp;

	assert(vtreq->vtq->vtgt);
	virtiot_fabrics_completion(comp, VIRTIO_OF_SUCCESS, le16toh(common->command_id));
	comp->value.u32 = htole32(vtreq->vtq->vtgt->vtdev->vendor_id);

	return 0;
}

static int virtiot_fabrics_get_device_id(struct virtiot_request *vtreq)
{
	struct virtio_of_command_common *common = &vtreq->vofcmd->common;
	struct virtio_of_completion *comp = vtreq->vofcomp;

	assert(vtreq->vtq->vtgt);
	virtiot_fabrics_completion(comp, VIRTIO_OF_SUCCESS, le16toh(common->command_id));
	comp->value.u32 = htole32(vtreq->vtq->vtgt->vtdev->device_id);

	return 0;
}

static int virtiot_fabrics_get_generation(struct virtiot_request *vtreq)
{
	struct virtio_of_command_common *common = &vtreq->vofcmd->common;
	struct virtio_of_completion *comp = vtreq->vofcomp;

	assert(vtreq->vtq->vtgt);
	virtiot_fabrics_completion(comp, VIRTIO_OF_SUCCESS, le16toh(common->command_id));
	comp->value.u32 = htole32(vtreq->vtq->vtgt->vtdev->generation);

	return 0;
}

static int virtiot_fabrics_get_num_queues(struct virtiot_request *vtreq)
{
	struct virtio_of_command_common *common = &vtreq->vofcmd->common;
	struct virtio_of_completion *comp = vtreq->vofcomp;
	struct virtiot_device *vtdev;
	__u16 num_queues = 1;

	assert(vtreq->vtq->vtgt);
	vtdev = vtreq->vtq->vtgt->vtdev;
	if (vtdev->get_queues) {
		num_queues = vtdev->get_queues(vtdev);
	}

	virtiot_fabrics_completion(comp, VIRTIO_OF_SUCCESS, le16toh(common->command_id));
	comp->value.u16 = htole16(num_queues);

	return 0;
}

static int virtiot_fabrics_get_queue_size(struct virtiot_request *vtreq)
{
	struct virtio_of_command_queue *queue = &vtreq->vofcmd->queue;
	struct virtio_of_completion *comp = vtreq->vofcomp;
	struct virtiot_device *vtdev;
	__u16 command_id = le16toh(queue->command_id);
	__u16 queue_id = le16toh(queue->queue_id);
	__u16 queue_size = VIRTIO_TARGET_VRING_SIZE;

	assert(vtreq->vtq->vtgt);
	vtdev = vtreq->vtq->vtgt->vtdev;
	if (vtdev->get_queue_size) {
		queue_size = vtdev->get_queue_size(vtdev, queue_id);
	}
	virtiot_fabrics_completion(comp, VIRTIO_OF_SUCCESS, command_id);
	comp->value.u16 = htole16(queue_size);

	return 0;
}

static int virtiot_fabrics_get_config(struct virtiot_request *vtreq)
{
	struct virtio_of_command_config *config = &vtreq->vofcmd->config;
	struct virtio_of_completion *comp = vtreq->vofcomp;
	unsigned char *src, *dst;
	__u16 offset;
	__u8 bytes;

	assert(vtreq->vtq->vtgt);

	offset = le16toh(config->offset);
	bytes = config->bytes;
	if (offset + bytes > vtreq->vtq->vtgt->vtdev->config_size) {
		goto error;
	}

	src = vtreq->vtq->vtgt->vtdev->config + offset;
	switch (bytes) {
	case 1:
		dst = &comp->value.u8;
		break;
	case 2:
		dst = (unsigned char *)&comp->value.u16;
		break;
	case 4:
		dst = (unsigned char *)&comp->value.u32;
		break;
	case 8:
		dst = (unsigned char *)&comp->value.u64;
		break;
	default:
		goto error;
	}
	virtiot_fabrics_completion(comp, VIRTIO_OF_SUCCESS, le16toh(config->command_id));
	memcpy(dst, src, bytes);

	return 0;

error:
	virtiot_fabrics_completion(comp, VIRTIO_OF_EINVAL, le16toh(config->command_id));
	return -EINVAL;
}

static int virtiot_fabrics_get_status(struct virtiot_request *vtreq)
{
	struct virtio_of_command_status *status = &vtreq->vofcmd->status;
	struct virtio_of_completion *comp = vtreq->vofcomp;

	assert(vtreq->vtq->vtgt);
	virtiot_fabrics_completion(comp, VIRTIO_OF_SUCCESS, le16toh(status->command_id));
	comp->value.u32 = htole32(vtreq->vtq->vtgt->vtdev->status);

	return 0;
}

static int virtiot_fabrics_get_device_feature(struct virtiot_request *vtreq)
{
	struct virtio_of_command_feature *feature = &vtreq->vofcmd->feature;
	struct virtio_of_completion *comp = vtreq->vofcomp;
	__u32 feature_select;

	assert(vtreq->vtq->vtgt);
	/* currently we have only 1 feature(in 64 bytes) */
	feature_select = le32toh(feature->feature_select);
	if (feature_select) {
		return virtiot_fabrics_completion(comp, VIRTIO_OF_EINVAL, le16toh(feature->command_id));
	}

	virtiot_fabrics_completion(comp, VIRTIO_OF_SUCCESS, le16toh(feature->command_id));
	comp->value.u64 = htole64(vtreq->vtq->vtgt->vtdev->dev_feature);

	return 0;
}


static int virtiot_fabrics_set_driver_feature(struct virtiot_request *vtreq)
{
	struct virtio_of_command_feature *feature = &vtreq->vofcmd->feature;
	struct virtio_of_completion *comp = vtreq->vofcomp;
	__u32 feature_select;

	assert(vtreq->vtq->vtgt);
	/* currently we have only 1 feature(in 64 bytes) */
	feature_select = le32toh(feature->feature_select);
	if (feature_select) {
		return virtiot_fabrics_completion(comp, VIRTIO_OF_EINVAL, le16toh(feature->command_id));
	}

	virtiot_fabrics_completion(comp, VIRTIO_OF_SUCCESS, le16toh(feature->command_id));
	//TODO comp->value.u64 = htole64(vtreq->vtq->vtgt->vtdev->dev_feature);

	return 0;
}

static int virtiot_fabrics_set_status(struct virtiot_request *vtreq)
{
	struct virtio_of_command_status *status = &vtreq->vofcmd->status;
	struct virtio_of_completion *comp = vtreq->vofcomp;

	assert(vtreq->vtq->vtgt);
	//TODO really set status on device
	vtreq->vtq->vtgt->vtdev->status = le32toh(status->status);
	virtiot_fabrics_completion(comp, VIRTIO_OF_SUCCESS, le16toh(status->command_id));

	return 0;
}

static int virtiot_fabrics_vring(struct virtiot_request *vtreq)
{
	assert(vtreq->vtq->vtgt);
	return vtreq->vtq->vtgt->vtdev->handle_vring(vtreq->vtq->vtgt->vtdev, vtreq);
}

static int __virtiot_fabrics_handle_command(struct virtiot_request *vtreq)
{
	__u16 opcode = le16toh(vtreq->vofcmd->common.opcode);

	//log_debug("handle opcode %s\n", virtiot_fabrics_opcode_string(opcode));
	switch (opcode) {
	case virtio_of_op_connect:
		return virtiot_fabrics_connect(vtreq);
	case virtio_of_op_get_vendor_id:
		return virtiot_fabrics_get_vendor_id(vtreq);
	case virtio_of_op_get_device_id:
		return virtiot_fabrics_get_device_id(vtreq);
	case virtio_of_op_get_generation:
		return virtiot_fabrics_get_generation(vtreq);
	case virtio_of_op_get_status:
		return virtiot_fabrics_get_status(vtreq);
	case virtio_of_op_set_status:
		return virtiot_fabrics_set_status(vtreq);
	case virtio_of_op_get_device_feature:
		return virtiot_fabrics_get_device_feature(vtreq);
	case virtio_of_op_set_driver_feature:
		return virtiot_fabrics_set_driver_feature(vtreq);
	case virtio_of_op_get_num_queues:
		return virtiot_fabrics_get_num_queues(vtreq);
	case virtio_of_op_get_queue_size:
		return virtiot_fabrics_get_queue_size(vtreq);
	case virtio_of_op_get_config:
		return virtiot_fabrics_get_config(vtreq);
	case virtio_of_op_vring:
		return virtiot_fabrics_vring(vtreq);
	default:
		log_warn("unknown opcode 0x%x\n", opcode);
	};

	return -EINVAL;
}

int virtiot_fabrics_handle_command(struct virtiot_request *vtreq)
{
	int ret = __virtiot_fabrics_handle_command(vtreq);

	/* control commands complete synchronously, vring command get completed by driver */
	if (!virtiot_fabrics_is_vring(vtreq->vofcmd))
		vtreq->complete(vtreq);

	return ret;
}
