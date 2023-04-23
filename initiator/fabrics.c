#include <endian.h>
#include <string.h>

#include "fabrics.h"

void vi_fabric_connect(struct virtio_of_command *vofcmd, struct virtio_of_connect *vofconnect, struct virtio_of_vring_desc *vofdesc, int target_id, int queue_id, char *tvqn, char *ivqn, unsigned char oftype)
{
	struct virtio_of_command_connect *connectcmd = &vofcmd->connect;

	/* 1, command */
	connectcmd->opcode = htole16(virtio_of_op_connect);
	connectcmd->target_id = htole16(target_id);
	connectcmd->queue_id = queue_id;
	connectcmd->ndesc = htole16(1);
	connectcmd->oftype = oftype;

	/* 2, a single desc */
	vofdesc->addr = htole64(0);
	vofdesc->length = htole32(sizeof(*vofconnect));
	vofdesc->id = htole16(0);
	vofdesc->flags = htole16(0);

	/* 3, connect command body */
	strncpy((char *)vofconnect->ivqn, ivqn, sizeof(vofconnect->ivqn));
	strncpy((char *)vofconnect->tvqn, tvqn, sizeof(vofconnect->tvqn));
}

/* for debug purpose, use a magic number for control command id */
static inline __u16 vi_fabric_command_id(__u16 opcode)
{
	return htole16(0xffff - opcode);
}

static void vi_fabric_get_common(struct virtio_of_command *vofcmd, __u16 opcode)
{
	struct virtio_of_command_common *commoncmd = &vofcmd->common;

	commoncmd->opcode = htole16(opcode);
	commoncmd->command_id = vi_fabric_command_id(opcode);
}

void vi_fabric_get_device_id(struct virtio_of_command *vofcmd)
{
	vi_fabric_get_common(vofcmd, virtio_of_op_get_device_id);
}

void vi_fabric_get_vendor_id(struct virtio_of_command *vofcmd)
{
	vi_fabric_get_common(vofcmd, virtio_of_op_get_vendor_id);
}

void vi_fabric_get_num_queues(struct virtio_of_command *vofcmd)
{
	vi_fabric_get_common(vofcmd, virtio_of_op_get_num_queues);
}

void vi_fabric_get_queue_size(struct virtio_of_command *vofcmd, __u16 queue_id)
{
	struct virtio_of_command_queue *queuecmd = &vofcmd->queue;

	queuecmd->opcode = htole16(virtio_of_op_get_queue_size);
	queuecmd->command_id = vi_fabric_command_id(virtio_of_op_get_queue_size);
	queuecmd->queue_id = htole16(queue_id);
}

void vi_fabric_get_config(struct virtio_of_command *vofcmd, __u16 offset, __u8 bytes)
{
        struct virtio_of_command_config *configcmd = &vofcmd->config;

        configcmd->opcode = htole16(virtio_of_op_get_config);
        configcmd->command_id = htole16(0xffff - virtio_of_op_get_config);
        configcmd->offset = htole16(offset);
        configcmd->bytes = bytes;
}

void vi_fabric_vring(struct virtio_of_command *vofcmd, __u16 command_id, __u32 length, __u16 ndesc)
{
	struct virtio_of_command_vring *vringcmd = &vofcmd->vring;

	vringcmd->opcode = htole16(virtio_of_op_vring);
	vringcmd->command_id = htole16(command_id);
	vringcmd->length = htole16(length);
	vringcmd->ndesc = htole16(ndesc);
}
