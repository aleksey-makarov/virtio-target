#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_blk.h>
#include <linux/virtio_ring.h>

#include "block.h"
#include "device.h"
#include "fabrics.h"
#include "log.h"
#include "utils.h"

#define VIRTIOT_BLK_MAX_SEGS 128

struct virtiot_device_block {
	struct virtiot_device vtdev;
	char serial[VIRTIO_BLK_ID_BYTES];
	struct virtiot_block_driver *driver;
	void *drvctx;
	__u16 num_queues;
};

static struct virtiot_device_block *to_block(struct virtiot_device *vtdev)
{
	return container_of(vtdev, struct virtiot_device_block, vtdev);
}

static int virtiot_block_set_queues(struct virtiot_device *vtdev, __u16 queues)
{
	struct virtiot_device_block *vtblk = to_block(vtdev);
	struct virtio_blk_config *config;

	if (queues > vtblk->num_queues) {
		return -EINVAL;
	}

	config = (struct virtio_blk_config *)vtdev->config;
	vtdev->dev_feature |= (1 << VIRTIO_BLK_F_MQ);
	config->num_queues = htole16(queues);

	return 0;
}

static __u16 virtiot_block_get_queue_size(struct virtiot_device *vtdev, __u16 queue_id)
{
	return VIRTIO_TARGET_VRING_SIZE;
}

static __u16 virtiot_block_get_max_segs(struct virtiot_device *vtdev, __u16 queue_id)
{
	return VIRTIOT_BLK_MAX_SEGS;
}

static __u16 virtiot_block_get_depth(struct virtiot_device *vtdev, __u16 queue_id)
{
	/* header[OUT], data[IN/OUT] ... status[IN] */
	return (virtiot_block_get_queue_size(vtdev, queue_id) + 3 - 1) / 3;
}

static __u16 virtiot_block_get_queues(struct virtiot_device *vtdev)
{
	struct virtiot_device_block *vtblk = to_block(vtdev);

	return vtblk->num_queues;
}

static int virtiot_block_get_id(struct virtiot_device_block *vtblk, struct virtiot_request *vtreq)
{
	struct virtio_of_vring_desc *desc;
	__u8 idx, len;
	__u8 *status;

	/* layout of desc[3]: header[OUT], serial[IN], status[IN] */
	if (vtreq->ndesc != 3) {
		return -EINVAL;
	}

	idx = 1;
	desc = &vtreq->vofdescs[idx];
	len = MAX_T(__u8, le32toh(desc->length), sizeof(vtblk->serial));
	memcpy(vtreq->addr[idx], vtblk->serial, len);
	vtreq->fill_desc(desc, 0, len);

	idx = 2;
	desc = &vtreq->vofdescs[idx];
	status = (__u8 *)vtreq->addr[idx];
	*status = VIRTIO_BLK_S_OK;
	vtreq->fill_desc(desc, len, 1);

	virtiot_fabrics_completion(vtreq->vofcomp, VIRTIO_OF_SUCCESS, le16toh(vtreq->vofcmd->vring.command_id));
	vtreq->vofcomp->ndesc = htole16(2);
	vtreq->vofcomp->value.u32 = htole32(len + 1);
	vtreq->complete(vtreq);

	return 0;
}

static int virtiot_block_handle_vring(struct virtiot_device *vtdev, struct virtiot_request *vtreq)
{
	struct virtiot_device_block *vtblk = to_block(vtdev);
	struct virtiot_block_driver *vtblkdrv = vtblk->driver;
	struct virtio_of_vring_desc *deschdr;
	struct virtio_blk_outhdr *blkhdr;
	__u64 offset;
	__u32 type;
	int ret = -EINVAL;

	if (vtreq->ndesc < 3 || vtreq->ndesc > VIRTIOT_BLK_MAX_SEGS) {
	log_error("command_id 0x%x, ndesc %d, length %d\n", le16toh(vtreq->vofcmd->vring.command_id), vtreq->ndesc, le32toh(vtreq->vofcmd->vring.length));
		goto error;
	}

	deschdr = vtreq->vofdescs;
	if ((le32toh(deschdr->length) != sizeof(*blkhdr)) || (le16toh(deschdr->flags) & VRING_DESC_F_WRITE)) {
		goto error;
	}

	blkhdr = (struct virtio_blk_outhdr *)vtreq->addr[0];
	//log_debug("type 0x%x, ioprio 0x%x, sector 0x%lx\n", le32toh(blkhdr->type), le32toh(blkhdr->ioprio), le64toh(blkhdr->sector));
	type = le32toh(blkhdr->type);
	offset = le64toh(blkhdr->sector) << 9;
	switch (type & ~VIRTIO_BLK_T_BARRIER) {
	case VIRTIO_BLK_T_IN:
		vtblkdrv->read(vtblk->drvctx, offset, vtreq);
		break;

	case VIRTIO_BLK_T_OUT:
		vtblkdrv->write(vtblk->drvctx, offset, vtreq);
		break;

	case VIRTIO_BLK_T_GET_ID:
		ret = virtiot_block_get_id(vtblk, vtreq);
		if (ret) {
			goto error;
		}
		break;

	default:
		assert(0);	//TODO remove
	}

	return 0;

error:
	virtiot_fabrics_completion(vtreq->vofcomp, virtiot_errno_to_status(ret), le16toh(vtreq->vofcmd->common.command_id));
	vtreq->complete(vtreq);

	return ret;
}

static int virtiot_block_init_property(struct virtiot_device_block *vtblk, const char *backend)
{
	char *serial, *queues;

	serial = virtiot_parse_string(backend, "serial");
	if (serial) {
		if (strlen(serial) > VIRTIO_BLK_ID_BYTES) {
			log_error("serial(%s) exceeds VIRTIO_BLK_ID_BYTES(%d)", serial, VIRTIO_BLK_ID_BYTES);
			free(serial);
			return -EINVAL;
		}

		strncpy(vtblk->serial, serial, VIRTIO_BLK_ID_BYTES);
		free(serial);
	}

	vtblk->num_queues = 1;
	queues = virtiot_parse_string(backend, "queues");
	if (queues) {
		vtblk->num_queues = atoi(queues);
		free(serial);
	}

	return 0;
}

static void virtiot_block_init_config(struct virtiot_device_block *vtblk)
{
	struct virtiot_device *vtdev = &vtblk->vtdev;
	struct virtiot_block_driver *vtblkdrv = vtblk->driver;
	struct virtio_blk_config *config;

	vtdev->config = calloc(vtdev->config_size, 1);
	assert(vtdev->config);

	config = (struct virtio_blk_config *)vtdev->config;
	config->capacity = htole64(vtblkdrv->get_capacity(vtblk->drvctx) >> 9);

	vtdev->dev_feature |= (1 << VIRTIO_BLK_F_SIZE_MAX);
	config->size_max = htole32(1024 * 1024);

	vtdev->dev_feature |= (1 << VIRTIO_BLK_F_SEG_MAX);
	config->seg_max = htole32(VIRTIOT_BLK_MAX_SEGS - 2);

	vtdev->dev_feature |= (1 << VIRTIO_BLK_F_MQ);
	config->num_queues = htole16(vtblk->num_queues);
}

static void virtiot_block_destroy(struct virtiot_device *vtdev)
{
	struct virtiot_device_block *vtblk = to_block(vtdev);

	virtiot_object_del(&vtblk->vtdev.vtobj);
	free(vtdev->config);
	free(vtblk);
}

static struct virtiot_device *virtiot_block_create(const char *id, const char *backend)
{
	struct virtiot_device_block *vtblk;
	struct virtiot_device *vtdev;
	struct virtiot_object *vtobj;
	struct virtiot_block_driver *vtblkdrv;

	vtblk = calloc(sizeof(struct virtiot_device_block), 1);
	assert(vtblk);

	if (virtiot_block_init_property(vtblk, backend)) {
		goto free_blk;
	}

	vtdev = &vtblk->vtdev;
	vtdev->vendor_id = VIRTIO_TARGET_VENDOR;
	vtdev->device_id = VIRTIO_ID_BLOCK;
	vtdev->generation = VIRTIO_ID_BLOCK;
	vtdev->config_size = sizeof(struct virtio_blk_config);
	vtdev->destroy = virtiot_block_destroy;
	vtdev->handle_vring = virtiot_block_handle_vring;
	vtdev->set_queues = virtiot_block_set_queues;
	vtdev->get_queues = virtiot_block_get_queues;
	vtdev->get_queue_size = virtiot_block_get_queue_size;
	vtdev->get_max_segs = virtiot_block_get_max_segs;
	vtdev->get_depth = virtiot_block_get_depth;

	vtblkdrv = virtiot_driver_find(backend, struct virtiot_block_driver, vtdrv);
	if (!vtblkdrv) {
		goto free_config;
	}

	vtblk->driver = vtblkdrv;
	vtblk->drvctx = vtblkdrv->open(backend);
	if (!vtblk->drvctx) {
		goto free_config;
	}

	virtiot_block_init_config(vtblk);
	vtobj = &vtblk->vtdev.vtobj;
	vtobj->id = strdup(id);
	vtobj->type = virtiot_object_device;
	virtiot_object_add(vtobj);

	return vtdev;

free_config:
	free(vtdev->config);

free_blk:
	free(vtblk);

	return NULL;
}

static struct virtiot_model virtiot_model_block = {
	.vtobj = {
		.id = "block",
		.type = virtiot_object_model,
	},
	.create = virtiot_block_create,
};

static void __attribute__((constructor)) virtiot_block_init(void)
{
	virtiot_model_register(&virtiot_model_block);
}
