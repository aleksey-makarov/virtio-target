#include <linux/virtio_ids.h>
#include <linux/virtio_blk.h>
#include <linux/virtio_ring.h>
#include <stddef.h>
#include <string.h>

#include "vinitiator.h"
#include "fabrics.h"

static void vi_block_show_config(struct vi_queue *viq, void *queue)
{
	struct virtio_blk_config blkconf = { 0 };

	blkconf.capacity = vi_queue_get_config(viq, queue, offsetof(struct virtio_blk_config, capacity), sizeof(blkconf.capacity));
	blkconf.size_max = vi_queue_get_config(viq, queue, offsetof(struct virtio_blk_config, size_max), sizeof(blkconf.size_max));
	blkconf.seg_max = vi_queue_get_config(viq, queue, offsetof(struct virtio_blk_config, seg_max), sizeof(blkconf.seg_max));
	blkconf.num_queues = vi_queue_get_config(viq, queue, offsetof(struct virtio_blk_config, num_queues), sizeof(blkconf.num_queues));

	printf("Block Config:\n");
	printf("\tcapacity: %lld\n", blkconf.capacity << 9);
	printf("\tsize_max: %d\n", blkconf.size_max);
	printf("\tseg_max: %d\n", blkconf.seg_max);
	printf("\tnum_queues: %d\n", blkconf.num_queues);
}

static int vi_block_get_serial(struct vi_queue *viq, void *queue, int niov, struct iovec *_iovs)
{
	struct virtio_of_command vofcmd;
	struct virtio_of_completion vofcomp;
	struct virtio_of_vring_desc *descs, *desc;
	struct virtio_blk_outhdr blkhdr;
	struct iovec *iovs;
	__u32 length;
	int i;
	__u8 status;

	ASSERT(niov == 1);
	iovs = calloc(sizeof(struct iovec), niov + 2);
	ASSERT(iovs);

	descs = calloc(sizeof(struct virtio_of_vring_desc), niov + 2);
	ASSERT(descs);

	/* virtio blk get serial: HDR[OUT], Data[IN], Status[IN] */
	blkhdr.type = htole32(VIRTIO_BLK_T_GET_ID);
	blkhdr.ioprio = htole32(0);
	blkhdr.sector = htole64(0);
	iovs[0].iov_base = &blkhdr;
	iovs[0].iov_len = sizeof(struct virtio_blk_outhdr);
	desc = &descs[0];
	desc->addr = htole64(0);
	desc->length = htole32(sizeof(blkhdr));
	desc->id = htole16(0);
	desc->flags = htole16(VRING_DESC_F_NEXT);
	length = iovs[0].iov_len;

	memcpy(iovs + 1, _iovs, sizeof(struct iovec) * niov);
	for (i = 0; i < niov; i++) {
		desc = &descs[i + 1];
		desc->addr = htole64(0);
		desc->length = htole32(_iovs[i].iov_len);
		desc->id = htole16(i + 1);
		desc->flags = htole16(VRING_DESC_F_NEXT | VRING_DESC_F_WRITE);
	}

	iovs[1 + niov].iov_base = &status;
	iovs[1 + niov].iov_len = sizeof(status);
        desc = &descs[1 + niov];
        desc->addr = htole64(0);
        desc->length = htole32(sizeof(status));
        desc->id = htole16(1 + niov);
        desc->flags = htole16(VRING_DESC_F_WRITE);

	vi_fabric_vring(&vofcmd, 0, length, niov + 2);
	ASSERT(viq->send_cmd(queue, &vofcmd, niov + 2, descs, iovs) >= 0);
	ASSERT(viq->recv_comp(queue, &vofcomp, niov + 2, descs, iovs) >= 0);
	ASSERT(le16toh(vofcomp.status) == VIRTIO_OF_SUCCESS);

	free(iovs);
	free(descs);

	return 0;
}

static int vi_block_read(struct vi_queue *viq, void *queue, int niov, struct iovec *_iovs, off_t offset)
{
	struct virtio_of_command vofcmd;
	struct virtio_of_completion vofcomp;
	struct virtio_of_vring_desc *descs, *desc;
	struct virtio_blk_outhdr blkhdr;
	struct iovec *iovs;
	__u32 length;
	__u32 seg_max;
	int i;
	__u8 status;

	seg_max = vi_queue_get_config(viq, queue, offsetof(struct virtio_blk_config, seg_max), sizeof(seg_max));
	ASSERT(niov <= seg_max);
	iovs = calloc(sizeof(struct iovec), niov + 2);
	ASSERT(iovs);

	descs = calloc(sizeof(struct virtio_of_vring_desc), niov + 2);
	ASSERT(descs);

	/* virtio blk read: HDR[OUT], Data[IN] ... Data[IN], Status[IN] */
	blkhdr.type = htole32(VIRTIO_BLK_T_IN);
	blkhdr.ioprio = htole32(0);
	blkhdr.sector = htole64(offset >> 9);
	iovs[0].iov_base = &blkhdr;
	iovs[0].iov_len = sizeof(struct virtio_blk_outhdr);
	desc = &descs[0];
	desc->addr = htole64(0);
	desc->length = htole32(sizeof(blkhdr));
	desc->id = htole16(0);
	desc->flags = htole16(VRING_DESC_F_NEXT);
	length = iovs[0].iov_len;

	memcpy(iovs + 1, _iovs, sizeof(struct iovec) * niov);
	for (i = 0; i < niov; i++) {
		desc = &descs[i + 1];
		desc->addr = htole64(0);
		desc->length = htole32(_iovs[i].iov_len);
		desc->id = htole16(i + 1);
		desc->flags = htole16(VRING_DESC_F_NEXT | VRING_DESC_F_WRITE);
	}

	iovs[1 + niov].iov_base = &status;
	iovs[1 + niov].iov_len = sizeof(status);
        desc = &descs[1 + niov];
        desc->addr = htole64(0);
        desc->length = htole32(sizeof(status));
        desc->id = htole16(1 + niov);
        desc->flags = htole16(VRING_DESC_F_WRITE);

	vi_fabric_vring(&vofcmd, 0, length, niov + 2);
	ASSERT(viq->send_cmd(queue, &vofcmd, niov + 2, descs, iovs) >= 0);
	ASSERT(viq->recv_comp(queue, &vofcomp, niov + 2, descs, iovs) >= 0);
	ASSERT(le16toh(vofcomp.status) == VIRTIO_OF_SUCCESS);

	free(iovs);
	free(descs);

	return 0;
}

static int vi_block_write(struct vi_queue *viq, void *queue, int niov, struct iovec *_iovs, off_t offset)
{
	struct virtio_of_command vofcmd;
	struct virtio_of_completion vofcomp;
	struct virtio_of_vring_desc *descs, *desc;
	struct virtio_blk_outhdr blkhdr;
	struct iovec *iovs;
	__u32 length;
	__u32 seg_max;
	int i;
	__u8 status;

	seg_max = vi_queue_get_config(viq, queue, offsetof(struct virtio_blk_config, seg_max), sizeof(seg_max));
	ASSERT(niov <= seg_max);
	iovs = calloc(sizeof(struct iovec), niov + 2);
	ASSERT(iovs);

	descs = calloc(sizeof(struct virtio_of_vring_desc), niov + 2);
	ASSERT(descs);

	/* virtio blk write: HDR[OUT], Data[OUT] ... Data[OUT], Status[IN] */
	blkhdr.type = htole32(VIRTIO_BLK_T_OUT);
	blkhdr.ioprio = htole32(0);
	blkhdr.sector = htole64(offset >> 9);
	iovs[0].iov_base = &blkhdr;
	iovs[0].iov_len = sizeof(struct virtio_blk_outhdr);
	desc = &descs[0];
	desc->addr = htole64(0);
	desc->length = htole32(sizeof(blkhdr));
	desc->id = htole16(0);
	desc->flags = htole16(VRING_DESC_F_NEXT);
	length = iovs[0].iov_len;

	memcpy(iovs + 1, _iovs, sizeof(struct iovec) * niov);
	for (i = 0; i < niov; i++) {
		desc = &descs[i + 1];
		desc->addr = htole64(length);
		desc->length = htole32(_iovs[i].iov_len);
		desc->id = htole16(i + 1);
		desc->flags = htole16(VRING_DESC_F_NEXT);
		length += _iovs[i].iov_len;
	}

	iovs[1 + niov].iov_base = &status;
	iovs[1 + niov].iov_len = sizeof(status);
        desc = &descs[1 + niov];
        desc->addr = htole64(0);
        desc->length = htole32(sizeof(status));
        desc->id = htole16(1 + niov);
        desc->flags = htole16(VRING_DESC_F_WRITE);

	vi_fabric_vring(&vofcmd, 0, length, niov + 2);
	ASSERT(viq->send_cmd(queue, &vofcmd, niov + 2, descs, iovs) >= 0);
	ASSERT(viq->recv_comp(queue, &vofcomp, niov + 2, descs, iovs) >= 0);
	ASSERT(le16toh(vofcomp.status) == VIRTIO_OF_SUCCESS);

	free(iovs);
	free(descs);

	return 0;
}

static struct vi_device vi_block = {
	.id = VIRTIO_ID_BLOCK,
	.name = "virtio block",
	.show_config = vi_block_show_config,
	.read = vi_block_read,
	.write = vi_block_write,
	.get_serial = vi_block_get_serial,
};

static void __attribute__((constructor)) vi_block_init(void)
{
	vi_device_register(&vi_block);
}
