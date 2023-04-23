#include <linux/virtio_ids.h>
#include <linux/virtio_ring.h>
#include <stddef.h>
#include <string.h>

#include "vinitiator.h"
#include "fabrics.h"

static int vi_rng_read(struct vi_queue *viq, void *queue, int niov, struct iovec *iovs, off_t offset)
{
	struct virtio_of_command vofcmd;
	struct virtio_of_completion vofcomp;
	struct virtio_of_vring_desc *descs, *desc;
	__u32 length;

	ASSERT(niov == 1);

	descs = calloc(sizeof(struct virtio_of_vring_desc), niov);
	ASSERT(descs);

	desc = &descs[0];
	desc->addr = htole64(0);
	desc->length = htole32(iovs[0].iov_len);
	desc->id = htole16(0);
	desc->flags = htole16(VRING_DESC_F_WRITE);
	length = iovs[0].iov_len;

	vi_fabric_vring(&vofcmd, 0, length, niov);
	ASSERT(viq->send_cmd(queue, &vofcmd, niov, descs, iovs) >= 0);
	ASSERT(viq->recv_comp(queue, &vofcomp, niov, descs, iovs) >= 0);
	ASSERT(le16toh(vofcomp.status) == VIRTIO_OF_SUCCESS);

	free(descs);

	return 0;
}

static struct vi_device vi_rng = {
	.id = VIRTIO_ID_RNG,
	.name = "virtio rng",
	.show_config = NULL,
	.read = vi_rng_read,
	.write = NULL,
	.get_serial = NULL,
};

static void __attribute__((constructor)) vi_rng_init(void)
{
	vi_device_register(&vi_rng);
}
