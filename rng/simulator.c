#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/virtio_ids.h>
#include <sys/uio.h>

#include "rng.h"
#include "device.h"
#include "fabrics.h"
#include "utils.h"
#include "log.h"

struct virtiot_rng_simulator_context {
	unsigned char idx;
};

static void *virtiot_rng_simulator_open(const char *backend)
{
	struct virtiot_rng_simulator_context *ctx;

	ctx = calloc(sizeof(struct virtiot_rng_simulator_context), 1);
	assert(ctx);

	return ctx;
}

static void virtiot_rng_simulator_close(void *context)
{
	free(context);
}

static int virtiot_rng_simulator_read(void *context, struct virtiot_request *vtreq)
{
	struct virtiot_rng_simulator_context *ctx = context;
	struct virtio_of_vring_desc *desc;
	char *addr;
	__u32 length, i;

	desc = vtreq->vofdescs;
	length = le32toh(desc->length);
	addr = (char *)vtreq->addr[0];

	for (i = 0; i < length; i++) {
		addr[i] = 'A' + ctx->idx % 26;
		ctx->idx++;
	}
	vtreq->fill_desc(desc, 0, length);

	virtiot_fabrics_completion(vtreq->vofcomp, VIRTIO_OF_SUCCESS, le16toh(vtreq->vofcmd->vring.command_id));
	vtreq->vofcomp->ndesc = htole16(1);
	vtreq->vofcomp->value.u32 = htole32(length);
	vtreq->complete(vtreq);

	return 0;
}

static struct virtiot_rng_driver virtiot_rng_simulator = {
	.vtdrv = {
		.vtobj = {
			.id = "rng-simulator",
			.type = virtiot_object_driver,
		},
	},
	.open = virtiot_rng_simulator_open,
	.close = virtiot_rng_simulator_close,
	.read = virtiot_rng_simulator_read,
};

static void __attribute__((constructor)) virtiot_be_rng_init(void)
{
	virtiot_driver_register(&virtiot_rng_simulator.vtdrv);
}
