#include <assert.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_blk.h>
#include <sys/uio.h>

#include "block.h"
#include "device.h"
#include "fabrics.h"
#include "utils.h"
#include "log.h"

struct virtiot_block_posix_context {
	char *path;
	int fd;
};

static void *virtiot_block_posix_open(const char *backend)
{
	struct virtiot_block_posix_context *ctx;

	ctx = calloc(sizeof(struct virtiot_block_posix_context), 1);
	assert(ctx);

	ctx->path = virtiot_parse_string(backend, "path");
	if (!ctx->path) {
		log_error("missing path argument");
		goto free_ctx;
	}

	ctx->fd = open(ctx->path, O_RDWR | O_DSYNC);
	if (ctx->fd == -1) {
		log_error("open [%s] failed: %m\n", ctx->path);
		goto free_ctx;
	}

	log_debug("open %s, fd %d\n", ctx->path, ctx->fd);

	return ctx;

free_ctx:
	free(ctx->path);
	free(ctx);

	return NULL;
}

static void virtiot_block_posix_close(void *context)
{
	struct virtiot_block_posix_context *ctx = context;

	close(ctx->fd);
	free(ctx->path);
	free(ctx);
}

static __u64 virtiot_block_posix_get_capacity(void *context)
{
	struct virtiot_block_posix_context *ctx = context;
	struct stat st = {0};

	assert(!fstat(ctx->fd, &st));
	return st.st_size;
}

static int virtiot_block_posix_read(void *context, off_t offset, struct virtiot_request *vtreq)
{
	struct virtiot_block_posix_context *ctx = context;
	struct virtio_of_vring_desc *desc;
	struct iovec *iovs, *iov;
	__u8 *status;
	__u64 total = 0;
	int i;

	iovs = calloc(sizeof(struct iovec), vtreq->ndesc - 2);

	for (i = 0; i < vtreq->ndesc - 2; i++) {
		desc = vtreq->vofdescs + i + 1;
		iov = iovs + i;
		iov->iov_base = vtreq->addr[i + 1];
		iov->iov_len = le32toh(desc->length);
		vtreq->fill_desc(desc, total, desc->length);
		total += iov->iov_len;
	}

	if (preadv(ctx->fd, iovs, vtreq->ndesc - 2, offset) < 0) {
		log_error("preadv failed: %m\n");
	}
	free(iovs);

	status = (__u8 *)vtreq->addr[vtreq->ndesc - 1];
	*status = VIRTIO_BLK_S_OK;
	desc = vtreq->vofdescs + vtreq->ndesc - 1;
	vtreq->fill_desc(desc, total, 1);

	virtiot_fabrics_completion(vtreq->vofcomp, VIRTIO_OF_SUCCESS, le16toh(vtreq->vofcmd->vring.command_id));
	vtreq->vofcomp->ndesc = htole16(vtreq->ndesc - 1);
	vtreq->vofcomp->value.u32 = htole32(total + 1);
	vtreq->complete(vtreq);

	return 0;
}

static int virtiot_block_posix_write(void *context, off_t offset, struct virtiot_request *vtreq)
{
	struct virtiot_block_posix_context *ctx = context;
	struct virtio_of_vring_desc *desc;
	struct iovec *iovs, *iov;
	__u8 *status;
	int i;

	iovs = calloc(sizeof(struct iovec), vtreq->ndesc - 2);

	for (i = 0; i < vtreq->ndesc - 2; i++) {
		desc = vtreq->vofdescs + i + 1;
		iov = iovs + i;
		iov->iov_base = vtreq->addr[i + 1];
		iov->iov_len = le32toh(desc->length);
	}

	if (pwritev(ctx->fd, iovs, vtreq->ndesc - 2, offset) < 0) {
		log_error("pwritev failed: %m\n");
	}
	free(iovs);

	status = (__u8 *)vtreq->addr[vtreq->ndesc - 1];
	*status = VIRTIO_BLK_S_OK;
	desc = vtreq->vofdescs + vtreq->ndesc - 1;
	vtreq->fill_desc(desc, 0, 1);

	virtiot_fabrics_completion(vtreq->vofcomp, VIRTIO_OF_SUCCESS, le16toh(vtreq->vofcmd->vring.command_id));
	vtreq->vofcomp->ndesc = htole16(1);
	vtreq->vofcomp->value.u32 = htole32(1);
	vtreq->complete(vtreq);

	return 0;
}

static struct virtiot_block_driver virtiot_block_posix = {
	.vtdrv = {
		.vtobj = {
			.id = "block-posix",
			.type = virtiot_object_driver,
		},
	},
	.open = virtiot_block_posix_open,
	.close = virtiot_block_posix_close,
	.get_capacity = virtiot_block_posix_get_capacity,
	.read = virtiot_block_posix_read,
	.write = virtiot_block_posix_write,
};

static void __attribute__((constructor)) virtiot_be_block_init(void)
{
	virtiot_driver_register(&virtiot_block_posix.vtdrv);
}
