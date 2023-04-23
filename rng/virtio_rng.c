#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_rng.h>

#include "device.h"
#include "fabrics.h"
#include "rng.h"

struct virtiot_device_rng {
        struct virtiot_device vtdev;
        struct virtiot_rng_driver *driver;
        void *drvctx;
};

static struct virtiot_device_rng *to_rng(struct virtiot_device *vtdev)
{
        return container_of(vtdev, struct virtiot_device_rng, vtdev);
}

static int virtiot_rng_handle_vring(struct virtiot_device *vtdev, struct virtiot_request *vtreq)
{
	struct virtiot_device_rng *vtrng = to_rng(vtdev);
	struct virtiot_rng_driver *vtrngdrv = vtrng->driver;
	int ret = -EINVAL;

	if (vtreq->ndesc != 1) {
		virtiot_fabrics_completion(vtreq->vofcomp, virtiot_errno_to_status(ret), le16toh(vtreq->vofcmd->common.command_id));
		vtreq->complete(vtreq);
		return ret;
	}

	vtrngdrv->read(vtrng->drvctx, vtreq);

        return 0;
}

static __u16 virtiot_rng_get_queue_size(struct virtiot_device *vtdev, __u16 queue_id)
{
        return 8;
}

static __u16 virtiot_rng_get_max_segs(struct virtiot_device *vtdev, __u16 queue_id)
{
        return 1;
}

static __u16 virtiot_rng_get_depth(struct virtiot_device *vtdev, __u16 queue_id)
{
        return virtiot_rng_get_queue_size(vtdev, queue_id);
}

static void virtiot_rng_destroy(struct virtiot_device *vtdev)
{
	struct virtiot_device_rng *vtrng = to_rng(vtdev);

	virtiot_object_del(&vtrng->vtdev.vtobj);
	free(vtrng);
}

static struct virtiot_device *virtiot_rng_create(const char *id, const char *backend)
{
	struct virtiot_device_rng *vtrng;
	struct virtiot_device *vtdev;
	struct virtiot_object *vtobj;
	struct virtiot_rng_driver *vtrngdrv;

	vtrng = calloc(sizeof(struct virtiot_device_rng), 1);
	assert(vtrng);

	vtdev = &vtrng->vtdev;
	vtdev->vendor_id = VIRTIO_TARGET_VENDOR;
	vtdev->device_id = VIRTIO_ID_RNG;
	vtdev->generation = 0;
	vtdev->config_size = 0;
	vtdev->destroy = virtiot_rng_destroy;
	vtdev->handle_vring = virtiot_rng_handle_vring;
	vtdev->get_queue_size = virtiot_rng_get_queue_size;
	vtdev->get_max_segs = virtiot_rng_get_max_segs;
	vtdev->get_depth = virtiot_rng_get_depth;

	vtrngdrv = virtiot_driver_find(backend, struct virtiot_rng_driver, vtdrv);
	if (!vtrngdrv) {
		goto free_rng;
	}

	vtrng->driver = vtrngdrv;
	vtrng->drvctx = vtrngdrv->open(backend);
	if (!vtrng->drvctx) {
		goto free_rng;
	}

	vtobj = &vtrng->vtdev.vtobj;
	vtobj->id = strdup(id);
	vtobj->type = virtiot_object_device;
	virtiot_object_add(vtobj);

	return vtdev;

free_rng:
	free(vtrng);

	return NULL;
}

static struct virtiot_model virtiot_model_rng = {
	.vtobj = {
		.id = "rng",
		.type = virtiot_object_model,
	},
	.create = virtiot_rng_create,
};

static void __attribute__((constructor)) virtiot_rng_init(void)
{
	virtiot_model_register(&virtiot_model_rng);
}
