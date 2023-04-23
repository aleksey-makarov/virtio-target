#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <linux/virtio_ids.h>
#include <linux/virtio_ring.h>

#include "crypto.h"
#include "virtio_crypto.h"
#include "device.h"
#include "fabrics.h"
#include "log.h"
#include "utils.h"

struct virtiot_device_crypto {
	struct virtiot_device vtdev;
	struct virtiot_crypto_driver *driver;
	void *drvctx;
	__u16 num_queues;
};

static struct virtiot_device_crypto *to_crypto(struct virtiot_device *vtdev)
{
	return container_of(vtdev, struct virtiot_device_crypto, vtdev);
}

static __u16 virtiot_crypto_get_queue_size(struct virtiot_device *vtdev, __u16 queue_id)
{
	return VIRTIO_TARGET_VRING_SIZE;
}

static __u16 virtiot_crypto_get_max_segs(struct virtiot_device *vtdev, __u16 queue_id)
{
	return 4;
}

static __u16 virtiot_crypto_get_depth(struct virtiot_device *vtdev, __u16 queue_id)
{
	return virtiot_crypto_get_queue_size(vtdev, queue_id);
}

static __u16 virtiot_crypto_get_queues(struct virtiot_device *vtdev)
{
	struct virtiot_device_crypto *vtcrypto = to_crypto(vtdev);

	return vtcrypto->num_queues;
}

static int virtiot_crypto_handle_data(struct virtiot_device *vtdev, struct virtiot_request *vtreq)
{
	struct virtiot_device_crypto *vtcrypto = to_crypto(vtdev);
	struct virtiot_crypto_driver *vtcryptodrv = vtcrypto->driver;
	struct virtio_of_vring_desc *vofdesc;
	struct virtio_crypto_op_data_req *req_data;
	__u32 opcode;
	__u64 session_id;
	void *src_buf, *dst_buf;
	__u32 src_len, dst_len, length = 0;
	__u8 *status;
	int ret;

	/* virtio crypto data queue request: header[OUT], data[OUT], (data[OUT],) input[IN] */
	vofdesc = &vtreq->vofdescs[0];
	if (le32toh(vofdesc->length) != sizeof(*req_data)) {
		log_warn("unexpected data req length %d\n", le32toh(vofdesc->length));
		return -EINVAL;
	}

	req_data = (struct virtio_crypto_op_data_req *)vtreq->addr[0];
	session_id = le64toh(req_data->header.session_id);
	opcode = le32toh(req_data->header.opcode);
	src_len = le32toh(req_data->u.akcipher_req.para.src_data_len);
	dst_len = le32toh(req_data->u.akcipher_req.para.dst_data_len);
//log_debug("session_id %lld, opcode 0x%x, src_len %d, dst_len %d\n", session_id, opcode, src_len, dst_len);
	src_buf = vtreq->addr[1];
	if (opcode == VIRTIO_CRYPTO_AKCIPHER_VERIFY) {
		dst_buf = vtreq->addr[1] + src_len;
		ret = vtcryptodrv->ak_verify(vtcrypto->drvctx, session_id, src_buf, src_len, dst_buf, dst_len);
		status = vtreq->addr[2];
		if (ret < 0) {
			*status = VIRTIO_CRYPTO_KEY_REJECTED;
		} else {
			*status = 0;
		}
		vofdesc = &vtreq->vofdescs[2];
		vtreq->fill_desc(vofdesc, 0, sizeof(__u8));
		vtreq->vofcomp->ndesc = htole16(1);
		vtreq->vofcomp->value.u32 = htole32(sizeof(__u8));
		vtreq->complete(vtreq);

		return 0;
	}

	dst_buf = vtreq->addr[2];
	switch (opcode) {
	case VIRTIO_CRYPTO_AKCIPHER_ENCRYPT:
		ret = vtcryptodrv->ak_encrypt(vtcrypto->drvctx, session_id, src_buf, src_len, dst_buf, dst_len);
		break;
	case VIRTIO_CRYPTO_AKCIPHER_DECRYPT:
		ret = vtcryptodrv->ak_decrypt(vtcrypto->drvctx, session_id, src_buf, src_len, dst_buf, dst_len);
		break;
	case VIRTIO_CRYPTO_AKCIPHER_SIGN:
		ret = vtcryptodrv->ak_sign(vtcrypto->drvctx, session_id, src_buf, src_len, dst_buf, dst_len);
		break;
	};

	if (ret > 0) {
		length = ret;
		vofdesc = &vtreq->vofdescs[2];
		vtreq->fill_desc(vofdesc, 0, length);
	}

	vofdesc = &vtreq->vofdescs[3];
	vtreq->fill_desc(vofdesc, length, sizeof(__u8));
	vtreq->vofcomp->ndesc = htole16(2);
	vtreq->vofcomp->value.u32 = htole32(length + sizeof(__u8));
	vtreq->complete(vtreq);

	return 0;
}

static int virtiot_crypto_handle_ctrl(struct virtiot_device *vtdev, struct virtiot_request *vtreq)
{
	struct virtiot_device_crypto *vtcrypto = to_crypto(vtdev);
	struct virtiot_crypto_driver *vtcryptodrv = vtcrypto->driver;
	struct virtio_of_vring_desc *vofdesc;
	struct virtio_crypto_op_ctrl_req *ctrl;
	struct virtio_crypto_session_input *input;
	struct virtio_crypto_inhdr *inhdr;
	__u32 opcode, algo, keylen, length;
	__u64 session_id;
	void *key;
	int ret;

	vofdesc = &vtreq->vofdescs[0];
	if (le32toh(vofdesc->length) != sizeof(struct virtio_crypto_op_ctrl_req)) {
		log_warn("unexpected ctrl req length %d\n", le32toh(vofdesc->length));
		return -EINVAL;
	}

	ctrl = (struct virtio_crypto_op_ctrl_req *)vtreq->addr[0];
	opcode = le32toh(ctrl->header.opcode);
	if ((opcode != VIRTIO_CRYPTO_AKCIPHER_CREATE_SESSION) &&
		(opcode != VIRTIO_CRYPTO_AKCIPHER_DESTROY_SESSION)) {
		log_warn("unexpected opcode: %d\n", opcode);
		return -EOPNOTSUPP;
	}

	if (opcode == VIRTIO_CRYPTO_AKCIPHER_CREATE_SESSION) {
//log_debug("create session\n");
		/* create session request: header[OUT], key[OUT], input[IN] */
		algo = le32toh(ctrl->header.algo);
		if (algo != VIRTIO_CRYPTO_AKCIPHER_RSA) {
			log_warn("unexpected algo: %d\n", algo);
			return -EOPNOTSUPP;
		}

		if (vtreq->ndesc != 3) {
			log_warn("unexpected ndesc %d for create session\n", vtreq->ndesc);
			return -EPROTO;
		}

		vofdesc = &vtreq->vofdescs[1];
		keylen = le32toh(vofdesc->length);
		key = vtreq->addr[1];
		ret = vtcryptodrv->create_session(vtcrypto->drvctx, &ctrl->u.akcipher_create_session, key, keylen);
		input = (struct virtio_crypto_session_input *)vtreq->addr[2];
		if (ret < 0) {
			input->status = htole32(ret);
		} else {
			input->session_id = htole64(ret);
			input->status = htole32(0);
		}
		vofdesc = &vtreq->vofdescs[2];
		length = sizeof(*input);
	} else {
//log_debug("destroy session\n");
		/* destroy session request: header[OUT], input[IN] */
		if (vtreq->ndesc != 2) {
			log_warn("unexpected ndesc %d for destroy session\n", vtreq->ndesc);
			return -EPROTO;
		}

		session_id = le64toh(ctrl->u.destroy_session.session_id);
		vtcryptodrv->destroy_session(vtcrypto->drvctx, session_id);
		inhdr = (struct virtio_crypto_inhdr *)vtreq->addr[1];
		inhdr->status = htole32(0);
		vofdesc = &vtreq->vofdescs[1];
		length = sizeof(*inhdr);
	}

	vtreq->fill_desc(vofdesc, 0, length);
	vtreq->vofcomp->ndesc = htole16(1);
	vtreq->vofcomp->value.u32 = htole32(length);
	vtreq->complete(vtreq);

	return 0;
}

static int virtiot_crypto_handle_vring(struct virtiot_device *vtdev, struct virtiot_request *vtreq)
{
	struct virtiot_device_crypto *vtcrypto = to_crypto(vtdev);
	__u16 queue_id = vtreq->vtq->queue_id;
	int ret = -EINVAL;

//log_debug("handle vring\n");
	/* the last queue of virtio crypto works as control queue */
	if (queue_id == (vtcrypto->num_queues - 1)) {
		ret = virtiot_crypto_handle_ctrl(vtdev, vtreq);
	} else {
		ret = virtiot_crypto_handle_data(vtdev, vtreq);
	}

	return ret;
}

static int virtiot_crypto_init_property(struct virtiot_device_crypto *vtcrypto, const char *backend)
{
	char *queues;

	/* n * data queues(at least 1) + 1 * control queue */
	vtcrypto->num_queues = 2;
	queues = virtiot_parse_string(backend, "queues");
	if (queues) {
		vtcrypto->num_queues = atoi(queues) + 1;
	}

	return 0;
}

static void virtiot_crypto_init_config(struct virtiot_device_crypto *vtcrypto)
{
	struct virtiot_device *vtdev = &vtcrypto->vtdev;
	struct virtio_crypto_config *config;

	vtdev->config = calloc(vtdev->config_size, 1);
	assert(vtdev->config);

	config = (struct virtio_crypto_config *)vtdev->config;
	config->max_dataqueues = htole32(vtcrypto->num_queues - 1);
	config->crypto_services = htole32(1u << VIRTIO_CRYPTO_SERVICE_AKCIPHER);
	config->akcipher_algo = htole32(1u << VIRTIO_CRYPTO_AKCIPHER_RSA);
	config->status = VIRTIO_CRYPTO_S_HW_READY;

	vtdev->dev_feature |= (1UL << VIRTIO_F_VERSION_1);
}

static void virtiot_crypto_destroy(struct virtiot_device *vtdev)
{
	struct virtiot_device_crypto *vtcrypto = to_crypto(vtdev);

	virtiot_object_del(&vtcrypto->vtdev.vtobj);
	free(vtdev->config);
	free(vtcrypto);
}

static struct virtiot_device *virtiot_crypto_create(const char *id, const char *backend)
{
	struct virtiot_device_crypto *vtcrypto;
	struct virtiot_device *vtdev;
	struct virtiot_object *vtobj;
	struct virtiot_crypto_driver *vtcryptodrv;

	vtcrypto = calloc(sizeof(struct virtiot_device_crypto), 1);
	assert(vtcrypto);

	if (virtiot_crypto_init_property(vtcrypto, backend)) {
		goto free_crypto;
	}

	vtdev = &vtcrypto->vtdev;
	vtdev->vendor_id = VIRTIO_TARGET_VENDOR;
	vtdev->device_id = VIRTIO_ID_CRYPTO;
	vtdev->generation = 0;
	vtdev->config_size = sizeof(struct virtio_crypto_config);
	vtdev->destroy = virtiot_crypto_destroy;
	vtdev->handle_vring = virtiot_crypto_handle_vring;
	vtdev->set_queues = NULL;
	vtdev->get_queues = virtiot_crypto_get_queues;
	vtdev->get_queue_size = virtiot_crypto_get_queue_size;
	vtdev->get_max_segs = virtiot_crypto_get_max_segs;
	vtdev->get_depth = virtiot_crypto_get_depth;

	vtcryptodrv = virtiot_driver_find(backend, struct virtiot_crypto_driver, vtdrv);
	if (!vtcryptodrv) {
		goto free_config;
	}

	vtcrypto->driver = vtcryptodrv;
	vtcrypto->drvctx = vtcryptodrv->open(backend);
	if (!vtcrypto->drvctx) {
		goto free_config;
	}

	virtiot_crypto_init_config(vtcrypto);
	vtobj = &vtcrypto->vtdev.vtobj;
	vtobj->id = strdup(id);
	vtobj->type = virtiot_object_device;
	virtiot_object_add(vtobj);

	return vtdev;

free_config:
	free(vtdev->config);

free_crypto:
	free(vtcrypto);

	return NULL;
}

static struct virtiot_model virtiot_model_crypto = {
	.vtobj = {
		.id = "crypto",
		.type = virtiot_object_model,
	},
	.create = virtiot_crypto_create,
};

static void __attribute__((constructor)) virtiot_crypto_init(void)
{
	virtiot_model_register(&virtiot_model_crypto);
}
