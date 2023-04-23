#include <string.h>

#include "virtio_of.h"
#include "queue.h"
#include "fabrics.h"
#include "vinitiator.h"

#define MAX_TRANSPORT	2
static struct vi_queue *vi_queues[MAX_TRANSPORT];	/* TCP & RDMA */

void vi_queue_register(struct vi_queue *viq)
{
	struct vi_queue *tmpviq;
	int i;

	for (i = 0; i < MAX_TRANSPORT; i++) {
		tmpviq = vi_queues[i];
		if (!tmpviq) {
			break;
		}
	}

	ASSERT(i < MAX_TRANSPORT);
	vi_queues[i] = viq;
}

struct vi_queue *vi_queue_lookup(const char *transport)
{
	struct vi_queue *viq;
	int i;

	for (i = 0; i < MAX_TRANSPORT; i++) {
		viq = vi_queues[i];
		if (viq && !strcmp(transport, viq->transport)) {
			return viq;
		}
	}

	return NULL;
}

void vi_queue_connect_queue(struct vi_queue *viq, void *queue, int *target_id, int queue_id, char *tvqn, char *ivqn)
{
	struct virtio_of_command vofcmd;
	struct virtio_of_connect vofconnect;
	struct virtio_of_vring_desc vofdesc;
	struct virtio_of_completion vofcomp;
	struct iovec iov;

	vi_fabric_connect(&vofcmd, &vofconnect, &vofdesc, *target_id, queue_id, tvqn, ivqn, viq->oftype);
	iov.iov_base = &vofconnect;
	iov.iov_len = le32toh(vofdesc.length);
	ASSERT(viq->send_cmd(queue, &vofcmd, 1, &vofdesc, &iov) >= 0);
	ASSERT(viq->recv_comp(queue, &vofcomp, 0, NULL, NULL) >= 0);
	ASSERT(!vofcomp.status);

	if (queue_id == 0xffff) {
		*target_id = le16toh(vofcomp.value.u16);
	}
}

unsigned int vi_queue_get_vendor_id(struct vi_queue *viq, void *queue)
{
	struct virtio_of_command vofcmd;
	struct virtio_of_completion vofcomp;

	vi_fabric_get_vendor_id(&vofcmd);
	ASSERT(viq->send_cmd(queue, &vofcmd, 0, NULL, NULL) >= 0);
	ASSERT(viq->recv_comp(queue, &vofcomp, 0, NULL, NULL) >= 0);
	ASSERT(le16toh(vofcomp.status) == VIRTIO_OF_SUCCESS);

	return le32toh(vofcomp.value.u32);
}

unsigned int vi_queue_get_device_id(struct vi_queue *viq, void *queue)
{
	struct virtio_of_command vofcmd;
	struct virtio_of_completion vofcomp;

	vi_fabric_get_device_id(&vofcmd);
	ASSERT(viq->send_cmd(queue, &vofcmd, 0, NULL, NULL) >= 0);
	ASSERT(viq->recv_comp(queue, &vofcomp, 0, NULL, NULL) >= 0);
	ASSERT(le16toh(vofcomp.status) == VIRTIO_OF_SUCCESS);

	return le32toh(vofcomp.value.u32);
}

unsigned int vi_queue_get_num_queues(struct vi_queue *viq, void *queue)
{
	struct virtio_of_command vofcmd;
	struct virtio_of_completion vofcomp;

	vi_fabric_get_num_queues(&vofcmd);
	ASSERT(viq->send_cmd(queue, &vofcmd, 0, NULL, NULL) >= 0);
	ASSERT(viq->recv_comp(queue, &vofcomp, 0, NULL, NULL) >= 0);
	ASSERT(le16toh(vofcomp.status) == VIRTIO_OF_SUCCESS);

	return le16toh(vofcomp.value.u16);
}

unsigned int vi_queue_get_queue_size(struct vi_queue *viq, void *queue, __u16 queue_id)
{
	struct virtio_of_command vofcmd;
	struct virtio_of_completion vofcomp;

	vi_fabric_get_queue_size(&vofcmd, queue_id);
	ASSERT(viq->send_cmd(queue, &vofcmd, 0, NULL, NULL) >= 0);
	ASSERT(viq->recv_comp(queue, &vofcomp, 0, NULL, NULL) >= 0);
	ASSERT(le16toh(vofcomp.status) == VIRTIO_OF_SUCCESS);

	return le16toh(vofcomp.value.u16);
}

__u64 vi_queue_get_config(struct vi_queue *viq, void *queue, __u16 offset, __u8 bytes)
{
	struct virtio_of_command vofcmd;
	struct virtio_of_completion vofcomp;

	vi_fabric_get_config(&vofcmd, offset, bytes);
	ASSERT(viq->send_cmd(queue, &vofcmd, 0, NULL, NULL) >= 0); 
	ASSERT(viq->recv_comp(queue, &vofcomp, 0, NULL, NULL) >= 0);
	ASSERT(le16toh(vofcomp.status) == VIRTIO_OF_SUCCESS);

        switch (bytes) {
        case 1:
                return vofcomp.value.u8;
        case 2:
                return le16toh(vofcomp.value.u16);
        case 4:
                return le32toh(vofcomp.value.u32);
        case 8:
                return le64toh(vofcomp.value.u64);
        }

	ASSERT(!"unsupported bytes");
}
