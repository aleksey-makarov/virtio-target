#include <stdio.h>
#include <string.h>

#include "fabrics.h"
#include "queue.h"
#include "vinitiator.h"

/* see VIRTIO_ID_XXX in virtio_ids.h */
static struct vi_device *videvs[42];

void vi_device_register(struct vi_device *videv)
{
	unsigned int id = videv->id;

	ASSERT(id < ARRAY_SIZE(videvs));
	ASSERT(!videvs[id]);
	videvs[id] = videv;
}

static struct vi_device *vi_get_device(unsigned int device_id)
{
	struct vi_device *videv;

	ASSERT(device_id < ARRAY_SIZE(videvs));
	videv = videvs[device_id];
	ASSERT(videv);

	return videv;
}

static char *vi_device_name(unsigned int device_id)
{
	return vi_get_device(device_id)->name;
}

static void vi_device_show_config(struct vi_queue *viq, void *queue, unsigned int device_id)
{
	if (vi_get_device(device_id)->show_config) {
		vi_get_device(device_id)->show_config(viq, queue);
	}
}

static void **vi_setup_vqs(struct vi_queue *viq, void *ctrlq, int target_id, int nqueues, char *taddr, int tport, char *tvqn, char *ivqn)
{
	void **queues;
	int queue_size;
	int i;

	queues = calloc(sizeof(void *), nqueues);
	ASSERT(queues);

	for (i = 0; i < nqueues; i++) {
		queue_size = vi_queue_get_queue_size(viq, ctrlq, i);
		printf("VirtQueue[%d] size %d\n", i, queue_size);
		queues[i] = viq->create_queue(taddr, tport);
		ASSERT(queues[i]);
		vi_queue_connect_queue(viq, queues[i], &target_id, i, tvqn, ivqn);
	}

	return queues;
}

static void vi_read(struct vi_queue *viq, void *queue, unsigned int device_id, off_t offset, int seg_size, int segs)
{
	struct iovec *iovs;
	char *readbuf;
	int i;

	iovs = calloc(sizeof(struct iovec), segs);
	ASSERT(iovs);

	readbuf = calloc(seg_size, seg_size);
	for (i = 0; i < segs; i++) {
		iovs[i].iov_len = seg_size;
		iovs[i].iov_base = readbuf + seg_size * i;
	}

	vi_get_device(device_id)->read(viq, queue, segs, iovs, offset);
	printf("read: %s\n", readbuf);

	free(readbuf);
	free(iovs);
}

static void bench(struct vi_queue *viq, void *queue, unsigned int device_id)
{
	struct iovec iovs[64];
	char *writebuf, *readbuf;
	int seg_size = 4096;
	int i;

	writebuf = calloc(seg_size, ARRAY_SIZE(iovs));
	for (i = 0; i < ARRAY_SIZE(iovs); i++) {
		iovs[i].iov_len = seg_size;
		iovs[i].iov_base = writebuf + seg_size * i;
		memset(iovs[i].iov_base, 'A' + random() % 26, iovs[i].iov_len);
	}

	vi_get_device(device_id)->write(viq, queue, ARRAY_SIZE(iovs), iovs, 0);

	readbuf = calloc(seg_size, ARRAY_SIZE(iovs));
	for (i = 0; i < ARRAY_SIZE(iovs); i++) {
		iovs[i].iov_len = seg_size;
		iovs[i].iov_base = readbuf + seg_size * i;
	}

	vi_get_device(device_id)->read(viq, queue, ARRAY_SIZE(iovs), iovs, 0);

	ASSERT(!memcmp(writebuf, readbuf, seg_size * ARRAY_SIZE(iovs)));

	free(writebuf);
	free(readbuf);
}

static void vi_show_serial(struct vi_queue *viq, void *queue, unsigned int device_id)
{
	struct iovec iov;
	char serial[128] = { 0 };

	if (!vi_get_device(device_id)->get_serial) {
		return;
	}

	iov.iov_base = serial;
	iov.iov_len = sizeof(serial) - 1;
	vi_get_device(device_id)->get_serial(viq, queue, 1, &iov);

	printf("Serial: %s\n", serial);
}

int main()
{
	struct vi_queue *viq;
	//char *transport = "tcp";
	char *transport = "rdma";
	char *taddr = "192.168.122.1";
	//char *tvqn = "virtio-target/block/block0.service";
	char *tvqn = "virtio-target/rng/rng0.service";
	char *ivqn = "virtio-target-test-initiator";
	int tport = 15771;
	void *ctrlq;
	void **queues;
	int target_id = 0xffff;
	unsigned int device_id, vendor_id, num_queues;
	int nqueues = 1;

	viq = vi_queue_lookup(transport);
	ASSERT(viq);

	ctrlq = viq->create_queue(taddr, tport);
	ASSERT(ctrlq);
	vi_queue_connect_queue(viq, ctrlq, &target_id, 0xffff, tvqn, ivqn);
	printf("Target ID: 0x%x\n", target_id);

	vendor_id = vi_queue_get_vendor_id(viq, ctrlq);
	printf("Vendor ID: 0x%x\n", vendor_id);

	device_id = vi_queue_get_device_id(viq, ctrlq);
	printf("Device ID: 0x%x (%s)\n", device_id, vi_device_name(device_id));

	num_queues = vi_queue_get_num_queues(viq, ctrlq);
	printf("Num Queues: %d\n", num_queues);

	vi_device_show_config(viq, ctrlq, device_id);

	queues = vi_setup_vqs(viq, ctrlq, target_id, nqueues, taddr, tport, tvqn, ivqn);
	ASSERT(queues);

	vi_read(viq, queues[0], device_id, 0, 32, 1);
	return 0;

	for (int i = 0; i < 1024; i++) {
	printf("loop %d\n", i);
	vi_show_serial(viq, queues[0], device_id);
	}

	bench(viq, queues[0], device_id);

	return 0;
}
