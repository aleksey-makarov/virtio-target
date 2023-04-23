#include <errno.h>
#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "virtio_of.h"
#include "iniparser.h"
#include "target.h"
#include "log.h"
#include "thread.h"
#include "transport.h"
#include "fabrics.h"
#include "utils.h"

static const char *virtiot_transport, *virtiot_address;
static int virtiot_port;
static unsigned int virtiot_threads;

static void virtiot_connect_handler(int epollfd, struct epoll_event *event, struct virtiot_queue *vtq)
{
	struct virtiot_transport *transport = vtq->transport;
	int ret;

//log_debug("fd %d, event 0x%x\n", vtq->fd, event->events);
	ret = transport->process(vtq);
	if (ret < 0) {
log_error("RET %d, %s\n", ret, strerror(-ret));
		virtiot_target_destroy(vtq->vtgt, epollfd);
		return;
	}
}

#define MAX_EVENTS 1
static void virtiot_server()
{
	struct virtiot_transport *transport;
	struct virtiot_queue *listener, *vtq;
	struct epoll_event event, events[MAX_EVENTS];
	int epollfd;
	int nevents, n;

	transport = virtiot_transport_lookup(virtiot_transport);
	assert(transport);

	listener = transport->listen(virtiot_address, virtiot_port);
	assert(listener);

	epollfd = epoll_create1(0);
	assert(epollfd > 0);
	event.events = EPOLLIN;
	event.data.ptr = listener;
	assert(!epoll_ctl(epollfd, EPOLL_CTL_ADD, listener->fd, &event));
log_debug("listener[%p]->fd %d\n", listener, listener->fd);

	while (true) {
		nevents = epoll_wait(epollfd, events, MAX_EVENTS, -1);
		if (!nevents) {
			continue;
		}

		if (unlikely(nevents < 0)) {
			assert(errno == EINTR);
			break;
		}

		for (n = 0; n < nevents; n++) {
			if (events[n].data.ptr == listener) {
				vtq = transport->accept(listener);
				if (!vtq) {
					continue;
				}

				virtiot_add_event(epollfd, vtq->fd, vtq);
			} else {
				virtiot_connect_handler(epollfd, &events[n], events[n].data.ptr);
			}
		}
	};
}

static char __virtiot_parse_error[1024];
static int virtiot_parse_error_callback(const char *format, ...)
{
	int ret;
	va_list argptr;

	va_start(argptr, format);
	ret = vsnprintf(__virtiot_parse_error, sizeof(__virtiot_parse_error), format, argptr);
	va_end(argptr);

	log_debug("%s %s\n", __func__, __virtiot_parse_error);
	return ret;
}

static char *virtiot_parse_error()
{
	char *error = NULL;

	if (__virtiot_parse_error[0]) {
		error = strdup(__virtiot_parse_error);
		memset(__virtiot_parse_error, 0x00, sizeof(__virtiot_parse_error));
	}

	return error;
}

static int virtiot_parse_target(dictionary *conf)
{
	int targets;

	virtiot_port = iniparser_getint(conf, "target:port", 15771);
	if (virtiot_port < 0 || virtiot_port > 65535) {
		virtiot_parse_error_callback("\"target:port\" should be [0, 65535]");
		return -EINVAL;
	}

	virtiot_transport = strdup(iniparser_getstring(conf, "target:transport", "tcp"));
	virtiot_address = strdup(iniparser_getstring(conf, "target:address", "127.0.0.1"));
	virtiot_threads = iniparser_getint(conf, "target:threads", 1);
	targets = iniparser_getint(conf, "target:targets", 128);
	if (targets >= 0xffff) {
		virtiot_parse_error_callback("\"target:targets\" should be (0, 65535)");
		return -EINVAL;
	}

	virtiot_target_init(targets);

	log_debug("TARGET: transport %s, address %s, port %d, threads %d, targets %d\n", virtiot_transport, virtiot_address, virtiot_port, virtiot_threads, targets);

	return 0;
}

static int virtiot_parse_one(dictionary *conf, const char *secname)
{
	char key[256];
	const char *tvqn, *model, *backend;

#define GET_CONF_STR(field) \
	snprintf(key, sizeof(key), "%s:" #field, secname); \
	field = iniparser_getstring(conf, key, NULL); \
	if (!field) { \
		return -EINVAL; \
	}

	GET_CONF_STR(tvqn);
	GET_CONF_STR(model);
	GET_CONF_STR(backend);

	log_debug("tvqn: %s, model: %s, backend: %s\n", tvqn, model, backend);
	if(!virtiot_target_create(secname, model, tvqn, backend)) {
		exit(errno);
	}

	return 0;
}

static int virtiot_parse_conf(const char *file)
{
	dictionary *conf;
	char *error;
	int ret = -EINVAL;
	int sec, secs;
	const char *secname;

	iniparser_set_error_callback(virtiot_parse_error_callback);
	conf = iniparser_load(file);
	if (!conf) {
		error = virtiot_parse_error();
		log_error("%s\n", error);
		return ret;
	}

	if (virtiot_parse_target(conf)) {
		goto free_conf;
	}

	secs = iniparser_getnsec(conf);
	for (sec = 0; sec < secs; sec++) {
		secname = iniparser_getsecname(conf, sec);
		if (strcmp(secname, "target")) {
			if (virtiot_parse_one(conf, secname)) {
				goto free_conf;
			}
		}
	}

	ret = 0;

free_conf:
	iniparser_freedict(conf);

	return ret;
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		printf("Usage: %s config\n", argv[0]);
		return 0;
	}

	if (virtiot_parse_conf(argv[1])) {
		printf("parse %s failed: %s\n", argv[1], virtiot_parse_error());
		return 0;
	}

	signal(SIGPIPE, SIG_IGN);

	virtiot_thread_init(virtiot_threads);
	virtiot_server();

	return 0;
}
