#pragma once

#include "vector.h"

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <net/if.h>
#include "taskqueue.h"
#include "socket.h"

#define PORT 27275
#define HELLO_INTERVAL 10
#define FMT_NONCE "0x%08"PRIx64

typedef struct interface {
	char ifname[IFNAMSIZ];
	int ifindex;
	bool ok;
} interface;

struct context {
	VECTOR(struct neighbour) neighbours;
	VECTOR(uint64_t) seen;
	VECTOR(interface) interfaces;
	taskqueue_ctx taskqueue_ctx;
	socket_ctx socket_ctx;
	struct sockaddr_in6 groupaddr;
	int efd;
	int tunfd;
	int intercomfd;
	bool verbose;
	bool debug;
};

extern struct context ctx;

struct __attribute__((__packed__)) header {
	uint64_t nonce;
};

struct neighbour {
	struct sockaddr_in6 address;
	char *ifname;
	taskqueue_t *timeout_task;
};
