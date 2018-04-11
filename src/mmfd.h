#pragma once

#include "vector.h"

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

#define PORT 27275

struct context {
	char *babeld_buffer;
	VECTOR(struct neighbour) neighbours;
	VECTOR(uint64_t) seen;
	VECTOR(char *) interfaces;
	int efd;
	int tunfd;
	int babelport;
	int timerfd;
	int babelfd;
	int babeld_reconnect_tfd;
	int udpfd;
	bool verbose;
	bool debug;
	bool bind;
};

struct __attribute__((__packed__)) header {
	uint32_t nonce;
};

struct neighbour {
	struct sockaddr_in6 address;
	char *ifname;
	int reach;
	int cost;
};
