#pragma once

#include "mmfd.h"
#define MMFD_PACKET_FORMAT_VERSION 1

typedef struct __attribute__((__packed__)) {
	struct header hdr;
} intercom_packet_hello;

bool intercom_send_hello();
void intercom_init(struct context *ctx);
bool if_add(char *ifname);
bool if_del(char *ifname);
void intercom_update_interfaces(struct context *ctx);

