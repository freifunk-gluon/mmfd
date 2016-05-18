#pragma once

#include "mmfd.h"

#include <netinet/in.h>

void neighbor_add(struct context *ctx, struct in6_addr *address, char *ifname, int reach, int cost);
void neighbor_change(struct context *ctx, struct in6_addr *address, char *ifname, int reach, int cost);
void neighbor_flush(struct context *ctx, struct in6_addr *address, char *ifname);

void print_neighbors(struct context *ctx);
