#pragma once

#include "mmfd.h"

#include <netinet/in.h>

void neighbour_add(struct context *ctx, struct in6_addr *address, char *ifname, int reach, int cost);
void neighbour_change(struct context *ctx, struct in6_addr *address, char *ifname, int reach, int cost);
void neighbour_flush(struct context *ctx, struct in6_addr *address, char *ifname);

void print_neighbours(struct context *ctx);
