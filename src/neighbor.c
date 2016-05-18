#include "neighbor.h"
#include "mmfd.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>

void print_neighbors(struct context *ctx) {
  puts("Neighbors:");

  for (int i = 0; i < VECTOR_LEN(ctx->neighbors); i++) {
    struct neighbor *neighbor = &VECTOR_INDEX(ctx->neighbors, i);

    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &neighbor->address.sin6_addr, ip_str, INET6_ADDRSTRLEN);

    printf(" - %s on %s (%d), reach %d, cost %d\n", ip_str, neighbor->ifname, neighbor->address.sin6_scope_id, neighbor->reach, neighbor->cost);
  }
}

bool cmp_neighbor(struct neighbor *neighbor, struct in6_addr *address, char *ifname) {
  return strcmp(ifname, neighbor->ifname) == 0 && memcmp(address, &neighbor->address.sin6_addr, sizeof(*address)) == 0;
}

struct neighbor *find_neighbor(struct context *ctx, struct in6_addr *address, char *ifname) {
  for (int i = 0; i < VECTOR_LEN(ctx->neighbors); i++) {
    struct neighbor *neighbor = &VECTOR_INDEX(ctx->neighbors, i);

    if (cmp_neighbor(neighbor, address, ifname))
      return neighbor;
  }

  return NULL;
}

struct neighbor *add_neighbor(struct context *ctx, struct in6_addr *address, char *ifname) {
  struct neighbor neighbor = {
    .ifname = strdup(ifname),
    .address = {
      .sin6_family = AF_INET6,
      .sin6_addr = *address,
    }
  };

  VECTOR_ADD(ctx->neighbors, neighbor);
	return &VECTOR_INDEX(ctx->neighbors, VECTOR_LEN(ctx->neighbors) - 1);
}

void remove_neighbor(struct context *ctx, struct in6_addr *address, char *ifname) {
  for (int i = 0; i < VECTOR_LEN(ctx->neighbors); i++) {
    struct neighbor *neighbor = &VECTOR_INDEX(ctx->neighbors, i);

    if (cmp_neighbor(neighbor, address, ifname)) {
      free(neighbor->ifname);
      VECTOR_DELETE(ctx->neighbors, i);
      break;
    }
  }
}

void neighbor_add(struct context *ctx, struct in6_addr *address, char *ifname, int reach, int cost) {
  unsigned int ifindex = if_nametoindex(ifname);

  if (ifindex == 0) {
    perror("Cannot find interface for neighbor");
    return;
  }

  struct neighbor *neighbor = add_neighbor(ctx, address, ifname);
  neighbor->address.sin6_scope_id = ifindex;
  neighbor->address.sin6_port = htons(PORT);
}

void neighbor_change(struct context *ctx, struct in6_addr *address, char *ifname, int reach, int cost) {
  struct neighbor *neighbor = find_neighbor(ctx, address, ifname);

  if (neighbor == NULL)
    return;

  neighbor->reach = reach;
  neighbor->cost = cost;
}

void neighbor_flush(struct context *ctx, struct in6_addr *address, char *ifname) {
  remove_neighbor(ctx, address, ifname);
}
