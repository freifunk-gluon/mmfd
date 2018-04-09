#include "neighbour.h"
#include "mmfd.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>

void print_neighbours(struct context *ctx) {
	puts("neighbours:");

	for (int i = 0; i < VECTOR_LEN(ctx->neighbours); i++) {
		struct neighbour *neighbour = &VECTOR_INDEX(ctx->neighbours, i);

		char ip_str[INET6_ADDRSTRLEN];
		inet_ntop(AF_INET6, &neighbour->address.sin6_addr, ip_str, INET6_ADDRSTRLEN);

		printf(" - %s on %s (%d), reach %d, cost %d\n", ip_str, neighbour->ifname, neighbour->address.sin6_scope_id, neighbour->reach, neighbour->cost);
	}
}

bool cmp_neighbour(struct neighbour *neighbour, struct in6_addr *address, char *ifname) {
	return strcmp(ifname, neighbour->ifname) == 0 && memcmp(address, &neighbour->address.sin6_addr, sizeof(*address)) == 0;
}

struct neighbour *find_neighbour(struct context *ctx, struct in6_addr *address, char *ifname) {
	for (int i = 0; i < VECTOR_LEN(ctx->neighbours); i++) {
		struct neighbour *neighbour = &VECTOR_INDEX(ctx->neighbours, i);

		if (cmp_neighbour(neighbour, address, ifname))
			return neighbour;
	}

	return NULL;
}

struct neighbour *add_neighbour(struct context *ctx, struct in6_addr *address, char *ifname) {
	struct neighbour neighbour = {
		.ifname = strdup(ifname),
		.address = {
			.sin6_family = AF_INET6,
			.sin6_addr = *address,
		}
	};

	VECTOR_ADD(ctx->neighbours, neighbour);
	return &VECTOR_INDEX(ctx->neighbours, VECTOR_LEN(ctx->neighbours) - 1);
}

void neighbour_remove(struct context *ctx, struct in6_addr *address, char *ifname) {
	for (int i = 0; i < VECTOR_LEN(ctx->neighbours); i++) {
		struct neighbour *neighbour = &VECTOR_INDEX(ctx->neighbours, i);

		if (cmp_neighbour(neighbour, address, ifname)) {

			free(neighbour->ifname);
			VECTOR_DELETE(ctx->neighbours, i);
			break;
		}
	}
}

void neighbour_add(struct context *ctx, struct in6_addr *address, char *ifname, int reach, int cost) {
	unsigned int ifindex = if_nametoindex(ifname);

	if (ifindex == 0) {
		perror("Cannot find interface for neighbour");
		return;
	}

	struct neighbour *neighbour = add_neighbour(ctx, address, ifname);
	neighbour->address.sin6_scope_id = ifindex;
	neighbour->address.sin6_port = htons(PORT);
}

void neighbour_change(struct context *ctx, struct in6_addr *address, char *ifname, int reach, int cost) {
	struct neighbour *neighbour = find_neighbour(ctx, address, ifname);

	if (neighbour == NULL)
	{
		if ( ctx->verbose )
			printf("did not find changed neighbour, adding\n");
		neighbour_add(ctx,address, ifname, reach, cost);
		return;
	}
	neighbour->reach = reach;
	neighbour->cost = cost;
}

void flush_neighbours(struct context *ctx) {
	for (int i = 0; i < VECTOR_LEN(ctx->neighbours); i++) {
		struct neighbour *neighbour = &VECTOR_INDEX(ctx->neighbours, i);

		free(neighbour->ifname);
		VECTOR_DELETE(ctx->neighbours, i);
	}
}
