#include "neighbour.h"
#include "mmfd.h"
#include "util.h"
#include "alloc.h"

#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/if.h>

void print_neighbours() {
	puts("neighbours:");

	for (int i = 0; i < VECTOR_LEN(ctx.neighbours); i++) {
		struct neighbour *neighbour = &VECTOR_INDEX(ctx.neighbours, i);

		printf(" - %s on %s\n", print_ip(&neighbour->address.sin6_addr), neighbour->ifname);
	}
}

bool cmp_neighbour(struct neighbour *neighbour, struct in6_addr *address, char *ifname) {
	bool is_sameif = (ifname && neighbour && neighbour->ifname) ? strncmp(ifname, neighbour->ifname, IFNAMSIZ) == 0 : 0;
	bool is_sameaddress = (memcmp(address, &(neighbour->address.sin6_addr), sizeof(struct in6_addr)) == 0);
	return is_sameif && is_sameaddress;
}

struct neighbour *find_neighbour(struct context *ctx, struct in6_addr *address, char *ifname) {
	if (!ifname || !address)
		return NULL;

	for (int i = 0; i < VECTOR_LEN(ctx->neighbours); i++) {
		struct neighbour *neighbour = &VECTOR_INDEX(ctx->neighbours, i);

		if (cmp_neighbour(neighbour, address, ifname))
			return neighbour;
	}

	return NULL;
}

void copy_neighbour(struct neighbour *dest, struct neighbour *source) {
	memcpy(dest, source, sizeof(struct neighbour));
	dest->ifname = source->ifname ? mmfd_strdup(source->ifname) : NULL;
}

void free_neighbour_members(struct neighbour *neighbour) {
	free(neighbour->ifname);
}

void free_neighbour(struct neighbour *neighbour) {
	free_neighbour_members(neighbour);
	free(neighbour);
}

void free_neighbour_task(void *neighbour) {
	free_neighbour((struct neighbour*)neighbour);
}

void neighbour_remove_task(void *d) {
	struct neighbour *n = (struct neighbour*)d;
	log_verbose("removing neighbour %s(s)\n", print_ip(&n->address.sin6_addr), n->ifname);
	neighbour_remove(&ctx, &(n->address.sin6_addr), n->ifname);
}

struct neighbour *add_neighbour(struct context *ctx, struct in6_addr *address, char *ifname, size_t ifindex) {
	struct neighbour neighbour = {
		.ifname = mmfd_strdup(ifname),
		.address = {},
	};

	log_verbose("copying ip %s from hello packet on interface %s\n", print_ip(address), ifname);
	memcpy(&neighbour.address.sin6_addr, address, sizeof(struct in6_addr));
	neighbour.address.sin6_family = AF_INET6;
	neighbour.address.sin6_port = htons(PORT);
	neighbour.address.sin6_scope_id = ifindex;


	struct neighbour *neighbour_task_data = mmfd_alloc(sizeof(struct neighbour));
	copy_neighbour(neighbour_task_data, &neighbour);
	neighbour.timeout_task = post_task(&ctx->taskqueue_ctx, HELLO_INTERVAL * 5, 0, neighbour_remove_task, free_neighbour_task, neighbour_task_data);
	VECTOR_ADD(ctx->neighbours, neighbour);
	return &VECTOR_INDEX(ctx->neighbours, VECTOR_LEN(ctx->neighbours) - 1);
}

void neighbour_remove(struct context *ctx, struct in6_addr *address, char *ifname) {
	for (int i = 0; i < VECTOR_LEN(ctx->neighbours); i++) {
		struct neighbour *neighbour = &VECTOR_INDEX(ctx->neighbours, i);

		if (cmp_neighbour(neighbour, address, ifname)) {
			free_neighbour_members(neighbour);
			VECTOR_DELETE(ctx->neighbours, i);
			break;
		}
	}
}

void neighbour_add(struct context *ctx, struct in6_addr *address, char *ifname) {
	unsigned int ifindex = if_nametoindex(ifname);

	if (ifindex == 0) {
		perror("Cannot find interface for neighbour");
		return;
	}

	add_neighbour(ctx, address, ifname, ifindex);
}

void neighbour_change(struct context *ctx, struct in6_addr *address, char *ifname) {

	struct neighbour *neighbour = find_neighbour(ctx, address, ifname);

	if (neighbour == NULL) {
		log_verbose("did not find changed neighbour, adding\n");
		neighbour_add(ctx, address, ifname);
		return;
	} else {
		reschedule_task(&ctx->taskqueue_ctx, neighbour->timeout_task, 5 * HELLO_INTERVAL, 0);
	}
}

void flush_neighbours(struct context *ctx) {
	for (int i = 0; i < VECTOR_LEN(ctx->neighbours); i++) {
		struct neighbour *neighbour = &VECTOR_INDEX(ctx->neighbours, i);

		free_neighbour_members(neighbour);
		VECTOR_DELETE(ctx->neighbours, i);
	}
}
