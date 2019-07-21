/*
 * Copyright (c) 2017, Christof Schulze <christof@christofschulze.com>
 *
 * This file is part of project l3roamd. It's copyrighted by the contributors
 * recorded in the version control history of the file, available from
 * its original location https://github.com/freifunk-gluon/l3roamd.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <json-c/json.h>
#include <stdio.h>
#include <unistd.h>

#include "alloc.h"
#include "error.h"
#include "intercom.h"
#include "mmfd.h"
#include "socket.h"
#include "util.h"

void socket_init(socket_ctx *ctx, char *path) {
	if (!path) {
		ctx->fd = -1;
		return;
	}

	log_verbose("Initializing unix socket: %s\n", path);

	unlink(path);

	size_t status_socket_len = strlen(path);
	ctx->path = mmfd_alloc(status_socket_len + 1);
	strncpy(ctx->path, path, status_socket_len);

	size_t len = offsetof(struct sockaddr_un, sun_path) + status_socket_len + 1;
	uint8_t buf[len] __attribute__((aligned(__alignof__(struct sockaddr_un))));
	memset(buf, 0, offsetof(struct sockaddr_un, sun_path));

	struct sockaddr_un *sa = (struct sockaddr_un *)buf;
	sa->sun_family = AF_UNIX;
	memcpy(sa->sun_path, path, status_socket_len + 1);

	ctx->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0);

	if (bind(ctx->fd, (struct sockaddr *)sa, len)) {
		switch (errno) {
			case EADDRINUSE:
				exit_error("unable to create status socket: the path `%s' already exists", path);
				break;
			default:
				exit_errno("unable to create status socket");
		}
	}

	if (listen(ctx->fd, 5)) {
		perror("unable to listen on unix-socket");
		exit(EXIT_FAILURE);
	}
}

bool parse_command(char *cmd, enum socket_command *scmd) {
	if (!strncmp(cmd, "verbosity ", 10))
		*scmd = SET_VERBOSITY;
	else if (!strncmp(cmd, "del_meshif ", 11))
		*scmd = DEL_MESHIF;
	else if (!strncmp(cmd, "get_meshifs", 11))
		*scmd = GET_MESHIFS;
	else if (!strncmp(cmd, "get_neighbours", 14))
		*scmd = GET_NEIGHBOURS;
	else if (!strncmp(cmd, "add_meshif ", 11))
		*scmd = ADD_MESHIF;
	else
		return false;

	return true;
}

void socket_get_neighbours(struct json_object *obj) {
	struct json_object *neighbours = json_object_new_array();
	for (size_t i = 0; i < VECTOR_LEN(ctx.neighbours); i++) {
		struct neighbour *neighbour = &VECTOR_INDEX(ctx.neighbours, i);

		struct json_object *jneighbour = json_object_new_object();

		json_object_object_add(jneighbour, "address",  json_object_new_string(print_ip(&neighbour->address.sin6_addr)));
		json_object_object_add(jneighbour, "interface",  json_object_new_string(neighbour->ifname));
		json_object_array_add(neighbours, jneighbour);
	}
	json_object_object_add(obj, "mmfd_neighbours", neighbours);
}

void socket_get_meshifs(struct json_object *obj) {
	struct json_object *jmeshifs = json_object_new_array();

	for (size_t i = 0; i < VECTOR_LEN(ctx.interfaces); i++) {
		struct interface *iface = &VECTOR_INDEX(ctx.interfaces, i);
		json_object_array_add(jmeshifs, json_object_new_string(iface->ifname));
	}
	json_object_object_add(obj, "mesh_interfaces", jmeshifs);
}

void socket_handle_in(socket_ctx *sctx) {
	log_debug("handling socket event\n");

	int fd = accept(sctx->fd, NULL, NULL);
	char line[LINEBUFFER_SIZE];

	int len = 0;
	int fill = 0;
	// TODO: it would be nice to be able to set a timeout here after which
	// the fd is closed
	while (fill < LINEBUFFER_SIZE) {
		len = read(fd, &(line[fill]), 1);
		if (line[fill] == '\n' || line[fill] == '\r') {
			line[fill] = '\0';
			break;
		}
		fill += len;
	}

	enum socket_command cmd;
	if (!parse_command(line, &cmd)) {
		fprintf(stderr, "Could not parse command on socket (%s)\n", line);
		goto end;
	}

	struct json_object *retval = json_object_new_object();
	char *str_meshif = NULL;
	char *verbosity = NULL;

	switch (cmd) {
		case SET_VERBOSITY:
			verbosity = strtok(&line[10], " ");
			if (!strncmp(verbosity, "none", 4)) {
				ctx.verbose = false;
				ctx.debug = false;
			} else if (!strncmp(verbosity, "verbose", 7)) {
				ctx.verbose = true;
				ctx.debug = false;
			} else if (!strncmp(verbosity, "debug", 5)) {
				ctx.verbose = true;
				ctx.debug = true;
			}

			break;
		case ADD_MESHIF:
			str_meshif = strndup(&line[11], IFNAMSIZ);
			if (!if_add(str_meshif)) {
				free(str_meshif);
				break;
			} else {
				intercom_update_interfaces(&ctx);
			}
			break;
		case GET_MESHIFS:
			socket_get_meshifs(retval);
			dprintf(fd, "%s", json_object_to_json_string(retval));
			break;
		case DEL_MESHIF:
			str_meshif = strndup(&line[11], IFNAMSIZ);
			if (!if_del(str_meshif))
				free(str_meshif);
			break;
		case GET_NEIGHBOURS:
			socket_get_neighbours(retval);
			dprintf(fd, "%s", json_object_to_json_string(retval));
			break;
	}

	json_object_put(retval);
end:
	close(fd);
}
