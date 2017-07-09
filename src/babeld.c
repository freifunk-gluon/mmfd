// connect to babeld
// reconnect
// notify about client changes

#include "babeld.h"
#include "neighbour.h"
#include "error.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define CHUNKSIZE 1024

void babeld_parse_line(struct context *ctx, char *line) {
	char *action = NULL;
	char *address_str = NULL;
	char *ifname = NULL;
	int reach, cost;

	print_neighbours(ctx);

	int n = sscanf(line, "%ms neighbour %*x address %ms if %ms reach %x rxcost %*d txcost %*d cost %d", &action, &address_str, &ifname, &reach, &cost);

	if (n != 5) {
		free(action);
		free(address_str);
		free(ifname);
		n = sscanf(line, "%ms neighbour %*x address %ms if %ms reach %x rxcost %*d txcost %*d rtt %*f rttcost %*d cost %d", &action, &address_str, &ifname, &reach, &cost);
		if (n != 5) {
			free(action);
			free(address_str);
			free(ifname);
			n = sscanf(line, "%ms neighbour %*s", &action);
			if (n == 2 ) {
				log_verbose(ctx, "Received changes on a neighbour but could not match them on any of the neighbour-patterns. Exiting parser %d. This is a bug that should be reported.\n", n);
			}

			goto end;
		}
	}
	struct in6_addr address;

	if (inet_pton(AF_INET6, address_str, &address) != 1) {
		log_verbose(ctx, "received garbage instead of IPv6-address, not parsing line from babeld\n");
		goto end;
	}

	if (strcmp(action, "add") == 0)
		neighbour_add(ctx, &address, ifname, reach, cost);

	if (strcmp(action, "change") == 0)
		neighbour_change(ctx, &address, ifname, reach, cost);

	if (strcmp(action, "flush") == 0)
		neighbour_flush(ctx, &address, ifname);

end:
	free(action);
	free(address_str);
	free(ifname);
}

bool babeld_handle_in(struct context *ctx, int fd) {
	size_t old_len = ctx->babeld_buffer == NULL ? 0 : strlen(ctx->babeld_buffer);
	size_t new_len = old_len + CHUNKSIZE + 1;

	ctx->babeld_buffer = realloc(ctx->babeld_buffer, new_len);

	if (ctx->babeld_buffer == NULL)
		exit_errno("Cannot allocate buffer");

	ssize_t len = read(fd, ctx->babeld_buffer + old_len, CHUNKSIZE);

	if (len == 0)
		return false;

	if (len == -1 && errno == EAGAIN)
		return true;

	ctx->babeld_buffer[old_len + len] = 0;

	char *stringp, *line;

	while (1) {
		stringp = ctx->babeld_buffer;
		line = strsep(&stringp, "\n");

		if ((ctx->verbose) && (strlen(line) > 1))
			log_verbose(ctx, "about to parse line: %s\n", line);

		if (stringp == NULL)
			break; // no line found

		babeld_parse_line(ctx, line);
		memmove(ctx->babeld_buffer, stringp, strlen(stringp) + 1);
		ctx->babeld_buffer = realloc(ctx->babeld_buffer, strlen(ctx->babeld_buffer) + 1);

		if (ctx->babeld_buffer == NULL)
			exit_errno("Cannot allocate buffer");
	}

	return true;
}

int babeld_connect(int port) {
	int fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);

	if (fd < 0)
		exit_errno("Unable to create TCP socket");

	struct sockaddr_in6 serveraddr = {
		.sin6_family = AF_INET6,
		.sin6_port = htons(port)
	};

	if (inet_pton(AF_INET6, "::1", &serveraddr.sin6_addr.s6_addr) != 1)
		exit_errno("Cannot parse hostname");

	if (connect(fd, (const struct sockaddr *)&serveraddr, sizeof(serveraddr)) != 0) {
		if (errno != EINPROGRESS)
			exit_errno("Can not connect to babeld");
	}

	// TODO: this is not a good idea? maybe we could receive EAGAIN!
	if (send(fd, "monitor\n", 8, 0) != 8) {
		exit_errno("Error while subscribing to babels events");
	}

	return fd;
}
