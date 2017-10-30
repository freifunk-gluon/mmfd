#include "babeld.h"
#include "neighbour.h"
#include "error.h"
#include "util.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <libbabelhelper/babelhelper.h>

bool babeld_parse_line(char *line, void *ctx_p) {
	struct context *ctx = (struct context*) ctx_p;
	struct babelneighbour bn = { };

	if (!strncmp(line, "ok", 2)) {
		return false;
	}

	if (ctx->debug)
		printf("parsing line: %s\n", line);

	if (babelhelper_get_neighbour(&bn, line)) {

		if (!strncmp(bn.action, "add", 3))
			neighbour_add(ctx, &(bn.address), bn.ifname, bn.reach, bn.cost);
		else if (!strncmp(bn.action, "change", 6))
			neighbour_change(ctx, &(bn.address), bn.ifname, bn.reach, bn.cost);
		else if (!strncmp(bn.action, "flush", 5))
			neighbour_remove(ctx, &(bn.address), bn.ifname);

		if (ctx->verbose)
			print_neighbours(ctx);

		babelhelper_babelneighbour_free_members(&bn);
	}
	return true;
}

bool babeld_handle_in(struct context *ctx, int fd) {
	return babelhelper_input_pump(fd, (void*)ctx, babeld_parse_line);
}

int babeld_connect(int port) {
	int fd=-1;

	do {
		fd = babelhelper_babel_connect(port);
		if (fd < 0)
			fprintf(stderr, "Connecting to babel socket failed. Retrying.\n");
	} while (fd < 0);

	// read and ignore babel socket header-data
	babelhelper_input_pump(fd, NULL, babelhelper_discard_response);

	int amount = 0;
	while (amount != 8 ) {
		printf(stderr, "Sending monitor command to babel socket\n");
		amount = babelhelper_sendcommand(fd, "monitor\n");
	}

	return fd;
}
