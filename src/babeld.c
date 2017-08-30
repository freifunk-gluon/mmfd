#include "babeld.h"
#include "neighbour.h"
#include "error.h"
#include "util.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <libbabelhelper/babelhelper.h>

void babeld_parse_line(char *line, void *ctx_p) {
	struct context *ctx = (struct context*) ctx_p;
	struct babelneighbour bn;

	if (ctx->debug)
		printf("parsing line: %s\n", line);

	if (! babelhelper_get_neighbour(&bn, line)) {

		if (!strncmp(bn.action, "add", 3))
			neighbour_add(ctx, &(bn.address), bn.ifname, bn.reach, bn.cost);
		else if (!strncmp(bn.action, "change", 6))
			neighbour_change(ctx, &(bn.address), bn.ifname, bn.reach, bn.cost);
		else if (!strncmp(bn.action, "flush", 5))
			neighbour_remove(ctx, &(bn.address), bn.ifname);

		babelhelper_babelneighbour_free(&bn);
	}

}

bool babeld_handle_in(struct context *ctx, int fd) {
	input_pump(fd,  (void*)ctx, 0, babeld_parse_line);

	if (ctx->verbose)
		print_neighbours(ctx);

	return true;
}

int babeld_connect(int port) {
	int fd = babelhelper_babel_connect(port);

	// read and ignore babel socket header-data
	input_pump(fd, NULL, 1, NULL);

	// TODO: this is not a good idea? We could receive EAGAIN!
	if (send(fd, "monitor\n", 8, 0) != 8) {
		exit_errno("Error while subscribing to babel events");
	}

	return fd;
}
