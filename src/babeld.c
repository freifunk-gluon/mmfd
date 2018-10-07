#include "babeld.h"
#include "neighbour.h"
#include "error.h"
#include "util.h"

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <libbabelhelper/babelhelper.h>

bool babeld_handle_neighbour(char **data, void *ctx_p) {
	struct context *ctx = (struct context*) ctx_p;
	if (ctx->debug)
		printrecognized(data);
	if (data[VERB] && data[NEIGHBOUR] && data[ADDRESS] && data[IF]) {
		if (ctx->verbose)
			printf("handling neighbour %s\n", data[ADDRESS]);
		struct in6_addr addr;
		inet_pton(AF_INET6, data[ADDRESS], &addr);
		if (data[COST] &&
		    data[REACH] &&
		   ( !strncmp(data[VERB], "add", 3) || !strncmp(data[VERB], "change", 6) )
		   )
				neighbour_change(ctx, &addr, data[IF], atoi(data[REACH]), atoi(data[COST]));
		else if (!strncmp(data[VERB], "flush", 5)) {
			if (ctx->verbose)
				printf("removing neighbour %s\n", data[ADDRESS]);
			neighbour_remove(ctx, &addr, data[IF]);
		}

	}
	return true;
}

int babeld_handle_in(struct context *ctx, int fd) {
	struct babelhelper_ctx bhelper_ctx = {};
	bhelper_ctx.debug=ctx->debug;
	return babelhelper_input_pump(&bhelper_ctx, fd, (void*)ctx, babeld_handle_neighbour);
}

int babeld_connect(struct context *ctx) {
	int fd=-1;

	struct babelhelper_ctx bhelper_ctx = {};
	bhelper_ctx.debug=ctx->debug;

	do {
		fd = babelhelper_babel_connect(ctx->babelport);
		if (fd < 0) {
			fprintf(stderr, "Connecting to babel socket failed. Retrying.\n");
			usleep(1000000);
		}
	} while (fd < 0);

	// read and ignore babel socket header-data
	while (! babelhelper_input_pump(&bhelper_ctx, fd, NULL, babelhelper_discard_response));

	int amount = 0;
	while (amount != 8 ) {
		if (ctx->debug)
			fprintf(stderr, "Sending monitor command to babel socket\n");
		amount = babelhelper_sendcommand(&bhelper_ctx, fd, "monitor\n");
	}

	return fd;
}
