#include "mmfd.h"

void log_verbose(struct context *ctx, const char *format, ...) {
	if (!ctx->verbose)
		return;

	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}
