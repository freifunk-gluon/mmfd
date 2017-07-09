#pragma once
#include "error.h"
#include "mmfd.h"

void log_verbose(struct context *ctx, const char *format, ...);
void log_debug(struct context *ctx, const char *format, ...);
