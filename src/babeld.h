#pragma once

#include "mmfd.h"

#include <stdbool.h>

bool babeld_handle_in(struct context *ctx, int fd);
int babeld_connect(struct context *ctx, int port);
