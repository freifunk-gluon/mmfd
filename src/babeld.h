#pragma once

#include "mmfd.h"

#include <stdbool.h>

int babeld_handle_in(struct context *ctx, int fd);
int babeld_connect(struct context *ctx);
