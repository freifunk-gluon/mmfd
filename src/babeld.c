// connect to babeld
// reconnect
// notifiy about client changes

#include "babeld.h"
#include "neighbor.h"
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

  int n = sscanf(line, "%ms neighbour %*x address %ms if %ms "
                       "reach %x rxcost %*d txcost %*d cost %d",
                       &action, &address_str, &ifname, &reach, &cost);

  if (n != 5)
    goto end;

  struct in6_addr address;

  if (inet_pton(AF_INET6, address_str, &address) != 1)
    // TODO print warning
    goto end;

  if (strcmp(action, "add") == 0)
    neighbor_add(ctx, &address, ifname, reach, cost);

  if (strcmp(action, "change") == 0)
    neighbor_change(ctx, &address, ifname, reach, cost);

  if (strcmp(action, "flush") == 0)
    neighbor_flush(ctx, &address, ifname);

  print_neighbors(ctx);

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

  return fd;
}
