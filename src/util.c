#include "util.h"
#include <arpa/inet.h>
#include "error.h"

#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>


union buffer strbuffer;
static int str_bufferoffset = 0;

void log_error(const char *format, ...) {
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}

void log_debug(const char *format, ...) {
	if (!ctx.debug)
		return;
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}

void log_verbose(const char *format, ...) {
	if (!ctx.verbose)
		return;
	va_list args;
	va_start(args, format);
	vfprintf(stderr, format, args);
	va_end(args);
}

/** print a timespec to buffer
** */
const char *print_timespec(const struct timespec *t) {
	str_bufferoffset = (str_bufferoffset + 1) % STRBUFELEMENTS;
	snprintf(strbuffer.element[str_bufferoffset], STRBUFELEMENTLEN, "%lu.%09lu", t->tv_sec, t->tv_nsec);
	return strbuffer.element[str_bufferoffset];
}

/* print a human-readable representation of an in6_addr struct to stdout
** ** */
const char *print_ip(const struct in6_addr *addr) {
	str_bufferoffset = (str_bufferoffset + 1) % STRBUFELEMENTS;
	return inet_ntop(AF_INET6, &(addr->s6_addr), strbuffer.element[str_bufferoffset], STRBUFELEMENTLEN);
}

void print_packet(unsigned char *buf, int size) {
	if (!ctx.debug)
		return;

	log_debug("Packet: [");
	for (int i = 0; i < size; i++) {
		if (i % 4 == 0)
			log_debug(" ");
		log_debug("%02hhX", buf[i]);
	}
	log_debug("]\n");
}


int obtainrandom(void *buf, size_t buflen, unsigned int flags) {
	int rc = 0;
	while (rc != (int)buflen) {
		rc = (int)syscall(SYS_getrandom, buf, buflen, flags);
		if (rc == -1) {
			if (errno != ENOSYS) {
				exit_error("syscall SYS_getrandom.");
			}
			perror("syscall SYS_getrandom failed. retrying");
		}
	}
	return rc;
}

