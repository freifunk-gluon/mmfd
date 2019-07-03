#pragma once
#include "error.h"
#include "timespec.h"
#include "mmfd.h"

#define STRBUFELEMENTLEN 64
#define STRBUFLEN 256
#define STRBUFELEMENTS (STRBUFLEN / STRBUFELEMENTLEN)

union buffer {
	char element[STRBUFLEN / STRBUFELEMENTLEN][STRBUFELEMENTLEN];
	char allofit[STRBUFLEN];
};

const char *print_timespec(const struct timespec *t);
void log_error(const char *format, ...);
void log_verbose(const char *format, ...);
void log_debug(const char *format, ...);
const char *print_ip(const struct in6_addr *addr);
void print_packet(unsigned char *buf, int size);
int obtainrandom(void *buf, size_t buflen, unsigned int flags);

