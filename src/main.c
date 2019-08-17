#include "mmfd.h"
#include "alloc.h"
#include "error.h"
#include "util.h"
#include "neighbour.h"
#include "taskqueue.h"
#include "intercom.h"

#include <linux/ipv6.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>

#define NEIGHBOUR_PRINT_INTERVAL 5
#define MTU 1280

static void change_fd(int efd, int fd, int type, uint32_t events);
static void handle_udp_packet(struct context *ctx,  struct sockaddr_in6 *src_addr, struct header *hdr, uint8_t *packet, ssize_t len);
bool is_seen(uint64_t nonce);
struct context ctx = {};

void send_hello_task(__attribute__ ((unused)) void *d) {
	intercom_send_hello();

	post_task(&ctx.taskqueue_ctx, HELLO_INTERVAL, 0, send_hello_task, NULL, NULL);
}

void print_neighbours_task(__attribute__ ((unused)) void *d) {
	if (ctx.verbose)
		print_neighbours();
	post_task(&ctx.taskqueue_ctx, NEIGHBOUR_PRINT_INTERVAL, 0, print_neighbours_task, NULL, NULL);
}

int udp_open() {
	int fd = socket(PF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);

	if (fd < 0)
		exit_error("creating socket");
	int on = 1;
	if(setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)))
		exit_error("error on setsockopt (IPV6_V6ONLY)");

	if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)))
		exit_error("error on setsockopt (IPV6_RECVPKTINFO)");

	struct sockaddr_in6 server_addr = {};

	server_addr.sin6_family = AF_INET6;
	server_addr.sin6_addr = in6addr_any;
	server_addr.sin6_port = htons(PORT);

	if (VECTOR_LEN(ctx.interfaces)) {
		for (size_t i = 0; i < VECTOR_LEN(ctx.interfaces); i++) {
			interface *iface = &VECTOR_INDEX(ctx.interfaces, i);
			if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface->ifname, strnlen(iface->ifname, IFNAMSIZ))) {
				exit_error("error on setsockopt (BIND)");
			}
		}
	}

	if (bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
		exit_errno("bind failed");

	return fd;
}

/**
 * tun_open - open a tun device, set mtu and return it
 * @ifname: name of the interface to open
 * @mtu: mtu to assign to the device
 * @dev_name: path to the tun device node (normally this should be "/dev/net/tun")
 *
 * Return: filedescriptor to tun device on success, otherwise -1
 */
int tun_open(const char *ifname, uint16_t mtu, const char *dev_name) {
	int ctl_sock = -1;
	struct ifreq ifr = {};

	// open tun iface
	int fd = open(dev_name, O_RDWR|O_NONBLOCK);
	if (fd < 0)
		exit_errno("could not open TUN/TAP device file");

	// set name of the iface
	if (ifname)
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

	if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
		puts("unable to open TUN/TAP interface: TUNSETIFF ioctl failed");
		goto error;
	}

	// open control socket to set the mtu of the iface
	ctl_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (ctl_sock < 0)
		exit_errno("socket");

	if (ioctl(ctl_sock, SIOCGIFMTU, &ifr) < 0)
		exit_errno("SIOCGIFMTU ioctl failed");

	if (ifr.ifr_mtu != mtu) {
		ifr.ifr_mtu = mtu;
		if (ioctl(ctl_sock, SIOCSIFMTU, &ifr) < 0) {
			puts("unable to set TUN/TAP interface MTU: SIOCSIFMTU ioctl failed");
			goto error;
		}
	}

	ifr.ifr_flags = IFF_UP | IFF_RUNNING| IFF_MULTICAST | IFF_NOARP | IFF_POINTOPOINT;
	if (ioctl(ctl_sock, SIOCSIFFLAGS, &ifr) < 0 ) {
		puts("unable to set TUN/TAP interface UP: SIOCSIFFLAGS ioctl failed");
		goto error;
	}

	if (close(ctl_sock))
		puts("close");

	return fd;

error:
	if (ctl_sock >= 0) {
		if (close(ctl_sock))
			puts("close");
	}

	close(fd);
	return -1;
}

bool is_seen(uint64_t nonce) {

	while (VECTOR_LEN(ctx.seen) > 2000)
		VECTOR_DELETE(ctx.seen, 0);

	for (size_t i = 0; i < VECTOR_LEN(ctx.seen); i++) {
		log_debug("checking whether we have seen packet " FMT_NONCE ", comparing with " FMT_NONCE "\n", nonce, VECTOR_INDEX(ctx.seen, i));
		if (VECTOR_INDEX(ctx.seen, i) == nonce) {
			log_verbose("we already saw nonce " FMT_NONCE "\n", nonce);
			return true;
		}
	}
	return false;
}

bool forward_packet(struct context *ctx, uint8_t *packet, ssize_t len, uint64_t nonce, struct sockaddr_in6 *src_addr) {

	struct header hdr = {
		.nonce = nonce,
	};

	struct iovec iov[2] = {
		{
			.iov_base = &hdr,
			.iov_len = sizeof(hdr),
		},
		{
			.iov_base = packet,
			.iov_len = len,
		}
	};

	struct ipv6hdr *packethdr = (struct ipv6hdr*)packet;

	if (VECTOR_LEN(ctx->neighbours) == 0) {
		log_verbose("No neighbour found. Cannot forward packet with destaddr=%s, nonce=" FMT_NONCE ".\n", print_ip(&packethdr->daddr), nonce);
		return true;
	}

	for (size_t i = 0; i < VECTOR_LEN(ctx->neighbours); i++) {
		struct neighbour *neighbour = &VECTOR_INDEX(ctx->neighbours, i);

		int forwardmessage =  src_addr ?
					memcmp(&src_addr->sin6_addr, &(neighbour->address.sin6_addr), sizeof(struct in6_addr)) &&
					src_addr->sin6_scope_id == neighbour->address.sin6_scope_id
				      : 1;

		if (forwardmessage) {
			struct msghdr msg = {
				.msg_name = &neighbour->address,
				.msg_namelen = sizeof(struct sockaddr_in6),
				.msg_iov = iov,
				.msg_iovlen = 2,
			};

			log_verbose("Forwarding packet from %s with destaddr=%s, nonce=" FMT_NONCE " to %s%%%s [%zd].\n",
				    src_addr ? print_ip(&src_addr->sin6_addr) : "local", print_ip(&packethdr->daddr), nonce,
				    print_ip(&neighbour->address.sin6_addr), neighbour->ifname, neighbour->address.sin6_scope_id);

			if (sendmsg(ctx->intercomfd, &msg, 0) < 0)
				perror("sendmsg");
		}
	}

	return true;
}

void udp_handle_in(struct context *ctx, int fd) {
	log_debug("handling intercom packet\n");
	while (1) {
		struct header hdr = {};
		uint8_t buffer[1500];
		struct sockaddr_in6 src_addr = {};

		struct iovec iov[2] = {{
					   .iov_base = &hdr, .iov_len = sizeof(hdr),
				       },
				       {
					   .iov_base = buffer, .iov_len = sizeof(buffer),
				       }};

		uint8_t cmbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];

		struct msghdr message = {
		    .msg_name = &src_addr,
		    .msg_namelen = sizeof(src_addr),
		    .msg_iov = iov,
		    .msg_iovlen = 2,
		    .msg_control = cmbuf,
		    .msg_controllen = sizeof(cmbuf),
		};

		ssize_t count = recvmsg(fd, &message, 0);
		log_debug("read %zd bytes\n", count);

		if (count == -1 && errno == EAGAIN)
			break;

		if (count == -1)
			perror("Error during recvmsg");
		else if (count > 0 && (size_t)count < sizeof(hdr))
			continue;
		else if (message.msg_flags & MSG_TRUNC)
			log_error("Message too long for buffer\n");
		else {
			if (is_seen(hdr.nonce))
				continue;
			VECTOR_ADD(ctx->seen, hdr.nonce);

			for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message); cmsg != NULL; cmsg = CMSG_NXTHDR(&message, cmsg)) {
				if ((cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO)) {
					struct in6_pktinfo *pi = (struct in6_pktinfo *)CMSG_DATA(cmsg);

					bool is_packet_dest_mcast = memcmp(&pi->ipi6_addr, &ctx->groupaddr.sin6_addr, sizeof(ctx->groupaddr.sin6_addr)) == 0;

					if (is_packet_dest_mcast) {
						log_verbose("received packet " FMT_NONCE " from %s for %s\n", hdr.nonce,
							    print_ip(&src_addr.sin6_addr), print_ip(&pi->ipi6_addr));
						char buf[IFNAMSIZ];
						char *ifname = if_indextoname(pi->ipi6_ifindex, buf);
						neighbour_change(ctx, &src_addr.sin6_addr, ifname);
					} else {
						handle_udp_packet(ctx, &src_addr, &hdr, buffer, count - sizeof(hdr));
					}
					break;
				}
			}
		}
	}
}

void handle_udp_packet(struct context *ctx,  struct sockaddr_in6 *src_addr, struct header *hdr, uint8_t *packet, ssize_t len) {
	if (forward_packet(ctx, packet, len, hdr->nonce, src_addr)) {
		log_verbose("writing packet to tun interface\n");
		write(ctx->tunfd, packet, len);
	}
}

void handle_packet(struct context *ctx, uint8_t *packet, ssize_t len) {
	uint64_t nonce;
	obtainrandom(&nonce, sizeof(nonce), 0);

	VECTOR_ADD(ctx->seen, nonce);
	forward_packet(ctx, packet, len, nonce, NULL);
}

void tun_handle_in(struct context *ctx, int fd) {
	ssize_t count;

	uint8_t buf[MTU];

	while (1) {
		count = read(fd, buf, MTU);

		if (count == -1) {
			/* If errno == EAGAIN, that means we have read all
			   data. So go back to the main loop. */
			if (errno != EAGAIN) {
				perror("read");
			}
			break;
		} else if (count == 0) {
			break;
		}

		if (count < 40) // ipv6 header has 40 bytes
			continue;

		struct ipv6hdr *hdr = (struct ipv6hdr*)buf;

		if (hdr->version != 6) {
			log_verbose("Dropping non-IPv6 packet.\n");
			continue;
		}

		// Ignore any non-multicast packets
		if (hdr->daddr.s6_addr[0] != 0xff) {
			log_verbose("Dropping non multicast packet destined to %s.\n", print_ip(&hdr->daddr));

			continue;
		}

		handle_packet(ctx, buf, count);
	}
}

void change_fd(int efd, int fd, int type, uint32_t events) {
	struct epoll_event event = {};
	event.data.fd = fd;
	event.events = events;

	int s = epoll_ctl(efd, type, fd, &event);
	if (s == -1)
		exit_error("epoll_ctl");
}

void loop(struct context *ctx) {
	ctx->efd = epoll_create(1);

	if (ctx->efd == -1)
		exit_errno("epoll_create");

	change_fd(ctx->efd, ctx->intercomfd, EPOLL_CTL_ADD, EPOLLIN | EPOLLET);
	change_fd(ctx->efd, ctx->tunfd, EPOLL_CTL_ADD, EPOLLIN | EPOLLET);
	change_fd(ctx->efd, ctx->taskqueue_ctx.fd, EPOLL_CTL_ADD, EPOLLIN);

	if (ctx->socket_ctx.fd)
		change_fd(ctx->efd, ctx->socket_ctx.fd, EPOLL_CTL_ADD, EPOLLIN);

	int maxevents = 64;
	struct epoll_event *events;
	events = mmfd_alloc0_array(maxevents, sizeof(struct epoll_event));

	while (1) {
		log_debug("epoll_wait: ... ");
		int n = epoll_wait(ctx->efd, events, maxevents, -1);
		log_debug("%i\n", n);

		for ( int i = 0; i < n; i++ ) {
			if (ctx->intercomfd == events[i].data.fd) {
				log_debug("event on intercomfd\n");
				if (events[i].events & EPOLLIN) {
					udp_handle_in(ctx, events[i].data.fd);
				}
			} else if (ctx->taskqueue_ctx.fd == events[i].data.fd) {
				log_debug("event on taskqueue\n");
				taskqueue_run(&ctx->taskqueue_ctx);
			} else if (ctx->socket_ctx.fd == events[i].data.fd) {
				log_debug("event on socketfd\n");
				socket_handle_in(&ctx->socket_ctx);
			} else if (ctx->tunfd == events[i].data.fd) {
				log_debug("event on tunfd\n");
				if (events[i].events & EPOLLIN)
					tun_handle_in(ctx, events[i].data.fd);
			} else {
				char junk;
				read(events[i].data.fd, &junk, 1);
				log_error("THIS SHOULD NEVER HAPPEN: Data arrived on fd %d which we are not monitoring in our loop, discarding data: %c\n", events[i].data.fd, junk);
			}
		}
	}

	free(events);
}

void usage() {
	puts("Usage: mmfd [-h] [-v] [-d] [-D <devicename>] [-i <mesh-device>] [-i <mesh-device>] [-s /path/to/socket]");
	puts("  -v     verbose");
	puts("  -d     debug");
	puts("  -D     name of the mmfd device");
	puts("  -s     socket on which the commands: verbosity [none, verbose,debug], add_meshif <ifname>, del_meshif <ifname>, get_neighbours and get_meshifs are valid");
	puts("  -i     bind to interface, may be specified multiple times");
	puts("  -h     this help");
}

int main(int argc, char *argv[]) {
	int c;
	char mmfd_device[IFNAMSIZ] = "mmfd0";
	memset(&ctx, 0, sizeof(ctx));
	ctx.verbose = false;
	ctx.debug = false;

	VECTOR_INIT(ctx.seen);
	VECTOR_INIT(ctx.neighbours);
	VECTOR_INIT(ctx.interfaces);

	while ((c = getopt(argc, argv, "vhds:D:i:")) != -1)
		switch (c) {
			case 'd':
				ctx.debug = true;
				break;
			case 'v':
				ctx.verbose = true;
				break;
			case 'h':
				usage();
				exit(EXIT_SUCCESS);
			case 'D':
				snprintf(mmfd_device, IFNAMSIZ, "%s", optarg);
				break;
			case 's':
				socket_init(&ctx.socket_ctx, optarg);
				break;
			case 'i':
				if (!if_add(optarg))
					fprintf(stderr, "Could not find device %s. ignoring.\n", optarg);
				break;
			default:
				fprintf(stderr, "Invalid parameter %c ignored.\n", c);
		}

	ctx.intercomfd = udp_open();

	int rfd = open("/dev/urandom", O_RDONLY);
	unsigned int seed;
	read(rfd, &seed, sizeof(seed));
	close(rfd);
	srand(seed);

	ctx.tunfd = tun_open(mmfd_device, MTU, "/dev/net/tun");

	if (ctx.tunfd == -1)
		exit_error("Can not create tun device");

	taskqueue_init(&ctx.taskqueue_ctx);

	print_neighbours_task(NULL);

	intercom_init(&ctx);

	send_hello_task(NULL);

	loop(&ctx);
	return 0;
}
