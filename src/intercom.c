#include <arpa/inet.h>
#include "intercom.h"
#include "error.h"
#include "mmfd.h"
#include "alloc.h"
#include "util.h"

#include <search.h>
#include <unistd.h>

#define INTERCOM_GROUP "ff02::6a8b"

void intercom_send_packet_allif(struct context *ctx, uint8_t *packet, ssize_t packet_len);

int assemble_header(intercom_packet_hello *packet) {
	obtainrandom(&packet->hdr.nonce, sizeof(packet->hdr.nonce), 0);
	return sizeof(packet->hdr);
}

bool intercom_send_hello() {

	intercom_packet_hello *packet = mmfd_alloc(sizeof(struct header));

	int currentoffset = assemble_header(packet);
	VECTOR_ADD(ctx.seen, packet->hdr.nonce);
	log_verbose("sending hello " FMT_NONCE "\n", packet->hdr.nonce);

	intercom_send_packet_allif(&ctx, (uint8_t *)packet, currentoffset);

	free(packet);
	return true;
}

bool leave_mcast(const struct in6_addr addr, interface *iface) {

	if (!iface || !iface->ifindex)
		return false;

	struct ipv6_mreq mreq;

	mreq.ipv6mr_multiaddr = addr;
	mreq.ipv6mr_interface = iface->ifindex;

	if (setsockopt(iface->unicastfd, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq, sizeof(mreq)) == 0)
		return true;

	log_error("Could not leave multicast group on %s: ", iface->ifname);
	return false;
}

interface *find_interface_by_name(const char *ifname) {
	interface *ret = NULL;
	for (size_t i = 0; !ret && i < VECTOR_LEN(ctx.interfaces); i++) {
		interface *iface = &VECTOR_INDEX(ctx.interfaces, i);
		if (!strncmp(iface->ifname, ifname, IFNAMSIZ)) ret = iface;
	}

	return ret;
}

bool join_mcast(const struct in6_addr addr, interface *iface) {
	struct ipv6_mreq mreq = {};

	mreq.ipv6mr_multiaddr = addr;
	if (iface && iface->ifindex)
		mreq.ipv6mr_interface = iface->ifindex;
	else
		mreq.ipv6mr_interface = 0;


	if (iface && setsockopt(iface->unicastfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == 0)
		return true;
	else if (errno == EADDRINUSE)
		return true;
	else {
		log_error("Could not join multicast group on %s: %s", iface ? iface->ifname : "?", strerror(errno));
		return false;
	}
}


bool if_del(char *ifname) {
	if (VECTOR_LEN(ctx.interfaces)) {
		for (size_t i = 0; i < VECTOR_LEN(ctx.interfaces); i++) {
			interface *iface = &VECTOR_INDEX(ctx.interfaces, i);
			if (!strcmp(ifname, iface->ifname)) {
				if (iface->ok)
					close(iface->unicastfd);
				VECTOR_DELETE(ctx.interfaces, i);
				return true;
			}
		}
	}
	return false;
}

int if_compare_by_name(const interface *a, const interface *b) {
	return strncmp(a->ifname, b->ifname, IFNAMSIZ);
}

int socket_prepare(interface *iface) {
	int fd = socket(PF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (fd < 0) exit_error("creating socket");
	int on = 1;
	if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof(on)))
		exit_error("error on setsockopt (IPV6_V6ONLY)");

	if (setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)))
		exit_error("error on setsockopt (IPV6_RECVPKTINFO)");

	if (setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface->ifname,
		       strnlen(iface->ifname, IFNAMSIZ))) {
		exit_error("error on setsockopt (BIND) in socket_prepare()");
	}

	return fd;
}

void udp_open(interface *iface) {
	iface->unicastfd = socket_prepare(iface);

	struct sockaddr_in6 server_addr = {};
	server_addr.sin6_family = AF_INET6;
	server_addr.sin6_addr = in6addr_any;
	server_addr.sin6_port = htons(PORT);

	if (bind(iface->unicastfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
		exit_errno("bind failed");

	iface->ok = join_mcast(ctx.groupaddr.sin6_addr, iface);
}


bool if_add(char *ifname) {
	interface iface;

	strncpy(iface.ifname, ifname, IFNAMSIZ);

	struct interface *ret = (struct interface *)VECTOR_LSEARCH(&iface, ctx.interfaces, if_compare_by_name);
	if (ret)
		return false;

	iface.ifindex = if_nametoindex(ifname);
	iface.ok=false;

	if (iface.ifindex) {
		udp_open(&iface);
		change_fd(ctx.efd, iface.unicastfd, EPOLL_CTL_ADD, EPOLLIN | EPOLLET);
		VECTOR_ADD(ctx.interfaces, iface);
		return true;
	}

	return false;
}

void intercom_update_interfaces(struct context *ctx) {
	if (VECTOR_LEN(ctx->interfaces)) {
		for (size_t i = 0; i < VECTOR_LEN(ctx->interfaces); i++) {
			interface *iface = &VECTOR_INDEX(ctx->interfaces, i);

			iface->ifindex = if_nametoindex(iface->ifname);

			if (iface->ifindex) {
				iface->ok = join_mcast(ctx->groupaddr.sin6_addr, iface);

				if (setsockopt(iface->unicastfd, SOL_SOCKET, SO_BINDTODEVICE, iface->ifname,
							strnlen(iface->ifname, IFNAMSIZ))) {
					exit_error("error on setsockopt (BIND) in intercom_update_interfaces()");
				}
			}
		}
	}
}

void intercom_send_packet_allif(struct context *ctx, uint8_t *packet, ssize_t packet_len) {
	for (size_t i = 0; i < VECTOR_LEN(ctx->interfaces); i++) {
		interface *iface = &VECTOR_INDEX(ctx->interfaces, i);
		ctx->groupaddr.sin6_scope_id = iface->ifindex;
		ssize_t rc = sendto(iface->unicastfd, packet, packet_len, 0, (struct sockaddr*)&ctx->groupaddr, sizeof(struct sockaddr_in6));
		if (rc < 0)
			perror("sendto");
		log_debug("sent intercom packet on %s to %s rc: %zi\n", iface->ifname, print_ip(&ctx->groupaddr.sin6_addr), rc);
	}
	ctx->groupaddr.sin6_scope_id = 0;
}

void intercom_init(struct context *ctx) {
	struct in6_addr mgroup_addr;
	if (inet_pton(AF_INET6, INTERCOM_GROUP, &mgroup_addr) < 1) {
		exit_errno("Could not convert intercom-group to network representation");
	};

	ctx->groupaddr = (struct sockaddr_in6){
	    .sin6_family = AF_INET6, .sin6_addr = mgroup_addr, .sin6_port = htons(PORT),
	};
}

