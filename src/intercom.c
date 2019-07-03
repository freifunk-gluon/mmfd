#include <arpa/inet.h>
#include "intercom.h"
#include "error.h"
#include "mmfd.h"
#include "alloc.h"
#include "util.h"

#define INTERCOM_GROUP "ff02::6a8b"

void intercom_send_packet(struct context *ctx, uint8_t *packet, ssize_t packet_len);

int assemble_header(intercom_packet_hello *packet) {
	obtainrandom(&packet->hdr.nonce, sizeof(uint32_t), 0);
	return sizeof(uint32_t);
}

bool intercom_send_hello() {

	intercom_packet_hello *packet = mmfd_alloc(sizeof(struct header));

	int currentoffset = assemble_header(packet);
	VECTOR_ADD(ctx.seen, packet->hdr.nonce);
	log_verbose("sending hello " FMT_NONCE "\n", packet->hdr.nonce);


	intercom_send_packet(&ctx, (uint8_t *)packet, currentoffset);

	free(packet);
	return true;
}

bool leave_mcast(const struct in6_addr addr, interface *iface) {
	struct ipv6_mreq mreq;

	mreq.ipv6mr_multiaddr = addr;
	mreq.ipv6mr_interface = iface->ifindex;

	if (mreq.ipv6mr_interface == 0)
		goto error;

	if (setsockopt(ctx.intercomfd, IPPROTO_IPV6, IPV6_LEAVE_GROUP, &mreq, sizeof(mreq)) == 0)
		return true;

error:
	log_error("Could not leave multicast group on %s: ", iface->ifname);
	perror(NULL);
	return false;
}

bool join_mcast(const struct in6_addr addr, interface *iface) {
	struct ipv6_mreq mreq;

	mreq.ipv6mr_multiaddr = addr;
	mreq.ipv6mr_interface = iface->ifindex;

	if (mreq.ipv6mr_interface == 0)
		goto error;

	setsockopt(ctx.intercomfd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &mreq, sizeof(mreq));
	if (setsockopt(ctx.intercomfd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == 0)
		return true;
	else if (errno == EADDRINUSE)
		return true;

error:
	log_error("Could not join multicast group on %s: ", iface->ifname);
	perror(NULL);
	return false;
}

void intercom_update_interfaces(struct context *ctx) {
	for (int i = 0; i < VECTOR_LEN(ctx->interfaces); i++) {
		interface *iface = &VECTOR_INDEX(ctx->interfaces, i);

		iface->ifindex = if_nametoindex(iface->ifname);

		if (!iface->ifindex)
			continue;

		iface->ok = join_mcast(ctx->groupaddr.sin6_addr, iface);
	}
}

void intercom_send_packet(struct context *ctx, uint8_t *packet, ssize_t packet_len) {
	for (int i = 0; i < VECTOR_LEN(ctx->interfaces); i++) {
		interface *iface = &VECTOR_INDEX(ctx->interfaces, i);

		if (!iface->ok)
			continue;

		struct sockaddr_in6 _groupaddr = {};
		memcpy(&_groupaddr, &ctx->groupaddr, sizeof(struct sockaddr_in6));

		ssize_t rc = sendto(ctx->intercomfd, packet, packet_len, 0, (struct sockaddr *)&_groupaddr,
				    sizeof(struct sockaddr_in6));
		log_debug("sent intercom packet to %s on iface %s rc: %zi\n", print_ip(&_groupaddr.sin6_addr),
			  iface->ifname, rc);

		if (rc < 0)
			iface->ok = false;
	}
}

void intercom_init(struct context *ctx) {
	struct in6_addr mgroup_addr;
	if (inet_pton(AF_INET6, INTERCOM_GROUP, &mgroup_addr) < 1) {
		exit_errno("Could not convert intercom-group to network representation");
	};

	ctx->groupaddr = (struct sockaddr_in6){
	    .sin6_family = AF_INET6, .sin6_addr = mgroup_addr, .sin6_port = htons(PORT),
	};

	intercom_update_interfaces(ctx);
}

