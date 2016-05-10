
void tun_open(const char *ifname, uint16_t mtu, const char *dev_name) {
  int ctl_sock = -1;
  struct ifreq ifr = {};

  int fd = open(dev_name, O_RDWR|O_NONBLOCK);
  if (fd < 0)
    exit_errno("could not open TUN/TAP device file");

  if (ifname)
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ-1);

  ifr.ifr_flags = IFF_TUN | IFF_NO_PI;

  if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
    puts("unable to open TUN/TAP interface: TUNSETIFF ioctl failed");
    goto error;
  }

  // TODO this must be freed eventually
  ctx->ifname = strndup(ifr.ifr_name, IFNAMSIZ-1);

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

  if (close(ctl_sock))
    puts("close");

  return;

error:
  if (ctl_sock >= 0) {
    if (close(ctl_sock))
      puts("close");
  }

  close(fd);
  return -1;
}

int main(int argc, char *argv[]) {
  // open tun socket
  // open network socket
  // connect to babeld
  // receive packets from babeld
  // receive packets from tun, only accept IPv6 with multicast destination
  // receive packets from network
  // forward packets to neighbors
}
