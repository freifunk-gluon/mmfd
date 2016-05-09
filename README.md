# Mesh Multicast Flooding Daemon

The Mesh Multicast Flooding Daemon helps with spreading packets in a layer 3
mesh. It provides a tun interface where it accepts packets for forwarding to all
other nodes. This is rather simple for now, but it may be improved in a future
release. After that, it'll be renamed to Mesh Multicast Forwarding Daemon.

mmfd is built to work in tandem with babeld. It'll connect to babeld's front-end
where it'll listen for mesh neighbours discovered by babeld.

# Todo

- connect to babeld
- listen for neighbours
- automatically create sockets as needed
- create tun device
- set MTU to 1280
