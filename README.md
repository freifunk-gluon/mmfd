# Mesh Multicast Flooding Daemon

The Mesh Multicast Flooding Daemon helps with spreading packets in a layer 3
mesh. It provides a tun interface where it accepts packets for forwarding to
all other nodes.

mmfd is built to work in tandem with babeld. Until
`22996796e2f62972c2d70f94b0f656ec4968a55a` it connects to babeld's front-end
where to listens for mesh neighbours discovered by babeld.

More recently, mmfd sends multicast messages to discover its own neighbours
making it independent from the mesh protocol and lightening the load on a
potentially very busy babeld.

## Build

Dependecies:
- json-c
- pkg-config
- cmake
- make
- gcc

Archlinux: `pacman -S base-devel cmake json-c`

```
mkdir build
cd build
cmake ..
make -j$(grep -c '^processor' /proc/cpuinfo)
cp src/mmfd /usr/local/bin/mmfd
```


