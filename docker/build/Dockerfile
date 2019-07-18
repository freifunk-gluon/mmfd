FROM mmfdbase:latest

ENV REPO=https://github.com/freifunk-gluon/mmfd.git

# Update & install packages & cleanup afterwards
RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update && \
    apt-get -y install libjson-c-dev && \
    rm -rf /var/lib/apt/lists/* && \
    git clone $REPO && \
    mkdir mmfd/build

WORKDIR mmfd

# ENTRYPOINT ["/bin/bash"]
CMD git fetch --all && git reset --hard origin/master && cd build && cmake .. && make -j4

