FROM mmfdbase:latest

ENV REPO=https://github.com/freifunk-gluon/mmfd.git

# Update & install packages & cleanup afterwards
RUN DEBIAN_FRONTEND=noninteractive \
    echo 'deb https://dl.ffm.freifunk.net/debian-packages sid main ## FFFFM APT repo' > /etc/apt/sources.list.d/ffffm.list && \
    apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install libjson-c-dev && \
    apt-get clean autoclean && \
    apt-get autoremove && \
    rm -rf /var/lib/apt/lists/*

RUN git clone $REPO
WORKDIR mmfd

RUN pwd

# RUN make update

ENTRYPOINT ["/bin/bash"]
# CMD ["./site/build.sh", "-v"] 

