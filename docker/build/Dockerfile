FROM mmfdbase:latest

ENV REPO=https://github.com/freifunk-gluon/mmfd.git

# Update & install packages & cleanup afterwards
RUN DEBIAN_FRONTEND=noninteractive \
    apt-get update && \
    apt-get -y install \
        libbabelhelper  && \
    rm -rf /var/lib/apt/lists/* && \
    git clone $REPO && \
    mkdir mmfd/build

WORKDIR mmfd

# RUN make update

#ENTRYPOINT ["/bin/bash","-c"]
CMD git fetch --all && git reset --hard origin/master && cd build && cmake .. && make -j4

