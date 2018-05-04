FROM gcc:7.2

# Update & install packages & cleanup afterwards
RUN DEBIAN_FRONTEND=noninteractive \
    sed 's/main/main contrib/' -i /etc/apt/sources.list && \
    apt-get update && \
    apt-get -y upgrade && \
    apt-get -y install \
        build-essential \
        git \
	cmake \
	checkinstall \
	apt-transport-https && \
    apt-key adv --keyserver hkp://keys.gnupg.net --recv-keys 390BF305 && \
    echo 'deb https://dl.ffm.freifunk.net/debian-packages sid main ## FFFFM APT repo' > /etc/apt/sources.list.d/ffffm.list && \
    apt-get update && \
    apt-get clean autoclean && \
    apt-get autoremove && \
    rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["/bin/bash", "-c"]

