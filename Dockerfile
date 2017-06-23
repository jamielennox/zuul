FROM ubuntu:xenial

MAINTAINER Jamie Lennox <jamielennox@gmail.com>

RUN apt-get update && \
    apt-get install -y --no-install-recommends software-properties-common && \
    add-apt-repository -y -u ppa:openstack-ci-core/bubblewrap && \
    apt-get install -y --no-install-recommends \
            build-essential \
            ca-certificates \
            bubblewrap \
            git \
            libffi-dev \
            libssl-dev \
            openssh-client \
            python3 \
            python3-dev \
            rsync \
            wget && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN wget -O- https://bootstrap.pypa.io/get-pip.py | python3

RUN groupadd -r zuul && \
    useradd -r -g zuul -d /var/lib/zuul -m zuul && \
    mkdir /var/lib/zuul/state /var/lib/zuul/merger && \
    chown -R zuul: /var/lib/zuul/

COPY . /opt/zuul

RUN pip install --no-cache-dir \
            /opt/zuul/ \
            statsd \
            git+https://github.com/sigmavirus24/github3.py.git@develop#egg=Github3.py

USER zuul
