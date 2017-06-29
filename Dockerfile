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
            supervisor \
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

RUN echo "[supervisord]" > /etc/supervisord-base.conf && \
    echo "nodaemon=True" >> /etc/supervisord-base.conf && \
    echo "" >> /etc/supervisord-base.conf && \
    echo "[program:zuul]" >> /etc/supervisord-base.conf && \
    echo "user=zuul" >> /etc/supervisord-base.conf && \
    echo "stdout_logfile=/dev/fd/1" >> /etc/supervisord-base.conf && \
    echo "stdout_logfile_maxbytes=0" >> /etc/supervisord-base.conf && \
    echo "stderr_logfile=/dev/fd/2" >> /etc/supervisord-base.conf && \
    echo "stderr_logfile_maxbytes=0" >> /etc/supervisord-base.conf && \
    cp /etc/supervisord-base.conf /etc/supervisord-sched.conf && \
    cp /etc/supervisord-base.conf /etc/supervisord-exec.conf && \
    cp /etc/supervisord-base.conf /etc/supervisord-merger.conf && \
    echo "command=/usr/local/bin/zuul-scheduler -d -c /etc/zuul/zuul.conf" >> /etc/supervisord-sched.conf && \
    echo "command=/usr/local/bin/zuul-executor -d -c /etc/zuul/zuul.conf --keep-jobdir" >> /etc/supervisord-exec.conf && \
    echo "command=/usr/local/bin/zuul-merger -d -c /etc/zuul/zuul.conf" >> /etc/supervisord-merger.conf && \
    echo "" >> /etc/supervisord-sched.conf && \
    echo "" >> /etc/supervisord-exec.conf && \
    echo "" >> /etc/supervisord-merger.conf

COPY . /opt/zuul

RUN pip install --no-cache-dir \
            /opt/zuul/ \
            statsd \
            git+https://github.com/sigmavirus24/github3.py.git@develop#egg=Github3.py

#USER zuul

CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
