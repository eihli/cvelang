FROM postgres:15

RUN apt-get update && apt-get install -y \
    make \
    gcc \
    libc6-dev \
    git \
    postgresql-server-dev-15 \
 && git clone --branch v0.4.0 https://github.com/pgvector/pgvector.git /tmp/pgvector \
 && cd /tmp/pgvector && make && make install \
 && rm -rf /tmp/pgvector \
 && apt-get remove -y git gcc libc6-dev postgresql-server-dev-15 \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*
