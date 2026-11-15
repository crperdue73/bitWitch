FROM python:3.12-slim

# bitWitch: a web front end for the attack tools, sized for a classroom.
#
# Deliberately NOT a Kali image. Kali is a distro built for an interactive
# operator with a terminal; this container runs a handful of tools behind a
# form. Installing the three or four packages we actually call keeps the
# image small and the tool list knowable.

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      nmap \
      curl \
      sshpass \
      openssh-client \
      ca-certificates \
      gobuster \
      hydra \
      sqlmap \
      netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*

# Nikto is not packaged in Debian, so it is built from source. It needs a
# handful of Perl modules that are packaged, and one (XML::Writer) that must be
# named explicitly — without it nikto exits with "Required module not found"
# before it scans anything.
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      perl \
      libnet-ssleay-perl \
      libjson-perl \
      libxml-writer-perl \
      git \
 && git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto \
 && apt-get purge -y git && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/* /opt/nikto/.git \
 && printf '#!/bin/sh\nexec perl /opt/nikto/program/nikto.pl "$@"\n' > /usr/local/bin/nikto \
 && chmod 755 /usr/local/bin/nikto \
 && nikto -Version

WORKDIR /app

# Build stamp. Passed as a build arg so the image knows what it is.
# `docker compose build --build-arg GIT_COMMIT=$(git rev-parse HEAD)`.
# Absent is allowed at build time and refused at run time by _require_stamp()
# in app/main.py: an unstamped image builds, and then will not serve.
ARG GIT_COMMIT=""
ARG GIT_DIRTY=""
ARG BUILT_AT=""
ENV GIT_COMMIT=${GIT_COMMIT} \
    GIT_DIRTY=${GIT_DIRTY} \
    BUILT_AT=${BUILT_AT}

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY static ./static
COPY tests ./tests

RUN mkdir -p /data
VOLUME /data

EXPOSE 8099

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD curl -fsS http://127.0.0.1:8099/login >/dev/null || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8099"]
