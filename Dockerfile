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
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY static ./static

RUN mkdir -p /data
VOLUME /data

EXPOSE 8099

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s \
  CMD curl -fsS http://127.0.0.1:8099/login >/dev/null || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8099"]
