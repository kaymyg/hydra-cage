# The containment layer image.
#
# Kept intentionally minimal: a layer is a security boundary, not a service.
# The smaller and more boring this image is, the smaller the measured surface
# and the fewer tools an escaped workload has to hand.
#
#   docker build -t hydra-layer:latest docker/
#
# Runtime hardening is applied at `docker run` time by the containment plane
# (--cap-drop ALL, --security-opt no-new-privileges, --read-only, --network
# internal, no docker socket, pids and memory limits). Nothing here needs to
# know about the supervisor, and nothing here can reach it.

FROM python:3.14-alpine

# Nothing added. Busybox only, no network clients, no build toolchain.
RUN rm -rf /var/cache/apk/* && \
    adduser -D -u 10001 -s /sbin/nologin hydra && \
    mkdir -p /hydra/payload /hydra/state && \
    chown -R hydra:hydra /hydra/state

# The payload is bind-mounted read-only at run time; this only reserves the
# mountpoint so the measurement has a stable path.
WORKDIR /hydra/payload

USER hydra

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HYDRA_STATE=/hydra/state

# Overridden by the containment plane with the real entrypoint path.
CMD ["python3", "/hydra/payload/layer_entrypoint.py"]
