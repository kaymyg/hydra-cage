# Hugging Face Space (Docker SDK).
#
# Note the recursion: this container hosts a demonstration of container-based
# containment. It cannot nest real containers -- Spaces do not expose a Docker
# daemon -- so the demo runs the process backend, which has the same trust
# topology. See docker/Dockerfile in the repo for the layer image the real
# containment plane uses.

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HYDRA_NO_COLOR=1 \
    GRADIO_SERVER_NAME=0.0.0.0 \
    GRADIO_SERVER_PORT=7860 \
    HOME=/home/user

RUN useradd -m -u 1000 user
USER user
ENV PATH=/home/user/.local/bin:$PATH
WORKDIR /home/user/app

COPY --chown=user requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

COPY --chown=user . .

EXPOSE 7860
CMD ["python", "app.py"]
