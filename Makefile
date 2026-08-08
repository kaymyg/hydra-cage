PY ?= python3
WORKDIR ?= ./.hydra
LAYERS ?= 4
GH_REPO ?= kaymyg/hydra-cage
HF_SPACE ?= Sahek/hydra-cage

.PHONY: help image demo demo-docker attack attack-docker up breach test forensics \
        space space-push clean

help:
	@echo "Hydra Cage"
	@echo ""
	@echo "  make image         build the containment layer container image"
	@echo "  make demo          full demo (process backend, no Docker needed)"
	@echo "  make demo-docker   full demo on real containers"
	@echo "  make attack        adversary suite, process backend"
	@echo "  make attack-docker adversary suite, real containers"
	@echo "  make up            boot and sweep continuously (ctrl-c to stop)"
	@echo "  make breach        force one breach transition and show all 8 stages"
	@echo "  make test          unit + integration tests"
	@echo "  make forensics     list sealed artifacts from the last run"
	@echo ""
	@echo "  make space         stage the Hugging Face Space into build/space"
	@echo "  make space-push    stage and upload to $(HF_SPACE)"
	@echo "  make clean         remove the workdir and any stray containers"

image:
	docker build -t hydra-layer:latest docker/

demo:
	$(PY) hydra_cli.py --backend process --layers $(LAYERS) --workdir $(WORKDIR) demo

demo-docker: image
	$(PY) hydra_cli.py --backend docker --layers $(LAYERS) --workdir $(WORKDIR) demo

attack:
	$(PY) hydra_cli.py --backend process --layers $(LAYERS) --workdir $(WORKDIR) attack

attack-docker: image
	$(PY) hydra_cli.py --backend docker --layers $(LAYERS) --workdir $(WORKDIR) attack

up:
	$(PY) hydra_cli.py --layers $(LAYERS) --workdir $(WORKDIR) up

breach:
	$(PY) hydra_cli.py --layers $(LAYERS) --workdir $(WORKDIR) breach --layer 0

test:
	$(PY) -m pytest tests/ -q

forensics:
	$(PY) hydra_cli.py --workdir $(WORKDIR) forensics

space:
	./scripts/build_space.sh

space-push:
	./scripts/push_space.sh $(HF_SPACE)

clean:
	-docker ps -aq --filter "name=hydra-" | xargs -r docker rm -f
	-docker network ls -q --filter "name=hydra-net-" | xargs -r docker network rm
	chmod -R u+w $(WORKDIR) build 2>/dev/null || true
	rm -rf $(WORKDIR) build
	find . -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
