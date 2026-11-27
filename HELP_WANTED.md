# Help wanted

The Hydra Cage is open to contributions. Below is the hardening work that would make it stronger, roughly in order of impact. Pick anything, comment on (or open) an issue so others know you are on it, and see [CONTRIBUTING.md](CONTRIBUTING.md) to get started.

Found a vulnerability instead? Please report it privately, see [SECURITY.md](SECURITY.md).


### Seccomp profile for the Docker backend

**Medium.** The container already drops all capabilities and runs read-only. A tight seccomp profile would cut the syscall surface further.

### Pin container images by digest

**Medium.** Reference base images by `@sha256:` digest so builds are reproducible and cannot change underneath you.

### New adversaries

**Medium.** Add escape techniques to the adversary suite. Each one should either be contained or produce a clear failing test.
