## What does this change do?

<!-- Brief description -->

## Checklist

- [ ] `make test` passes (58 tests)
- [ ] `make attack` still shows 10/10 blocked
- [ ] If this touches `web/` or `space_publish.py`: `python space_publish.py --build` succeeds
- [ ] `payload/` still doesn't import anything from `hydra/`
- [ ] If this changes what's reachable from the execution plane:
      `ExecutionPlane.audit_reachability()` still returns `[]`
- [ ] Updated the README (architecture, "Honest limits", or "Layout") if this
      changes behavior, guarantees, or structure
- [ ] Added/updated tests for the change

## Related issue

<!-- Closes #123, if applicable -->
