<!--
Thank you for contributing to iso20022-evidence-pack-mcp! Please complete the
checklist below. Use a Conventional Commit style title, e.g. "feat: add pack
export format".
-->

## Summary

Briefly describe what this PR changes and why.

## Linked Issue

Closes #<!-- issue number -->

## Type of Change

- [ ] Bug fix (`fix:`)
- [ ] New feature (`feat:`)
- [ ] Documentation (`docs:`)
- [ ] Refactor / chore (no behaviour change)

## Checklist

- [ ] PR title follows [Conventional Commits](https://www.conventionalcommits.org/)
- [ ] Linked to a tracking issue
- [ ] All commits are signed (SSH or GPG)
- [ ] Tests added or updated for the change
- [ ] `poetry run pytest tests/` passes with **100% coverage**
- [ ] `poetry run ruff check iso20022_evidence_pack_mcp/` passes
- [ ] `poetry run black --check iso20022_evidence_pack_mcp/ tests/` passes
- [ ] `poetry run mypy iso20022_evidence_pack_mcp/` passes (strict)
- [ ] Documentation updated (README / CHANGELOG / docstrings) where relevant
- [ ] CHANGELOG.md updated under the `Unreleased` section

## Additional Notes

Anything reviewers should pay particular attention to.
