---
name: release
description: Cut a new mattstash release. Bumps the version in a pull request, tags the merge commit, and lets the tag-triggered workflow publish to PyPI, GitHub Releases and GHCR, then verifies all three. Use ONLY when the user explicitly asks to release, publish or ship a version.
---

# Releasing mattstash

Releases are **manual**. Merging to `main` publishes nothing, whatever the PR was (Dependabot included). The user decides
when a release happens and which version it is; this file is the runbook for doing it safely.

How it works: a pull request changes `version` in `pyproject.toml`; after the user merges it, a tag `vX.Y.Z` is pushed on
the merge commit; that tag starts `.github/workflows/release.yml`, which checks the tag, runs CI on it, publishes to PyPI,
creates the GitHub Release and pushes `ghcr.io/cornyhorse/mattstash:vX.Y.Z` (and `:latest`). Credentials live in GitHub
(the `pypi` environment and `PYPI_API_TOKEN`); you never handle them.

## Ground rules

- **Start only when the user has asked for a release in this conversation.** A green CI run, a merged Dependabot PR or a
  version gap is not a reason to release.
- **Never push to `main`.** The version bump goes through a PR that the user merges. Do not merge it yourself unless they
  tell you to.
- **Never move, delete or re-create a pushed tag, and never reuse a version number.** A bad release is fixed by releasing
  the next version. (Yanking a PyPI release is done by the owner on pypi.org.)
- **Never publish by hand.** No `twine upload`, no `docker push`, no PyPI/GHCR tokens in your environment.
  `scripts/update-pypi.sh` is a break-glass tool for the human owner, not for you.
- The old `[minor]`, `[major]` and `[skip-release]` markers in commit messages no longer do anything.

## 1. Look at the state

```bash
git fetch origin main --tags
git tag --merged origin/main --sort=-v:refname | head -3      # the last release on main (ignore tags that are not on main)
git log --oneline "$(git tag --merged origin/main --sort=-v:refname | head -1)"..origin/main
```

- Confirm CI is green on the tip of `main` (Actions, or `actions_list` / `get_workflow_run` through the GitHub tools).
- List open PRs the user may want in this release and ask if any should land first.
- If nothing user-facing changed since the last tag, say so and stop.
- Recommend a version and **ask the user to confirm it** (unless they named one). While the version is below 1.0: a
  breaking change or a new feature is a **minor** bump (0.X.0); fixes, docs, CI and dependency updates are a **patch**
  bump (0.x.Y). From 1.0 on, plain semantic versioning.

## 2. The version-bump pull request

1. Branch from `origin/main`.
2. Change **only** `version = "..."` in `pyproject.toml`. There is no changelog file: GitHub generates the release notes
   from the merged PR titles. (If the user wants curated notes, edit the GitHub Release after it is published.)
3. Open a PR titled `release: vX.Y.Z`. Say in the description what is in the release (the PR titles since the last tag).
4. Wait for CI to pass, then tell the user it is ready to merge.

Deployment manifests pin an image tag (`server/k8s/**`, `server/docker-compose*.yml`, `README.md`, `server/README.md`:
`grep -rn "ghcr.io/cornyhorse/mattstash:v" .`). Do **not** point them at a tag whose image does not exist yet: update them
in a follow-up PR after step 5, unless they already name this version.

## 3. Tag the merge commit (after the user has merged)

```bash
git fetch origin main --tags
git switch --detach origin/main                  # HEAD must be exactly the tip of origin/main
scripts/check-release.sh vX.Y.Z --preflight      # must print "ok"; if it fails, fix the cause, do not bypass it
git tag -a vX.Y.Z -m "mattstash vX.Y.Z"
git push origin vX.Y.Z                           # push only this tag
```

If your environment will not let you switch the checkout, do the same in a detached worktree instead
(`git worktree add --detach <dir> origin/main`, then run the commands from `<dir>`).

`check-release.sh` verifies that the tag is `vMAJOR.MINOR.PATCH`, equals the version in `pyproject.toml`, the commit is on
`origin/main`, and the tag does not exist yet. The workflow runs the same script again.

If your environment refuses to create or push the tag, ask the user to create it in the GitHub UI instead (Releases ->
Draft a new release -> choose a new tag `vX.Y.Z` on `main` -> Publish): that pushes the tag and starts the same workflow.

## 4. Watch the Release workflow

Jobs, in order: `verify` -> `ci` -> `release` -> `docker`.

- `release` runs in the `pypi` environment. If the owner configured required reviewers there, the run **waits for their
  approval**: tell the user to click "Review deployments".
- Follow it with `actions_list` (`list_workflow_runs`, workflow `release.yml`) and `get_job_logs` for a failed job.
- On a failure, **do not touch the tag**. Diagnose first:
  - `verify` or `ci` failed: nothing was published. Fix the cause in a normal PR. Because a tag cannot be moved, that
    means releasing the next version (the failed tag was never published, so ask the user before deleting it).
  - `release` failed before the PyPI upload, or `docker` failed: nothing is wrong with the tag. Re-run the failed jobs
    (Actions -> the run -> "Re-run failed jobs"), or Actions -> Release -> "Run workflow" with the tag selected as the ref.
  - PyPI already has the files but a later step failed: a re-run fails with "file already exists". Finish the missing
    pieces (GitHub Release, image) with the user and report exactly what is and is not published.

## 5. Verify and report

- GitHub Release `vX.Y.Z` exists (`get_release_by_tag`).
- PyPI serves it: `pip index versions mattstash` or `curl -s https://pypi.org/pypi/mattstash/X.Y.Z/json` (allow a minute).
- The image exists: `docker buildx imagetools inspect ghcr.io/cornyhorse/mattstash:vX.Y.Z` where Docker is available;
  otherwise check the `docker` job log (it prints the pushed digest).

Report the version, the three links, and anything unusual. Then offer the follow-up PR that updates pinned image tags.

## After a bad release

Do not delete anything. Fix forward with the next version. If users should not install the bad one, the owner yanks it
on pypi.org (project -> Manage -> the release -> Options -> Yank).

## One-time repository settings (owner actions; check, do not change)

- A tag ruleset for `v*`: only maintainers may create or delete these tags (Settings -> Rules).
- The `pypi` environment with required reviewers, if the owner wants an approval click before every publish.
- Optional: PyPI trusted publishing instead of the stored `PYPI_API_TOKEN` (the steps are in `release.yml`).

If one is missing, mention it once; do not try to work around it.
