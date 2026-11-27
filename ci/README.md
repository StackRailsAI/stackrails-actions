# StackRails governance in your CI

StackRails holds **no write permission** on your repositories and posts nothing on any git host. Your own CI sends the
change to StackRails with an `sr_live_` service key, gets the verdict back, and shows it with its own short-lived token.
A blocking verdict fails the CI job, and that failed job is the merge gate.

Every host runs the same standard-library script, [`actions/pr-check/stackrails_check.py`](../actions/pr-check/stackrails_check.py)
(Python 3.10+ and git on the runner, nothing else). It:

1. diffs the merge base against the head with git and sends the changed files to `POST <stackrails-url>/api/cli/check-event`.
   Files with credential-looking names (`.env*`, `*.pem`, `id_rsa*`, `service-account*.json`, ...) are never read or
   sent. Binary files and files over 400,000 characters are left out and named as not covered. Over 200 files, nothing
   is sent and the check finishes neutral ("too many files").
2. polls the job every 5 s for up to 10 minutes (`--timeout`);
3. writes a markdown summary (blocking findings first) to the job log and the host's report surface;
4. exits 1 only on a `failure` verdict (a block-severity finding the change introduces) or a misconfiguration
   (HTTP 400/401/403/404: a bad key, a repository the key may not check, a wrong URL). A run a newer push superseded
   finishes neutral ("superseded by a newer run"): the newer run owns the verdict, and the PR comment is left alone.
   With fail-open on (the default), StackRails down, slow, rate limited or unreachable finishes **neutral** with a
   message and does not block.

Create a service key in the StackRails portal with access to the repositories, and store it only as a CI secret. The script reads it from `STACKRAILS_SERVICE_KEY` and never prints it.

**Pinning.** Everything here is published to the public [`StackRailsAI/stackrails-actions`](https://github.com/StackRailsAI/stackrails-actions)
repository with each StackRails release. Pin the action, template or script to a release tag there or a commit sha, never a branch. For the
downloaded script you can also set `STACKRAILS_CHECK_SHA256` to its sha256 (`sha256sum stackrails_check.py` on the
pinned ref), or vendor the file into your repository or an internal mirror and point the URL there.

## GitHub (`actions/pr-check`)

```yaml
name: StackRails
on:
  pull_request:
    types: [opened, synchronize, reopened, ready_for_review, closed]
  merge_group:
  push:
    branches: [main] # your default branch

permissions:
  contents: read
  checks: write
  pull-requests: write

jobs:
  stackrails:
    name: StackRails check
    runs-on: <your runner>
    steps:
      - uses: actions/checkout@<sha>
        with:
          fetch-depth: 0
      - uses: StackRailsAI/stackrails-actions/actions/pr-check@<release tag>
        with:
          stackrails-url: https://app.stackrails.ai
          service-key: ${{ secrets.STACKRAILS_SERVICE_KEY }}
          # fail-open: "false"   # block when StackRails cannot answer
```

- **opened / synchronize / reopened / ready_for_review** send `pr_updated`. The action posts a check run named exactly
  **`StackRails governance`** on the PR head (success, neutral or failure, with the findings as annotations and a link
  to the StackRails report), and keeps **one** PR comment up to date (found by a hidden marker). The comment is the
  text StackRails returns, already redacted for the repository's audience; it is only created when there are findings,
  and updated once it exists.
- **closed** sends `pr_merged` (merged, with the merge commit) or `pr_closed`. No check run, no comment.
- **push** to the default branch sends `default_branch_push` with the new head commit, so StackRails rebuilds the graph after
  every merge, direct push or merge-queue landing. A push to any other branch is skipped. No check run, no comment.
- **merge_group** checks the merge-group commit against its base as an advisory `pre_merge` (never recorded) and answers
  `StackRails governance` on the merge-group head, so a required check resolves in the merge queue.
- **Required check.** In branch protection or a ruleset, require **`StackRails governance`**. Neutral counts as passing.
- **Fork pull requests** get no secrets, so the key is empty: the step finishes neutral and says why. Their token is
  read-only too, so the `StackRails governance` check run cannot be created; on a repository that takes fork PRs,
  require the job (`StackRails check`) instead. `pull_request_target` would hand the key to a workflow that checks out
  untrusted code, so the action does not use it; if you choose it anyway, run the action from the base branch's
  workflow and never execute the fork's code in that job.

Outputs: `state`, `blocking`, `report-id`.

## GitLab ([`ci/gitlab/stackrails-pr-check.gitlab-ci.yml`](gitlab/stackrails-pr-check.gitlab-ci.yml))

```yaml
include:
  - remote: https://raw.githubusercontent.com/StackRailsAI/stackrails-actions/<release tag>/ci/gitlab/stackrails-pr-check.gitlab-ci.yml

variables:
  STACKRAILS_URL: https://app.stackrails.ai
  STACKRAILS_CHECK_REF: <the same release tag>
  STACKRAILS_CHECK_SHA256: <sha256 of stackrails_check.py at that tag>   # optional
```

Add `STACKRAILS_SERVICE_KEY` under **Settings → CI/CD → Variables** (masked, protected only if every MR pipeline runs
on protected refs). The `stackrails-governance` job runs on `merge_request_event` (merged-results pipelines included:
it diffs the MR's source commit, not the merge result), fails on a blocking verdict, prints the summary in the job log,
and uploads `gl-code-quality-report.json` as a `codequality` report so findings show in the MR widget. It posts no MR
notes. Turn on **Settings → Merge requests → Pipelines must succeed**; that is the gate.

**Default branch updates** (`default_branch_push`): the `stackrails-default-branch-push` job runs on every push to the default
branch (a merge, a direct push or a merge train) and sends the new head commit, so StackRails rebuilds the graph. It
needs no token beyond the service key.

**Merge credit** (`pr_merged`, optional): the `stackrails-merge-credit` job looks up the merge request of the
default-branch commit, which needs an API token. Set `STACKRAILS_GITLAB_TOKEN` to a project access token with
`read_api` (masked) to turn it on. Without it the merge is not credited to its MR, and the graph is still refreshed.
GitLab CI has no event for an MR closed without merging, so `pr_closed` is not sent.

Variables: `STACKRAILS_FAIL_OPEN` (`true`), `STACKRAILS_TIMEOUT` (`600`), `STACKRAILS_CHECK_IMAGE` (`python:3.13`; any
image with Python 3.10+, git and curl), `STACKRAILS_CHECK_SCRIPT_URL` (a mirror of the script).

## Bitbucket Cloud ([`ci/bitbucket/stackrails-pr-check.bitbucket-pipelines.yml`](bitbucket/stackrails-pr-check.bitbucket-pipelines.yml))

Merge both steps into your `bitbucket-pipelines.yml` (the check under `pipelines: pull-requests:`, the update under
`pipelines: branches:` for your default branch), and add `STACKRAILS_SERVICE_KEY`
as a **secured** repository variable (plus `STACKRAILS_URL`, `STACKRAILS_CHECK_REF`, optionally `STACKRAILS_CHECK_SHA256`
and `STACKRAILS_FAIL_OPEN`). The step sends `pr_updated`; the build status comes from the pipeline itself. Findings go
to a **Code Insights** report (`StackRails governance`, with annotations) through the pipeline's own auth proxy
(`localhost:29418`), so no token is needed. Require a passing build in **Repository settings → Branch restrictions →
Merge checks**. The `StackRails default branch push` step sends `default_branch_push` with the new head commit on every push to
the default branch, so StackRails rebuilds the graph. Pipelines have no PR-merged or PR-declined trigger, so the merge is
not credited to its pull request.

**Bitbucket Server / Data Center**: use the [`pre-receive` sample](git/pre-receive.sample) through a hook runner, or run
the same script from Jenkins or Bamboo with `--kind pr_updated --repository <url> --pr-number <id> --base
origin/<target> --head <commit>`.

## Plain git server ([`ci/git/pre-receive.sample`](git/pre-receive.sample))

Install it as `hooks/pre-receive` (executable) in the bare repository (also works through Gitea's or Bitbucket Data
Center's hook runners). Each pushed branch is checked as an advisory `pre_push` (never recorded) against its previous
tip (a new branch against the default branch), and a push with a blocking verdict is rejected with the findings.

| Server environment | |
|---|---|
| `STACKRAILS_SERVICE_KEY` | the `sr_live_` service key (required; never commit it) |
| `STACKRAILS_URL` | e.g. `https://app.stackrails.ai` (required) |
| `STACKRAILS_CHECK_SCRIPT` | path to `stackrails_check.py` from a pinned release (required) |
| `STACKRAILS_REPOSITORY` | the repository as StackRails knows it (default: the repository's directory name) |
| `STACKRAILS_FAIL_OPEN` | `true` (default) lets a push through when StackRails cannot answer |
| `STACKRAILS_TIMEOUT` | seconds per ref (default 120: the pusher waits) |
| `STACKRAILS_REFS` | extended regex of the refs to check (default `^refs/heads/`) |

## Any other CI

```bash
export STACKRAILS_SERVICE_KEY=...   # from your CI's secret store
python3 stackrails_check.py --url https://app.stackrails.ai --kind pr_updated --repository <clone url> \
  --pr-number <n> --base <target branch or sha> --head <PR head sha> --summary-file summary.md
```

After a push to the default branch, send `--kind default_branch_push --repository <clone url> --head <sha>` (plus `--scm-repository-id <host id>` when you have it).
`--result-file` writes `{state, title, exit_code, job_id, report_id, blocking, introduced_total}`; `--codequality-file`
writes a GitLab Code Quality report; `--no-fail-open` blocks when StackRails cannot answer.
