#!/usr/bin/env python3
"""Send a change to StackRails from CI, wait for the governance verdict, and report it (epic 124hhvu6zh1).

    STACKRAILS_SERVICE_KEY=sr_live_... stackrails_check.py --url https://app.stackrails.ai --host github

StackRails holds no write permission on the repository and posts nothing: this script computes the change from git,
POSTs it to ``<url>/api/cli/check-event``, polls the job, and writes the verdict to the host's own report surface with
the host's own token. It exits 1 only on a ``failure`` verdict or a misconfiguration (400/401/403/404). Standard
library only, Python 3.10+, so it runs on any runner and on a git server.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import PurePosixPath

CHECK_NAME = "StackRails governance"
COMMENT_MARKER = "<!-- stackrails-governance -->"
MAX_FILES = 200
MAX_FILE_CHARS = 400_000
MAX_TOTAL_CHARS = 2_000_000
MAX_WAIT_SECONDS = 25
MAX_ROWS = 50
KINDS = ("pr_updated", "pr_merged", "pr_closed", "pre_push", "pre_merge")
WITH_CHANGES = ("pr_updated", "pre_push", "pre_merge")
ADVISORY = ("pre_push", "pre_merge")
ZERO_SHA = "0" * 40
USER_AGENT = "stackrails-pr-check/1"

# The contract's credential-looking names; they are dropped before anything is read.
CREDENTIAL_NAMES = (
    ".env*",
    ".npmrc",
    ".pypirc",
    ".netrc",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "*.p8",
    "*.jks",
    "*.keystore",
    "*.token",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    "service-account*.json",
)


class ConfigError(Exception):
    """A misconfiguration the job must show: it always fails the job."""


class Superseded(Exception):
    """A newer check of the same pull request replaced this one; the newer run owns the verdict."""


class Unavailable(Exception):
    """StackRails could not answer in time; `--fail-open` decides what that means."""


# ── change collection ────────────────────────────────────────────────────────────────────────────────────────────


def is_credential_name(path: str) -> bool:
    name = PurePosixPath(path).name.lower()
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in CREDENTIAL_NAMES)


def _git(args: list[str], cwd: str | None = None) -> bytes:
    try:
        return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True).stdout
    except FileNotFoundError as err:
        raise ConfigError("git is not on PATH") from err
    except subprocess.CalledProcessError as err:
        detail = err.stderr.decode("utf-8", "replace").strip().splitlines()
        raise ConfigError(f"git {' '.join(args[:2])} failed: {detail[-1] if detail else err.returncode}") from err


def merge_base(base: str, head: str, cwd: str | None = None) -> str:
    try:
        return _git(["merge-base", base, head], cwd).decode().strip()
    except ConfigError as err:
        raise ConfigError(
            f"no merge base between {base} and {head}: fetch both with full history (fetch-depth: 0 / GIT_DEPTH: 0)"
        ) from err


def parse_name_status(raw: bytes) -> list[tuple[str, str, str | None]]:
    """`git diff --name-status -M -z` as (status letter, path, old path)."""
    parts = raw.decode("utf-8", "surrogateescape").split("\0")
    out: list[tuple[str, str, str | None]] = []
    i = 0
    while i < len(parts) and parts[i]:
        letter = parts[i][0]
        if letter in "RC":
            out.append((letter, parts[i + 2], parts[i + 1]))
            i += 3
        else:
            out.append((letter, parts[i + 1], None))
            i += 2
    return out


def _blob_text(rev: str, path: str, cwd: str | None) -> tuple[str | None, str | None]:
    """The file's text at rev, or (None, why it is not covered)."""
    try:
        data = _git(["cat-file", "blob", f"{rev}:{path}"], cwd)
    except ConfigError:
        return None, "not a file (submodule or unreadable)"
    if b"\0" in data[:8192]:
        return None, "binary"
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None, "binary"
    if len(text) > MAX_FILE_CHARS:
        return None, f"over {MAX_FILE_CHARS:,} characters"
    return text, None


@dataclass
class ChangeSet:
    changes: list[dict] = field(default_factory=list)
    not_covered: list[tuple[str, str]] = field(default_factory=list)
    too_many: int = 0  # the count seen when the cap was passed; nothing is sent then


def collect_changes(base_rev: str, head_rev: str, cwd: str | None = None) -> ChangeSet:
    raw = _git(["diff", "--name-status", "-M", "-z", "--no-color", base_rev, head_rev, "--"], cwd)
    entries = parse_name_status(raw)
    result = ChangeSet()
    total = 0
    for letter, path, old_path in entries:
        if is_credential_name(path) or (old_path and is_credential_name(old_path)):
            result.not_covered.append((path, "credential-looking name"))
            continue
        status = {"A": "added", "C": "added", "D": "deleted", "R": "renamed"}.get(letter, "modified")
        change: dict = {"path": path, "status": status}
        reason = None
        if status != "deleted":
            change["head"], reason = _blob_text(head_rev, path, cwd)
        if reason is None and status != "added":
            source = old_path if status == "renamed" else path
            change["base"], reason = _blob_text(base_rev, source, cwd)
        if status == "renamed":
            change["old_path"] = old_path
        if reason:
            result.not_covered.append((path, reason))
            continue
        size = len(change.get("head") or "") + len(change.get("base") or "")
        if total + size > MAX_TOTAL_CHARS:
            result.not_covered.append((path, f"past the {MAX_TOTAL_CHARS:,}-character total"))
            continue
        if len(result.changes) == MAX_FILES:
            result.too_many = len(entries)
            result.changes = []
            return result
        total += size
        result.changes.append(change)
    return result


# ── host context ─────────────────────────────────────────────────────────────────────────────────────────────────


@dataclass
class Context:
    kind: str | None = None
    repository: str | None = None
    base: str | None = None
    head: str | None = None
    pr_number: int | None = None
    merge_commit_sha: str | None = None
    pr_url: str | None = None
    pr_title: str | None = None
    author: str | None = None
    fork: bool = False
    report_sha: str | None = None  # the commit the host's check / report is attached to
    skip: str | None = None  # an event this script has nothing to send for


GITHUB_PR_ACTIONS = ("opened", "synchronize", "reopened", "ready_for_review")


def github_context(event_name: str, event: dict, env: dict) -> Context:
    repo = event.get("repository") or {}
    server = env.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    repository = f"{server}/{repo.get('full_name') or env.get('GITHUB_REPOSITORY', '')}"
    if event_name == "merge_group":
        group = event.get("merge_group") or {}
        head = group.get("head_sha")
        return Context(kind="pre_merge", repository=repository, base=group.get("base_sha"), head=head, report_sha=head)
    if event_name not in ("pull_request", "pull_request_target"):
        return Context(skip=f"the {event_name} event has nothing to check: run on pull_request or merge_group")
    pr = event.get("pull_request") or {}
    head_repo = (pr.get("head") or {}).get("repo") or {}
    ctx = Context(
        repository=repository,
        pr_number=pr.get("number"),
        pr_url=pr.get("html_url"),
        pr_title=pr.get("title"),
        author=(pr.get("user") or {}).get("login"),
        head=(pr.get("head") or {}).get("sha"),
        fork=head_repo.get("full_name") != repo.get("full_name"),
    )
    action = event.get("action")
    if action == "closed":
        if pr.get("merged"):
            ctx.kind, ctx.merge_commit_sha = "pr_merged", pr.get("merge_commit_sha")
        else:
            ctx.kind, ctx.head = "pr_closed", None
        return ctx
    if action not in GITHUB_PR_ACTIONS:
        ctx.skip = f"pull_request {action} changes nothing StackRails checks"
        return ctx
    ctx.kind, ctx.base, ctx.report_sha = "pr_updated", (pr.get("base") or {}).get("sha"), ctx.head
    return ctx


def gitlab_context(env: dict) -> Context:
    if env.get("CI_PIPELINE_SOURCE") != "merge_request_event":
        return Context(skip="not a merge request pipeline: the job runs on merge_request_event")
    iid = env.get("CI_MERGE_REQUEST_IID")
    project_url = env.get("CI_PROJECT_URL", "")
    target = env.get("CI_MERGE_REQUEST_TARGET_BRANCH_NAME")
    source_project = env.get("CI_MERGE_REQUEST_SOURCE_PROJECT_ID")
    return Context(
        kind="pr_updated",
        repository=project_url,
        base=env.get("CI_MERGE_REQUEST_DIFF_BASE_SHA") or (f"origin/{target}" if target else None),
        # In a merged-results pipeline CI_COMMIT_SHA is the merge result; the MR's own head is the source sha.
        head=env.get("CI_MERGE_REQUEST_SOURCE_BRANCH_SHA") or env.get("CI_COMMIT_SHA"),
        pr_number=int(iid) if iid else None,
        pr_url=f"{project_url}/-/merge_requests/{iid}" if iid else None,
        pr_title=env.get("CI_MERGE_REQUEST_TITLE"),
        author=env.get("GITLAB_USER_LOGIN"),
        fork=bool(source_project) and source_project != env.get("CI_MERGE_REQUEST_PROJECT_ID"),
    )


def gitlab_merged_context(env: dict, merge_requests: list[dict]) -> Context:
    """pr_merged for the default-branch commit, from GitLab's commit → merge requests API."""
    sha = env.get("CI_COMMIT_SHA")
    merged = [mr for mr in merge_requests if mr.get("state") == "merged"]
    if not merged:
        return Context(skip=f"no merged merge request points at {sha}: nothing to credit")
    mr = merged[0]
    return Context(
        kind="pr_merged",
        repository=env.get("CI_PROJECT_URL"),
        pr_number=mr.get("iid"),
        head=mr.get("sha"),
        merge_commit_sha=mr.get("merge_commit_sha") or mr.get("squash_commit_sha") or sha,
        pr_url=mr.get("web_url"),
        pr_title=mr.get("title"),
        author=(mr.get("author") or {}).get("username"),
    )


def bitbucket_context(env: dict) -> Context:
    pr_id = env.get("BITBUCKET_PR_ID")
    if not pr_id:
        return Context(skip="not a pull-request pipeline: put the step under pipelines: pull-requests:")
    origin = env.get("BITBUCKET_GIT_HTTP_ORIGIN", "")
    dest = env.get("BITBUCKET_PR_DESTINATION_BRANCH")
    head = env.get("BITBUCKET_COMMIT")
    return Context(
        kind="pr_updated",
        repository=origin,
        base=f"origin/{dest}" if dest else env.get("BITBUCKET_PR_DESTINATION_COMMIT"),
        head=head,
        pr_number=int(pr_id),
        pr_url=f"{origin}/pull-requests/{pr_id}" if origin else None,
        report_sha=head,
    )


# ── StackRails client ────────────────────────────────────────────────────────────────────────────────────────────


@dataclass
class Http:
    status: int
    body: dict
    retry_after: float | None = None


def _request(
    method: str, url: str, body: object = None, headers: dict | None = None, proxy: str | None = None, timeout=60
) -> Http:
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method=method)  # noqa: S310 - https/http URLs from the operator
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Accept", "application/json")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    handlers = [urllib.request.ProxyHandler({"http": proxy, "https": proxy} if proxy else {})]
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(req, timeout=timeout) as resp:
            return Http(resp.status, _json(resp.read()))
    except urllib.error.HTTPError as err:
        retry = err.headers.get("Retry-After") if err.headers else None
        return Http(err.code, _json(err.read()), float(retry) if retry and retry.isdigit() else None)


def _json(raw: bytes) -> dict:
    try:
        value = json.loads(raw or b"{}")
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {"data": value}


def check_event(
    url: str, key: str, body: dict, timeout: float, poll: float, sleep=time.sleep, clock=time.monotonic
) -> dict:
    """POST the event and poll its job until it settles; returns the complete reply."""
    endpoint = url.rstrip("/") + "/api/cli/check-event"
    headers = {"Authorization": f"Bearer {key}"}
    deadline = clock() + timeout
    request, errors = {**body, "wait_seconds": MAX_WAIT_SECONDS}, 0
    while True:
        try:
            resp = _request("POST", endpoint, request, headers, timeout=MAX_WAIT_SECONDS + 35)
        except (urllib.error.URLError, OSError) as err:
            resp, reason = None, f"StackRails is unreachable ({getattr(err, 'reason', err)})"
        if resp is not None:
            error = str(resp.body.get("error") or "")
            if resp.status in (400, 401, 403, 404):
                why = {401: "the service key was refused", 403: "the service key may not check this repository"}
                raise ConfigError(f"HTTP {resp.status}: {error or why.get(resp.status, 'bad request')}")
            if resp.status == 200:
                status = resp.body.get("status")
                if status == "complete":
                    return resp.body
                if status == "cancelled" and "superseded" in error.lower():
                    raise Superseded(error)
                if status in ("failed", "cancelled"):
                    raise Unavailable(f"the check {status}: {error or 'no reason given'}")
                job_id = resp.body.get("job_id")
                if status != "running" or not job_id:
                    raise Unavailable(f"StackRails answered an unknown status {status!r}")
                request, errors = {"job_id": job_id, "wait_seconds": MAX_WAIT_SECONDS}, 0
                reason = None
            else:
                reason = f"HTTP {resp.status}: {error or 'StackRails is unavailable'}"
        # 429 waits out the deadline; three 5xx / network errors in a row give up early.
        if reason and (resp is None or resp.status != 429):
            errors += 1
            if errors >= 3:
                raise Unavailable(reason)
        wait = poll if resp is None or resp.retry_after is None else max(poll, resp.retry_after)
        if clock() + wait >= deadline:
            raise Unavailable(reason or f"no verdict within {int(timeout)} s")
        sleep(wait)


# ── rendering ────────────────────────────────────────────────────────────────────────────────────────────────────

_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")
_MD_SPECIAL = re.compile(r"([\\`*_\[\]#!|~>])")


def clean(value: object) -> str:
    """Reply text as one plain line: no control characters, so it cannot steer a log or terminal."""
    return _CONTROL.sub("", " ".join(str(value if value is not None else "").split()))


def md(value: object) -> str:
    """Reply text as inert markdown: escaped, no HTML, no @mentions."""
    text = _MD_SPECIAL.sub(r"\\\1", clean(value))
    return text.replace("&", "&amp;").replace("<", "&lt;").replace("@", "@​")


def md_lines(value: object) -> list[str]:
    """Multi-line reply text, each line inert; table rows are dropped, as the findings table below repeats them."""
    raw = str(value if value is not None else "").splitlines()
    return [line for line in (md(r) for r in raw if not r.lstrip().startswith("|")) if line]


def describe(item: object) -> str:
    if isinstance(item, dict):
        for key in ("policy", "name", "path", "component", "id"):
            if item.get(key):
                rest = item.get("reason") or item.get("detail") or item.get("hint")
                return f"{item[key]}: {rest}" if rest else str(item[key])
        return json.dumps(item, sort_keys=True)
    return str(item)


@dataclass
class Outcome:
    state: str  # success | neutral | failure
    title: str
    summary: str  # markdown
    exit_code: int
    reply: dict = field(default_factory=dict)
    findings: list[dict] = field(default_factory=list)
    superseded: bool = False


def _is_blocking(finding: dict) -> bool:
    return str(finding.get("severity", "")).lower() in ("block", "blocking", "blocker")


def _bullets(label: str, items: list) -> list[str]:
    if not items:
        return []
    lines = [f"**{label}** ({len(items)})", ""]
    lines += [f"- {md(describe(i))}" for i in items[:MAX_ROWS]]
    if len(items) > MAX_ROWS:
        lines.append(f"- and {len(items) - MAX_ROWS} more")
    return [*lines, ""]


def render_verdict(reply: dict, not_covered: list[tuple[str, str]]) -> Outcome:
    state = reply.get("state") if reply.get("state") in ("success", "neutral", "failure") else "neutral"
    introduced = [f for f in reply.get("introduced") or [] if isinstance(f, dict)]
    introduced.sort(key=lambda f: not _is_blocking(f))
    total = int(reply.get("introduced_total") or len(introduced))
    blocking = int(reply.get("blocking") or sum(map(_is_blocking, introduced)))
    title = (
        clean(reply.get("title"))
        or {
            "success": "No new policy findings",
            "neutral": "Nothing blocks this change",
            "failure": f"{blocking} blocking finding(s)",
        }[state]
    )
    lines = [f"### {CHECK_NAME}: {state}", "", f"**{md(title)}**", ""]
    if reply.get("summary"):
        lines += [*md_lines(reply["summary"]), ""]
    if reply.get("restricted"):
        lines += [f"Finding details are withheld: {md(reply['restricted'])}", ""]
    if introduced:
        lines += [
            f"**Introduced findings**: {total} ({blocking} blocking)",
            "",
            "| Severity | Policy | Component | Where | Detail |",
            "|---|---|---|---|---|",
        ]
        for f in introduced[:MAX_ROWS]:
            cells = [md(f.get(k)) for k in ("severity", "policy", "component", "where", "detail")]
            lines.append("| " + " | ".join(cells) + " |")
        if total > min(len(introduced), MAX_ROWS):
            lines.append(
                f"\n{total - min(len(introduced), MAX_ROWS)} more not shown; open the PR report in StackRails."
            )
        lines.append("")
    else:
        lines += [f"**Introduced findings**: {total}", ""]
    counts = [("Resolved", "resolved"), ("Evaluated after merge", "evaluated_after_merge")]
    lines += [f"- {label}: {int(reply.get(key) or 0)}" for label, key in counts] + [""]
    lines += _bullets("Needs setup", reply.get("needs_setup") or [])
    lines += _bullets("Not applicable", reply.get("not_applicable") or [])
    lines += _bullets("Partial", reply.get("partial") or [])
    uncovered = [f"{p} ({why})" for p, why in not_covered]
    uncovered += [f"{p} (ignored)" for p in reply.get("ignored_paths") or []]
    uncovered += [f"{p} (not mapped to a component)" for p in reply.get("unmapped_paths") or []]
    lines += _bullets("Files not covered", uncovered)
    graph = reply.get("graph") or {}
    if graph.get("indexed_commit"):
        lines.append(f"Judged against the graph indexed at {md(graph['indexed_commit'])[:12]}.")
    return Outcome(state, title, "\n".join(lines).strip() + "\n", 1 if state == "failure" else 0, reply, introduced)


def render_record(kind: str, reply: dict) -> Outcome:
    if kind == "pr_merged":
        parts = [f"{k.replace('_', ' ')}: {reply.get(k)}" for k in ("credited", "candidates", "skipped", "excepted")]
        title = "Merge credit recorded"
    else:
        parts, title = [f"closed: {reply.get('closed')}"], "Pull request marked closed"
    body = "\n".join(f"- {md(p)}" for p in parts)
    return Outcome("success", title, f"### {CHECK_NAME}\n\n**{title}**\n\n{body}\n", 0, reply)


def neutral(title: str, detail: str, exit_code: int = 0, state: str = "neutral") -> Outcome:
    return Outcome(state, title, f"### {CHECK_NAME}: {state}\n\n**{md(title)}**\n\n{md(detail)}\n", exit_code)


# ── host report surfaces ─────────────────────────────────────────────────────────────────────────────────────────


def _warn(message: str) -> None:
    print(f"warning: {clean(message)}", file=sys.stderr)


def github_check_payload(outcome: Outcome, sha: str) -> dict:
    notes = [
        {
            "path": n["path"],
            "start_line": n["line"],
            "end_line": n["line"],
            "annotation_level": n["level"],
            "message": n["message"][:64000],
            **({"title": n["title"][:255]} if n["title"] else {}),
        }
        for n in annotations(outcome)
    ]
    output = {"title": outcome.title[:255], "summary": outcome.summary[:65000]}
    if notes:
        output["annotations"] = notes
    payload = {"name": CHECK_NAME, "head_sha": sha, "status": "completed", "conclusion": outcome.state}
    details_url = clean(outcome.reply.get("details_url"))
    if details_url.startswith("https://"):
        payload["details_url"] = details_url
    return {**payload, "output": output}


def github_comment_body(outcome: Outcome) -> str:
    """The reply's ready-to-post `comment` (redacted for the repo's audience by StackRails), else the summary."""
    comment = outcome.reply.get("comment")
    text = comment if isinstance(comment, str) and comment.strip() else outcome.summary
    text = _CONTROL.sub("", text.replace("\r\n", "\n").replace("\t", " ")).replace(COMMENT_MARKER, "")
    return f"{COMMENT_MARKER}\n{text}"[:65000]


def _gh(method: str, path: str, token: str, body: object = None) -> Http:
    api = os.environ.get("GITHUB_API_URL", "https://api.github.com").rstrip("/")
    headers = {"Authorization": f"Bearer {token}", "X-GitHub-Api-Version": "2022-11-28"}
    return _request(method, f"{api}{path}", body, headers, timeout=30)


def github_report(outcome: Outcome, ctx: Context, token: str, repo: str, comment: bool) -> None:
    if not token:
        _warn("no GitHub token: the check run and comment were not posted")
        return
    try:
        if ctx.report_sha:
            resp = _gh("POST", f"/repos/{repo}/check-runs", token, github_check_payload(outcome, ctx.report_sha))
            if resp.status >= 300:
                _warn(f"could not post the check run (HTTP {resp.status}; the token needs checks: write)")
        if comment and ctx.pr_number:
            upsert_github_comment(outcome, repo, ctx.pr_number, token)
    except (urllib.error.URLError, OSError) as err:
        _warn(f"could not reach the GitHub API: {err}")


def upsert_github_comment(outcome: Outcome, repo: str, number: int, token: str) -> None:
    existing = None
    for page in range(1, 11):
        resp = _gh("GET", f"/repos/{repo}/issues/{number}/comments?per_page=100&page={page}", token)
        rows = resp.body.get("data") if resp.status == 200 else None
        if not rows:
            break
        existing = next((c for c in rows if COMMENT_MARKER in str(c.get("body", ""))), existing)
    if existing is None and not int(outcome.reply.get("introduced_total") or len(outcome.findings)):
        return
    body = {"body": github_comment_body(outcome)}
    if existing is not None:
        resp = _gh("PATCH", f"/repos/{repo}/issues/comments/{existing['id']}", token, body)
        if resp.status < 300:
            return
    resp = _gh("POST", f"/repos/{repo}/issues/{number}/comments", token, body)
    if resp.status >= 300:
        _warn(f"could not post the PR comment (HTTP {resp.status}; the token needs pull-requests: write)")


_WHERE = re.compile(r"^(?P<path>[^\s:]+[/.][^\s:]*)(?::(?P<line>\d+))?")


def _location(finding: dict) -> tuple[str | None, int]:
    match = _WHERE.match(clean(finding.get("where")))
    if not match:
        return None, 1
    return match["path"], int(match["line"] or 1)


def annotations(outcome: Outcome) -> list[dict]:
    """The reply's `annotations` ({path, line, level, message, title}); derived from `introduced` when absent."""
    raw = outcome.reply.get("annotations")
    if not isinstance(raw, list):
        raw = []
        for finding in outcome.findings:
            path, line = _location(finding)
            if path:
                level = "failure" if _is_blocking(finding) else "warning"
                message = f"{finding.get('policy')}: {finding.get('detail')}"
                raw.append({"path": path, "line": line, "level": level, "message": message, "title": None})
    out = []
    for note in raw[:50]:
        if not isinstance(note, dict) or not clean(note.get("path")):
            continue
        line = note.get("line")
        out.append(
            {
                "path": clean(note["path"]).lstrip("/"),
                "line": line if isinstance(line, int) and line > 0 else 1,
                "level": "failure" if note.get("level") == "failure" else "warning",
                "message": clean(note.get("message")) or "StackRails finding",
                "title": clean(note.get("title")) or None,
            }
        )
    return out


def _note_id(note: dict) -> str:
    key = "|".join(str(note[k]) for k in ("path", "line", "level", "message"))
    return hashlib.sha256(key.encode()).hexdigest()


def codequality_report(outcome: Outcome) -> list[dict]:
    """GitLab Code Quality entries, so the findings show in the merge request widget."""
    return [
        {
            "description": (f"{note['title']}: {note['message']}" if note["title"] else note["message"])[:1000],
            "check_name": note["title"] or "stackrails-governance",
            "fingerprint": _note_id(note),
            "severity": "blocker" if note["level"] == "failure" else "major",
            "location": {"path": note["path"], "lines": {"begin": note["line"]}},
        }
        for note in annotations(outcome)
    ]


BITBUCKET_REPORT_ID = "stackrails-governance"


def bitbucket_report_payload(outcome: Outcome) -> dict:
    reply = outcome.reply
    details = clean(reply.get("summary") or outcome.title)
    return {
        "title": CHECK_NAME,
        "details": details[:2000],
        "report_type": "SECURITY",
        "reporter": "StackRails",
        "result": "FAILED" if outcome.state == "failure" else "PASSED",
        "data": [
            {"title": "Verdict", "type": "TEXT", "value": outcome.state},
            {"title": "Blocking", "type": "NUMBER", "value": int(reply.get("blocking") or 0)},
            {"title": "Introduced", "type": "NUMBER", "value": int(reply.get("introduced_total") or 0)},
            {"title": "Resolved", "type": "NUMBER", "value": int(reply.get("resolved") or 0)},
        ],
    }


def bitbucket_annotations(outcome: Outcome) -> list[dict]:
    return [
        {
            "external_id": _note_id(note)[:50],
            "annotation_type": "VULNERABILITY" if note["level"] == "failure" else "CODE_SMELL",
            "summary": (note["title"] or note["message"])[:450],
            "details": note["message"][:2000],
            "severity": "CRITICAL" if note["level"] == "failure" else "MEDIUM",
            "path": note["path"],
            "line": note["line"],
        }
        for note in annotations(outcome)
    ]


def bitbucket_report(outcome: Outcome, env: dict, proxy: str) -> None:
    repo = f"{env.get('BITBUCKET_WORKSPACE') or env.get('BITBUCKET_REPO_OWNER')}/{env.get('BITBUCKET_REPO_SLUG')}"
    base = f"http://api.bitbucket.org/2.0/repositories/{repo}/commit/{env.get('BITBUCKET_COMMIT')}"
    report = f"{base}/reports/{BITBUCKET_REPORT_ID}"
    try:
        _request("DELETE", report, proxy=proxy, timeout=30)
        resp = _request("PUT", report, bitbucket_report_payload(outcome), proxy=proxy, timeout=30)
        if resp.status >= 300:
            _warn(f"could not post the Code Insights report (HTTP {resp.status})")
            return
        notes = bitbucket_annotations(outcome)
        for start in range(0, len(notes), 100):
            resp = _request("POST", f"{report}/annotations", notes[start : start + 100], proxy=proxy, timeout=30)
            if resp.status >= 300:
                _warn(f"could not post the Code Insights annotations (HTTP {resp.status})")
                return
    except (urllib.error.URLError, OSError) as err:
        _warn(f"could not reach the Bitbucket report proxy: {err}")


# ── main ─────────────────────────────────────────────────────────────────────────────────────────────────────────


def build_body(ctx: Context, changes: list[dict] | None) -> dict:
    body: dict = {"kind": ctx.kind, "repository": ctx.repository}
    if ctx.kind in ("pr_updated", "pr_merged", "pr_closed"):
        body["pr_number"] = ctx.pr_number
    if ctx.kind in ("pr_updated", "pr_merged") and ctx.head:
        body["head_sha"] = ctx.head
    if ctx.kind == "pr_merged" and ctx.merge_commit_sha:
        body["merge_commit_sha"] = ctx.merge_commit_sha
    for key in ("pr_url", "pr_title", "author"):
        if getattr(ctx, key) and ctx.kind not in ADVISORY:
            body[key] = getattr(ctx, key)
    if ctx.kind in WITH_CHANGES:
        body["changes"] = changes or []
    return body


def evaluate(ctx: Context, args: argparse.Namespace, key: str, sleep=time.sleep, clock=time.monotonic) -> Outcome:
    if ctx.skip:
        return neutral("Nothing to check", ctx.skip)
    if not key:
        if ctx.fork:
            return neutral(
                "Not checked: fork pull request",
                "CI secrets are not given to pull requests from forks, so the StackRails service key is empty. "
                "A maintainer can run the check from a branch in this repository.",
            )
        raise ConfigError("STACKRAILS_SERVICE_KEY is empty: store the sr_live_ service key as a CI secret")
    if ctx.kind not in KINDS:
        raise ConfigError(f"kind must be one of {', '.join(KINDS)}")
    if not ctx.repository:
        raise ConfigError("no repository: pass --repository")
    if ctx.kind not in ADVISORY and ctx.pr_number is None:
        raise ConfigError(f"{ctx.kind} needs --pr-number")
    not_covered: list[tuple[str, str]] = []
    changes = None
    if ctx.kind in WITH_CHANGES:
        if not ctx.base or not ctx.head:
            raise ConfigError(f"{ctx.kind} needs --base and --head")
        collected = collect_changes(merge_base(ctx.base, ctx.head), ctx.head)
        if collected.too_many:
            return neutral(
                "Not checked: too many files",
                f"This change touches {collected.too_many} files; StackRails checks at most {MAX_FILES} per event.",
            )
        if not collected.changes:
            detail = "; ".join(f"{p} ({why})" for p, why in collected.not_covered) or "the diff is empty"
            return neutral("Nothing StackRails can check", f"No text file to send: {detail}")
        changes, not_covered = collected.changes, collected.not_covered
    try:
        reply = check_event(args.url, key, build_body(ctx, changes), args.timeout, args.poll_interval, sleep, clock)
    except Superseded as err:
        outcome = neutral(
            "Superseded by a newer run", f"A newer push replaced this check; that run owns the verdict. ({err})"
        )
        outcome.superseded = True
        return outcome
    except Unavailable as err:
        if args.fail_open:
            return neutral("StackRails was not reached; the change is not blocked", f"{err} (fail-open)")
        return neutral("StackRails was not reached", f"{err} (fail-open is off)", 1, "failure")
    if ctx.kind in WITH_CHANGES:
        return render_verdict(reply, not_covered)
    return render_record(ctx.kind, reply)


def _gitlab_merge_requests(env: dict) -> list[dict]:
    token = env.get("STACKRAILS_GITLAB_TOKEN")
    if not token:
        raise ConfigError("merge credit on GitLab needs STACKRAILS_GITLAB_TOKEN (read_api)")
    url = f"{env['CI_API_V4_URL']}/projects/{env['CI_PROJECT_ID']}/repository/commits/{env['CI_COMMIT_SHA']}"
    resp = _request("GET", f"{url}/merge_requests", headers={"PRIVATE-TOKEN": token}, timeout=30)
    if resp.status != 200:
        raise ConfigError(f"GitLab merge request lookup answered HTTP {resp.status}")
    return [r for r in resp.body.get("data") or [] if isinstance(r, dict)]


def host_context(args: argparse.Namespace, env: dict) -> Context:
    if args.host == "github":
        with open(env["GITHUB_EVENT_PATH"], encoding="utf-8") as fh:
            ctx = github_context(env.get("GITHUB_EVENT_NAME", ""), json.load(fh), env)
    elif args.host == "gitlab":
        ctx = gitlab_merged_context(env, _gitlab_merge_requests(env)) if args.gitlab_merged else gitlab_context(env)
    elif args.host == "bitbucket":
        ctx = bitbucket_context(env)
    else:
        ctx = Context()
    for key in ("kind", "repository", "base", "head", "pr_number", "merge_commit_sha", "pr_url", "pr_title", "author"):
        if getattr(args, key) is not None:
            setattr(ctx, key, getattr(args, key))
    return ctx


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--url", required=True, help="StackRails portal origin, e.g. https://app.stackrails.ai")
    p.add_argument("--host", choices=("github", "gitlab", "bitbucket", "git"), default="git")
    p.add_argument("--kind", choices=KINDS)
    p.add_argument("--repository")
    p.add_argument("--base", help="base ref or sha; the merge base with --head is computed")
    p.add_argument("--head")
    p.add_argument("--pr-number", type=int)
    p.add_argument("--merge-commit-sha")
    p.add_argument("--pr-url")
    p.add_argument("--pr-title")
    p.add_argument("--author")
    p.add_argument("--fail-open", action=argparse.BooleanOptionalAction, default=True)
    p.add_argument("--timeout", type=float, default=600)
    p.add_argument("--poll-interval", type=float, default=5)
    p.add_argument("--summary-file", help="append the markdown summary here (e.g. $GITHUB_STEP_SUMMARY)")
    p.add_argument("--result-file", help="write {state, title, exit_code, ...} as JSON")
    p.add_argument("--github-check", action="store_true", help="post the check run and the PR comment")
    p.add_argument("--codequality-file", help="write a GitLab Code Quality report")
    p.add_argument("--bitbucket-report", action="store_true", help="post a Code Insights report via the proxy")
    p.add_argument("--bitbucket-proxy", default="http://localhost:29418")
    p.add_argument("--gitlab-merged", action="store_true", help="credit the merged MR of this default-branch commit")
    return p.parse_args(argv)


def main(argv: list[str] | None = None, env: dict | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    env = dict(os.environ) if env is None else env
    key = env.get("STACKRAILS_SERVICE_KEY", "").strip()
    ctx = Context()
    try:
        ctx = host_context(args, env)
        outcome = evaluate(ctx, args, key)
    except ConfigError as err:
        outcome = neutral("StackRails check is misconfigured", str(err), 1, "failure")
    # GitHub reads `::` workflow commands from stdout; reply text is data, so they are off while it prints.
    stop = secrets.token_hex(16) if args.host == "github" else None
    if stop:
        print(f"::stop-commands::{stop}")
    print(outcome.summary)
    if stop:
        print(f"::{stop}::")
        if outcome.exit_code:
            print(f"::error title={CHECK_NAME}::{clean(outcome.title)}")
    if args.summary_file:
        with open(args.summary_file, "a", encoding="utf-8") as fh:
            fh.write(outcome.summary + "\n")
    if args.result_file:
        result = {
            "state": outcome.state,
            "title": outcome.title,
            "exit_code": outcome.exit_code,
            "kind": ctx.kind,
            "job_id": outcome.reply.get("job_id"),
            "report_id": outcome.reply.get("report_id"),
            "blocking": int(outcome.reply.get("blocking") or 0),
            "introduced_total": int(outcome.reply.get("introduced_total") or 0),
        }
        with open(args.result_file, "w", encoding="utf-8") as fh:
            json.dump(result, fh)
    if args.codequality_file:
        with open(args.codequality_file, "w", encoding="utf-8") as fh:
            json.dump(codequality_report(outcome), fh, indent=2)
    if args.github_check and ctx.kind in WITH_CHANGES:
        token = env.get("STACKRAILS_GITHUB_TOKEN", "")
        github_report(
            outcome,
            ctx,
            token,
            env.get("GITHUB_REPOSITORY", ""),
            comment=ctx.kind == "pr_updated" and not outcome.superseded,
        )
    if args.bitbucket_report and ctx.kind in WITH_CHANGES:
        bitbucket_report(outcome, env, args.bitbucket_proxy)
    return outcome.exit_code


if __name__ == "__main__":
    sys.exit(main())
