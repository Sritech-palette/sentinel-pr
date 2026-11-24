import base64
import json
import re
import httpx
from pydantic import BaseModel, Field
from langchain_core.tools import tool
from app.config import settings
from app.safety import scrub_pii_and_secrets, inspect_for_prompt_injection


# --- Strict Input Schemas ---

class FetchPRInput(BaseModel):
    pr_url: str = Field(
        description="Full GitHub Pull Request URL, e.g., https://github.com/owner/repo/pull/123"
    )


class ScanCVEInput(BaseModel):
    package_name: str = Field(description="Exact package name, e.g., fastapi, lodash, requests")
    version: str = Field(description="Exact package version string, e.g., 0.100.0")
    ecosystem: str = Field(
        default="PyPI",
        description="Package ecosystem: PyPI, npm, Go, Maven, or crates.io",
    )


class CreateRemediationPRInput(BaseModel):
    owner: str = Field(description="GitHub repository owner or organization")
    repo: str = Field(description="GitHub repository name")
    base_branch: str = Field(default="main", description="Target branch to merge into, e.g., main")
    file_path: str = Field(description="Path of the file to patch, e.g., requirements.txt or app/auth.py")
    patched_content: str = Field(description="Complete updated file content with the security fix applied")
    pr_title: str = Field(description="Clear security remediation PR title")
    pr_body: str = Field(description="Detailed markdown explanation of the vulnerability and fix")


def _github_headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {settings.GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


# --- Agent Tools ---

@tool("fetch_github_pr", args_schema=FetchPRInput)
async def fetch_github_pr(pr_url: str) -> str:
    """
    Fetches metadata, changed files, and code diffs from a GitHub Pull Request.
    Automatically scrubs PII/secrets and scans external PR text for indirect prompt injections.
    """
    match = re.match(r"https?://github\.com/([^/]+)/([^/]+)/pull/(\d+)", pr_url.strip())
    if not match:
        return "ERROR: Invalid GitHub PR URL. Expected format: https://github.com/owner/repo/pull/123"

    owner, repo, pr_number = match.groups()
    base_api = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"

    async with httpx.AsyncClient(timeout=15.0) as client:
        pr_res = await client.get(base_api, headers=_github_headers())
        if pr_res.status_code != 200:
            return f"ERROR: GitHub API returned {pr_res.status_code} - {pr_res.text[:300]}"
        pr_data = pr_res.json()

        files_res = await client.get(f"{base_api}/files", headers=_github_headers())
        files_data = files_res.json() if files_res.status_code == 200 else []

    raw_summary = {
        "owner": owner,
        "repo": repo,
        "pr_number": int(pr_number),
        "title": pr_data.get("title", ""),
        "author": pr_data.get("user", {}).get("login", "unknown"),
        "base_branch": pr_data.get("base", {}).get("ref", "main"),
        "description": (pr_data.get("body") or "")[:1500],
        "changed_files": [
            {
                "filename": f.get("filename"),
                "status": f.get("status"),
                "patch": (f.get("patch") or "")[:2500],
            }
            for f in files_data[:10]
        ],
    }

    serialized = json.dumps(raw_summary, indent=2)

    # Layer 1 & 2: Scrub any accidental secrets or emails inside the PR diff
    sanitized_text, redactions = scrub_pii_and_secrets(serialized)

    # Layer 3: Scan external GitHub content for Indirect Prompt Injection
    verdict = await inspect_for_prompt_injection(sanitized_text, source=f"github_pr_{owner}/{repo}#{pr_number}")
    if not verdict.is_safe:
        return (
            f"SECURITY_BLOCK: Indirect prompt injection detected inside GitHub PR content! "
            f"Category={verdict.threat_category} | Reason={verdict.reason}"
        )

    if redactions:
        return f"[Note: Scrubbed sensitive entities from PR: {redactions}]\n{sanitized_text}"
    return sanitized_text


@tool("scan_package_cve", args_schema=ScanCVEInput)
async def scan_package_cve(package_name: str, version: str, ecosystem: str = "PyPI") -> str:
    """
    Queries the live Open Source Vulnerabilities (OSV.dev) database for known CVEs
    affecting a specific package version and returns severity and patched versions.
    """
    payload = {
        "version": version.strip(),
        "package": {"name": package_name.strip(), "ecosystem": ecosystem.strip()},
    }

    async with httpx.AsyncClient(timeout=12.0) as client:
        res = await client.post("https://api.osv.dev/v1/query", json=payload)
        if res.status_code != 200:
            return f"ERROR: OSV API returned {res.status_code}"
        data = res.json()

    vulns = data.get("vulns", [])
    if not vulns:
        return f"CLEAN: No known CVEs found for {package_name}=={version} ({ecosystem})."

    findings = []
    for v in vulns[:5]:
        fixed_versions = []
        for affected in v.get("affected", []):
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        fixed_versions.append(event["fixed"])
        findings.append(
            {
                "id": v.get("id"),
                "aliases": v.get("aliases", []),
                "summary": v.get("summary", "No summary provided"),
                "fixed_in": list(set(fixed_versions)),
            }
        )

    return json.dumps(
        {
            "package": package_name,
            "version": version,
            "vulnerability_count": len(vulns),
            "findings": findings,
        },
        indent=2,
    )


@tool("create_remediation_pr", args_schema=CreateRemediationPRInput)
async def create_remediation_pr(
    owner: str,
    repo: str,
    base_branch: str,
    file_path: str,
    patched_content: str,
    pr_title: str,
    pr_body: str,
) -> str:
    """
    HIGH-IMPACT WRITE TOOL (Gated by Human-in-the-Loop Approval):
    Creates a new remediation branch, commits the patched file, and opens a Pull Request on GitHub.
    """
    branch_name = f"sentinel-fix/{re.sub(r'[^a-zA-Z0-9_-]', '-', file_path.lower())}"
    base_api = f"https://api.github.com/repos/{owner}/{repo}"

    async with httpx.AsyncClient(timeout=15.0) as client:
        # 1. Get latest commit SHA of base_branch
        ref_res = await client.get(f"{base_api}/git/ref/heads/{base_branch}", headers=_github_headers())
        if ref_res.status_code != 200:
            return f"ERROR: Could not resolve base branch '{base_branch}': {ref_res.text[:250]}"
        base_sha = ref_res.json()["object"]["sha"]

        # 2. Create new remediation branch (ignore 422 if branch already exists)
        await client.post(
            f"{base_api}/git/refs",
            headers=_github_headers(),
            json={"ref": f"refs/heads/{branch_name}", "sha": base_sha},
        )

        # 3. Get existing file SHA if updating an existing file
        file_res = await client.get(
            f"{base_api}/contents/{file_path}",
            headers=_github_headers(),
            params={"ref": branch_name},
        )
        file_sha = file_res.json().get("sha") if file_res.status_code == 200 else None

        # 4. Commit patched file content
        commit_payload = {
            "message": f"fix(security): {pr_title}",
            "content": base64.b64encode(patched_content.encode("utf-8")).decode("utf-8"),
            "branch": branch_name,
        }
        if file_sha:
            commit_payload["sha"] = file_sha

        put_res = await client.put(
            f"{base_api}/contents/{file_path}",
            headers=_github_headers(),
            json=commit_payload,
        )
        if put_res.status_code not in (200, 201):
            return f"ERROR: Failed to commit patch: {put_res.text[:250]}"

        # 5. Open the Pull Request
        pr_res = await client.post(
            f"{base_api}/pulls",
            headers=_github_headers(),
            json={
                "title": f"[SentinelPR] {pr_title}",
                "head": branch_name,
                "base": base_branch,
                "body": f"{pr_body}\n\n---\n*Generated & human-approved via **SentinelPR Autonomous Security Agent***",
            },
        )
        if pr_res.status_code != 201:
            return f"ERROR: Failed to open PR: {pr_res.text[:250]}"

        pr_html_url = pr_res.json().get("html_url")
        return f"SUCCESS: Remediation Pull Request created at {pr_html_url}"


READ_ONLY_TOOLS = [fetch_github_pr, scan_package_cve]
WRITE_TOOLS = [create_remediation_pr]
ALL_TOOLS = READ_ONLY_TOOLS + WRITE_TOOLS