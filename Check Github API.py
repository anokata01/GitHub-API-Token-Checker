"""
GitHub API Token Checker
========================
Validates GitHub API tokens and discovers their privileges/scope.

Usage:
    1. Run interactively:  python "Check Github API.py"
    2. Pass tokens as args: python "Check Github API.py" TOKEN1 TOKEN2
    3. Or hardcode tokens in the TOKENS list below.
"""

import re
import requests
import sys
from typing import Optional

# ── Configuration ──────────────────────────────────────────────────────────
# Add your GitHub API tokens here
TOKENS: list[str] = [
    # "ghp_your-token-here",
]

BASE_URL = "https://api.github.com"

# Scopes for classic PATs and what they grant
SCOPE_DESCRIPTIONS: dict[str, str] = {
    "repo": "Full control of private repositories",
    "repo:status": "Access commit status",
    "repo_deployment": "Access deployment status",
    "public_repo": "Access public repositories only",
    "repo:invite": "Access repository invitations",
    "security_events": "Read/write security events",
    "admin:repo_hook": "Full control of repository hooks",
    "write:repo_hook": "Write repository hooks",
    "read:repo_hook": "Read repository hooks",
    "admin:org": "Full control of orgs and teams",
    "write:org": "Read and write org membership",
    "read:org": "Read org and team membership",
    "admin:org_hook": "Full control of organization hooks",
    "admin:public_key": "Full control of user public keys",
    "write:public_key": "Write user public keys",
    "read:public_key": "Read user public keys",
    "admin:gpg_key": "Full control of user GPG keys",
    "write:gpg_key": "Write user GPG keys",
    "read:gpg_key": "Read user GPG keys",
    "gist": "Create gists",
    "notifications": "Access notifications",
    "user": "Update ALL user data",
    "read:user": "Read user profile data",
    "user:email": "Access user email addresses",
    "user:follow": "Follow and unfollow users",
    "delete_repo": "Delete repositories",
    "write:discussion": "Read and write team discussions",
    "read:discussion": "Read team discussions",
    "write:packages": "Upload packages to GitHub Packages",
    "read:packages": "Download packages from GitHub Packages",
    "admin:enterprise": "Full control of enterprises",
    "manage_runners:enterprise": "Manage enterprise runners",
    "manage_billing:enterprise": "Read/write enterprise billing data",
    "read:enterprise": "Read enterprise profile data",
    "workflow": "Update GitHub Actions workflow files",
    "project": "Full access to projects",
    "read:project": "Read-only access to projects",
    "codespace": "Full control of codespaces",
    "audit_log": "Full access to audit log",
    "read:audit_log": "Read audit log data",
    "copilot": "Manage GitHub Copilot settings",
}


# ── Helpers ────────────────────────────────────────────────────────────────
def _get(endpoint: str, token: str,
         params: Optional[dict] = None) -> requests.Response:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    return requests.get(
        f"{BASE_URL}{endpoint}",
        headers=headers,
        params=params or {},
        timeout=30,
    )


def sanitize_token(token: str) -> str:
    token = token.strip().strip("'\"")
    token = re.sub(r"[^\x20-\x7E]", "", token)
    return token.strip()


def mask_token(token: str) -> str:
    if len(token) <= 12:
        return token[:3] + "***" + token[-3:]
    return token[:6] + "..." + token[-4:]


# ── Step 1: Validate the token ────────────────────────────────────────────
def check_token_validity(token: str) -> dict:
    result = {
        "valid": False,
        "token_type": None,   # "classic", "fine-grained", or "unknown"
        "user": None,
        "scopes": [],         # Classic PAT scopes from X-OAuth-Scopes
        "rate_limit": None,
        "rate_remaining": None,
        "error": None,
    }

    resp = _get("/user", token)

    result["rate_limit"] = resp.headers.get("X-RateLimit-Limit")
    result["rate_remaining"] = resp.headers.get("X-RateLimit-Remaining")

    if resp.status_code == 200:
        result["valid"] = True
        user_data = resp.json()
        result["user"] = {
            "login": user_data.get("login"),
            "name": user_data.get("name"),
            "type": user_data.get("type"),
            "site_admin": user_data.get("site_admin", False),
        }

        # Classic PATs return X-OAuth-Scopes; fine-grained ones don't
        oauth_scopes = resp.headers.get("X-OAuth-Scopes", "")
        if oauth_scopes:
            result["token_type"] = "classic"
            result["scopes"] = [s.strip() for s in oauth_scopes.split(",")
                                if s.strip()]
        else:
            result["token_type"] = "fine-grained"
    elif resp.status_code == 401:
        result["error"] = "Invalid or expired token"
    elif resp.status_code == 403:
        result["error"] = f"Forbidden — {resp.json().get('message', '')}"
    else:
        result["error"] = f"HTTP {resp.status_code}: {resp.text[:200]}"

    return result


# ── Step 2: Discover privileges ───────────────────────────────────────────
def discover_privileges(token: str) -> dict:
    privileges = {
        "repos_accessible": 0,
        "private_repos": 0,
        "orgs": [],
        "capabilities": {},
    }

    # ── Repos ──
    resp = _get("/user/repos", token, params={"per_page": 100, "type": "all"})
    if resp.status_code == 200:
        repos = resp.json()
        privileges["repos_accessible"] = len(repos)
        privileges["private_repos"] = sum(
            1 for r in repos if r.get("private")
        )
        privileges["capabilities"]["List Repositories"] = True
    else:
        privileges["capabilities"]["List Repositories"] = False

    # ── Orgs ──
    resp = _get("/user/orgs", token, params={"per_page": 100})
    if resp.status_code == 200:
        orgs = resp.json()
        privileges["orgs"] = [o.get("login", "?") for o in orgs]
        privileges["capabilities"]["List Organizations"] = True
    else:
        privileges["capabilities"]["List Organizations"] = False

    # ── Probe endpoints to discover what the token can do ──
    probes = [
        ("/user/emails", "Read Emails"),
        ("/user/gpg_keys", "Read GPG Keys"),
        ("/user/keys", "Read SSH Keys"),
        ("/gists", "Access Gists"),
        ("/notifications", "Access Notifications"),
        ("/user/starred", "Access Starred Repos"),
    ]
    for endpoint, label in probes:
        resp = _get(endpoint, token, params={"per_page": 1})
        privileges["capabilities"][label] = resp.status_code == 200

    # ── Probe repo-level permissions using the first accessible repo ──
    resp = _get("/user/repos", token, params={"per_page": 1, "type": "all"})
    if resp.status_code == 200 and resp.json():
        repo = resp.json()[0]
        owner = repo["owner"]["login"]
        name = repo["name"]
        full = f"{owner}/{name}"

        repo_probes = [
            (f"/repos/{full}/collaborators", "List Collaborators"),
            (f"/repos/{full}/hooks", "List Webhooks"),
            (f"/repos/{full}/actions/workflows", "View GitHub Actions"),
            (f"/repos/{full}/pulls", "List Pull Requests"),
            (f"/repos/{full}/issues", "List Issues"),
            (f"/repos/{full}/branches", "List Branches"),
            (f"/repos/{full}/releases", "List Releases"),
            (f"/repos/{full}/deployments", "List Deployments"),
            (f"/repos/{full}/environments", "List Environments"),
            (f"/repos/{full}/secret-scanning/alerts",
             "View Secret Scanning Alerts"),
            (f"/repos/{full}/code-scanning/alerts",
             "View Code Scanning Alerts"),
        ]
        privileges["_probe_repo"] = full
        for endpoint, label in repo_probes:
            resp = _get(endpoint, token, params={"per_page": 1})
            privileges["capabilities"][label] = resp.status_code == 200

    return privileges


# ── Pretty printer ────────────────────────────────────────────────────────
def print_report(index: int, token: str, validity: dict,
                 privileges: Optional[dict]):
    sep = "=" * 64
    print(f"\n{sep}")
    print(f"  TOKEN #{index}: {mask_token(token)}")
    print(sep)

    if not validity["valid"]:
        print(f"  Status : INVALID")
        print(f"  Error  : {validity['error']}")
        print(sep)
        return

    user = validity["user"]
    print(f"  Status     : VALID")
    print(f"  Token Type : {validity['token_type'].upper()} PAT")
    print(f"  User       : {user['login']} ({user['name'] or 'no name'})")
    print(f"  Account    : {user['type']}"
          f"{'  [SITE ADMIN]' if user['site_admin'] else ''}")
    print(f"  Rate Limit : {validity['rate_remaining']}"
          f" / {validity['rate_limit']} remaining")

    # ── Classic PAT scopes ──
    if validity["token_type"] == "classic" and validity["scopes"]:
        print(f"\n  SCOPES ({len(validity['scopes'])}):")
        for scope in sorted(validity["scopes"]):
            desc = SCOPE_DESCRIPTIONS.get(scope, "")
            print(f"    - {scope:30s} {desc}")

        # Highlight full-access scopes
        full_access = {"repo", "admin:org", "user", "delete_repo",
                       "admin:enterprise", "workflow"}
        granted = full_access & set(validity["scopes"])
        if granted:
            print(f"\n  ** HIGH-PRIVILEGE SCOPES: {', '.join(sorted(granted))}")
    elif validity["token_type"] == "fine-grained":
        print(f"\n  Fine-grained tokens don't expose scopes in headers.")
        print(f"  Permissions are discovered by probing endpoints below.")

    # ── Probed capabilities ──
    if privileges:
        print(f"\n  ACCESSIBLE RESOURCES:")
        print(f"    Repositories : {privileges['repos_accessible']}"
              f" ({privileges['private_repos']} private)")
        if privileges["orgs"]:
            print(f"    Organizations: {', '.join(privileges['orgs'])}")
        else:
            print(f"    Organizations: none visible")

        if "_probe_repo" in privileges:
            print(f"    (Probed on: {privileges['_probe_repo']})")

        print(f"\n  CAPABILITIES:")
        for cap, has_access in privileges["capabilities"].items():
            status = "YES" if has_access else "NO"
            print(f"    {'[' + status + ']':6s} {cap}")

    print(f"\n{sep}")


# ── Main ──────────────────────────────────────────────────────────────────
def main():
    tokens = TOKENS

    if len(sys.argv) > 1:
        tokens = sys.argv[1:]

    if not tokens:
        print("No tokens configured. Enter them below (one per line).")
        print("Press Enter on an empty line when done:\n")
        while True:
            try:
                line = input("  Token: ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                break
            if not line:
                break
            tokens.append(line)

    if not tokens:
        print("No tokens provided. Exiting.")
        sys.exit(1)

    tokens = [sanitize_token(t) for t in tokens]
    tokens = [t for t in tokens if t]

    print(f"\nChecking {len(tokens)} GitHub token(s)...\n")

    for i, token in enumerate(tokens, start=1):
        print(f"[{i}/{len(tokens)}] Checking {mask_token(token)} ...")

        validity = check_token_validity(token)

        privileges = None
        if validity["valid"]:
            privileges = discover_privileges(token)

        print_report(i, token, validity, privileges)

    print("\nDone.")


if __name__ == "__main__":
    main()
