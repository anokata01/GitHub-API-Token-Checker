# GitHub API Token Checker

A Python tool that validates GitHub Personal Access Tokens (PATs) and discovers their privileges, scopes, and accessible resources.

## What It Does

1. **Validates tokens** - Checks if each token is active and authenticates successfully against the GitHub API.
2. **Detects token type** - Identifies whether the token is a **Classic PAT** or a **Fine-Grained PAT**.
3. **Lists scopes (Classic PATs)** - Reads granted scopes from the `X-OAuth-Scopes` response header and flags high-privilege ones.
4. **Probes capabilities** - Tests real endpoints to discover what the token can actually do:
   - Account-level: repos, orgs, emails, SSH/GPG keys, gists, notifications
   - Repo-level: collaborators, webhooks, actions, pull requests, issues, branches, releases, deployments, secret scanning, code scanning

## Token Types

| Type | How It Works | Scope Discovery |
|------|-------------|-----------------|
| **Classic PAT** (`ghp_...`) | Broad scopes like `repo`, `admin:org`, `user` | Scopes returned in `X-OAuth-Scopes` header |
| **Fine-Grained PAT** (`github_pat_...`) | Granular per-repository permissions | No scope header; discovered by probing endpoints |

## Requirements

- Python 3.10+
- `requests` library

## Setup

```bash
# Create a virtual environment
python3 -m venv .venv

# Activate it
source .venv/bin/activate        # macOS / Linux
.venv\Scripts\activate           # Windows

# Install dependencies
pip install requests
```

## Usage

### Option 1: Interactive Mode (Recommended)

Run the script with no arguments and paste your tokens when prompted:

```bash
python "Check Github API.py"
```

```
No tokens configured. Enter them below (one per line).
Press Enter on an empty line when done:

  Token: ghp_xxxxxxxxxxxxxxxxxxxx
  Token: github_pat_xxxxxxxxxxxx
  Token:
```

### Option 2: Command-Line Arguments

```bash
python "Check Github API.py" ghp_YOUR_TOKEN_1 ghp_YOUR_TOKEN_2
```

### Option 3: Hardcode in the Script

Edit the `TOKENS` list at the top of `Check Github API.py`:

```python
TOKENS: list[str] = [
    "ghp_your-token-1",
    "ghp_your-token-2",
]
```

> **Warning:** Never commit real tokens to version control. Use Option 1 or 2 for security.

## Example Output

### Valid Classic PAT

```
================================================================
  TOKEN #1: ghp_Ab...xYz9
================================================================
  Status     : VALID
  Token Type : CLASSIC PAT
  User       : octocat (The Octocat)
  Account    : User
  Rate Limit : 4998 / 5000 remaining

  SCOPES (3):
    - read:org                       Read org and team membership
    - repo                           Full control of private repositories
    - user                           Update ALL user data

  ** HIGH-PRIVILEGE SCOPES: repo, user

  ACCESSIBLE RESOURCES:
    Repositories : 42 (15 private)
    Organizations: my-org, another-org
    (Probed on: my-org/my-repo)

  CAPABILITIES:
    [YES]  List Repositories
    [YES]  List Organizations
    [YES]  Read Emails
    [YES]  Read GPG Keys
    [YES]  Read SSH Keys
    [YES]  Access Gists
    [YES]  Access Notifications
    [YES]  Access Starred Repos
    [YES]  List Collaborators
    [YES]  List Webhooks
    [YES]  View GitHub Actions
    [YES]  List Pull Requests
    [YES]  List Issues
    [YES]  List Branches
    [YES]  List Releases
    [YES]  List Deployments
    [NO]   List Environments
    [NO]   View Secret Scanning Alerts
    [NO]   View Code Scanning Alerts

================================================================
```

### Valid Fine-Grained PAT

```
================================================================
  TOKEN #1: github...ab12
================================================================
  Status     : VALID
  Token Type : FINE-GRAINED PAT
  User       : octocat (The Octocat)
  Account    : User
  Rate Limit : 4999 / 5000 remaining

  Fine-grained tokens don't expose scopes in headers.
  Permissions are discovered by probing endpoints below.

  ACCESSIBLE RESOURCES:
    Repositories : 3 (2 private)
    Organizations: none visible

  CAPABILITIES:
    [YES]  List Repositories
    [NO]   List Organizations
    [NO]   Read Emails
    [YES]  List Pull Requests
    [YES]  List Issues
    [NO]   List Collaborators
    ...

================================================================
```

### Invalid Token

```
================================================================
  TOKEN #1: badtok...en12
================================================================
  Status : INVALID
  Error  : Invalid or expired token
================================================================
```

## Scopes Reference (Classic PATs)

The script recognizes and describes all standard GitHub OAuth scopes:

| Scope | Access Level |
|-------|-------------|
| `repo` | Full control of private repositories |
| `public_repo` | Access public repositories only |
| `admin:org` | Full control of orgs and teams |
| `read:org` | Read org and team membership |
| `user` | Update ALL user data |
| `read:user` | Read user profile data |
| `user:email` | Access user email addresses |
| `delete_repo` | Delete repositories |
| `workflow` | Update GitHub Actions workflow files |
| `admin:repo_hook` | Full control of repository hooks |
| `gist` | Create gists |
| `notifications` | Access notifications |
| `write:packages` / `read:packages` | GitHub Packages access |
| `admin:gpg_key` / `admin:public_key` | Manage cryptographic keys |
| `admin:enterprise` | Full control of enterprises |
| `codespace` | Full control of codespaces |
| `copilot` | Manage GitHub Copilot settings |
| `audit_log` | Access audit log |

High-privilege scopes (`repo`, `admin:org`, `user`, `delete_repo`, `admin:enterprise`, `workflow`) are flagged in the output.

## Capabilities Probed

| Capability | Endpoint | Level |
|-----------|----------|-------|
| List Repositories | `GET /user/repos` | Account |
| List Organizations | `GET /user/orgs` | Account |
| Read Emails | `GET /user/emails` | Account |
| Read GPG Keys | `GET /user/gpg_keys` | Account |
| Read SSH Keys | `GET /user/keys` | Account |
| Access Gists | `GET /gists` | Account |
| Access Notifications | `GET /notifications` | Account |
| Access Starred Repos | `GET /user/starred` | Account |
| List Collaborators | `GET /repos/{repo}/collaborators` | Repository |
| List Webhooks | `GET /repos/{repo}/hooks` | Repository |
| View GitHub Actions | `GET /repos/{repo}/actions/workflows` | Repository |
| List Pull Requests | `GET /repos/{repo}/pulls` | Repository |
| List Issues | `GET /repos/{repo}/issues` | Repository |
| List Branches | `GET /repos/{repo}/branches` | Repository |
| List Releases | `GET /repos/{repo}/releases` | Repository |
| List Deployments | `GET /repos/{repo}/deployments` | Repository |
| List Environments | `GET /repos/{repo}/environments` | Repository |
| Secret Scanning Alerts | `GET /repos/{repo}/secret-scanning/alerts` | Repository |
| Code Scanning Alerts | `GET /repos/{repo}/code-scanning/alerts` | Repository |

## Rate Limits

GitHub API allows **5,000 requests per hour** for authenticated tokens. The script displays your current remaining quota in the output. Each run uses approximately 15-20 API calls per token.

## API Reference

- [GitHub REST API - Authentication](https://docs.github.com/en/rest/authentication)
- [Scopes for OAuth Apps](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps)
- [Managing Personal Access Tokens](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)
- [Fine-Grained PAT Permissions](https://docs.github.com/en/rest/authentication/permissions-required-for-fine-grained-personal-access-tokens)
