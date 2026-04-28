# Threat Model

**Last updated:** 2026-04-28  
**Version:** 0.5.1

This document describes what KeySmith protects against, what it does not, and the security assumptions it makes.

---

## Scope

KeySmith is designed for:

- **Personal development workflows**
- **Small trusted teams** (2-5 people)
- **Non-critical API credentials** (not production secrets at scale)
- **Local-first secret management** (no cloud dependency)

KeySmith is **NOT designed** for:

- Adversarial environments  
- Regulated compliance (HIPAA, PCI-DSS, SOC2)  
- High-security contexts  
- Large teams with complex RBAC needs  

---

## Assets

### What KeySmith Protects

1. **API credentials** (GitHub tokens, OpenAI keys, FEC API keys, etc.)  
2. **Team secret sharing metadata** (who has access, when rotated)  
3. **Audit trail** (cryptographic receipts of credential operations)  
4. **Credential policies** (rotation schedules, access scopes)  

### What KeySmith Does NOT Store

- Production database passwords  
- Private keys for code signing  
- SSH keys  
- Cryptocurrency wallets  
- High-value production secrets  

---

## Threat Actors

### In Scope

**Accidental Exposure (Primary Threat)**

- Developer accidentally pastes API key in AI chat  
- Credentials committed to git repository  
- `.env` files shared via Slack/email  
- Secrets in screenshot/screen share  

**Negligent Developer**

- Forgets to rotate credentials  
- Shares credentials insecurely  
- Uses weak credentials  
- Does not notice expired keys  

**Curious Teammate (Trusted but Nosy)**

- Wants to see which credentials exist  
- Checks rotation status  
- Views audit logs  
- Not actively malicious, just curious  

### Out of Scope

**Advanced Persistent Threat (APT)**

- Nation-state actors  
- Sophisticated malware  
- Supply chain attacks on dependencies  
- Zero-day exploits against OS keychain  

**Malicious Insider (Team Member)**

- Team member intentionally exfiltrating secrets  
- Backdooring credential operations  
- Tampering with receipts  
- Social engineering other team members  

**Why out of scope:** KeySmith assumes **trusted team members**. If your threat model includes malicious insiders, use enterprise-grade secret management with RBAC, audit logs, and separation of duties.

---

## Attack Scenarios

### ✅ Protected Against

#### 1. Accidental AI Chat Leak

**Attack:** Developer pastes API key in Claude/ChatGPT/Copilot to get help.

**Protection:**

- MCP integration provides handles (`sec://project/provider/api-key`), not raw secrets  
- AI tools integrated this way avoid KeySmith-mediated secret exposure  

**Limitations:**

- Does not prevent a developer from manually typing a key  
- Does not protect against screen sharing with a secret visible  

---

#### 2. Git Commit with Secrets

**Attack:** Developer accidentally `git add .env` and commits secrets.

**Protection:**

- Pre-commit hook scans staged files for API key patterns  
- Blocks commit if secrets detected  
- Suggests storing in keychain instead  

**Command:** `keysmith install-hook`

**Limitations:**

- Can be bypassed with `git commit --no-verify`  
- Only scans files, not commit messages  
- Pattern-based (may have false positives/negatives)  

---

#### 3. Shell History Leak

**Attack:** Credentials typed in terminal commands (for example `curl -H "Authorization: Bearer …"`).

**Protection:**

- `keysmith scrub-history` removes secrets from bash/zsh/fish history backups (with `.bak`)  
- Backups kept before modification  

**Limitations:**

- Only removes known/heuristic patterns  
- Does not prevent future leaks  
- Does not scrub tmux or screen scrollback  

---

#### 4. Forgotten Rotation

**Attack:** API key compromised months ago, but never rotated.

**Protection:**

- Rotation policies with reminders  
- Optional enforcement (`settings.enforce: true`) can block overdue `inject` beyond a configurable grace window  

**Limitations:**

- Enforcement can be bypassed with `--skip-rotation-check`  
- Does not auto-rotate (manual process at providers)  
- Enforcement applies at KeySmith `inject` boundaries, not to every conceivable credential use  

---

#### 5. Receipt Tampering

**Attack:** Attacker modifies audit log line to hide credential access.

**Protection:**

- Ed25519 signatures per receipt (`keysmith receipts --verify`)  
- Append-only mental model  

**Limitations:**

- Attacker with filesystem access may delete logs wholesale  
- Receipts do not magically replicate off-machine  
- Receipts attest to “KeySmith recorded this,” not independent third-party attestation  

---

### ❌ NOT Protected Against

#### 1. Compromised Developer Machine

**Attack:** Attacker gains access to the developer laptop or desktop.

**Why unprotected:**

- OS keychain is reachable to processes running as that user  

**Mitigation (external to KeySmith):**

- Full-disk encryption  
- Screen lock when away  
- OS-level malware protection  
- Hardware security keys where appropriate  

---

#### 2. Malicious Team Member

**Attack:** Team member with legitimate access intentionally exfiltrates secrets.

**Why unprotected:**

- Shared age ciphertext decrypts with any bundled recipient key identity  
- A trusted user can invoke tools or read keychain-backed material subject to OS rules  

**Mitigation (external to KeySmith):**

- Hiring and access hygiene  
- Principle of least privilege  
- Separation of duties tooling for adversarial contexts  

---

#### 3. Supply Chain Attack

**Attack:** Malicious dependency (for example compromised `cryptography`) exfiltrates secrets.

**Why unprotected:**

- Same class of risk as any Python application using PyPI dependencies  

**Mitigation (external to KeySmith):**

- Pin dependencies  
- Audit updates  
- Supply-chain tooling suited to your org  

---

#### 4. Side-Channel Attacks

**Attack:** Timing or cache-timing style attacks.

**Why unprotected:**

- Typical Python cryptography usage; not hardened for exotic side-channel budgets  

---

#### 5. Coercion / “Rubber-Hose”

**Attack:** Attacker physically forces credential disclosure.

**Why unprotected:**

- This is developer tooling under normal OS protections, not a deniable cryptography system  

---

## Security Assumptions

KeySmith makes assumptions. **If these are false, security breaks.**

### 1. Operating System Keychain is Secure

Assume macOS Keychain, Windows Credential Manager, or compatible Linux backends behave as advertised for the logged-in user.

### 2. Team Members Are Non-Adversarial (for Sharing)

Assume collaborators with decryption keys participate in good faith before giving them ciphertext or repo access.

### 3. Git Repository Access Matches Your Intended Audience

Assume public repos should not carry sensitive plaintext; configure `.gitignore` for `.keysmith/secrets/` if ciphertext in Git is unacceptable.

### 4. Cryptography Dependencies Behave Correctly

Assume mature libraries (`cryptography` for receipts, OS `age` binary for sharing) behave as upstream documents.

### 5. age Binary Is Trustworthy When Used Off-CLI

Assume you install vetted binaries and PATH is not sabotaged.

### 6. Honest Operational Use

Assume operators do not treat `--skip-rotation-check` as their default workflow.

---

## Enforcement Limitations

### Rotation Enforcement

**What it is:**

- Opt-in blocking for `keysmith inject` when team policy YAML sets `enforce: true`  
- Compared against schedules in `~/.keysmith/rotation.json`  

**Bypass methods:**

1. `--skip-rotation-check`  
2. Read credentials outside KeySmith (direct OS keychain or provider flows)  

**Recommendation:** Treat bypass as deliberate; current `credential_injected` receipts do **not** record whether `--skip-rotation-check` was used—add process review rather than pretending automated detection exists yet.

---

## Known Vulnerabilities

No CVE catalog is maintained inline in-repo. Report issues privately as described in [SECURITY.md](SECURITY.md).

---

## Security Testing

### What Has Been Covered

Automated tests exercise broker paths, receipts, scheduler logic, representative team flows—**best-effort, not exhaustive**.

### What Has Not Been Done

Formal audit, fuzzing programmes, penetration tests as a packaged deliverable—**not shipped**.

---

## Compliance

Not evaluated against HIPAA, PCI-DSS, SOC2, FedRAMP, ISO 27001, GDPR, or similar. **Assume non-compliance.**

---

## Recommended Usage

### ✅ Typically Appropriate

1. Personal development credentials  
2. Small trusted teams prototyping  
3. Learning MCP + local secret hygiene patterns  

### ❌ Typically Inappropriate Without Extra Controls

Production-scale secrets orchestration or regulated mandates where certified controls are contractual.

---

## Incident Response Sketches

### If a Credential Might Be Compromised

Rotate at the provider, revoke old material, regenerate team ciphertext if rotation involved shared blobs, replay `doctor`/`receipts` review as breadcrumbs only.

### If Receipts Fail Verification

Restore from backups or SCM history (`git`), investigate who rewrote logs, regenerate signing setup if suspicion warrants.

---

## Conclusion

KeySmith prioritizes accidental-leak mitigation and reproducible workflows for small teams—not enterprise adversarial certification.

Questions: GitHub Issues or maintainer channels per profile disclosure preferences.
