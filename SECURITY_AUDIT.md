# CTFd Security Vulnerability Analysis

**Date:** 2026-02-06
**Target:** CTFd v3.8.2 (OSS)
**Framework:** Flask 2.1.3 / SQLAlchemy 1.4.54 / Jinja2 (Sandboxed)

---

## Executive Summary

This report documents a static security analysis of the CTFd Capture The Flag platform. The analysis identified **15 vulnerabilities** across multiple categories, including 3 critical, 4 high, 5 medium, and 3 low severity issues. The most concerning findings involve JavaScript code execution via `eval()` in admin panel Vue components, HTML sanitization disabled by default, unauthenticated API endpoints leaking notification data, and plaintext password comparison for preset admin authentication.

---

## Critical Severity

### VULN-01: JavaScript Code Execution via `eval()` in Flag Form Components

**Files:**
- `CTFd/themes/admin/assets/js/components/flags/FlagCreationForm.vue:98`
- `CTFd/themes/admin/assets/js/components/flags/FlagEditForm.vue:83`

**Description:** Both flag form components use `eval()` to execute JavaScript extracted from server-rendered HTML templates. When a flag type plugin returns HTML containing `<script>` tags, the content is parsed with jQuery and passed directly to `eval()`.

```javascript
// FlagCreationForm.vue:98
eval($(this).html());
```

**Impact:** If a malicious or compromised flag type plugin injects arbitrary JavaScript into its template response, it achieves full code execution in the admin's browser context. This could lead to session hijacking, admin account takeover, or data exfiltration. While this requires a malicious plugin, the pattern is inherently unsafe and could be exploited in supply-chain attacks against plugins.

**CVSS Estimate:** 8.4 (High) — requires malicious plugin or compromised API response

**Recommendation:** Replace `eval()` with a safe DOM insertion method. Use `document.createElement('script')` or a controlled script loader instead.

---

### VULN-02: HTML Sanitization Disabled by Default

**File:** `CTFd/config.py:263`

```python
HTML_SANITIZATION: bool = process_boolean_str(
    empty_str_cast(config_ini["optional"]["HTML_SANITIZATION"], default=False)
)
```

**Description:** The `HTML_SANITIZATION` configuration defaults to `False`. This means all HTML content rendered in pages, challenges, hints, and notifications is served without sanitization. The `|safe` Jinja2 filter is used extensively across templates (`CTFd/themes/core/templates/page.html:5`, `CTFd/themes/core/templates/challenge.html:114`), rendering raw HTML directly into the page.

**Impact:** Any admin-created content (pages, challenge descriptions, hints, notifications) can contain arbitrary JavaScript that executes for all users viewing that content. In a multi-admin environment, a compromised or malicious admin can achieve stored XSS against all users including other admins.

**CVSS Estimate:** 8.1 (High) — stored XSS affecting all users, requires admin privileges to inject

**Recommendation:** Change the default to `HTML_SANITIZATION = True`. Audit all uses of `|safe` filter and `Markup()` to ensure sanitization is applied.

---

### VULN-03: Plaintext Password Comparison for Preset Admin

**File:** `CTFd/auth.py:459`

```python
if (
    name == preset_admin_name or name == preset_admin_email
) and password == preset_admin_password:
```

**Description:** The preset admin authentication mechanism compares the submitted password directly against the `PRESET_ADMIN_PASSWORD` environment variable using Python's `==` operator. This has two issues:

1. **Timing attack:** String equality comparison in Python is not constant-time, potentially leaking password length/content information through response timing differences.
2. **Plaintext storage:** The preset admin password must be stored in plaintext in environment variables or configuration files, unlike regular user passwords which are bcrypt-hashed.

**Impact:** An attacker with access to environment variables, container configurations, or process memory can directly read the admin password. The timing side-channel, while difficult to exploit over a network, is a deviation from security best practices.

**CVSS Estimate:** 7.5 (High) — plaintext credential storage, timing oracle

**Recommendation:** Use `hmac.compare_digest()` for constant-time comparison, or better, hash the preset password with bcrypt and use `verify_password()`.

---

## High Severity

### VULN-04: Unauthenticated Notification API Endpoints (IDOR)

**File:** `CTFd/api/v1/notifications.py:67-83, 169-176`

**Description:** The notification listing (`GET /api/v1/notifications`) and detail (`GET /api/v1/notifications/<id>`) endpoints have **no authentication decorator**. The `POST` and `DELETE` methods correctly use `@admins_only`, but the read endpoints are completely open.

The `Notifications` model contains `user_id` and `team_id` fields (linking to specific users/teams), meaning notifications can be targeted. The listing endpoint also accepts `user_id` and `team_id` as query filter parameters, allowing unauthenticated enumeration of notifications by user or team.

```python
# No @authed_only or @admins_only decorator
def get(self, query_args):
    notifications = (
        Notifications.query.filter_by(**query_args).filter(*filters).all()
    )
```

**Impact:** Unauthenticated attackers can read all notifications, including potentially sensitive announcements. They can enumerate notifications per user/team, revealing competition metadata and potentially flag hints or sensitive information shared via notifications.

**CVSS Estimate:** 6.5 (Medium-High) — unauthenticated information disclosure

**Recommendation:** Add `@authed_only` decorator to GET endpoints. For targeted notifications, verify the requesting user matches the `user_id`/`team_id`.

---

### VULN-05: Stored XSS via Admin Theme Header/Footer Injection

**Files:**
- `CTFd/constants/config.py:33-42`
- `CTFd/utils/helpers/__init__.py:11`

**Description:** The `theme_header` and `theme_footer` configuration properties wrap their values with `Markup()`, which explicitly marks the content as safe HTML, bypassing Jinja2's autoescaping:

```python
@property
def theme_header(self):
    from CTFd.utils.helpers import markup
    return markup(get_config("theme_header", default=""))
```

These values are configurable by admins via `PATCH /api/v1/configs` and are rendered on every page.

**Impact:** An admin can inject persistent JavaScript into every page of the CTFd instance, affecting all users. While this requires admin access, it enables privilege persistence — a compromised admin session can install a persistent XSS backdoor that survives session expiration.

**CVSS Estimate:** 6.1 (Medium) — requires admin, but provides persistence

**Recommendation:** Sanitize theme header/footer content, or at minimum require a separate "super admin" privilege for modifying theme HTML.

---

### VULN-06: HMAC Uses SHA-1 as Default Digest Algorithm

**File:** `CTFd/utils/security/signing.py:44`

```python
def hmac(data, secret=None, digest=hashlib.sha1):
```

**Description:** The HMAC function defaults to SHA-1 as its digest algorithm. While HMAC-SHA1 is not currently considered broken for HMAC specifically (unlike raw SHA-1 for collision resistance), NIST deprecated SHA-1 in 2011 and modern security standards require SHA-256 or higher.

This HMAC function is used for session validation and security-critical signing operations throughout the application.

**Impact:** Non-compliance with modern cryptographic standards. While not immediately exploitable, SHA-1's reduced security margins make it a liability for long-lived deployments.

**CVSS Estimate:** 4.7 (Medium) — cryptographic weakness, not immediately exploitable

**Recommendation:** Change the default digest to `hashlib.sha256`.

---

### VULN-07: Configuration Bug — MAILGUN_BASE_URL Reads Wrong Key

**File:** `CTFd/config.py:210`

```python
MAILGUN_BASE_URL: str = empty_str_cast(config_ini["email"]["MAILGUN_API_KEY"])
#                                                          ^^^^^^^^^^^^^^^^
#                                          Should be: "MAILGUN_BASE_URL"
```

**Description:** A copy-paste error causes `MAILGUN_BASE_URL` to be populated with the value of `MAILGUN_API_KEY` instead of the actual base URL. This means the Mailgun API key could be inadvertently used as a URL component.

**Impact:** If Mailgun is the configured mail provider, the API key may be leaked in HTTP request URLs (appearing in server logs, proxy logs, or browser history). Additionally, email sending will fail since the base URL is incorrect.

**CVSS Estimate:** 5.3 (Medium) — potential API key leakage

**Recommendation:** Fix the key reference to `config_ini["email"]["MAILGUN_BASE_URL"]`.

---

## Medium Severity

### VULN-08: Missing `SESSION_COOKIE_SECURE` Flag

**File:** `CTFd/config.py:149-159`

**Description:** The session cookie security configuration sets `SESSION_COOKIE_HTTPONLY=True` and `SESSION_COOKIE_SAMESITE="Lax"`, but does not set `SESSION_COOKIE_SECURE`. This flag is entirely absent from both the config class and the config.ini template.

**Impact:** Session cookies will be transmitted over unencrypted HTTP connections, allowing session hijacking via network sniffing (e.g., on public WiFi at CTF events).

**Recommendation:** Add `SESSION_COOKIE_SECURE = True` as a configurable default.

---

### VULN-09: SQL Injection in Import Function (Type-Guarded)

**File:** `CTFd/utils/exports/__init__.py:397-400`

```python
config_id = int(entry["id"])
side_db.query(
    f"DELETE FROM config WHERE id={config_id}"
)
```

**Description:** An f-string is used to construct a SQL DELETE query. While the `int()` cast provides type safety (preventing string injection), this pattern is inherently unsafe and sets a bad precedent. The `side_db.query()` method (from the `dataset` library) does not use parameterized queries.

**Impact:** Currently mitigated by `int()` conversion, but fragile. Any future modification that removes the type cast or changes the interpolated value could introduce SQL injection.

**Recommendation:** Use parameterized queries: `side_db.query("DELETE FROM config WHERE id=:id", id=config_id)`.

---

### VULN-10: PostgreSQL Sequence Reset with String-Formatted Table Names

**File:** `CTFd/utils/exports/__init__.py:411-415`

```python
if '"' not in table_name and "'" not in table_name:
    query = "SELECT setval(pg_get_serial_sequence('{table_name}', 'id'), ...)".format(
        table_name=table_name
    )
    side_db.engine.execute(query)
```

**Description:** Table names from the import data are interpolated into raw SQL via `.format()`. The quote-checking validation (`'"' not in table_name and "'" not in table_name`) is an incomplete defense — attackers might use other SQL injection techniques depending on the database encoding and parser behavior.

**Impact:** Limited by the fact that table names come from the CTFd backup format (controlled data), but a crafted malicious backup file could potentially exploit this during import.

**Recommendation:** Use proper SQL identifier quoting (e.g., `psycopg2.sql.Identifier`) or SQLAlchemy's `text()` with bound parameters.

---

### VULN-11: No File Type Validation on Upload

**Files:**
- `CTFd/api/v1/files.py:110`
- `CTFd/utils/uploads/__init__.py:16-71`

**Description:** The file upload system sanitizes filenames (via `secure_filename()`) and generates random directory paths, but does not validate file content types or extensions. There is no allowlist/denylist for uploaded file types.

**Impact:** Malicious files (e.g., HTML files containing JavaScript, SVG with embedded scripts, or executable files) can be uploaded and served back to users. If served with incorrect Content-Type headers, this could lead to stored XSS via file upload.

**Recommendation:** Implement file extension allowlisting and validate Content-Type headers on served files.

---

### VULN-12: Missing Content Security Policy (CSP) Header

**File:** `CTFd/utils/initialization/__init__.py:371`

**Description:** The application sets `Cross-Origin-Opener-Policy: same-origin-allow-popups` but does not set a `Content-Security-Policy` header. There is also no `X-Frame-Options` header configured.

**Impact:** Without CSP, any XSS vulnerability becomes significantly more exploitable (inline scripts execute freely, external resources can be loaded). Without `X-Frame-Options`, the application may be vulnerable to clickjacking attacks.

**Recommendation:** Implement a strict CSP policy (at minimum: `default-src 'self'; script-src 'self'`). Add `X-Frame-Options: DENY` or `SAMEORIGIN`.

---

## Low Severity

### VULN-13: Debug Mode Enabled in Development Scripts

**Files:**
- `wsgi.py:14` — `app.run(debug=True, ...)`
- `serve.py:43` — `app.run(debug=True, ...)`

**Description:** Development entry points enable Flask debug mode, which exposes the Werkzeug interactive debugger, detailed stack traces, and automatic code reloading.

**Impact:** If these scripts are used in production, attackers can execute arbitrary code via the Werkzeug debugger console, view source code, and access environment variables.

**Recommendation:** Ensure production deployments use gunicorn/uwsgi (as specified in the Dockerfile) and never use these development scripts.

---

### VULN-14: Weak Secret Key in Test Configuration

**File:** `CTFd/config.py:308`

```python
SECRET_KEY = "AAAAAAAAAAAAAAAAAAAA"
```

**Description:** The test configuration class uses a trivially guessable secret key. If this configuration is accidentally used in production, all session signing, CSRF tokens, and cryptographic operations are compromised.

**Impact:** Low in practice (only affects test environments), but represents a risk if deployment processes are misconfigured.

**Recommendation:** Add runtime validation that rejects known-weak secret keys in non-test environments.

---

### VULN-15: MySQL Process Kill via F-String SQL

**File:** `CTFd/utils/exports/__init__.py:246`

```python
db.session.execute(f"KILL {proc_id}")
```

**Description:** Uses f-string interpolation for a MySQL `KILL` command. The `proc_id` value comes from `SHOW PROCESSLIST` output (not user input), limiting exploitability.

**Impact:** Minimal — the value is internally sourced. However, this pattern should not be replicated.

**Recommendation:** Use parameterized execution if MySQL supports it for `KILL`, or validate the integer type explicitly.

---

## Positive Security Practices Observed

The following security measures are properly implemented:

| Practice | Implementation |
|---|---|
| **Password Hashing** | bcrypt_sha256 via passlib with SQLAlchemy validator (`CTFd/models/__init__.py`) |
| **CSRF Protection** | Nonce-based tokens validated on all state-changing requests (`CTFd/utils/security/csrf.py`) |
| **Template Sandboxing** | Jinja2 `SandboxedEnvironment` prevents SSTI (`CTFd/__init__.py:54`) |
| **Rate Limiting** | Applied to authentication endpoints — 10 requests per 5-60 seconds (`CTFd/auth.py`) |
| **Secure Token Generation** | Uses `os.urandom(32)` for tokens and nonces (`CTFd/utils/security/csrf.py`) |
| **Safe URL Validation** | Open redirect prevention via `is_safe_url()` with netloc verification (`CTFd/utils/validators/__init__.py:15`) |
| **Path Traversal Prevention** | `secure_filename()` + `safe_join()` for file uploads (`CTFd/utils/uploads/uploaders.py`) |
| **Zip Extraction Validation** | Checks for path traversal, absolute paths, `..` sequences in zip imports (`CTFd/utils/exports/__init__.py:138-161`) |
| **Session Security** | Server-side session storage with signed cookie IDs, HttpOnly flag (`CTFd/utils/sessions/`) |
| **Account Enumeration Prevention** | Password reset endpoint does not reveal whether email exists |

---

## Summary

| Severity | Count | Key Issues |
|----------|-------|------------|
| **Critical** | 3 | `eval()` in Vue components, HTML sanitization disabled by default, plaintext preset admin password |
| **High** | 4 | Unauthenticated notification endpoints, stored XSS via theme config, SHA-1 HMAC default, Mailgun config bug |
| **Medium** | 5 | Missing SESSION_COOKIE_SECURE, SQL injection patterns in import, no file type validation, no CSP header |
| **Low** | 3 | Debug mode in dev scripts, weak test secret key, f-string SQL for MySQL KILL |
| **Total** | **15** | |

---

## Recommendations Priority

1. **Immediate:** Enable `HTML_SANITIZATION` by default (VULN-02)
2. **Immediate:** Add authentication to notification GET endpoints (VULN-04)
3. **Immediate:** Fix Mailgun config copy-paste bug (VULN-07)
4. **Short-term:** Replace `eval()` with safe DOM script loading (VULN-01)
5. **Short-term:** Add `SESSION_COOKIE_SECURE` configuration (VULN-08)
6. **Short-term:** Implement Content Security Policy header (VULN-12)
7. **Short-term:** Use constant-time comparison for preset admin password (VULN-03)
8. **Medium-term:** Upgrade HMAC default to SHA-256 (VULN-06)
9. **Medium-term:** Add file upload type validation (VULN-11)
10. **Medium-term:** Convert raw SQL to parameterized queries (VULN-09, VULN-10, VULN-15)
