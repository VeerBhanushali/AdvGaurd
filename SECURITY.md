# 🛡️ AdvGuard Security & Privacy Architecture
**Engineered by Veer Bhanushali**

AdvGuard is built on a **Security & Privacy First** foundation. Whether you are running a private self-hosted instance for your home or relying on our official public endpoint (`advgaurd.veerbhanushali.com`), security and user privacy are strictly enforced.

---

## 1. Public Cloud vs. Self-Hosted: The Key Differences

| Dimension | 🌐 Official Public Service (`advgaurd.veerbhanushali.com`) | 🏠 Self-Hosted Private Instance (Your Server) |
| :--- | :--- | :--- |
| **Target Audience** | General public, mobile devices, family & friends worldwide | Home lab, personal devices, local network (LAN) |
| **Data Protection** | **Strict Zero-PII**: No personal data or identities are logged | Full LAN IP tracking (`192.168.1.50`) for device debugging |
| **IP Anonymization** | **Enforced**: Last octet of IPv4 and host bits of IPv6 are masked | Optional: Can be disabled to identify specific devices |
| **Log Retention** | **Strict 30-Day Auto Purge**: Records older than 30 days are destroyed | Configurable (from 1 day to indefinite) |
| **Abuse & Anti-DDoS** | High-velocity sliding window rate limiter (prevents DNS amplification) | Tuned for local high-throughput requests |
| **Spam TLD Blocking** | Active by default (blocks malicious extensions like `.top`, `.work`, `.click`) | Configurable per user rules |

---

## 2. Zero-PII IP Anonymization (Public Service)

When operating a public DNS resolver, handling other people's network requests carries profound responsibility. Storing raw IP addresses alongside requested domains creates a privacy hazard.

AdvGuard solves this by scrubbing all incoming network addresses before saving:
* **IPv4 Addresses**: Truncated to the subnet level (`103.21.244.78` &rarr; `103.21.244.xxx`).
* **IPv6 Addresses**: Masked to the `/64` prefix (`2405:201:2004:...` &rarr; `2405:201:2004::xxxx`).
* **Result**: Query logs show overall network patterns and blocked threat trends, but can **never** be reverse-engineered to identify an individual user or browser.

---

## 3. Automated 30-Day Data Purging (GDPR & Privacy Compliant)

No DNS logs should live forever. AdvGuard enforces an automated lifecycle:
* **Database Function**: `delete_old_query_logs()` deletes all records where `timestamp < NOW() - INTERVAL '30 days'`.
* **Background Worker**: Every 12 hours, the server automatically executes the purge routine, ensuring storage never balloons and historical browsing metadata is permanently discarded.

---

## 4. GitHub & Secret Management Rules

To protect your cloud infrastructure:
1. **Never Commit Secrets**: Never push `.env`, `.env.local`, API keys, database passwords, or personal access tokens to GitHub.
2. **Gitignore Protection**: AdvGuard's `.gitignore` explicitly blocks all `.env*` files, tokens, and certificates while allowing only `.env.example`.
3. **Environment Separation**:
   * Production secrets belong in your hosting environment variables (e.g. Hostinger WebApp Environment settings, Vercel Project Settings).
   * Local development uses `.env.local`.

---

## 5. Reporting Security Vulnerabilities

If you discover a security vulnerability in AdvGuard, please contact Veer Bhanushali directly or open a confidential security advisory on GitHub:
* **Author**: Veer Bhanushali
* **Repository**: [https://github.com/VeerBhanushali/AdvGaurd.git](https://github.com/VeerBhanushali/AdvGaurd.git)

