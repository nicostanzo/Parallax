# 👁️ Parallax
You can visit the website here: https://parallaxtool.vercel.app/
**Parallax** is a zero-dependency, API-key-free infrastructure mapping and passive/active reconnaissance tool. Designed to operate as an **AI Agent Skill** or a standalone CLI utility, Parallax provides bidirectional network mapping, co-habitation discovery, extended port scanning, and CVE correlation.

---

## ⚡ Features

- **Passive Subdomain Enumeration**: Certificate Transparency log inspection (`crt.sh`) with dynamic fallback handling.
- **Bidirectional DNS Mapping**:
  - **Forward DNS**: Resolves hostnames to IPv4 targets.
  - **Reverse DNS & PTR**: Discovers co-hosted domains and PTR records via `HackerTarget` and `ip-api`.
- **Infrastructure Enrichment**: Automatic ASN (Autonomous System) and hosting organization identification.
- **High-Performance Port Scanner**: Multi-threaded scanning across **100 critical ports** (Web, Database, DevOps, K8s, Cloud, RPC).
- **Passive Vulnerability Intelligence**: Queries Shodan InternetDB for historical port data, host tags, and known **CVEs** without requiring API credentials.

---

## 📂 Repository Structure

```text
parallax/
├── parallax.py           # Main Python script
├── requirements.txt      # Python dependencies
└── README.md             # Documentation
```

---

## 🔧 Installation

```bash
# Clone the repository
git clone https://github.com/nicostanzo/Parallax.git
cd parallax

# Install dependencies
pip install -r requirements.txt
```

---

## 🚀 Usage

### Standard CLI Mode

```bash
python parallax.py
```

## ⚖️ Disclaimer

This tool is created strictly for educational purposes and authorized security assessments. Usage of Parallax for attacking targets without prior mutual consent is illegal. The author assumes no liability for misuse or damage caused by this program.
