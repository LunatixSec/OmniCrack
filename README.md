🔓 OmniCrack Professional

**Enterprise-Grade Password Cracking Suite**  
*Combining Hydra + Hashcat + AI for Ultimate Cracking Power*

![OmniCrack Banner](docs/images/banner.png)

[![Made by Lunatix](https://img.shields.io/badge/Made%20by-Lunatix-red.svg)](https://github.com/freakzplayz22-netizen)
[![Version](https://img.shields.io/badge/version-2.0.0-blue.svg)](https://github.com/freakzplayz22-netizen/OmniCrack)
[![License](https://img.shields.io/badge/license-Proprietary-yellow.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.8+-green.svg)](https://python.org)

---

## ⚡ Features

| Category | Capabilities |
|----------|--------------|
| **Attack Modes** | Online brute force, Offline dictionary, Mask attack, Rule-based, Hybrid, AI probabilistic |
| **Online Protocols** | SSH, FTP, HTTP/S, SMB, RDP, VNC, Telnet, MySQL, PostgreSQL, MongoDB, Redis, LDAP, SMTP, POP3, IMAP |
| **Hash Algorithms** | MD5, SHA1, SHA256, SHA512, NTLM, bcrypt, Argon2, WPA2, MySQL, Oracle H |
| **Performance** | Multi-threaded, GPU acceleration (CUDA/OpenCL), Distributed cracking support |
| **AI Engine** | GPT-4 integration for intelligent password generation |
| **Visualization** | Real-time graphs, progress tracking, heat maps |
| **Export** | JSON, CSV, TXT, HTML reports |

---

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/freakzplayz22-netizen/OmniCrack.git
cd OmniCrack

# Install dependencies
pip install -r requirements.txt

# Run OmniCrack
python src/omnicrack.py
```

Basic Usage

```bash
# Online brute force
python src/omnicrack.py --mode online --target 192.168.1.1 --protocol ssh --user admin --wordlist wordlists/rockyou.txt

# Offline hash cracking
python src/omnicrack.py --mode offline --hash-file hashes.txt --hash-type md5 --wordlist wordlists/rockyou.txt

# AI-powered attack
python src/omnicrack.py --mode ai --target-info "company:acme, keywords:admin,2024"
```

---

🖥️ GUI Mode

```bash
python src/omnicrack.py --gui
```

docs/images/gui.png

---

📊 Performance Benchmarks

Attack Type Speed (p/sec) Hardware
MD5 Dictionary 15,000,000 RTX 4090
SHA256 Dictionary 8,000,000 RTX 4090
bcrypt (cost=12) 1,200 RTX 4090
SSH Brute Force 500 16 threads

---

🛠️ Advanced Configuration

Custom Wordlists

```bash
# Download rockyou
wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt -O wordlists/rockyou.txt
```

GPU Acceleration

```bash
# Enable CUDA
python src/omnicrack.py --gpu cuda

# Enable OpenCL
python src/omnicrack.py --gpu opencl
```

Distributed Cracking

```bash
# Start master
python src/omnicrack.py --master --port 5555

# Connect workers
python src/omnicrack.py --worker --master-ip 192.168.1.100
```

---

📁 Project Structure

```
OmniCrack/
├── src/
│   ├── omnicrack.py          # Main entry point
│   ├── core/                  # Core engine
│   ├── modules/               # Attack modules
│   ├── gui/                   # GUI components
│   └── utils/                 # Utilities
├── wordlists/                  # Password lists
├── results/                    # Cracked passwords
├── profiles/                   # Saved configs
├── docs/                       # Documentation
│   └── images/                 # Screenshots
├── tests/                      # Unit tests
├── requirements.txt            # Dependencies
├── LICENSE                     # License file
└── README.md                   # This file
```

---

🔒 Security & Ethics

IMPORTANT: OmniCrack is designed for:

· ✅ Authorized penetration testing
· ✅ Security research
· ✅ Educational purposes
· ✅ Password recovery on your own systems

NEVER USE FOR ILLEGAL ACTIVITIES. Unauthorized access is a crime.

---

👨‍💻 Author

Lunatix
LunatixLeaks Research

· GitHub: @freakzplayz22-netizen
· Website: https://lunatixleaks.ct.ws

---

⚖️ License

Proprietary – All rights reserved.
Unauthorized distribution or modification prohibited.

---

🙏 Acknowledgments

· Hashcat team for GPU cracking algorithms
· Hydra developers for online attack patterns
· OpenAI for GPT integration
· The security research community

---

Made with 🔥 by Lunatix
