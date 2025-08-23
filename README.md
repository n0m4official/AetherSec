# AetherSec
<img width="1024" height="1024" alt="AetherSec" src="https://github.com/user-attachments/assets/d4fed0d8-d879-4c51-9cda-e3cc11ffae42" />

**AetherSec** is a professional-grade, modular cybersecurity platform designed for ethical red-teaming, vulnerability research, and proactive exploit simulation.

> “We get our hands dirty so others stay clean.”

NOTE:
This is currently a work in progress, this is still in active development and may have bugs or security exploits, use at own risk.

---

## ⚙️ Features

- 🔍 **Modular Exploit Engine** — Tiered exploit system from basic scans to advanced multi-stage.
- 🔐 **Ethical by Design** — Built with safety in mind. No real weaponization or illegal activity.
- 🧠 **Advanced Intelligence Modules** — Fingerprinting, misconfig detection, honeypot avoidance, and more.
- 💾 **C# Native** — Built in .NET with performance, portability, and integration in mind.

---

## 📁 Project Structure

```plaintext
AetherSec/
├── Agent/                                        # Carrier and agent logic
│   ├── IAgent.cs                                 # Interface for agent functionality
│   ├── AgentCore.cs                              # Core agent functionality
│   ├── Propagation/                              # Propagation logic
│   |   ├── PropagationAgent.cs                   # Main propagation agent
│   |   ├── PropagationConfig.cs                  # Config options for propagation
│   |   ├── PropagationController.cs              # Controls propagation flow
│   |   └── PropagationServices.cs                # Handles file drop & remote execution
├── CLI/                                          # Command-line interface
│   └── Program.cs                                # Entry point for CLI
├── Core/                                         # Core scanning interfaces
│   └── IScanModule.cs                            # Interface for scan modules
├── Engine/                                       # Scanning engine & module loader
│   ├── ModuleLoader.cs                           # Dynamically loads modules
│   └── ScanEngine.cs                             # Orchestrates scan execution
├── Logging/                                      # Reporting and logging
│   └── ReportLogger.cs                           # Handles scan results and logs
├── Modules/                                      # Individual scan/exploit modules
│   ├── ApacheStrutsCVE20175638Exploit.cs
│   ├── BlueKeepDetector.cs
│   ├── ClickJackingScan.cs
│   ├── CloudMetadataExposureScan.cs
│   ├── CmsFingerprinterScan.cs
│   ├── CmsPluginEnumeratorScan.cs
│   ├── ConfluenceOnglInjectionScan.cs
│   ├── DirectoryTraversalDetector.cs
│   ├── DnsRecursionDetector.cs
│   ├── ElasticsearchCVE20151427RceDetector.cs
│   ├── ElasticsearchExposureDetector.cs
│   ├── EternalBlueDetector.cs
│   ├── FtpAnonymousLoginDetector.cs
│   ├── FtpAnonymousScan.cs
│   ├── HeartbleedDetector.cs
│   ├── HoneypotDetector.cs
│   ├── HttpsServerBannerDetector.cs
│   ├── JenkinsPanelExploit.cs
│   ├── JwtWeakSecretBruteForce.cs
│   ├── KubernetesApiExposureDetector.cs
│   └── KubernetesDashboardUnauthAccessDetector.cs
├── .gitattributes
├── .gitignore
├── AetherSec.csproj                               # Project
├── AetherSec.exe                                  # Application
├── AetherSec.sln                                  # Solution
├── LICENSE.txt                                    # License
├── README.md                                      # This file
└── README_MODULES.md                              # Modules explanations
```
---

## Modules Overview

- **Agent** – Handles agent lifecycle, propagation logic, and communication.  
- **CLI** – Command-line interface to start scans, configure modules, and report results.  
- **Core** – Interfaces for scan modules, ensuring consistent structure.  
- **Engine** – Loads modules dynamically and executes scans in a controlled manner.  
- **Logging** – Reports and logs scan results for auditing and review.  
- **Modules** – Individual vulnerability/exploit detection implementations, including:  
  - Network vulnerabilities: EternalBlue, BlueKeep, SMB checks  
  - Web vulnerabilities: Apache Struts, ClickJacking, Elasticsearch RCE, Log4Shell simulations  
  - Service exposures: MongoDB, Kubernetes, FTP, HTTP servers  
  - Security misconfigurations: Cloud metadata, Honeypots, JWT weak secrets

See `README_MODULES.md` for more info on specifics.

---

## 🚀 Getting Started

### 🔧 Requirements
- [.NET 8 SDK](https://dotnet.microsoft.com/en-us/download)
- Windows/Linux (tested on both)
- Admin/root access (for low-level tests)

### 🧪 Build & Run

```
dotnet build
dotnet run --project AetherSec
```

Or run a specific exploit:

```
dotnet run --project AetherSec -- --target 192.168.1.100 --exploit [EXPLOIT_NAME]
```

---

## 🧩 Module Tiers

| Tier | Focus |
|------|-------|
| Tier 1 | Basic surface scans & port checks |
| Tier 2 | Known CVEs & weak configurations |
| Tier 3 | Evasive techniques & misconfigs |
| Tier 4 | Subdomain brute-forcing, honeypots, cloud exposures |
| Tier 5 | Multi-stage attack simulations (e.g. Log4Shell, SSRF, cloud theft) |

---

## ✍️ Contributing

Contributions are welcome! Clone the repo, add a new exploit module (With a description of what it does and how it works), and submit a pull request.

---

## ⚠️ Disclaimer

This project is strictly for educational and ethical purposes.  
Unauthorized use on networks you do not own or have permission to test is **illegal**.  
Use responsibly.  

The author (**n0m4official**) is **not and cannot be held responsible** for how individuals use this project.

This software is provided 'as is' without any warranties, and by using this code, you agree to take full responsibility for any actions performed using it.

---

## 🧙‍♂️ Maintainer

**n0m4official**  
Creator of AetherSec  

---

## 📜 License

MIT License — See `LICENSE.txt` for details.
