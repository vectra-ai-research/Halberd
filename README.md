# Halberd: Multi-Cloud Agentic Attack Tool

<p align="center">
  <img src="assets/halberd_logo_banner.jpg" alt="Halberd Logo" width="100%" align="center"/>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> •
  <a href="#installation">Installation</a> •
  <a href="#features">Features</a> •
  <a href="#documentation">Documentation</a> •
  <a href="#contributing">Contributing</a>
</p>

---

## Overview

Halberd is a multi-cloud attack tool designed for security teams to validate cloud defenses through realistic attack emulation. Supporting Microsoft Entra ID, Microsoft 365, Azure, AWS, and Google Cloud Platform, Halberd enables comprehensive security assessments across your entire cloud ecosystem via an intuitive web interface that runs directly in the browser.

<p align="center">
  <img src="https://github.com/openrec0n/Halberd-Media-Assets/blob/main/Media/Halberd_3_0_preview.gif" width="100%" align="center"/>
</p>

## Quick Start

### Option 1 : Automated - Docker Install (Recommended)

```bash
# Pull and run the latest version
docker run -d --name halberd -p 8050:8050 ghcr.io/vectra-ai-research/halberd:main

# Access the web interface
open http://localhost:8050
```

#### Docker Compose

```bash
git clone https://github.com/vectra-ai-research/Halberd.git
cd Halberd
docker compose up -d
```
[Detailed docker deployment documentation](https://github.com/vectra-ai-research/Halberd/wiki/Deployment-Guide#docker-deployment)

### Option 2 : Manual Setup

#### Prerequisites

- Python 3.8.x - 3.12.x

1. **Clone the repository**
   ```bash
   git clone https://github.com/vectra-ai-research/Halberd.git
   cd Halberd
   ```

2. **Set up Python virtual environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Optional : **Install Azure CLI** (Required for Azure testing)
   ```bash
   # Linux/macOS
   curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
   
   # macOS with Homebrew
   brew install azure-cli
   
   # Windows - Download from Microsoft documentation
   ```
   [Microsoft Azure CLI install doc](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-windows?tabs=azure-cli)

4. **Launch Halberd**
   ```bash
   python run.py
   ```

5. **Access Halberd**

   Navigate to `http://127.0.0.1:8050` in your browser

### Advanced Options

```bash
# Custom host and port
python run.py --host 0.0.0.0 --port 8080

# Enable TLS
python run.py --ssl-cert /path/to/cert.pem --ssl-key /path/to/key.pem

# Development mode with debugging
python run.py --dev-server --dev-server-debug
```

## Features

### Core Capabilities

- **Multi-Cloud Coverage**: Comprehensive testing across Azure, AWS, GCP, Entra ID, and M365
- **Attack Automation**: Create and execute complex attack playbooks
- **Scheduling Engine**: Automate & schedule attacks
- **Detailed Reporting**: Generate automated reports with actionable insights
- **Analysis Dashboard**: Real-time visualization of attack paths and results

### Attack Framework

- **Technique Library**: Extensive collection of cloud attack techniques
- **Playbook Engine**: Chain multiple techniques into sophisticated attack scenarios
- **Access Management**: Built-in credential and session management
- **Result Analysis**: Rich output formatting with detailed execution logs

### Halberd Attack Agent

Fully integrated AI attack agent to enhance security testing capabilities:
- **LLM Integration**: [Claude](https://www.anthropic.com/claude) powered AI attack agent
- **Technique Discovery**: Intelligent attack path discovery & context-aware attack execution
- **Automated Reporting**: AI-generated testing reports tailored to your specific testing scenarios
- **Research Integration**: Attach images and documents to rapidly create and execute attack paths based on new research and threat intelligence

> **Enable Attack Agent**: Simply click on settings icon in Halberd app and add your Anthropic API key.

## Usage

### Basic Workflow

1. **Select Target Cloud**: Navigate to `Attack` page and choose target cloud (Azure, AWS, GCP, etc.)
2. **Establish Access**: Establish access using a `Initial Access` technique
3. **Select Technique**: Browse and select attack techniques
4. **Execute**: Configure & run the attack technique
5. **Review Result**: Review technique result in `Response` window
6. **Analysis**: Analyze overall testing through the `Analyze` dashboard
7. **Reporting**: Generate comprehensive security assessment report

For detailed usage instructions, checkout [Halberd Wiki - Usage](https://github.com/vectra-ai-research/Halberd/wiki/Usage)

## Documentation

- **[User Guide](https://github.com/vectra-ai-research/Halberd/wiki/Usage)** - Comprehensive usage instructions
- **[Deployment Guide](https://github.com/vectra-ai-research/Halberd/wiki/Deployment-Guide)** - Detailed deployment instructions
- **[Halberd CLI](https://github.com/vectra-ai-research/Halberd/wiki/Halberd-CLI)** - Integration and automation guides

## Contributing

We welcome contributions from the security community! Please review our [contribution guidelines](https://github.com/vectra-ai-research/Halberd/wiki/Contributions) before submitting pull requests.

## Support

- **Issues**: [GitHub Issues](https://github.com/vectra-ai-research/Halberd/issues)
- **Documentation**: [Halberd Wiki](https://github.com/vectra-ai-research/Halberd/wiki)
- **Community**: [Discussions](https://github.com/vectra-ai-research/Halberd/discussions)

## Acknowledgments

Halberd is developed by [Arpan Sarkar](https://www.linkedin.com/in/arpan-sarkar/) and inspired by the outstanding work of the [cloud security community](https://github.com/vectra-ai-research/Halberd/wiki/Additional-(Amazing)-Resources). Special thanks to all contributors who have helped make this project possible.

---

**⚠️ Disclaimer**: Halberd is intended for authorized security testing only. Users are responsible for ensuring compliance with applicable laws and obtaining proper authorization before conducting security assessments.