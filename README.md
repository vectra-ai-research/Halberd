# Halberd: Multi-Cloud Agentic Attack Tool

<p align="center">
  <img src="assets/halberd_logo_banner.jpg" alt="Halberd Logo" width="100%" align="center"/>
</p>

<p align="center">
  <strong>Validate your multi-cloud defenses through realistic attack emulation</strong>
</p>

<p align="center">
  <a href="#-quick-start">🚀 Get Started</a> •
  <a href="#-what-is-halberd">📖 About</a> •
  <a href="#-key-features">✨ Features</a> •
  <a href="#-getting-started-guide">📚 Guide</a> •
  <a href="#-documentation--resources">📋 Docs</a> •
  <a href="#-contributing">🤝 Contributing</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-3.0.0-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/license-GPL--3.0-green.svg" alt="License">
  <img src="https://img.shields.io/badge/clouds-5-orange.svg" alt="Cloud Platforms">
  <img src="https://img.shields.io/badge/techniques-120+-red.svg" alt="Attack Techniques">
</p>

<p align="center">
  <img src="https://github.com/openrec0n/Halberd-Media-Assets/blob/main/Media/Halberd_3_0_preview.gif" width="100%" align="center" alt="Halberd Preview"/>
</p>

---

## 🚀 Quick Start

Get Halberd running in under 60 seconds. Choose the installation method that works best for you.

### Option 1: Docker (Recommended)

The fastest way to get started. One command and you're ready:

```bash
docker run -d --name halberd -p 8050:8050 ghcr.io/vectra-ai-research/halberd:main
```

Then open your browser to `http://localhost:8050` and you're ready to go!

**Using Docker Compose?**

```bash
git clone https://github.com/vectra-ai-research/Halberd.git
cd Halberd
docker compose up -d
```

> 📖 **Need more details?** Check out our [Docker Deployment Guide](https://github.com/vectra-ai-research/Halberd/wiki/Deployment-Guide#docker-deployment)

### Option 2: Manual Setup

Perfect for development or custom configurations.

**Prerequisites:**
- Python 3.8.x - 3.13.x

**Steps:**

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

3. **Optional: Install Azure CLI** (Required for Azure testing)
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

5. **Access the web interface**
   
   Navigate to `http://127.0.0.1:8050` in your browser.

**✅ Success!** You should see the Halberd web interface. If you see the dashboard, you're all set!

---

## 📖 What is Halberd?

Halberd is an open-source, multi-cloud attack emulation tool built for cybersecurity professionals who need to validate their cloud security defenses. Testing cloud security across multiple platforms is complex, time-consuming, and often requires deep expertise in each cloud provider's unique attack surfaces.

**Halberd solves this by providing:**

- **Unified Multi-Cloud Testing**: Test Azure, AWS, GCP, Entra ID, and M365 from a single interface
- **120+ Attack Techniques**: Pre-built techniques mapped to MITRE ATT&CK and Azure TRM frameworks
- **AI-Powered Intelligence**: Claude-powered attack agent that helps discover and execute attack paths
- **Web-Based Interface**: No CLI expertise required—everything runs in your browser
- **Automation & Orchestration**: Create playbooks, schedule attacks, and generate comprehensive reports

Whether you're conducting red team exercises, validating security controls, or training your security team, Halberd makes cloud security testing accessible, repeatable, and actionable.

---

## ✨ Key Features

### 🌐 Multi-Cloud Coverage

Test across **5 major cloud platforms** from a single interface:
- **Microsoft Azure** - Resource enumeration, privilege escalation, data exfiltration
- **Amazon Web Services (AWS)** - IAM abuse, S3 manipulation, CloudTrail evasion
- **Google Cloud Platform (GCP)** - Service account abuse, project enumeration, persistence
- **Microsoft Entra ID** - Identity attacks, role assignment, token abuse
- **Microsoft 365** - Email manipulation, Teams exploitation, SharePoint access

### 🎯 Attack Library

**120+ attack techniques** organized by MITRE ATT&CK tactics:
- Initial Access, Execution, Persistence
- Privilege Escalation, Defense Evasion
- Credential Access, Discovery
- Lateral Movement, Collection
- Exfiltration, Impact

Each technique is mapped to industry-standard frameworks and includes detailed execution logs.

### 🤖 AI-Powered Attack Agent

Intelligent attack planning and execution powered by Claude:
- **Technique Discovery**: AI suggests attack paths based on your environment
- **Context-Aware Execution**: Understands your testing context and adapts recommendations
- **Automated Reporting**: Generates tailored security assessment reports
- **Research Integration**: Upload threat intelligence documents to create custom attack paths

> **Enable the Attack Agent**: Click the settings icon in Halberd and add your Anthropic API key.

### ⚙️ Automation & Orchestration

- **Playbook Engine**: Chain multiple techniques into sophisticated attack scenarios
- **Scheduling**: Automate attacks on a schedule for continuous security validation
- **Access Management**: Built-in credential and session management across cloud platforms
- **Result Analysis**: Rich output formatting with detailed execution logs and visualizations

### 📊 Analysis & Reporting

- **Real-Time Dashboards**: Visualize attack paths, success rates, and technique coverage
- **Attack History**: Review all technique executions with full output logs
- **Export Capabilities**: Generate comprehensive security assessment reports

---

## 📚 Getting Started Guide

Ready to run your first attack? Follow these steps:

### Step 1: Install Halberd

If you haven't already, follow the [Quick Start](#-quick-start) instructions above to get Halberd running.

### Step 2: Access the Web Interface

Open your browser and navigate to `http://localhost:8050` (or your configured host/port).

### Step 3: Establish Cloud Access

1. Navigate to the **Attack** page
2. Select your target cloud platform (Azure, AWS, GCP, Entra ID, or M365)
3. Choose an **Initial Access** technique
4. Configure the technique with your cloud credentials
5. Execute to establish your session

### Step 4: Execute Your First Attack Technique

1. Browse available techniques by tactic (Discovery, Credential Access, etc.)
2. Select a technique that matches your testing goals
3. Configure required parameters
4. Click **Execute** and review the results

### Step 5: Review and Analyze

- **Response Window**: View detailed technique output immediately after execution
- **Attack History**: Access the history page to review all past executions
- **Analyse Dashboard**: Use the Analyse page to visualize attack patterns and generate reports

### 🎯 First Technique Suggestions

**Azure:**
- `azure_enumerate_vm` - Discover virtual machines in your subscription
- `azure_enumerate_storage_accounts` - List all storage accounts

**AWS:**
- `aws_enumerate_s3_buckets` - List all S3 buckets
- `aws_enumerate_iam_users` - Discover IAM users in the account

**GCP:**
- `gcp_enumerate_projects` - List all GCP projects
- `gcp_enumerate_service_accounts` - Discover service accounts

**Entra ID:**
- `entra_enumerate_users` - List directory users
- `entra_enumerate_apps` - Discover registered applications

**M365:**
- `m365_enumerate_teams` - List Microsoft Teams
- `m365_search_outlook_messages` - Search email messages

> 💡 **Pro Tip**: Start with enumeration techniques to understand your environment before attempting more advanced attacks.

### 📋 Example Playbook

Halberd comes with a ready-to-use example playbook that demonstrates how to chain multiple techniques into a comprehensive attack scenario.

**AWS Cloud Discovery and Reconnaissance**

This playbook emulates the reconnaissance phase an attacker performs after gaining initial access to an AWS environment. It systematically discovers identities, data stores, compute infrastructure, and security monitoring configurations.

The playbook executes 9 non-destructive, read-only techniques:
- Enumerate IAM users and roles
- Gather account authorization information
- List S3 buckets and identify publicly accessible ones
- Discover EC2 instances
- Identify overpermissive security groups
- Enumerate CloudTrail trails and GuardDuty detectors

**How to Use:**
1. Ensure you have established AWS access
2. Navigate to the **Automator** page in Halberd
3. Load the playbook: `AWS Cloud Discovery and Reconnaissance`
4. Click **Execute** to run the playbook

> 💡 **Custom Playbooks**: You can create your own playbooks by defining sequences of techniques in YAML format or directly from the Halberd `Automator` UI. All playbooks are stored in the `automator/Playbooks/` directory.

---

## 🏗️ Architecture & Capabilities

### Supported Cloud Platforms

| Platform | Techniques | Key Capabilities |
|----------|-----------|-----------------|
| **Azure** | 39+ | Resource enumeration, VM manipulation, Key Vault access, Storage account operations |
| **AWS** | 25+ | IAM abuse, S3 operations, EC2 enumeration, CloudTrail manipulation |
| **GCP** | 13+ | Project enumeration, Service account abuse, Storage operations, IAM manipulation |
| **Entra ID** | 33+ | Identity attacks, Role assignment, Token abuse, User enumeration |
| **M365** | 14+ | Email manipulation, Teams exploitation, SharePoint access, OneDrive operations |

### Web Interface Pages

- **Attack**: Configure and execute individual attack techniques
- **Automator**: Create, manage, and schedule attack playbooks
- **Analyse**: Visualize attack results, generate reports, and analyze patterns
- **Agent**: Interact with the AI-powered attack agent for intelligent attack planning
- **Attack History**: Review all technique executions with full output logs

### CLI Capabilities

Halberd includes a command-line interface for automation and integration:

```bash
# List all available techniques
python cli.py list-techniques

# List techniques by cloud platform
python cli.py list-techniques --category aws

# List techniques by MITRE tactic
python cli.py list-techniques --tactic "Initial Access"

# Get technique details
python cli.py get-technique --technique-id AWSEnumerateS3Buckets
```

> 📖 **Learn more**: Check out the [Halberd CLI Guide](https://github.com/vectra-ai-research/Halberd/wiki/Halberd-CLI) for detailed CLI documentation.

---

## ⚙️ Advanced Configuration

### Custom Host and Port

```bash
python run.py --host 0.0.0.0 --port 8080
```

### Enable TLS/HTTPS

```bash
python run.py --ssl-cert /path/to/cert.pem --ssl-key /path/to/key.pem
```

### Development Mode

```bash
python run.py --dev-server --dev-server-debug
```

### Environment Variables

Configure Halberd using environment variables:

- `HALBERD_HOST`: Host address to bind the server (default: `127.0.0.1`)
- `HALBERD_PORT`: Port number to run the server (default: `8050`)
- `ANTHROPIC_API_KEY`: API key for Halberd Attack Agent (optional)

### Docker Compose Configuration

For production deployments, customize `docker-compose.yml`:

```yaml
services:
  halberd:
    image: ghcr.io/vectra-ai-research/halberd:main
    ports:
      - "8050:8050"
    environment:
      - HALBERD_HOST=0.0.0.0
      - HALBERD_PORT=8050
    volumes:
      - ./local:/app/local
```

---

## 📋 Documentation & Resources

### Official Documentation

- **[User Guide](https://github.com/vectra-ai-research/Halberd/wiki/Usage)** - Comprehensive usage instructions and workflows
- **[Deployment Guide](https://github.com/vectra-ai-research/Halberd/wiki/Deployment-Guide)** - Detailed deployment instructions for various environments
- **[Halberd CLI](https://github.com/vectra-ai-research/Halberd/wiki/Halberd-CLI)** - CLI reference and automation guides

### Community Resources

- **[GitHub Issues](https://github.com/vectra-ai-research/Halberd/issues)** - Report bugs, request features, or ask questions
- **[GitHub Discussions](https://github.com/vectra-ai-research/Halberd/discussions)** - Community discussions and Q&A
- **[Halberd Wiki](https://github.com/vectra-ai-research/Halberd/wiki)** - Complete documentation hub

### External References

- **[MITRE ATT&CK](https://attack.mitre.org/)** - Industry-standard attack framework
- **[Azure Threat Research Matrix](https://microsoft.github.io/Azure-Threat-Research-Matrix/)** - Azure-specific attack techniques
- **[Additional Resources](https://github.com/vectra-ai-research/Halberd/wiki/Additional-(Amazing)-Resources)** - Curated list of cloud security resources

---

## 🤝 Contributing

We welcome contributions from the security community! Halberd is open source and thrives on community involvement.

**How to contribute:**

1. Review our [contribution guidelines](https://github.com/vectra-ai-research/Halberd/wiki/Contributions)
2. Fork the repository
3. Create a feature branch
4. Submit a pull request

**Areas where contributions are especially welcome:**

- New attack techniques for existing cloud platforms
- Support for additional cloud platforms
- Improvements to the web interface
- Documentation enhancements
- Bug fixes and performance improvements

---

## 💬 Support & Community

**Need help?**

- **Issues**: [GitHub Issues](https://github.com/vectra-ai-research/Halberd/issues) - Report bugs or request features
- **Discussions**: [GitHub Discussions](https://github.com/vectra-ai-research/Halberd/discussions) - Ask questions and share ideas
- **Documentation**: [Halberd Wiki](https://github.com/vectra-ai-research/Halberd/wiki) - Comprehensive guides and references

**Stay connected:**

- Follow the project on GitHub for updates
- Join discussions to share your use cases and experiences
- Contribute to make Halberd even better

---

## 🙏 Acknowledgments

Halberd is developed by [Arpan Sarkar](https://www.linkedin.com/in/arpan-sarkar/) and inspired by the outstanding work of the [cloud security community](https://github.com/vectra-ai-research/Halberd/wiki/Additional-(Amazing)-Resources). Special thanks to all contributors who have helped make this project possible.

---

## ⚠️ Disclaimer

**Halberd is intended for authorized security testing only.**

Users are responsible for ensuring compliance with applicable laws and obtaining proper authorization before conducting security assessments. Unauthorized access to computer systems is illegal and may result in criminal prosecution.

Always:
- Obtain written authorization before testing
- Test only systems you own or have explicit permission to test
- Follow responsible disclosure practices
- Comply with all applicable laws and regulations

---

<p align="center">
  <strong>Made with ❤️ for the security community</strong>
</p>

<p align="center">
  <a href="#halberd-multi-cloud-agentic-attack-tool">⬆️ Back to Top</a>
</p>
