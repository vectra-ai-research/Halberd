# Halberd: Multi-Cloud Security Testing Platform 🛡️

<p align="center">
  <img src="assets/halberd_logo_banner.jpg" alt="logo" width="100%" align="center"/>
</p>

Halberd is an advanced security testing platform that enables security teams to validate cloud security controls through sophisticated attack emulation. By providing comprehensive coverage across Microsoft Entra ID, Microsoft 365, Microsoft Azure, Amazon Web Services (AWS), and Google Cloud Platform (GCP), Halberd helps organizations:

* **Validate Security Controls** : Test detection and prevention capabilities across your cloud infrastructure
* **Generate Attack Telemetry**: Create realistic security events to tune and optimize your security monitoring
* **Automate Security Testing**: Build and execute complex attack chains to assess security resilience
* **Accelerate Red Team Operations**: Rapidly deploy testing scenarios through an intuitive interface

<p align="center">
  <img src="assets/halberd_attack_view_v2_0.png" width=100% align="center"/>
</p>

## Key Capabilities

* 🔬 **Advanced Attack Framework**: Execute sophisticated attack techniques mapped to MITRE ATT&CK
* 📊 **Intelligence Dashboards**: Gather deep insights into security posture through visual analysis
* 🔄 **Automated Playbooks**: Chain multiple techniques into comprehensive attack scenarios
* 📈 **Detailed Reporting**: Generate executive and technical reports on security testing outcomes
* 🔌 **Extensible Architecture**: Add custom techniques through a robust development framework
* 🌐 **Cross-Platform Support**: Test security controls across all major cloud providers
* 🤖 **Halberd-Attack Agent**: Leverage LLM and agentic framework to supercharge security testing

## Quick Start Guide

1. Clone the repository:
   ```
   git clone https://github.com/vectra-ai-research/Halberd.git
   ```

2. Configure the environment::
   ```
   cd Halberd
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   pip install -r requirements.txt
   ```

3. Install Azure CLI:
   * Windows: [Official Microsoft guide](https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-windows?tabs=azure-cli)
   * Linux: `curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash`
   * macOS: `brew update && brew install azure-cli`

4. Launch Halberd:
   ```
   python3 run.py
   ```

5. Access the interface at `http://127.0.0.1:8050/` and begin testing

> Optionally, see steps to enable Halberd Attack Agent [here](https://github.com/vectra-ai-research/Halberd/wiki/Deployment-Guide#setup-halberd-attack-agent)

#### Advanced Deployment Options

```
# Custom Host & Port
python3 run.py --host 0.0.0.0 --port 8050

# Enable TLS
python3 run.py --ssl-cert /path/to/cert.pem --ssl-key /path/to/key.pem

# Configure Logging
python3 run.py --log-level debug

# Development Mode
python3 run.py --dev-server --dev-server-debug
```

## Core Workflows

1. **Attack Execution & Testing**:
   * Select target environment (Entra ID/M365/Azure/AWS/GCP)
   * Browse techniques by MITRE ATT&CK tactics
   * Execute attacks across multiple clouds
   * Manage access with built-in access manager
   * View results with rich output formatting
   * Generate attack telemetry

2. **Attack Automation**:
   * Create automated attack playbooks
   * Chain multiple techniques into attack sequences
   * Import/Export playbooks for sharing
   * Schedule recurring security tests

3. **Security Analysis**:
   * Track testing metrics through intuitive dashboards
   * Visualize attack paths and impact
   * Identify security gaps
   * Generate comprehensive test reports
   * Export results for compliance evidence

For detailed usage instructions, visit [Halberd Wiki - Usage](https://github.com/vectra-ai-research/Halberd/wiki/Usage).

## Want to Join the Party? 🎉

Got ideas? Found a bug? Want to add that new cool feature? Check out the [contribution guidelines](https://github.com/vectra-ai-research/Halberd/wiki/Contributions) and let's make Halberd even more awesome together.

## About
Halberd is developed by [Arpan Sarkar](https://www.linkedin.com/in/arpan-sarkar/) and is [inspired](https://github.com/vectra-ai-research/Halberd/wiki/Additional-(Amazing)-Resources) by the excellent work of the cloud security community.

***
**Now go forth and hack responsibly! 🚀**