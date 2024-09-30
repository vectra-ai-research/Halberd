<h1 align="center">    
    <img src="assets/halberd_logo_banner.jpg" alt="logo" width="100%" align="center"/>
</h1>
<p align="center">
Halberd is a multi-cloud open-source security testing framework, designed to proactively assess cloud security by executing a comprehensive array of attack techniques.
</p>
Leveraging Halberd, security teams can very quickly & easily execute attack techniques to generate telemetry and validate their detection & response capabilities via a simple intuitive web application.

Evaluate defenses across multiple attack surfaces, including [Entra ID](https://learn.microsoft.com/en-us/entra/identity/), [M365](https://learn.microsoft.com/en-us/microsoft-365/?view=o365-worldwide), [Azure](https://learn.microsoft.com/en-us/azure/?product=popular) and [AWS](https://docs.aws.amazon.com).

<h1 align="center">    
    <img src="assets/Halberd_Attack_View.png" width=100% align="center"/>
</h1>
<p align="center">

## Overview
[Module details](https://github.com/vectra-ai-research/Halberd/wiki/Module-Details) & [usage](https://github.com/vectra-ai-research/Halberd/wiki/Usage) elaborates on specific executable techniques and interesting capabalities of Halberd.

Checkout [Testing Use Cases](https://github.com/vectra-ai-research/Halberd/wiki/Testing-Use-Cases) for examples. 

- Entra ID Techniques
- M365 Techniques
- Azure Techniques
- AWS Techniques
- Execute Attack Playbooks
- Advanced Recon Dashboards
- Generate Testing Reports
- Execute Attacks via Intutive Web-App
- Automate further with CLI access

Note: Halberd is continuously evolving and getting better with more testing techniques, new capabilities & fixes. Ensure to use the latest version available whenever possible. 

## Setup



### Install
Halberd works on Linux, macOS & Windows. Checkout detailed OS specific setup instructions in [deployment guide](https://github.com/vectra-ai-research/Halberd/wiki/Deployment-Guide). 

1. Clone / download Halberd
```
$ git clone https://github.com/vectra-ai-research/Halberd.git
```
2. Move to Halberd directory
```
$ cd Halberd
```
3. Create virtual environment
```
$ python3 -m venv venv
```
4. Activate virtual environment

***Windows***
```
.venv/Scripts/activate
```
***Linux / macOS***
```
source venv/bin/activate
```
5. Install requirements
```
$ pip install -r requirements.txt
```
6. Install Azure CLI

***Windows***
```
Install Azure CLI : https://learn.microsoft.com/en-us/cli/azure/install-azure-cli-windows?tabs=azure-cli
```
***Linux / macOS***
```
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash
```
***macOS***
```
$ brew update && brew install azure-cli
```
7. Start Halberd
```
$ python3 Halberd.py
```

## Getting Started

Once Halberd is deployed & running, start testing by accessing ```http://127.0.0.1:8050/``` in your browser. 

### Access

Manage access-tokens/clients/sessions and review current access information for various targets.

### Attack

Configure and execute techniques for testing. From the `Attack` view, select `Attack Surface > Tactic > Technique > Execute`.  

### Recon

Provides advanced reconnaissance dashboards enabling fast and easy information gathering by automatically executing sequence of reconnaissance in the environment.

Example: Navigate to `Recon` > `Entity Map` > `Generate Entity Map` to generate an interactive graph of access & privileges in the cloud environment.

### Automator

Manage & execute attack playbooks.

### Trace

Review log of executed techniques and generate comprehensive testing report.

Note: Different techniques require varying access & privileges for successful execution. Start by establishing relevant access using `Initial Access` tactic under each attack surface. 

Checkout [usage](https://github.com/vectra-ai-research/Halberd/wiki/Usage) for detailed information on testing with Halberd. 

Some Quick Links: 
- [Executing Technique](https://github.com/vectra-ai-research/Halberd/wiki/Execute-Attack-Techniques)
- [Manage Access](https://github.com/vectra-ai-research/Halberd/wiki/Manage-Access)

## Contribute
Thanks for considering contributing to Halberd! Your contributions will make security testing easier & better. If you are interested in contributing to Halberd, checkout guidance on [contributions](https://github.com/vectra-ai-research/Halberd/wiki/Contributions) & [development focus areas](https://github.com/vectra-ai-research/Halberd/wiki/Development-Focus-Areas).
- Submit bugs & issues [here](https://github.com/vectra-ai-research/Halberd/issues/new)

## Contact
If you found this tool useful, want to share interesting use-cases or ideas - reach out & share them!
 - Creator & Maintainer : [Arpan Sarkar](https://www.linkedin.com/in/arpan-sarkar/)

## Inspiration
Halberd is inspired from many amazing ideas and work produced by several talented members/groups of the security community. Checkout some of them [here](https://github.com/vectra-ai-research/Halberd/wiki/Additional-(Amazing)-Resources).