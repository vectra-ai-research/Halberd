<h1 align="center">    
    <img src="assets/halberd_nbg_lg.png" height="25" width="25">
    Halberd
</h1>
<p align="center">
Halberd is an open-source security testing tool to proactively assess cloud threat detection by executing a comprehensive array of attack techniques across multiple surfaces.
</p>
Leveraging Halberd, security teams can very quickly & easily execute attack techniques to generate telemetry and validate their detection & response capabilities via a simple intuitive web application.

Evaluate defenses across multiple attack surfaces, including [Entra ID](https://learn.microsoft.com/en-us/entra/identity/), [M365](https://learn.microsoft.com/en-us/microsoft-365/?view=o365-worldwide), [Azure](https://learn.microsoft.com/en-us/azure/?product=popular) and [AWS](https://docs.aws.amazon.com).

<h1 align="center">    
    <img src="assets/Halberd_Attack_View.png" height="600" width="1200">
</h1>
<p align="center">

## Setup

Halberd works on Linux, macOS & Windows and can be setup easily in just a few steps.

### Install

Checkout detailed and OS specific setup instructions in [deployment guide](https://github.com/vectra-ai-research/Halberd/wiki/Deployment-Guide). 

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
```
$ source venv/bin/activate
```
5. Install requirements
```
$ pip install -r requirements.txt
```
6. Install Azure CLI
```
$ brew update && brew install azure-cli
```
7. Start Halberd
```
$ python3 Halberd.py
```

### Usage
Once setup start testing by accessing the Halberd web app in your browser. 
```
Visit: http://127.0.0.1:8050/
```

## Overview
[Module details](https://github.com/vectra-ai-research/Halberd/wiki/Module-Details) & [usage](https://github.com/vectra-ai-research/Halberd/wiki/Usage) elaborates on specific executable techniques and interesting capabalities of Halberd.

Checkout [Testing Use Cases](https://github.com/vectra-ai-research/Halberd/wiki/Testing-Use-Cases) for examples. 

- Entra ID Techniques
- M365 Techniques
- Azure Techniques
- AWS Techniques
- Playbook Automation
- Advanced Recon Widgets
- Reporting
- Technique Execution via Intutive Web-App

Note: Halberd is continuously evolving and getting better with more testing techniques, new capabilities & fixes. Ensure to use the latest version available whenever possible. 

## Getting Started

Once Halberd is deployed & running, start testing by accessing http://127.0.0.1:8050/ in your browser. 

### Access

Manage access-tokens/clients/sessions and review current access information for various targets.

### Attack

Configure and execute techniques for testing. From the `Attack` view, select `Attack Surface > Tactic > Technique > Execute`.  

### Recon

Provides numerous advanced reconnaissance dashboards enabling fast and easy information gathering by automatically executing sequence of reconnaissance in the environment.

Example: Navigate to `Recon` > `Entity Map` > `Generate Entity Map` to generate an interactive graph of access & privileges in the cloud environment.

### Automator

Manage & execute attack playbooks. Also, setup automation with scheduler. 

### Trace

Displays log of all executed techniques and allows downloading report.

Note: Different techniques require varying access & privileges for successful execution. Start by establishing relevant access using `Initial Access` tactic under each attack surface. 

Checkout [usage](https://github.com/vectra-ai-research/Halberd/wiki/Usage) for more information on testing with Halberd. 

## Contribute
- Thanks for considering contributing to Halberd! Your contributions will make security testing easier & better.
- Submit bugs & issues [here](https://github.com/vectra-ai-research/Halberd/issues/new)

If you are interested in contributing to Halberd, checkout [development focus areas](https://github.com/vectra-ai-research/Halberd/wiki/Contributions#areas-of-focus) & guidance on [contributions](https://github.com/vectra-ai-research/Halberd/wiki/Contributions).

## Contact
If you found this tool useful, want to share interesting use-cases or ideas - reach out & share them!
 - Author : [Arpan Sarkar](https://www.linkedin.com/in/arpan-sarkar/)
 - Maintainer : [Arpan Sarkar](https://www.linkedin.com/in/arpan-sarkar/)

## Inspiration
Halberd is inspired from many amazing ideas and work produced by several talented members/groups of the security community. Checkout some of them [here](https://github.com/vectra-ai-research/Halberd/wiki/Additional-(Amazing)-Resources).