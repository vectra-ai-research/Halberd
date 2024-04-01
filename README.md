<h1 align="center">    
    <img src="assets/halberd_nbg_lg.png" height="25" width="25">
    Halberd
</h1>
<p align="center">
Halberd is an open-source security testing tool to proactively assess cloud security by executing a comprehensive array of attack techniques across multiple surfaces.
</p>

Leveraging Halberd, security teams can execute attack techniques such as cloud resource discovery, priv esc by tenant config modification, persistence through backdoor creation, deleting / modifying cloud resources and several others via a simple interactive web interface. This means no need to find or learn commmands to execute techniques.

Evaluate defenses across multiple attack surfaces, including [Entra ID](https://learn.microsoft.com/en-us/entra/identity/), [M365](https://learn.microsoft.com/en-us/microsoft-365/?view=o365-worldwide), [Azure](https://learn.microsoft.com/en-us/azure/?product=popular) and [AWS](https://docs.aws.amazon.com).

## Setup

Halberd works on Linux, macOS & Windows and can be setup easily in just a few minutes.

### Install

```
$ git clone https://github.com/vectra-ai-research/Halberd.git
$ cd Halberd
$ pip install -r requirements.txt
$ python3 Halberd.py
```

Checkout detailed instructions in [deployment guide](https://github.com/vectra-ai-research/Halberd/wiki/Deployment-Guide). 

### Usage
Once setup start testing by accessing the Halberd web interface in your browser. 
```
Visit: http://127.0.0.1:8050/
```

## Overview
[Module details](https://github.com/vectra-ai-research/Halberd/wiki/Module-Details) & [usage](https://github.com/vectra-ai-research/Halberd/wiki/Usage) elaborates on specific executable techniques and interesting capabalities of Halberd. 

- Entra ID Testing Modules
- M365 Testing Modules
- Azure Testing Modules
- AWS Testing Modules
- Reconnaissance Graphs
- Access Manager
- Reporting
- Technique Execution via Web-Interface

## Getting Started

Once Halberd is deployed, start testing by visiting http://127.0.0.1:8050/ in your browser. 

`Access` allows users to manage access tokens / clients and review current access information for various targets.

`Attack` allows users to view and execute attack techniques. Select an attack surface from the attack tab to view available tactics & attack modules. 

> Example : To start testing EntraID, navigate to `Attack` -> `EntraID` -> `Initial Access` -> `EntraID Delegated Access`. Enter the required details and hit `Execute Technique`. Navigate back to `Access` to view details of your established access.

`Recon` provides numerous advanced reconnaissance dashboards enabling fast and easy information gathering by automatically executing sequence of reconnaissance in the environment. 

> Example: Navigate to `Recon` -> `Entity Map` and click on `Generate Entity Map` to access an interactive graph of access & privileges in the cloud environment.

`Trace` displays trace of all executed attack techniques and allows users to download a report.

Note: Attack modules require varying access & privileges for successful execution. Start by establishing relevant access using `Initial Access` under each attack surface to continue testing with other attack modules. 

Checkout [usage](https://github.com/vectra-ai-research/Halberd/wiki/Usage) for more information on testing with Halberd. 

## Contribute
- Thanks for considering contributing to Halberd! Your contributions will make security testing easier & better.
- Submit bugs & issues [here](https://github.com/vectra-ai-research/Halberd/issues/new)

If you are interested in contributing to Halberd, checkout [development focus areas](https://github.com/vectra-ai-research/Halberd/wiki/Contributions#areas-of-focus) & guidance on [contributions](https://github.com/vectra-ai-research/Halberd/wiki/Contributions).

## Contact
If you found this tool useful, want to share an interesting use-case or idea - reach out & share them
 - Maintainer : [Arpan Sarkar](https://www.linkedin.com/in/arpan-sarkar/)