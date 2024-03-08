# Halberd

![logo](/assets/favicon.ico)

Halberd is an open-source security testing tool to proactively assess security measures by executing a comprehensive array of attack techniques across multiple surfaces.

Developed & maintained by Vectra AI, Halberd's intuitive web interface makes effective testing easier than ever.

Harnessing a collection of meticulously crafted executable attack techniques, Halberd enables users to evaluate their defenses across various attack vectors, including [Entra ID](https://learn.microsoft.com/en-us/entra/identity/), [M365](https://learn.microsoft.com/en-us/microsoft-365/?view=o365-worldwide), [Azure](https://learn.microsoft.com/en-us/azure/?product=popular) and [AWS](https://docs.aws.amazon.com).

## Setup

Halberd is an easy & quick to setup tool.

### Install

```
$ git clone https://github.com/vectra-ai-research/Halberd.git
$ cd Halberd
$ pip install -r requirements.txt
$ python3 Halberd.py
```

Checkout detailed instructions in [deployment guide](https://github.com/vectra-ai-research/Halberd/wiki/Deployment-Guide). 

### Launch
```
Access: http://127.0.0.1:8050/
```

### Requirements
- Officially supported on Linux and macOS
- [Python 3.9+](https://www.python.org/downloads/) & few Python libraries

## Overview
[Module details](https://github.com/vectra-ai-research/Halberd/wiki/Module-Details) & [usage](https://github.com/vectra-ai-research/Halberd/wiki/Usage) elaborates on specific testing modules and other capabalities of Halberd. 

- Intutive Web-Interface for security testing
- Entra ID Testing Modules
- M365 Testing Modules
- Azure Testing Modules
- AWS Testing Modules
- Useful Visualizations
- Access Manager
- Reporting

## Getting Started

Once Halberd is deployed, start testing by visiting http://127.0.0.1:8050/ in your browser. 

`Access` allows users to manage access tokens / clients and review current access information for various targets.

`Attack` allows users to view and execute attack techniques. Select an attack surface from the attack tab to view available tactics & attack modules. 

> Example - To get started with EntraID testing, navigate to `Attack` -> `EntraID` -> `Initial Access` -> `EntraID Delegated Access`. Enter the required config and hit `Execute Technique`. Once done, navigate back to `Access` to view details of your access.

`Attack Trace` displays trace of all executed attack techniques and allows users to download a report.

`Entity Map` executes sequence of automatic recon and generates an interactive graph of target entity's access & privilege in Entra ID environment.

Attack modules require varying access & privileges for successful execution. Start by establishing relevant access using `Initial Access` tactic under each attack surface to continue testing with other attack modules. 

Checkout [usage](https://github.com/vectra-ai-research/Halberd/wiki/Usage) for more information on testing with Halberd. 

## Contribute
- Thanks for considering contributing to Halberd! Your contributions will help make security testing easier & better.
- Submit bugs & issues [here](https://github.com/vectra-ai-research/Halberd/issues/new)

If you are interested in contributing to Halberd, checkout [development focus areas](https://github.com/vectra-ai-research/Halberd/wiki/Contributions#areas-of-focus) & guidance on [contributions](https://github.com/vectra-ai-research/Halberd/wiki/Contributions).

## Contact
If you found this tool useful, want to share an interesting use-case or idea - reach out & share them
 - Maintainer : [Arpan Sarkar](https://www.linkedin.com/in/arpan-sarkar/)