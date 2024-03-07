# Halberd
<p align="center">
    ![logo](/assets/favicon.ico)
</p>
Halberd is an open-source security testing tool that enables cyber security professionals to proactively assess their security measures by executing a comprehensive array of attack techniques across multiple surfaces.

Developed & maintained by Vectra AI, Halberd's intuitive web interface makes effective testing easier than ever.

Harnessing a collection of meticulously crafted executable attack techniques, Halberd enables users to evaluate their defenses across various attack vectors, including Entra ID, M365, Azure and AWS.

## Setup
```
$ git clone https://github.com/vectra-ai-research/Halbred
$ cd Halbred
$ pip install -r requirements.txt
$ python3 Halbred.py
```

### Usage
```
Access: http://127.0.0.1:8050/
```

### Requirements
- Officially supported in Linux and macOS
- Python 3.9+

## Overview
- Intutive Web-Interface for security testing
- Entra ID Testing Modules
- M365 Testing Modules
- Azure Testing Modules
- AWS Testing Modules
- Useful Visualizations
- Access Manager
- Download Testing Report

## Getting Started
Once you are setup, access Halbert by visiting http://127.0.0.1:8050/ in your browser. 

The `Access` page allows your to manage access token and review your current access to various environments.

The `Attack` page allows your to view and execute various attack techniques. Select an attack surface Tab to see its available Tactics & Attack Modules. 

For example, to get started with EntraID / M365, go to `Attack` -> `EntraID` -> `Initial Access` and choose a module to establish access. Once done, go back to `Access` page to view details of your access.

The `Attack Trace` page displays trace of all executed attack techniques and allows users to download a report.

Attack Modules require different access & privileges for execution. Start by leveraging modules within `Initial Access` tactic under each attack surface to continue testing with other attack modules. 

## Project Development Goals
- Increase Attack Testing Coverage - Add new attack techniques to allow for more robust testing
- Enhance Usability - Add new useful features & visualizations to assist in testing process and post testing evaluation

## Contribute
- Thanks for considering contributing to Halbert! Your contributions will help make security testing easier & better.
- Submit bugs & issues directly to GitHub Issues
- Share ideas or suggestions in GitHub Discussions

## Contact
If you found this tool useful, want to share an interesting use-case or idea - reach out & share them
 - Maintainer : [Arpan Sarkar](https://www.linkedin.com/in/arpan-sarkar/)