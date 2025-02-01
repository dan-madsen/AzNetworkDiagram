# Introduction 
The Get-AzNetworkDiagram.ps1 visualizes Azure networking utilizing Graphviz and the "DOT", diagram-as-code language to export a PDF and PNG with a network digram containing:
  - VNets, including:
    - VNet peerings
    - Subnets (will be marked with an "#" if a Network Security Group is associated)
        - Special subnets - AzureBastionSubnet, GatewaySubnet, AzureFirewallSubnet and associated resources
        - Associated Route Tables
  - Gateways
    - VPN incl. associated Local Network Gateways and static remote subnets
    - ER (excl. connected cicuits!)

The idea is _not_ to diagram everything - but enough to get an overview of routing across the entire network environment, with documentation and trobleshooting in mind.

```diff
- Disclaimer: I take no resposibility for any actions caused by this script!
```

# Demo output:
![Demo output](https://github.com/dan-madsen/AzNetworkDiagram/blob/main/DemoOutput/Demo.png)  



# Requirements
The script depends on Graphviz (the "DOT", diagram-as-code language) to genereate the diagrams in .PDF and .PNG format.

Graphviz can be downloaded from: https://graphviz.org/. But note that the default install doesn't add the executable to $PATH, so make sure to enable that during install.

It can also be installed using "Winget", but that will _NOT_ add the executable to $PATH - so you will have to do that manually.

# Getting started (with GIT version)
Import module (will be available on PSGallary in the near future)
```code
PS> Import-Module .\AzNetworkDiagram.psm1
```
Examples:
```diff
PS> Get-AzNetworkDiagram [-outputPath C:\temp\]
PS> Get-AzNetworkDiagram 
```

# Getting started (PSGallery)
```code
Install-Module -Name AzNetworkDiagram
```
Examples:
```diff
PS> Get-AzNetworkDiagram [-outputPath C:\temp\]
PS> Get-AzNetworkDiagram 
```

# Flow
It will loop over any subscriptions available and process supported resource types. After data is collected, a .PDF and .PNG file with the digram will be created.

# Future ideas
- Support for
    - Express Route Circuits
    - Azure vWAN support
- Azure DevOps pipeline for automated runs, with output saved to storage account
    - Mail on changes?
- Subnet marks for other special purposes (SQLMI, App Services, etc.)
- Proper indents in the .dot file
- Subscription scoping via parameters