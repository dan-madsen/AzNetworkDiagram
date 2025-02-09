# Introduction 
The **Get-AzNetworkDiagram** (Powershell)Cmdlet visualizes Azure networking utilizing Graphviz and the "DOT", diagram-as-code language to export a PDF and PNG with a network digram containing:
  - VNets, including:
    - VNet peerings
    - Subnets (will be marked with an "#" if a Network Security Group is associated)
        - Special subnets - AzureBastionSubnet, GatewaySubnet, AzureFirewallSubnet and associated resources
        - Delegations will be noted, and commonly used delegations will be given a proper icon
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

# Getting started 
## Install from Github repo 
Clone repository, switch to the cloned directory, then:
```code
PS> Import-Module .\AzNetworkDiagram.psm1
```

## Install using PSGallery
```code
PS> Install-Module -Name AzNetworkDiagram
```

## Runtime options
**-OutputPath c:\temp** - set output directory. Default: "."

**-Subscriptions "subid1","subid2","..."** - a list of subscriptions in scope for the digram

**-EnableRanking $bool** ($true/$false) - enable ranking (equal hight in the output) of certain resource types. For larger networks, this might be worth a shot. **Default: $true**


## Running the Powershell module
**Examples:**
```diff
PS> Get-AzNetworkDiagram [-Subscriptions "subid1","subid2","..."] [-OutputPath C:\temp\] [-EnableRanking $true]

PS> Get-AzNetworkDiagram 
```

Beware, that by using "-Subscriptions" to limit the scope of data collection, you might end up with peerings being created to sparsely defined VNets (which would be out of your defined scope). These would appear as a long string, that is the id of the vnet, with special characters stripped for DOT-compatability.

# Flow
It will loop over any subscriptions available (or those defined as the parameter) and process supported resource types. After data is collected, a .PDF and .PNG file with the digram will be created.

# Future ideas
- Support for
    - Express Route Circuits
    - Azure vWAN support
- Azure DevOps pipeline for automated runs, with output saved to storage account
    - Mail on changes?