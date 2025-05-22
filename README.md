# Introduction 
The **Get-AzNetworkDiagram** (Powershell)Cmdlet visualizes Azure networking utilizing Graphviz and the "DOT", diagram-as-code language to export a PDF and PNG with a network digram containing:
  - VNets, including:
    - VNet peerings
    - Subnets
        - Special subnet: AzureBastionSubnet and associated Azure Bastion resource
        - Special subnet: GatewaySubnet and associated resources, incl. Network Gateways, Local Network Gateways and connections with the static defined remote subnets. But excluding Express Route Cirtcuits.
        - Special subnet:  AzureFirewallSubnet and associated Azure Firewall Policy
        - Associated Route Tables
        - A * will be added to the subnet name, if a subnet is delegated. Commonly used delegations will be given a proper icon
        - A # will be added to the subnet name, in case an NSG is associated

The idea is _not_ to diagram everything - but enough to get an overview of routing across the entire network environment, with documentation and troubleshooting in mind.

```diff
- Disclaimer: I take no resposibility for any actions caused by this script!
```

# Demo output, version 0.3.1:
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
**-OutputPath <path>** - set output directory. Default: "."

**-Subscriptions "<subid1>","<subid2>","..."** - a list of subscriptions in scope for the digram

**-EnableRanking $bool** ($true/$false) - enable ranking (equal hight in the output) of certain resource types. For larger networks, this might be worth a shot. **Default: $true**

**-Tenant <tenantId>**

**-OnlyCoreNetwork** ($true/$false) - if $true/enabled, only cores network resources are processed - ie. non-network resources are skipped for a cleaner diagram.


## Running the Powershell module
**Examples:**
```diff
PS> Get-AzNetworkDiagram [-Subscriptions "subid1","subid2","..."] [-OutputPath C:\temp\] [-EnableRanking $true]

PS> Get-AzNetworkDiagram 
```

Beware, that by using "-Subscriptions" to limit the scope of data collection, you might end up with peerings being created to sparsely defined vNets (which would be out of your defined scope). These would appear as a long string, that is the id of the vNet, with special characters stripped for DOT-compatability.

# Flow
It will loop over any subscriptions available (or those defined as the parameter) and process supported resource types. After data is collected, a .PDF, .PNG and .SVG file with the diagram will be created. For very large environments the PNG format could display a scaling error. The .SVG format is editable with Microsoft Visio.

The .DOT settings in the .DOT file try to make the diagram as compact as possible and the ranking tries to keep similar resources ranked accordingly. Though it is inevitable that large environments make the diagram very large but zooming into the PDF or SVG works the best.

In Hub-Spoke and vWAN environments only resources in scope are depicted to avoid a very large number of links to orphan vNets from a scope point of view. Both vWAN resources and standalone versions of them are handled accordingly with similar data drawn.

If links to other resources exist then these links are drawn too. For example, if the vWAN Firewall has a DNS proxy enabled which points to a Private DNS Resolver then that link will be displayed too. If an IP Group is used in a Firewall Policy then that link is also displayed.

# Currently Supported Resources
This module will include in the diagram:
  - Subscriptions
  - vNets & Subnets & Delegations
  - Route Tables
  - NSG's
  - IP Groups
  - Application Gateways
  - Express Routes Circuits and ER Direct ports & Links
  - vWAN's & Hubs
  - Azure Firewall
  - VPN Gateway
  - NAT Gateway
  - Bastion
  - Private Endpoints
    
# Work in progress...
  - Support for
    - SSH Keys
    - APIM
    - ACR
    - AKS
    - Storage Accounts
    - VM, VMSS
    - Keyvaults
    - MongoDB, MySQL, PostgreSQL
    - EventHub
    - Redis
    - App Services
  - Azure DevOps pipeline for automated runs, with output saved to storage account
    - Mail on changes?

# Issues, bugs, comments and ideas
Please submit using the issues option in GitHub