# Introduction 
The **Get-AzNetworkDiagram** (Powershell)Cmdlet visualizes Azure networking (and other relevant resources) utilizing Graphviz and the "DOT", diagram-as-code language to export a PDF, SVG or PNG with a network digram containing the supported resources (see below list)

The idea was _not_ to diagram everything - but enough to get an overview of routing across the entire network environment, with documentation and troubleshooting in mind. But good ideas and contributions emerged - it is now quite capable of documentating quite a bit of resourse types.

```diff
- Disclaimer: We take no resposibility for any actions caused by this script!
```

# Demo output
**Additional demo outputs are available in the "DemoOutput" folder.**

Version 1.0.1:

![Demo output](https://github.com/dan-madsen/AzNetworkDiagram/blob/main/DemoOutput/Demo.png)  


# Requirements
The script depends on Graphviz (the "DOT", diagram-as-code language) to genereate the graphical output.

Graphviz can be downloaded from: https://graphviz.org/. But note that the default install doesn't add the executable to $PATH, so make sure to enable that during install.

It can also be installed using "Winget", but that will _NOT_ add the executable to $PATH - so you will have to do that manually.

# Getting started 
## Install using PSGallery (prefered method)
```powershell
Install-Module -Name AzNetworkDiagram
```

## Install from Github repo 
Clone repository, switch to the cloned directory, then:
```powershell
Import-Module .\AzNetworkDiagram.psm1
```

## Runtime options
- **-OutputPath <path>** - set output directory. Default: "."
- **-Subscriptions "subid1","subid2","subname","..."** - a list of subscriptions in scope for the diagram. They can be names or Id's
- **-EnableRanking $bool** ($true/$false) - enable ranking (equal hight in the output) of certain resource types. For larger networks, this might be worth a shot. **Default: $true**
- **-Tenant "tenantId"** Specifies the tenant Id to be used in all subscription authentication. Handy when you have multiple tenants to work with. **Default: current tenant**
- **-Sanitize $bool** ($true/$false) - Sanitizes all names, locations, IP addresses and CIDR blocks. **Default: $false**
- **-Prefix "string"** - Adds a prefix to the output file name. For example is cases where you want to do multiple automated runs then the file names will have the prefix per run that you specify. **Default: No Prefix**
- **-OnlyCoreNetwork** ($true/$false) - if $true/enabled, only cores network resources are processed - ie. non-network resources are skipped for a cleaner diagram. Default is $false.
- **-KeepDotFile** ($true/$false) - if $true/enabled, the DOT file is not deleted after the diagrams have been generated. Default is $false and DOT files are deleted.
- **OutputFormat** (pdf, svg, png) - One or more output files get generated with the specified formats. Default is PDF.

## Running the Powershell module
**Examples:**
```powershell
Get-AzNetworkDiagram [-Tenant tenantId] [-Subscriptions "subid1","subid2","..."] [-OutputPath C:\temp\] [-EnableRanking $true] [-OnlyCoreNetwork $true] [-Sanitize $true] [-Prefix prefixstring] [-KeepDotFile $true] [-OutputFormat [pdf,svg,png]]

Get-AzNetworkDiagram 
```

Beware, that by using "-Subscriptions" to limit the scope of data collection, you might end up with peerings being created to sparsely defined vNets (which would be out of your defined scope). These would appear as a long string, that is the id of the vNet, with special characters stripped for DOT-compatability.

# Flow
It will loop over any subscriptions available (or those defined as the parameter) and process supported resource types. After data is collected, a .PDF, .PNG and/or .SVG file with the diagram will be created. For very large environments the PNG format could display a scaling error. The .SVG format is editable with Microsoft Visio.

The .DOT settings in the .DOT file try to make the diagram as compact as possible and the ranking tries to keep similar resources ranked accordingly. Though it is inevitable that large environments make the diagram very large but zooming into the PDF or SVG works the best.

In Hub-Spoke and vWAN environments only resources in scope are depicted to avoid a very large number of links to orphan vNets from a scope point of view. Both vWAN resources and standalone versions of them are handled accordingly with similar data drawn.

If links to other resources exist then these links are drawn too. For example, if the vWAN Firewall has a DNS proxy enabled which points to a Private DNS Resolver then that link will be displayed too. If an IP Group is used in a Firewall Policy then that link is also displayed.

# Currently Supported Resources
The module is now compatible with both Ubuntu and Windows so you can run it successfully on either system. The requirement of having Graphviz installed exists on both platforms. You can look into the YAML file in the pipeline example on how to install Graphviz on Ubuntu unattended.

This module will include in the diagram in separate colors:
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
  - SSH Keys
  - ACR
  - AKS
  - Storage Accounts
  - VM, VMSS
  - Keyvaults
  - APIM
  - MongoDB, MySQL, PostgreSQL
  - SQL Server (logical server), Azure SQL, SQL Managed Instance
  - EventHubs
  - Redis Cache
  - App Services
  - Compute Galleries
  - Azure Container Apps
  - Azure Container Instances
  - Static Web Apps

# Pipeline Runs
An example ADO pipeline YAML file has been added with support Powershell scripts. This pipeline does the following:
  - It assumes you have a Wiki in use for your project
  - It pulls this Wiki and the azNetworkDiagram repo on the standard runner
  - Installs GraphViz and Powershell modules
  - Then generates diagrams using the AzNetworkDiagram and generates Markdown files using the PSDocs Powershell module
  - Pushes the generated markdown files into the Wiki
  - The cron schedule example shows how to make it run regularly on a schedule.
  - There are links in the code to show where you can get more detailed information if you want to modify your output

# Changelog (since v1.0.1)
## v1.2
- Resources can now be links, if enabled (only PDF support!), which will take you directly to the Azure portal
- Optionally, add Management Group and Subscription overview to the diagram
- New parameters
  - -EnableLinks $true
    - Links can be enabled using the flag 
  - EnableMgmtGroups $true
    - Add Management Group and Subscription overview to the diagram
  - OnlyMgmtGroups $true
    - Creates a Management Group and Subscription overview diagram - everything else is skipped
- Bug fixes
  - Azure Firewall: Fixed crash when no Azure Firewall policy is attached
  - Azure Firewall Policy: Fixed crash when IP Groups are not in use at all
  - MySQL: admin retrievel changed (but will potentially give less output)
  - vWAN: Removed from output, if no hubs are present (to avoid id with to icon or proper label)
  - Container Instances - crash when instance is in stopped state
## v1.1
- Diagrams are now colorized
- Linux support
- Pipeline scripts added for Azure DevOps
- AzNetworkDiagram info added in footer
- Legend added to output
- vWAN bug/scenario with first peered vNet in another sub fixed
- New parameters
  - KeepDotFile
  - OutputFormat
- New support for:
  - Container instances
  - Container Apps
  - Static Web Apps
## v1.0.2
- Local Gateway (Site 2 Site VPNs) - FQDN support (prevent runtime crash)

# Issues, bugs, comments and ideas
Please submit using the issues option in GitHub
