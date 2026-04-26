# Table of contents
* [Introduction](#introduction)
* [Demo Output](#demo-output-v11)
* [Requirements](#Requirements)
* [Getting started](#Getting-started)
  - [Install](#install-using-psgallery-recommended-method)
  - [Runtime options](#runtime-options)
    - [Primary (Setting scope and output)](#primary-setting-scope-and-output)
    - [Others (Change behavior and/or features)](#others-change-behavior-andor-features)
  - [Running the Powershell module](#running-the-powershell-module)
* [Recommendation](#recommendation)
* [Runtime flow](#Runtime-flow)
* [Currently Supported Resources](#currently-supported-resources)
* [Pipeline runs](#pipeline-runs)
* [Changelog](#changelog)
* [Issues, bugs, comments and ideas](#issues-bugs-comments-and-ideas)

---

# Introduction 
The **Get-AzNetworkDiagram** (Powershell)Cmdlet visualizes Azure infrastructure leveraging Graphviz and the "DOT" (diagram-as-code) language to export a PDF, SVG or PNG with a digram containing the [supported resources](#currently-supported-resources).

Initially it was with network as a focus, but it has emerged into some more - it is quite capable of documenting a broader spectrum of resource types. It is a robust utility for generating comprehensive network and infrastructure diagrams, useful for documentation and/or troubleshooting.

## Created by
- [Dan](https://github.com/dan-madsen/) - Creator, inventor
- [Hanno](https://github.com/hannovdm) - Major contributor

```diff
- Disclaimer: We take no resposibility for any actions caused by running AzNetworkDiagram!
```
---

# Demo output v1.1
Some examples of the diagrams. **Additional demo outputs are available in the "DemoOutput" folder.**

## Demo output (partial):
![Demo output (partial)](https://github.com/dan-madsen/AzNetworkDiagram/blob/main/DemoOutput/Demo-Workload-AzNetworkDiagram-Partial.png) 

## Management group overview:
![Management Group overview](https://github.com/dan-madsen/AzNetworkDiagram/blob/main/DemoOutput/Management-Groups-AzNetworkDiagram.png) 

---

# Requirements
**The script depends on _Graphviz_** (the "DOT", diagram-as-code language) to generate the graphical output.

Graphviz can be downloaded from: https://graphviz.org/. But note that the default install doesn't add the executable to $PATH, so make sure to enable that during install (or manually afterwards).

It can also be installed using "Winget", but that will **_NOT_** add the executable to $PATH - so you will have to do that **_manually_**.

---

# Getting started 
The recommended way of running AzNetworkDiagram is by installing from PSGallery. But should you wish to have the absolute latest and greatest, you could opt for a version from GitHub, potentially with not-yet released features.
## Install using PSGallery (recommended method)
```powershell
Install-Module -Name AzNetworkDiagram
```

### Install **_beta_** from PSGallery (for testing and/or new yet-to-be-released features)
```powershell
Install-Module -Name AzNetworkDiagram -AllowPrerelease
```

## Install from GitHub repo 
Clone repository (or download the file referenced below), switch to the cloned directory, then:
```powershell
Import-Module .\AzNetworkDiagram.psm1
```

## Runtime options
### Primary (setting scope and output)
- **-ManagementGroups "ManagementGroupID1","ManagementGroupID2","..."** - a list of management groups. Subscriptions under any of the listed management group IDs (ie. NOT name!) will be added to the list of subscriptions in scope for data collection. Can be used in conjunction with -Subscriptions.
- **-OnlyIPPlan** - Creates an IP Plan of all VNets in scope. Everything else is skipped.
  - If **-OnlyMgmtGroups** is set - that will take precedence over the IP Plan !
- **-OnlyMgmtGroups** - Creates a Management Group and Subscription overview diagram - everything else is skipped.
- **-OutputPath <path>** - set output directory. Default: "."
- **-Prefix "string"** - Adds a prefix to the output file name. For example is cases where you want to do multiple automated runs then the file names will have the prefix per run that you specify. **Default: No Prefix**
- **-Subscriptions "subid1","subid2","subname","..."** - a list of subscriptions in scope for the diagram. They can be names or Id's
- **-Tenant "tenantId"** Specifies the tenant Id to be used in all subscription authentication. Handy when you have multiple tenants to work with. **Default: current tenant**

### Others (change behavior and/or features)
- **-DisableRanking** - Disables automatic ranking for resource types. For larger networks, this might be worth a shot.
- **-EnableADO** - Add list of Azure DevOps Organizations to the output
- **-EnableEntraDomains** - Add list of Entra ID Domains to the output
- **-EnableEntraLicenses** - Add list of Entra/M365 licenses to the output
- **-EnableLinks** - Many resources become links to the Azure portal can be enabled using this flag.
- **-EnableXXX** - Enable a chosen non-core network resource type regardless of it being skipped (-EnableXXXX will take precedence!) - use tab completion to see current list.
- **-KeepDotFile** - Keep the DOT file after the diagrams have been generated (normally it is deleted)
- **-OutputFormat** (pdf, svg, png) - One or more output files get generated with the specified formats. Default is PDF.
- **-Sanitize** Sanitizes all names, locations, IP addresses and CIDR blocks.
- **-SkipNonCoreNetwork** - Only rocess cores network resources (unless resource types are explicitly enabled using -EnableXXXX options) - ie. non-network resources are skipped for a cleaner diagram - but you will also lack some references from shown resources. 
- **-SkipXXX** - Skips a chosen non-core network resource type - use tab completion to see current list.

## Running the Powershell module
**Examples:**
```powershell
Get-AzNetworkDiagram [-Tenant tenantId] [-Subscriptions "subid1","subid2","..."] [-OutputPath C:\temp\] [-SkipNonCoreNetwork] [-Sanitize] [-Prefix prefixstring] [-KeepDotFile] [-OutputFormat [pdf,svg,png]] [-OnlyMgmtGroups] [-EnableLinks]
Get-AzNetworkDiagram [-Tenant tenantId] [-OutputPath C:\temp\] [-OnlyMgmtGroups] [-Sanitize] [-Prefix prefixstring] [-KeepDotFile] [-OutputFormat [pdf,svg,png]]
Get-AzNetworkDiagram 
```

Beware, that by using "-Subscriptions" to limit the scope of data collection, you might end up with peerings being created to sparsely defined vNets (which would be out of your defined scope). These would appear as a long string, that is the id of the vNet, with special characters stripped for DOT-compatability.

---

# Recommendation
It is inevitable that large environments make the diagram **very large** (in this case "wide"), but zooming into the PDF or SVG works the best. In cases where diagrams gets too big/wide, you should consider scoping the digram (ie. utilize **-Subscriptions "subid","subid2"....**) to create smaller diagrams with a scope that matches your deployment(s), instead of your entire infrastructure. For many environments, you could probably go with something like this:
- A management group diagram (-OnlyMgmtGroups)
- A core network diagram (-SkipNonCoreNetwork) that spans part of your core infrastructure (or maybe everything), which will only include the core network resources listed under "Currently supported resources"
- Multiple minor diagrams for individual workloads

---

# Flow
It will loop over any subscriptions available (or those defined as the parameter) and process supported resource types. After data is collected, a .PDF, .PNG and/or .SVG file with the diagram will be created. For very large environments the PNG format could display a scaling error. The .SVG format is editable with Microsoft Visio. **Consult above recommendation.**

The .DOT settings in the .DOT file try to make the diagram as compact as possible and the ranking tries to keep similar resources ranked accordingly. 

In Hub-Spoke and vWAN environments only resources in scope are depicted to avoid a very large number of links to orphan vNets from a scope point of view. Both vWAN resources and standalone versions of them are handled accordingly with similar data drawn.

If links to other resources exist then these links are drawn too. For example, if the vWAN Firewall has a DNS proxy enabled which points to a Private DNS Resolver then that link will be displayed too. If an IP Group is used in a Firewall Policy then that link is also displayed.

---

# Currently Supported Resources
The module is now compatible with both Ubuntu and Windows so you can run it successfully on either system. The requirement of having Graphviz installed exists on both platforms. You can look into the YAML file in the pipeline example on how to install Graphviz on Ubuntu unattended.

This module will include in the diagram in separate colors:
  - Mangement Groups and Subscriptions
  - **Core network resources**
    - Azure Firewall, including IP Groups
    - Bastion
    - NAT Gateway
    - NSG's
    - Route Server
    - Route Tables
    - VPN/ER Gateways and connections
      - Express Routes Circuits, ER Direct ports and Links
    - vNets incl. delegations, peerings and subnets 
    - vWAN's & Hubs
  - API Management (APIM)
  - App Service Plans and App Services
  - Application Gateways
  - Azure Container Apps
  - Azure Container Instances
  - Azure Container Registry
  - Azure Kubernetes Services
  - Azure VMware Solution
  - Azure Virtual Desktop
  - Backup Vaults
  - Compute Galleries
  - Elastic SAN
  - EventHubs
  - Keyvaults
  - Load Balancers
  - Open Source DBs
    - CosmosDB
    - MongoDB
    - MySQL
    - PostgreSQL
  - Private Endpoints
  - Recovery Service Vaults
  - Redis Cache
  - SQL Managed Instance
  - SQL Server (logical server), Azure SQL
  - SSH Keys
  - Static Web Apps
  - Storage Accounts
  - Virtual Machines and Virtual Machine Scale Sets

---

# Pipeline Runs
An example [ADO pipeline YAML file](https://github.com/dan-madsen/AzNetworkDiagram/tree/main/pipeline) has been added with support Powershell scripts. This pipeline does the following:
  - It assumes you have a Wiki in use for your project
  - It pulls this Wiki and the azNetworkDiagram repo on the standard runner
  - Installs GraphViz and Powershell modules
  - Then generates diagrams using the AzNetworkDiagram and generates Markdown files using the PSDocs Powershell module
  - Pushes the generated markdown files into the Wiki
  - The cron schedule example shows how to make it run regularly on a schedule.
  - There are links in the code to show where you can get more detailed information if you want to modify your output

---

# Changelog 
See change log in [CHANGELOG.md](CHANGELOG.md)

---

# Issues, bugs, comments and ideas
Please submit these using the issues option in GitHub. Remember to supply at least version information, error description and error message from the command line. If the Azure resource/object in question have a "special/exotic/rarely used" configuration that you are aware of, please include that is well, to ease troubleshooting.
