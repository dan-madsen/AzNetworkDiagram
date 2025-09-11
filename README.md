# Introduction 
The **Get-AzNetworkDiagram** (Powershell)Cmdlet visualizes Azure infrastructure utilizing Graphviz and the "DOT" (diagram-as-code) language to export a PDF, SVG or PNG with a digram containing the supported resources (see below list)

At this point it is now quite capable of documentating quite a bit of resourse types. Initially it was with network as a focus - but it has emerged into some more. It will document network and infrastructure in a diagram, useful for documentation and/or troubleshooting.

```diff
- Disclaimer: We take no resposibility for any actions caused by this script!
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
**The script depends on Graphviz** (the "DOT", diagram-as-code language) to genereate the graphical output.

Graphviz can be downloaded from: https://graphviz.org/. But note that the default install doesn't add the executable to $PATH, so make sure to enable that during install.

It can also be installed using "Winget", but that will _NOT_ add the executable to $PATH - so you will have to do that manually.

---

# Getting started 
## Install using PSGallery (prefered method)
```powershell
Install-Module -Name AzNetworkDiagram
```

## Install from Github repo 
Clone repository (or download the file referenced), switch to the cloned directory, then:
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
- **-OnlyCoreNetwork** ($true/$false) - if $true/enabled, only cores network resources are processed - ie. non-network resources are skipped for a cleaner diagram - but you will also lack some references from shown resources. Default is $false.
- **-OnlyMgmtGroups** ($true/$false) - Creates a Management Group and Subscription overview diagram - everything else is skipped. Default is $false.
- **-KeepDotFile** ($true/$false) - if $true/enabled, the DOT file is not deleted after the diagrams have been generated. Default is $false and DOT files are deleted.
- **-OutputFormat** (pdf, svg, png) - One or more output files get generated with the specified formats. Default is PDF.
- **-EnableLinks** ($true/$false) - Many resources become links to the Azure portal can be enabled using this flag. Default is $false.
- **-SkipXXX** ($true/$false) - Skips a chosen non-core network resource type - use tab completion to see current list.


## Running the Powershell module
**Examples:**
```powershell
Get-AzNetworkDiagram [-Tenant tenantId] [-Subscriptions "subid1","subid2","..."] [-OutputPath C:\temp\] [-EnableRanking $true] [-OnlyCoreNetwork $true] [-Sanitize $true] [-Prefix prefixstring] [-KeepDotFile $true] [-OutputFormat [pdf,svg,png]] [-OnlyMgmtGroups  $true] [-EnableLinks $true]

Get-AzNetworkDiagram 
```

Beware, that by using "-Subscriptions" to limit the scope of data collection, you might end up with peerings being created to sparsely defined vNets (which would be out of your defined scope). These would appear as a long string, that is the id of the vNet, with special characters stripped for DOT-compatability.

---

# Recommendation
It is inevitable that large environments make the diagram **very large** (in this case "wide"), but zooming into the PDF or SVG works the best. In cases where diagrams gets too bug/wide, you should consider scoping the digram (ie. utilize **-Subscriptions "subid","subid2"....**) to create smaller diagrams with a scope that matches your deployment(s), instead of your entire infrastructure. For many environments, you could probably go with something like this:
- A management group diagram (-OnlyMgmtGroups $true)
- A core network diagram (-OnlyCoreNetwork $true) that spans part of your infrastructure (or maybe everything), which will include
  - Route tables
  - IP Groups
  - vNets (incl. subnets, peerings, Azure Bastion, Azure Firewall)
  - NSGs
  - VPN Connections
  - Express Route Circuits
  - vWAN / Virtual WAN
  - Private Endpoints
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
  - Recovery Service Vaults
  - Backup Vaults
  - Azure VMware Solution

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

# Changelog (since v1.0.1)
## Upcoming releas (not released to Powershell Gallary yet)
- New support for
  - NICs connected to VMs now appear as seperate resources, with its own link to subnets and NSGs. That is handy when utilizing NVAs (Network Virtual Appliances) for example.
## v1.2.1
- Bug fix - versions with a minor of "0", now shows correctly (showed "-1")
## v1.2
- New support for
  - Backup Vaults (not to be confused with Recovery Service Vaults below!)
    - References to Storage Accounts blobs/containers, PostgreSQL, etc...
  - Recovery Service Vaults
    - References to VMs, MSSQL in VMs and Azure File Shares
  - Storage account/Azure File Share
  - Storage account/Container
  - Azure Container Registry - added repositories to diagram
  - Azure VMware Solution
- Changed parameters for Mangement Groups
  - EnableMgmtGroups removed, rarely a case where it would make sense to have mangement groups in a diagram with everything else. Utilize [-OnlyMgmtGroups $true] for management groups overview moving forward.
- New parameters
  - All non-core network resource, now have a corrosponding -Skip option. A few examples:
    - -SkipSA $true
    - -SkipVM $true
    - Use tab completion for a full list
- New features
  - NAT GW
    - Link addedd
  - Routes Tables
    - Routes are now sorted by Address Prefix
    - Route names are now part of the output
- Bugs fixed
  - Azure Firewall parsing when in VNet (ie. not vWAN configurations)
  - NAT Gateway: Public IP Prefixes are now showing correctly
  - Express Routes circuits are now validated prior to making links, to avoid non-sense in the output
## v1.1
- New support for
  - Container instances
  - Container Apps
  - Static Web Apps
  - Multiple NICs pr. VM
  - VMs (or rather the NICs associated with the VM) now references associated NSG(s)
- New features
  - Diagrams are now colorized
  - Linux support
  - Pipeline (template) scripts added for Azure DevOps
  - Legend added to output, incl. AzNetworkDiagram info (and link)
  - Resources can now be links, if enabled (only PDF support!), which will take you directly to the Azure portal
  - Optionally, add Management Group and Subscription overview to the diagram
- New parameters
  - KeepDotFile $true
    - Keeps the DOT file, instead of deleting it
  - OutputFormat 'pdf','svg','png'
    - Set one of more output formats - defaults to PDF
  - EnableLinks $true
    - Many resources become links to the Azure portal (only supported in PDF format)
  - EnableMgmtGroups $true
    - Add Management Group and Subscription overview to the diagram
  - OnlyMgmtGroups $true
    - Only the Management Group and Subscription overview are exported - everything else is skipped
- Bugs fixed
  - vWAN: Crashed when first peered vNet was in another sub fixed
  - Azure Firewall: Crashed when no Azure Firewall policy is attached
  - Azure Firewall Policy: Fixed crash when IP Groups are not in use at all
  - MySQL: admin retrievel changed (but will potentially give less output)
  - vWAN: Removed from output, if no hubs are present (to avoid id with to icon or proper label)
  - Container Instances: Crashed when instance is in stopped state

## v1.0.2
- Local Gateway (Site 2 Site VPNs) - FQDN support (prevent runtime crash)

---

# Issues, bugs, comments and ideas
Please submit using the issues option in GitHub
