# Introduction 
The Get-AzNetworkDiagram.ps1 visualizes Azure networking utilizing GraphViz and the "DOT", diagram-as-code language to export a PNG with a network digram containing:
  - VNets, including:
    - VNet peerings
    - Subnets (will be marked with an "#" if a Network Security Group is associated)
        - Special subnets - AzureBastionSubnet, GatewaySubnet, AzureFirewallSubnet
        - Associated Route Tables
  - Gateways
    - VPN incl. associated Local Network Gateways and static remote subnets
    - ER (excl. connected cicuits!)

IMPORTANT:
Icons in the .\icons\ folder is necessary in order to generate the diagram. If module is run from another working directory, it will generate the diagram without proper images!

```diff
+ Demo output:
```
![Demo output](https://github.com/dan-madsen/AzNetworkDiagram/blob/main/DemoOutput/Demo.png)  

```diff
- Disclaimer: I take no resposibility for any actions caused by this script!
```

# Future ideas
- Upload to PSGallery
- Support for
    - Express Route Circuits
    - Azure vWAN support
- Azure DevOps pipeline for automated runs, with output saved to storage account
    - Mail on changes?
- Subnet marks for other special purposes (SQLMI, App Services, etc.)
- Proper indents in the .dot file