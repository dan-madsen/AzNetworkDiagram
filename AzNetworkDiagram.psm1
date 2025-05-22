<#
  .SYNOPSIS
  Creates a Network Diagram of your Azure networking infrastructure.

  .DESCRIPTION
  The Get-AzNetworkDiagram (Powershell)Cmdlet visualizes Azure networking utilizing Graphviz and the "DOT", diagram-as-code language to export a PDF and PNG with a network digram containing:
  - VNets, including:
    - VNet peerings
    - Subnets
        - Special subnet: AzureBastionSubnet and associated Azure Bastion resource
        - Special subnet: GatewaySubnet and associated resources, incl. Network Gateways, Local Network Gateways and connections with the static defined remote subnets. But excluding Express Route Cirtcuits.
        - Special subnet:  AzureFirewallSubnet and associated Azure Firewall Policy
        - Associated Route Tables
        - A * will be added to the subnet name, if a subnet is delegated. Commonly used delegations will be given a proper icon
        - A # will be added to the subnet name, in case an NSG is associated

  IMPORTANT:
  Icons in the .\icons\ folder is necessary in order to generate the diagram. If not present, they will be downloaded to the output directory during runtime.
  
  .PARAMETER OutputPath
  -OutputPath specifies the path for the DOT-based output file. If unset - current working directory will be used.

  .PARAMETER Subscriptions
  -Subscriptions "subid1","subid2","..."** - a list of subscriptions in scope for the digram. Default is all available subscriptions.

  .PARAMETER EnableRanking
  -EnableRanking $true ($true/$false) - enable ranking (equal hight in the output) of certain resource types. For larger networks, this might be worth a shot. **Default: $true**

  .INPUTS
  None. It will however require previous authentication to Azure

  .OUTPUTS
  None. .\Get-AzNetworkDiagram.psm1 doesn't generate any output (Powershell-wise). File based out will be save in the OutputPath

  .EXAMPLE
  PS> Get-AzNetworkDiagram [-Subscriptions "subid1","subid2","..."] [-OutputPath C:\temp\] [-EnableRanking $true]
  PS> .\Get-AzNetworkDiagram 

  .LINK
   https://github.com/dan-madsen/AzNetworkDiagram
#>

# Change Execution Policy for current process, if prohibited by policy
# Set-ExecutionPolicy -scope process -ExecutionPolicy bypass

# Action preferences
$ErrorActionPreference = 'Stop'
$WarningPreference = 'Continue'
$InformationPreference = 'Continue'

##### Functions for standard definitions #####
function Export-dotHeader {
    [CmdletBinding()]

    $Data = "digraph G {
    fontname=`"Arial,sans-serif`"
    node [fontname=`"Arial,sans-serif`"]
    edge [fontname=`"Arial,sans-serif`"]
    
    # Ability for peerings arrows/connections to end at border
    compound = true;
    #concentrate = true;
    clusterrank = local;
    
    # Rank (height in picture) support
    newrank = true;
    rankdir = TB;
    ranksep=`"2.0 equally`"
    nodesep=`"2.0`"
    "
    Export-CreateFile -Data $Data
}

function Export-dotFooterRanking {
    Export-AddToFile -Data "`n    ##########################################################################################################"
    Export-AddToFile -Data "    ##### RANKS"
    Export-AddToFile -Data "    ##########################################################################################################`n"
    Export-AddToFile -Data "    ### AddressSpace ranks"
    Export-AddToFile "    { rank=min; $($script:rankvnetaddressspaces -join '; ') }`n "
    Export-AddToFile -Data "`n    ### Subnets ranks"
    Export-AddToFile "    { rank=same; $($script:ranksubnets -join '; ') }`n "
    Export-AddToFile -Data "`n    ### Route table ranks"
    Export-AddToFile "    { rank=same; $($script:rankrts -join '; ') }`n "
    Export-AddToFile -Data "`n    ### vWAN ranks"
    Export-AddToFile "    { rank=same; $($script:rankvwans -join '; ') }`n "
    Export-AddToFile -Data "`n    ### vWAN Hub ranks"
    Export-AddToFile "    { rank=same; $($script:rankvwanhubs -join '; ') }`n "
    Export-AddToFile -Data "`n    ### ER Circuit ranks"
    Export-AddToFile "    { rank=same; $($script:rankercircuits -join '; ') }`n "
    Export-AddToFile -Data "`n    ### VPN Site ranks"
    Export-AddToFile "    { rank=same; $($script:rankvpnsites -join '; ') }`n "        
    Export-AddToFile -Data "`n    ### IP Groups ranks"
    Export-AddToFile "    { rank=max; $($script:rankipgroups -join '; ') }`n "        
}

function Export-dotFooter {
    Export-AddToFile -Data "}" #EOF
}

function Export-CreateFile {
    [CmdletBinding()]
    param([string]$Data)

    $Data | Out-File -Encoding ASCII $OutputPath\AzNetworkDiagram.dot
}

function Export-AddToFile {
    [CmdletBinding()]
    param([string]$Data)

    $Data | Out-File -Encoding ASCII -Append $OutputPath\AzNetworkDiagram.dot
}

function Export-AKSCluster {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Aks
    )

    try {
        # Check if ACR integration is enabled and which ACRs are attached
        #$Aks.IdentityProfile.kubeletidentity.ClientId
        $roleAssignments = Get-AzRoleAssignment -ObjectId $Aks.IdentityProfile.kubeletidentity.ObjectId -ErrorAction Stop

        # Filter for ACR-related role assignments
        $acrRoleAssignments = $roleAssignments | Where-Object { 
            $_.Scope -like "*/Microsoft.ContainerRegistry/registries/*" -and 
            ($_.RoleDefinitionName -eq "AcrPull" -or $_.RoleDefinitionName -eq "AcrPush")
        }

        # Display the linked ACRs
        if ($null -ne $acrRoleAssignments) {
            $aksacr = $acrRoleAssignments.Scope.split("/")[-1] 
            $aksacrid = $acrRoleAssignments.Scope.replace("-", "").replace("/", "").replace(".", "").ToLower()
        } else {
            $aksacr = "None"
            $aksacrid = ""
        }

        $aksid = $Aks.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $data = "
        # $($Aks.Name) - $aksid
        subgraph cluster_$aksid {
            style = solid;
            color = black;
            node [color = white;];
        "

        $data += "        $aksid [label = `"\nLocation: $($Aks.Location)\nVersion: $($Aks.KubernetesVersion)\nSKU Tier: $($Aks.Sku.Tier)\nPrivate Cluster: $($Aks.ApiServerAccessProfile.EnablePrivateCluster)\nDNS Service IP: $($Aks.DnsServiceIP)\nMax Agent Pools: $($Aks.MaxAgentPools)\nContainer Registry: $aksacr\nPod CIDR: $($Aks.NetworkProfile.PodCidr)\nService CIDR: $($Aks.NetworkProfile.ServiceCidr)\n`" ; color = lightgray;image = `"$OutputPath\icons\aks-service.png`";imagepos = `"tc`";labelloc = `"b`";height = 3.0;];"
        
        #$Aks.PrivateLinkResources.PrivateLinkServiceId

        foreach ($agentpool in $Aks.AgentPoolProfiles) {
            $agentpoolid = $aksid + $agentpool.Name.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $agentpoolsubnetid = $agentpool.VnetSubnetId.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "        $($agentpoolid) [label = `"\nName: $($agentpool.Name)\nMode: $($agentpool.Mode)\nZones: $($agentpool.AvailabilityZones)\nVM Size: $($agentpool.VmSize)\nMax Pods: $($agentpool.MaxPods)\nOS SKU: $($agentpool.OsSKU)\nAgent Pools: $($agentpool.MinCount) >= Pod Count <=  $($agentpool.MaxCount)\nEnable AutoScaling: $($agentpool.EnableAutoScaling)\nPublic IP: $($agentpool.EnableNodePublicIP)\n`" ; color = lightgray;image = `"$OutputPath\icons\aks-node-pool.png`";imagepos = `"tc`";labelloc = `"b`";height = 3.0;];`n" 
            $data += "        $agentpoolid -> $agentpoolsubnetid;`n"
            $data += "        $aksid -> $agentpoolid;`n"
        }
        $data += "`n"
        if ($aksacr -ne "None") {
            $data += "        $aksid -> $aksacrid;`n"
        }   
        $data += "   label = `"$($Aks.Name)`";
                }`n"
        Export-AddToFile -Data $data
    } catch {
        Write-Host "Can't export AKS Cluster: $($Aks.name)" $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of an Azure Application Gateway for inclusion in a network diagram.

.DESCRIPTION
The `Export-ApplicationGateway` function processes a specified Azure Application Gateway object, retrieves its details, and formats the data for inclusion in a network diagram. It visualizes the gateway's name, SKU, zones, SSL certificates, frontend IP configurations, and associated firewall policies.

.PARAMETER agw
Specifies the Azure Application Gateway object to be processed.

.EXAMPLE
PS> Export-ApplicationGateway -agw $applicationGateway

This example processes the specified Azure Application Gateway and exports its details for inclusion in a network diagram.

#>
function Export-ApplicationGateway {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$agw 
    )   
    
    try {
        $agwid = $agw.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $agwSubnetId = $agw.GatewayIPConfigurations.Subnet.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $data = "
        # $GatewayName - $agwid
        subgraph cluster_$agwid {
            style = solid;
            color = black;
            node [color = white;];
        "

        $skuname = $agw.Sku.Name
        if ($agw.SslCertificates) {
            $sslcerts = $agw.SslCertificates.Name -join ", "
        } else {
            $sslcerts = "None"
        }
        if ($agw.FrontendIPConfigurations.PrivateIPAddress) {
            $pvtips = $agw.FrontendIPConfigurations.PrivateIPAddress -join ", "
        } else {
            $pvtips = "None"
        }
        $polname = $agw.FirewallPolicy.Id.split("/")[-1]
        if ($agw.Zones) {
            $zones = $agw.Zones -join ","
        } else {
            $zones = "None"
        }
        if ($agw.FrontendPorts) {
            $feports = $agw.FrontendPorts.Port -join ", "
        } else {
            $feports = "None"
        }

        $data += "        $agwid [label = `"\nPolicy name: $polname\nPrivate IP's: $pvtips\nSKU: $skuname\nZones: $zones\nSSL Certificates: $sslcerts\nFrontend ports: $feports\n`" ; color = lightgray;image = `"$OutputPath\icons\agw.png`";imagepos = `"tc`";labelloc = `"b`";height = 3.0;];"
        $data += "`n"
        $data += "        $agwid -> $agwSubnetId;`n"
        $data += "   label = `"$GatewayName`";
                }`n"

        Export-AddToFile $data

    } catch {
        Write-Host "Can't export Application Gateway: $($agw.name)" $_.Exception.Message
    }
}
function Export-ACR {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$acr
    )   
    
    try {
        $acrid = $acr.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        
        $data = "
        # $($acr.Name) - $acrid
        subgraph cluster_$acrid {
            style = solid;
            color = black;
            node [color = white;];
        "


        $data += "        $acrid [label = `"\nName: $($acr.Name))\nLocation: $($acr.Location)\nSKU: $($acr.SkuName.ToString())\nZone Redundancy: $($acr.ZoneRedundancy.ToString())\nPublic Network Access: $($acr.PublicNetworkAccess.ToString())\n`" ; color = lightgray;image = `"$OutputPath\icons\acr.png`";imagepos = `"tc`";labelloc = `"b`";height = 2.5;];"
        $data += "`n"
        if ($acr.PrivateEndpointConnection.PrivateEndpointId) {
            $acrpeid = $acr.PrivateEndpointConnection.PrivateEndpointId.ToString().replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "        $acrid -> $($acrpeid);`n"
        }
        $data += "   label = `"$($acr.Name)`";
                }`n"

        Export-AddToFile $data

    } catch {
        Write-Host "Can't export ACR: $($acr.name)" $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of an Azure Firewall and its associated policies for inclusion in a network diagram.

.DESCRIPTION
The `Export-AzureFirewall` function processes a specified Azure Firewall object, retrieves its details, and formats the data for inclusion in a network diagram. It visualizes the firewall's name, private and public IP addresses, SKU tier, zones, and associated firewall policies, including DNS settings and IP groups.

.PARAMETER FirewallId
Specifies the unique identifier of the Azure Firewall to be processed.

.PARAMETER ResourceGroupName
Specifies the resource group of the Azure Firewall.

.EXAMPLE
PS> Export-AzureFirewall -FirewallId "/subscriptions/xxxx/resourceGroups/rg1/providers/Microsoft.Network/azureFirewalls/fw1" -ResourceGroupName "rg1"

This example processes the specified Azure Firewall and exports its details for inclusion in a network diagram.

#>
function Export-AzureFirewall {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$FirewallId,
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName
    )
                
    $azFWId = $FirewallId.replace("-", "").replace("/", "").replace(".", "").ToLower()
    $azFWName = $FirewallId.split("/")[-1]
    $azFW = Get-AzFirewall -ResourceGroupName $ResourceGroupName -Name $azFWName -ErrorAction Stop

    if ($azFW.IpConfigurations.count -gt 0) {
        # Standalone Azure Firewall
        $PrivateIPAddress = $azFW.IpConfigurations.PrivateIPAddress -join ""
        $ipConfigs = $azFW.IpConfigurations
        $PublicIPs = @()
        if ($ipConfigs) {
            foreach ($ipConfig in $ipConfigs) {
                $publicIpId = $ipConfig.PublicIpAddress.Id
                $publicIpName = $publicIpId.Split('/')[-1]
                $publicIpRG = $publicIpId.Split('/')[4]
                
                $PublicIps += (Get-AzPublicIpAddress -ResourceGroupName $publicIpRG -Name $publicIpName -ErrorAction Stop).IpAddress
            }
        }
    }
    else {
        # Hub Integrated Azure Firewall
        $PrivateIPAddress = $azFW.HubIPAddresses.PrivateIPAddress
        $PublicIPs = ""
        foreach ($publicIP in $azFW.HubIPAddresses.PublicIPs.Addresses) { $PublicIPs += ($publicIP.Address + "\n") }
    }
    $data = "`n"
    $data += "        $azFWId [label = `"\n\n$azFWName\nPrivate IP Address: $PrivateIPAddress\nSKU Tier: $($azfw.Sku.Tier)\nZones: $($azfw.zones -join "," )\nPublic IP(s):\n$($PublicIPs -join "\n")`" ; color = lightgray;image = `"$OutputPath\icons\afw.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 

    # Get the Azure Firewall policy
    $firewallPolicyName = $azfw.FirewallPolicy.id.split("/")[-1]
    $firewallPolicy = Get-AzFirewallPolicy -ResourceGroupName $ResourceGroupName -Name $firewallPolicyName -ErrorAction Stop
    $fwpolid = $firewallPolicy.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()

    $data += "`n"
    $data += "        $fwpolid [label = `"\n\n$firewallPolicyName\nSKU Tier: $($firewallPolicy.sku.tier)\nThreat Intel Mode: $($firewallPolicy.ThreatIntelMode)\nDNS Servers: $($firewallPolicy.DnsSettings.Servers -join '; ')\nProxy Enabled: $($firewallPolicy.DnsSettings.EnableProxy)`" ; color = lightgray;image = `"$OutputPath\icons\firewallpolicy.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 
    $data += "`n    $azFWId -> $fwpolid;"

    $index = $firewallPolicy.DnsSettings.Servers.IndexOf($script:PDNSREpIp)
    if ($index -ge 0) {
        $data += "        $fwpolid -> $script:PDNSRId [label = `"DNS Query`"; ];`n" 
    }
    
    # Initialize an array to store IP Group names
    $ipGroupIds = @()

    foreach ($ruleCollectionGroupId in $firewallPolicy.RuleCollectionGroups.Id) {
        $rcgName = $ruleCollectionGroupId.split("/")[-1]
        $rcg = Get-AzFirewallPolicyRuleCollectionGroup -Name $rcgName -AzureFirewallPolicy $firewallPolicy -ErrorAction Stop
        $ipGroupIds += $rcg.Properties.RuleCollection.rules.SourceIpGroups 
        $ipGroupIds += $rcg.Properties.RuleCollection.rules.DestinationIpGroups
    }

    # Remove duplicates and display the IP Group names
    $ipGroupIds = $ipGroupIds | Sort-Object -Unique
    $ipGroupIds = $ipGroupIds.replace("-", "").replace("/", "").replace(".", "").ToLower()
    foreach ($ipGroupId in $ipGroupIds) {
        $data += "`n    $fwpolid -> $ipGroupId;"
    }
    return $data
}

<#
.SYNOPSIS
Exports details of a Virtual WAN Hub for inclusion in a network diagram.

.DESCRIPTION
The `Export-Hub` function processes a specified Virtual WAN Hub object, retrieves its details, and formats the data for inclusion in a network diagram. It visualizes the hub's name, location, SKU, address prefix, routing preference, and associated resources such as VPN gateways, ExpressRoute gateways, and Azure Firewalls.

.PARAMETER hub
Specifies the Virtual WAN Hub object to be processed.

.EXAMPLE
PS> Export-Hub -hub $vwanHub

This example processes the specified Virtual WAN Hub and exports its details for inclusion in a network diagram.

#>
function Export-Hub {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$hub
    )
    $hubname = $hub.Name
    $id = $hub.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
    $location = $hub.Location
    $sku = $hub.Sku
    $AddressPrefix = $hub.AddressPrefix
    $HubRoutingPreference = $hub.HubRoutingPreference

    try {
        Write-Host "Exporting Hub: $hubname"
        # DOT
        # Hub details

        # Find out the Hub's own vNet
        if ($null -ne $hub.VirtualNetworkConnections) {
            $vnetname = ($hub.VirtualNetworkConnections[0].RemoteVirtualNetwork.id).Split("/")[-1]
            $vnetrg = ($hub.VirtualNetworkConnections[0].RemoteVirtualNetwork.id).Split("/")[4]
            $vnet = Get-AzVirtualNetwork -name $vnetname -ResourceGroupName $vnetrg -ErrorAction Stop
            $HubvNetID = $vnet.VirtualNetworkPeerings.RemoteVirtualNetwork.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $headid = $HubvNetID
            $script:AllInScopevNetIds += $vnet.VirtualNetworkPeerings.RemoteVirtualNetwork.id
            $data = "
            # $hubname - $id
            subgraph cluster_$headid {
                style = solid;
                color = black;
                node [color = white;];
            "
            $data += "        $HubvNetID [label = `"\n\n$hubname\nLocation: $location\nSKU: $sku\nAddress Prefix: $AddressPrefix\nHub Routing Preference: $HubRoutingPreference`" ; color = lightgray;image = `"$OutputPath\icons\vWAN-Hub.png`";imagepos = `"tc`";labelloc = `"b`";height = 2.5;];"
        } else {
            $data += "        $id [label = `"\n$hubname\nLocation: $location\nSKU: $sku\nAddress Prefix: $AddressPrefix\nHub Routing Preference: $HubRoutingPreference`" ; color = lightgray;image = `"$OutputPath\icons\vWAN-Hub.png`";imagepos = `"tc`";labelloc = `"b`";height = 2.5;];"
            $headid = $id
        }
        $script:rankvwanhubs += $headid

        # Hub Items

        if ($null -ne $hub.VpnGateway) {
            $vgwId = $hub.VpnGateway.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $vgwName = $hub.VpnGateway.id.split("/")[-1]
            $vpngw = Get-AzVpnGateway -ResourceGroupName $hub.ResourceGroupName -Name $vgwName -ErrorAction Stop

            $data += "`n"
            $data += "        $vgwId [label = `"\n\n$vgwName\nScale Units: $($vpngw.VpnGatewayScaleUnit)\nPublic IP(s):\n$($vpngw.IpConfigurations.PublicIpAddress -join ",")\n`" ; color = lightgray;image = `"$OutputPath\icons\vgw.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 
            $data += "`n    $headid -> $vgwId;"

            # Connections
            $VpnSites = Get-AzVPNSite -ResourceGroupName $hub.ResourceGroupName  -ErrorAction Stop | Where-Object { $_.VirtualWan.id -eq $hub.virtualwan.id }
            # Get the VPN connections from this gateway
            $vpnConnections = $vpngw.Connections

            #foreach ($VpnSite in $VpnSites) {
            foreach ($connection in $vpnConnections) {
                # Find which VPN site this connection is linked to
                $siteId = $connection.RemoteVpnSite.Id
                $vpnSite = $VpnSites | Where-Object { $_.Id -eq $siteId }
            
                if ($vpnSite) {
                    $vpnsiteId = $siteId.replace("-", "").replace("/", "").replace(".", "").ToLower()
                    $script:rankvpnsites += $vpnsiteId
                    $vpnsiteName = $VpnSite.Name
                    $data += "`n"
                    $data += "        $vpnsiteId [label = `"\n\n\n$vpnsiteName\nAddressPrefixes: $($VpnSite.AddressSpace.AddressPrefixes)\nDevice Vendor: $($VpnSite.DeviceProperties.DeviceVendor)\nLink Speed: $($VpnSite.VpnSiteLinks.LinkProperties.LinkSpeedInMbps) Mbps\nLinks: $($VpnSite.VpnSiteLinks.count)\n`" ; color = lightgray;image = `"$OutputPath\icons\VPN-Site.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 
                    $data += "`n    $vgwId -> $vpnsiteId;"
                }
            }
        }
        if ($null -ne $hub.ExpressRouteGateway) {
            $ergwId = $hub.ExpressRouteGateway.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $ergwName = $hub.ExpressRouteGateway.id.split("/")[-1]
            $ergw = Get-AzExpressRouteGateway -ResourceGroupName $hub.ResourceGroupName -Name $ergwName -ErrorAction Stop
            $data += "`n"
            $data += "        $ergwId [label = `"\n\n\n$ergwName\nAuto Scale Configuration: $($ergw.AutoScaleConfiguration.Bounds.min)-$($ergw.AutoScaleConfiguration.Bounds.max)`" ; color = lightgray;image = `"$OutputPath\icons\ergw.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 
            $data += "`n    $headid -> $ergwId;"
            $peerings = $ergw.ExpressRouteConnections.ExpressRouteCircuitPeering.id
            foreach ($peering in $peerings) {
                $peeringId = $peering.replace("-", "").replace("/", "").replace(".", "").replace("peeringsAzurePrivatePeering", "").ToLower()
                $data += "`n    $ergwId -> $peeringId ;"
            }
        }
        if ($null -ne $hub.P2SVpnGateway) {
            $p2sgwId = $hub.P2SVpnGateway.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $p2sgwName = $hub.P2SVpnGateway.id.split("/")[-1]
            $data += "`n"
            $data += "        $p2sgwId [label = `"\n\n\n$p2sgwName\n`" ; color = lightgray;image = `"$OutputPath\icons\ergw.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 
            $data += "`n    $headid -> $p2sgwId;"
        }
        if ($null -ne $hub.AzureFirewall) {
            $data += Export-AzureFirewall -FirewallId $hub.AzureFirewall.id -ResourceGroupName $hub.ResourceGroupName
            $azFWId = $hub.AzureFirewall.id.replace("-", "").replace("/", "").replace(".", "").ToLower()

            $data += "`n    $headid -> $azFWId;"
        }
        $vWANId = $hub.VirtualWAN.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $data += "`n    $vWANId -> $headid;"
        $footer = "
        label = `"$hubname`";
        }
        "
        $data += $footer

        return $data
    } catch {
        Write-Error "Can't export Hub: $($hub.name)" $_.Exception.Message
        return $null
    }
}

<#
.SYNOPSIS
Exports details of a Virtual Network Gateway for inclusion in a network diagram.

.DESCRIPTION
The `Export-VirtualGateway` function processes a specified Virtual Network Gateway object, retrieves its details, and formats the data for inclusion in a network diagram. It visualizes the gateway's name, type (VPN or ExpressRoute), and associated public IP addresses.

.PARAMETER GatewayName
Specifies the name of the Virtual Network Gateway to be processed.

.PARAMETER ResourceGroupName
Specifies the resource group of the Virtual Network Gateway.

.PARAMETER GatewayId
Specifies the unique identifier of the Virtual Network Gateway.

.PARAMETER HeadId
Specifies the identifier of the parent resource to which the gateway is connected.

.EXAMPLE
PS> Export-VirtualGateway -GatewayName "MyGateway" -ResourceGroupName "MyResourceGroup" -GatewayId "gateway123" -HeadId "vnet123"

This example processes the specified Virtual Network Gateway and exports its details for inclusion in a network diagram.

#>
function Export-VirtualGateway {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$GatewayName, 
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName, 
        [Parameter(Mandatory = $true)]
        [string]$GatewayId, 
        [Parameter(Mandatory = $true)]
        [string]$HeadId
    )   
    
    $gw = Get-AzVirtualNetworkGateway -ResourceGroupName $ResourceGroupName -ResourceName $GatewayName -ErrorAction Stop
    $gwtype = $gw.Gatewaytype

    # ER vs VPN GWs are handled differently
    if ($gwtype -eq "Vpn" ) {
        $gwipobjetcs = $gw.IpConfigurations.PublicIpAddress
        $gwips = ""
        $gwipobjetcs.id | ForEach-Object {
            $rgname = $_.split("/")[4]
            $ipname = $_.split("/")[8]
            $publicip = (Get-AzPublicIpAddress -ResourceName $ipname -ResourceGroupName $rgname -ErrorAction Stop).IpAddress
            $gwips += "$ipname : $publicip \n"
        
        }
        $data += "        $GatewayId [color = lightgray;label = `"\n\nName: $GatewayName`\n\nPublic IP(s):\n$gwips`";image = `"$OutputPath\icons\vgw.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];"
    }
    elseif ($gwtype -eq "ExpressRoute") {
        $data += "        $GatewayId [color = lightgray;label = `"\nName: $GatewayName`";image = `"$OutputPath\icons\ergw.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];"
    }
    $data += "`n"
    $data += "        $HeadId -> $GatewayId"
    $data += "`n"
}

<#
.SYNOPSIS
Exports details of a subnet configuration for inclusion in a network diagram.

.DESCRIPTION
The `Export-SubnetConfig` function processes a list of subnet objects, retrieves their details, and formats the data for inclusion in a network diagram. It visualizes subnet properties such as name, address prefix, associated NSGs, route tables, NAT gateways, and special configurations like Azure Firewall, Bastion, and Gateway subnets.

.PARAMETER subnets
Specifies the list of subnet objects to be processed.

.EXAMPLE
PS> Export-SubnetConfig -subnets $subnetList

This example processes the specified list of subnets and exports their details for inclusion in a network diagram.

#>
function Export-SubnetConfig {
    [CmdletBinding()]
    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [PSCustomObject[]] $subnets
    )

    try {
        $data = ""

        #Loop over subnets
        foreach ($subnet in $subnets) {
            $id = $subnet.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $name = $subnet.Name
            $AddressPrefix = $subnet.AddressPrefix
            $script:ranksubnets += $id

            # vNet      
            $vnetid = $subnet.id
            $vnetid = $vnetid -split "/subnets/"
            $vnetid = $vnetid[0].replace("-", "").replace("/", "").replace(".", "").ToLower()
            $nsgid = $null

            ##########################################
            ##### Special subnet characteristics #####
            ##########################################
                    
            ### NSG ###
            if ($null -ne $subnet.NetworkSecurityGroup) {
                $nsgname = $subnet.NetworkSecurityGroup.id.split("/")[8]
                $nsgid = $subnet.NetworkSecurityGroup.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
                if ($nsgid -ne "null") { 
                    $data += "`n        $nsgid [label = `"\n$nsgname`" ; color = lightgray;image = `"$OutputPath\icons\nsg.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 
                    $data += "`n        $id -> $nsgid`n"
                }
            }

            ### Route Table ###
            $routetableid = $subnet.RouteTableText.ToLower()
            if ($routetableid -ne "null" ) { $routetableid = (($subnet.RouteTableText | ConvertFrom-Json).id).replace("-", "").replace("/", "").replace(".", "").ToLower() }
            if ($routetableid -ne "null" ) { $data += "        $id -> $routetableid" + "`n" }
            # Moved route table association from just before NATGW

            ### Private subnet - ie. no default outbound internet access ###
            $subnetDefaultOutBoundAccess = $subnet.DefaultOutboundAccess #(false if activated)
            if ($subnetDefaultOutBoundAccess -eq $false ) { $name += " *" }


            ##############################################
            ##### Special subnet characteristics END #####
            ##############################################
            
            # Support for different types of subnets (AzFW, Bastion etc.)
            # DOT
            switch ($name) {
                "AzureFirewallSubnet" { 
                    if ($subnet.IpConfigurations.Id) {
                        $AzFWid = $subnet.IpConfigurations.Id.ToLower().split("/azurefirewallipconfigurations/ipconfig1")[0]
                        $AzFWname = $subnet.IpConfigurations.Id.split("/")[8]
                        $AzFWrg = $subnet.IpConfigurations.id.split("/")[4]

                        $data += "        $id [label = `"\n\n$name\n$AddressPrefix`" ; color = lightgray;image = `"$OutputPath\icons\afw.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 

                        $data += Export-AzureFirewall -FirewallId $AzFWid -ResourceGroupName $AzFWrg
                        $AzFWDotId = $AzFWid.replace("-", "").replace("/", "").replace(".", "").ToLower()
                        $data += "`n    $id -> $azFWDotId;"
                    }
                }
                "AzureBastionSubnet" { 
                    if ($subnet.IpConfigurations.Id) { 
                        $AzBastionName = $subnet.IpConfigurations.Id.split("/")[8].ToLower()
                    
                        $data += "        $id [label = `"\n\n$name\n$AddressPrefix\nName: $AzBastionName`" ; color = lightgray;image = `"$OutputPath\icons\bas.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 
                    }
                }
                "AppGatewaySubnet" { 
                    if ($subnet.IpConfigurations.Id) { 
                        $AppGatewayName = $subnet.IpConfigurations.Id.split("/")[8].ToLower()
                    
                        $data += "        $id [label = `"\n\n$name\n$AddressPrefix\nName: $AppGatewayName`" ; color = lightgray;image = `"$OutputPath\icons\agw.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 
                    }
                }
                "GatewaySubnet" { 
                    $data += "        $id [label = `"\n\n$name\n$AddressPrefix`" ; color = lightgray;image = `"$OutputPath\icons\vgw.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 
                    $data += "`n"
                    
                    #GW DOT
                    if ($subnet.IpConfigurations.Id) { 
                        $gwid = $subnet.IpConfigurations.Id.split("/ipConfigurations/vnetGatewayConfig")[0]
                        $gwname = $subnet.IpConfigurations.Id.split("/")[8].ToLower()
                        $gwrg = $subnet.IpConfigurations.Id.split("/")[4].ToLower()
                        Export-VirtualGateway -GatewayName $gwname -ResourceGroupName $gwrg -GatewayId $gwid -HeadId $id
                    }
                }
                default { 
                    ##### Subnet delegations #####
                    # Might be moved to subnet switch "default" ???
                    # Just change the icon, or maybe a line with "Delegation info" ?
                    $subnetDelegationName = $subnet.Delegations.Name
                    
                    if ( $null -ne $subnetDelegationName ) {
                        # Delegated

                        $iconname = ""
                        switch ($subnetDelegationName) {
                            "Microsoft.Web/serverFarms" { $iconname = "asp" }
                            "Microsoft.Sql/managedInstances" { $iconname = "sqlmi" } 
                            "Microsoft.Network/dnsResolvers" { $iconname = "dnspr" }
                            Default { $iconname = "snet" }
                        }
                        $data = $data + "        $id [label = `"\n\n$name\n$AddressPrefix\n\nDelegated to:\n$subnetDelegationName`" ; color = lightgray;image = `"$OutputPath\icons\$iconname.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 
                    }
                    else {
                        # No Delegation
                        $data = $data + "        $id [label = `"\n$name\n$AddressPrefix`" ; color = lightgray;image = `"$OutputPath\icons\snet.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 
                    }
                    $data += "`n"
                    foreach ($pe in $subnet.PrivateEndpoints) {
                        $peid = $pe.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
                        $data += "        $id -> $peid ;`n"
                    }
                }
            }
            $data += "`n"
            
            # DOT VNET->Subnet
            $data = $data + "        $vnetid -> $id"
            $data += "`n"
        
            #NATGW
            if ($subnet.NatGateway.count -gt 0 ) {
                #Define NAT GW
                $NATGWID = $subnet.NatGateway.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
                
                $name = $subnet.NatGateway.id.split("/")[8]
                $rg = $subnet.NatGateway.id.split("/")[4]
                $NATGWobject = Get-AzNatGateway -Name $name -ResourceGroupName $rg -ErrorAction Stop
                
                #Public IPs associated
                $ips = $NATGWobject.PublicIpAddresses
                $ipsstring = ""
                $ips.id | ForEach-Object {
                    $rgname = $_.split("/")[4]
                    $ipname = $_.split("/")[8]
                    $publicip = (Get-AzPublicIpAddress -ResourceName $ipname -ResourceGroupName $rgname -ErrorAction Stop).IpAddress
                    $ipsstring += "$ipname : $publicip \n"
                }

                #Public IP prefixes associated
                $ipprefixes = $NATGWobject.PublicIpPrefixes
                $ipprefixesstring = ""
                $ipprefixes.id | ForEach-Object {
                    $rgname = $_.split("/")[4]
                    $ipname = $_.split("/")[8]
                    $prefix = (Get-AzPublicIpPrefix -ResourceName $ipname -ResourceGroupName $rgname -ErrorAction Stop).IPPrefix
                    $ipprefixesstring += "$ipname : $prefix \n"
                }
            
                $data += "        $NATGWID [color = lightgrey;label = `"\n\nName: $name\n\nPublic IP(s):\n$ipsstring\nPublic IP Prefix(es):\n$ipprefixesstring`";image = `"$OutputPath\icons\ng.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];"
                $data += "        $id -> $NATGWID" + "`n"

            }
        }
    } catch {
        Write-Host "Can't export Subnet: $($subnet.name)" $_.Exception.Message
    }
    return $data
}

<#
.SYNOPSIS
Exports details of a virtual network (VNet) for inclusion in a network diagram.

.DESCRIPTION
The `Export-vnet` function processes a specified virtual network object, retrieves its details, and formats the data for inclusion in a network diagram. It visualizes the VNet's name, address spaces, subnets, associated private DNS resolvers, and other configurations.

.PARAMETER vnet
Specifies the virtual network object to be processed.

.EXAMPLE
PS> Export-vnet -vnet $vnet

This example processes the specified virtual network and exports its details for inclusion in a network diagram.

#>
function Export-vnet {
    [CmdletBinding()]
    param ([PSCustomObject[]]$vnet)

    try {
        $vnetname = $vnet.Name
        $id = $vnet.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $vnetAddressSpaces = $vnet.AddressSpace.AddressPrefixes
        $script:rankvnetaddressspaces += $id

        $header = "
        # $vnetname - $id
        subgraph cluster_$id {
            style = solid;
            color = black;
            node [color = white;];
        "

        # Convert addressSpace prefixes from array to string
        $vnetAddressSpacesString = ""
        $vnetAddressSpaces | ForEach-Object {
            $vnetAddressSpacesString = $vnetAddressSpacesString + $_ + "\n"
        }

        $vnetdata = "    $id [color = lightgray;label = `"\nAddress Space(s):\n$vnetAddressSpacesString`";image = `"$OutputPath\icons\vnet.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];`n"

        # Subnets
        if ($vnet.Subnets) {
            $subnetdata = Export-SubnetConfig $vnet.Subnets
        }
        # Retrieve all Private DNS Resolvers in a specific resource group
        $dnsResolvers = Get-AzDnsResolver -ResourceGroupName $vnet.resourceGroupName -VirtualNetworkName $vnet.name -ErrorAction Stop
        $dnsprdata = ""
        if ($dnsResolvers) {
            # Display details of each Private DNS Resolver
            foreach ($resolver in $dnsResolvers) {
                $resolverName = $resolver.Id.split("/")[-1]
                $inboundEp = (Get-AzDnsResolverInboundEndpoint -DnsResolverName $resolverName -ResourceGroupName $vnet.resourceGroupName -ErrorAction Stop)
                $outboundEp = (Get-AzDnsResolverOutboundEndpoint -DnsResolverName $resolverName -ResourceGroupName $vnet.resourceGroupName -ErrorAction Stop)
                $inboundEpIp = $inboundEp.IPConfiguration.PrivateIPAddress 
                $pdnsrId = $resolver.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
                $dnsFrs = Get-AzDnsForwardingRuleset -ResourceGroupName $vnet.ResourceGroupName -ErrorAction Stop | Where-Object { ($_.DnsResolverOutboundEndpoint).id -eq $outboundEp.id }
                
                if ($dnsFrs) {
                    # Retrieve and display Forwarding Rulesets associated with the resolver
                    $dnsFrsId = $dnsFrs.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
                    $frsRules = Get-AzDnsForwardingRulesetForwardingRule -DnsForwardingRulesetName $dnsFrs.name -ResourceGroupName $vnet.resourceGroupName -ErrorAction Stop

                    # DOT
                    $dnsprdata += "`n        subgraph cluster_$pdnsrId {
                        style = solid;
                        color = black;
                        node [color = white;];
                            
                        $pdnsrId [label = `"\n$($resolverName)\nInbound IP Address: $($inboundEpIp)`" ; color = lightgray;image = `"$OutputPath\icons\dnspr.png`";imagepos = `"tc`";labelloc = `"b`";height = 3.0;]; 
                        $pdnsrId [shape=none; label = <
                                        <TABLE border=`"1`" style=`"rounded`" align=`"left`">
                                        <TR><TD colspan=`"3`" border=`"0`">$($dnsFrs.Name)</TD></TR>
                                        <TR><TD>Name</TD><TD>Domain Name</TD><TD>Target DNS</TD></TR>
                    "

                    foreach ($rule in $frsRules) {
                        $dnsprdata += "                <TR><TD align=`"left`">$($rule.Name)</TD><TD align=`"left`">$($rule.DomainName)</TD><TD align=`"left`">$($rule.TargetDnsServer.IPAddress -join ', ')</TD></TR>`n"                    
                    }
                    # End table                     $pdnsrId -> $dnsFrsId;     

                    $dnsprdata += "</TABLE>>;
                            ];
                        label = `"$resolverName`";
                    }
                    "
                    $script:PDNSRepIP = $inboundEpIp
                    $script:PDNSRId = $pdnsrId
                }
            }
        }                            

        $footer = "
            label = `"$vnetname`";
        }
        "
        $alldata = $header + $vnetdata + $subnetdata + $footer + $dnsprdata
        Export-AddToFile -Data $alldata
    } catch {
        Write-Error "Can't export VNet: $($vnet.name)" $_.Exception.Message 
    }
}

<#
.SYNOPSIS
Exports details of a Virtual WAN (vWAN) for inclusion in a network diagram.

.DESCRIPTION
The `Export-vWAN` function processes a specified Virtual WAN object, retrieves its details, and formats the data for inclusion in a network diagram. It visualizes the vWAN's name, type, location, and associated hubs, along with their configurations.

.PARAMETER vwan
Specifies the Virtual WAN object to be processed.

.EXAMPLE
PS> Export-vWAN -vwan $vWAN

This example processes the specified Virtual WAN and exports its details for inclusion in a network diagram.

#>
function Export-vWAN {
    [CmdletBinding()]
    param ([PSCustomObject[]]$vwan)

    $vwanname = $vwan.Name
    $id = $vwan.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
    $VirtualWANType = $vwan.VirtualWANType
    $ResourceGroupName = $vwan.ResourceGroupName
    $AllowVnetToVnetTraffic = $vwan.AllowVnetToVnetTraffic
    $AllowBranchToBranchTraffic = $vwan.AllowBranchToBranchTraffic
    $Location = $vwan.Location

    try {
        Write-Host "Exporting vWAN: $vwanname"
        $script:rankvwans += $id
        $hubs = Get-AzVirtualHub -ResourceGroupName $ResourceGroupName -ErrorAction Stop | Where-Object { $($_.VirtualWAN.id) -eq $($vwan.id) }
        if ($null -ne $hubs) {
            $header = "
            # $vwanname - $id
            subgraph cluster_$id {
                style = solid;
                color = black;
                node [color = white;];
            "
        
            # Convert addressSpace prefixes from array to string
            $vWANDetails = "Virtual WAN Type: $VirtualWANType\nLocation: $Location\nAllow Vnet to Vnet Traffic: $AllowVnetToVnetTraffic\nAllow Branch to Branch Traffic: $AllowBranchToBranchTraffic"
            
            $vwandata = "    $id [color = lightgray;label = `"\n$vWANDetails`";image = `"$OutputPath\icons\vwan.png`";imagepos = `"tc`";labelloc = `"b`";height = 2.0;];`n"
        
            # Hubs
            $hubdata = ""
            foreach ($hub in $hubs) {
                $hubdata += Export-Hub -Hub $hub
            }
            $footer = "
                label = `"$vwanname`";
            }
            "
        
            $alldata = $header + $vwandata + $hubdata + $footer
            Export-AddToFile -Data $alldata
        }            
    } catch {
        Write-Error "Can't export Hub: $($hub.name)" $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of an ExpressRoute Circuit for inclusion in a network diagram.

.DESCRIPTION
The `Export-ExpressRouteCircuit` function processes a specified ExpressRoute Circuit object, retrieves its details, and formats the data for inclusion in a network diagram. It visualizes the circuit's name, SKU, bandwidth, provider, peering details, and associated ExpressRoute Direct ports if applicable.

.PARAMETER er
Specifies the ExpressRoute Circuit object to be processed.

.EXAMPLE
PS> Export-ExpressRouteCircuit -er $expressRouteCircuit

This example processes the specified ExpressRoute Circuit and exports its details for inclusion in a network diagram.

#>
function Export-ExpressRouteCircuit {
    [CmdletBinding()]
    param ([PSCustomObject[]]$er)

    $ername = $er.Name
    $ResourceGroupName = $er.ResourceGroupName
    $id = $er.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
    if ($er.ServiceProviderProperties) {
        $ServiceProviderName = $er.ServiceProviderProperties.ServiceProviderName
        $Peeringlocation = $er.ServiceProviderProperties.PeeringLocation
        $Bandwidth = $er.ServiceProviderProperties.BandwidthInMbps.ToString() + " Mbps"
        $BillingType = "N/A"
        $Encapsulation = "N/A"
    }
    else {
        # ExpressRoute Direct
        $erport = Get-AzExpressRoutePort -ResourceId $er.ExpressRoutePort.Id -ErrorAction Stop
        $erportid = $erport.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $erportname = $erport.Name.ToLower()
        $ServiceProviderName = "N/A"
        $Peeringlocation = $erport.PeeringLocation
        $Bandwidth = $erport.ProvisionedBandwidthInGbps.ToString() + " Gbps"
        $BillingType = $erport.BillingType
        $Encapsulation = $er.Encapsulation

        $erportdata = "
        # $erportname - $erportid
        subgraph cluster_$erportid {
            style = solid;
            color = black;
            node [color = white;];
    
            $erportid [label = `"\n$erportname`" ; color = lightgray;image = `"$OutputPath\icons\erport.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];
        "
        foreach ($link in $erport.Links) { 
            $linkid = $link.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $linkname = $link.Name.ToLower()
            if ($link.MacSecConfig.SciState -eq "Enabled") {
                $macsec = "Enabled"
            }
            else {
                $macsec = "Disabled"
            }

            $erportdata += "
                            $linkid [shape = none;label = <
                                <TABLE border=`"1`" style=`"rounded`" align=`"left`">
                                <tr><td colspan=`"2`" border=`"0`">$linkname</td></tr>
                                <tr><td>Router Name</td><td>$($link.RouterName)</td></tr>
                                <tr><td>Interface Name</td><td>$($link.InterfaceName)</td></tr>
                                <tr><td>Patch Panel Id</td><td>$($link.PatchPanelId)</td></tr>
                                <tr><td>Rack Id</td><td>$($link.RackId)</td></tr>
                                <tr><td>Connector Type</td><td>$($link.ConnectorType)</td></tr>
                                <tr><td>MACSEC</td><td>$macsec</td></tr>
                                </TABLE>>;
                                ];
                            $erportid -> $linkid;
            "
        }
        $erportdata += "
            label = `"$erportname`";
            }
            $id -> $erportid;
        "
        Export-AddToFile -Data $erportdata
    }
    $skuTier = $er.sku.tier
    $skuFamily = $er.sku.family

    $header = "
    # $ername - $id
    subgraph cluster_$id {
        style = solid;
        color = black;
        node [color = white;];

        $id [label = `"\n$ername`" ; color = lightgray;image = `"$OutputPath\icons\ercircuit.png`";imagepos = `"tc`";labelloc = `"b`";height = 3.5;];
        $id [shape = none;label = <
            <TABLE border=`"1`" style=`"rounded`">
            <tr><td>SKU Tier</td><td>$skuTier</td></tr>
            <tr><td>SKU Family</td><td>$skuFamily</td></tr>
            <tr><td>Billing Type</td><td>$BillingType</td></tr>
            <tr><td>Provider</td><td>$ServiceProviderName</td></tr>
            <tr><td>Location</td><td>$Peeringlocation</td></tr>
            <tr><td>Bandwidth</td><td>$Bandwidth</td></tr>
            <tr><td>Encapsulation</td><td>$Encapsulation</td></tr>
    "
    $script:rankercircuits += $id
    # End table
    $header = $header + "</TABLE>>;
            ];
            label = `"$ername`";
        }
    "

    # Express Route Circuit Peerings
    $PeeringData = ""
    $erPeerings = $er.Peerings
    foreach ($peering in $erPeerings) {
        $peeringName = $peering.Name
        $peeringId = $peering.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $peeringType = $peering.PeeringType
        $AzureASN = $peering.AzureASN
        $PeerASN = $peering.PeerASN
        $PrimaryPeerAddressPrefix = $peering.PrimaryPeerAddressPrefix
        $SecondaryPeerAddressPrefix = $peering.SecondaryPeerAddressPrefix
        $VlanId = $peering.VlanId

        # DOT
        $PeeringData = $PeeringData + "
            # $peeringName - $peeringId
            subgraph cluster_$peeringId {
                style = solid;
                color = black;
                node [color = white;];
        
                $peeringId [label = `"\n$peeringName`" ; color = lightgray;image = `"$OutputPath\icons\peerings.png`";imagepos = `"tc`";labelloc = `"b`";height = 2.5;];
                $peeringId [shape = none;label = <
                    <TABLE border=`"1`" style=`"rounded`" align=`"left`">
                    <tr><td>Peering Type</td><td COLSPAN=`"2`">$peeringType</td></tr>
                    <tr><td>Address Prefixes</td><td>$PrimaryPeerAddressPrefix</td><td>$SecondaryPeerAddressPrefix</td></tr>
                    <tr><td>ASN Azure/Peer</td><td>$AzureASN</td><td>$PeerASN</td></tr>
                    <tr><td>VlanId</td><td colspan=`"2`">$VlanId</td></tr>
                    </TABLE>>;
                    ];

                $id -> $peeringId [ltail = cluster_$id; lhead = cluster_$peeringId;];

                label = `"$peeringName`";
            }
            "
    }
    $footer = ""
    $alldata = $header + $PeeringData + $footer
    Export-AddToFile -Data $alldata
}

<#
.SYNOPSIS
Exports details of a route table for inclusion in a network diagram.

.DESCRIPTION
The `Export-RouteTable` function processes a specified route table object, retrieves its routes, and formats the data for inclusion in a network diagram. It visualizes the route table name, address prefixes, next hop types, and next hop IP addresses.

.PARAMETER routetable
Specifies the route table object to be processed.

.EXAMPLE
PS> Export-RouteTable -routetable $routeTable

This example processes the specified route table and exports its details for inclusion in a network diagram.

#>
function Export-RouteTable {
    [CmdletBinding()]
    param ([PSCustomObject[]]$routetable)

    $routetableName = $routetable.Name
    $id = $routetable.id.replace("-", "").replace("/", "").replace(".", "").ToLower()

    $script:rankrts += $id

    $header = "
    subgraph cluster_$id {
        style = solid;
        color = black;
        
        $id [shape = none;label = <
            <TABLE border=`"1`" style=`"rounded`">
            <TR><TD colspan=`"3`" border=`"0`">$routetableName</TD></TR>
            <TR><TD>Route</TD><TD>NextHopType</TD><TD>NextHopIpAddress</TD></TR>
            "
    
    # Individual Routes        
    $data = ""
    $routetable.Routes | ForEach-Object {
        $route = $_
        $addressprefix = $route.AddressPrefix
        $nexthoptype = $route.NextHopType
        $nexthopip = $route.NextHopIpAddress
        $data = $data + "<TR><TD>$addressprefix</TD><TD>$nexthoptype</TD><TD>$nexthopip</TD></TR>"
    }

    # End table
    $footer = "
            </TABLE>>;
            ];
    }
            "
    $alldata = $header + $data + $footer
    Export-AddToFile -Data $alldata
}

<#
.SYNOPSIS
Exports details of an IP Group for inclusion in a network diagram.

.DESCRIPTION
The `Export-IpGroup` function processes a specified IP Group object, retrieves its details, and formats the data for inclusion in a network diagram. It visualizes the IP Group name and associated IP addresses.

.PARAMETER IpGroup
Specifies the IP Group object to be processed.

.EXAMPLE
PS> Export-IpGroup -IpGroup $ipGroup

This example processes the specified IP Group and exports its details for inclusion in a network diagram.

#>
function Export-IpGroup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$IpGroup
    )

    $id = $ipGroup.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
    $script:rankipgroups += $id

    $alldata = "
    subgraph cluster_$id {
        style = solid;
        color = black;
        
        $id [label = `"\n$($ipGroup.Name)\n$($ipGroup.IpAddresses -join '\n')`" ; color = lightgray;image = `"$OutputPath\icons\ipgroup.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];
    }
    "
    Export-AddToFile -Data $alldata
}

<#
.SYNOPSIS
Exports details of a VPN connection and its associated gateways.

.DESCRIPTION
The `Export-VPNConnection` function processes a specified VPN connection object, retrieves details about the associated virtual network gateway or local network gateway, and formats the data for inclusion in a network diagram. It visualizes the connection type, peer information, and static remote subnets if applicable.

.PARAMETER connection
Specifies the VPN connection object to be processed.

.EXAMPLE
PS> Export-VPNConnection -connection $vpnConnection

This example processes the specified VPN connection and exports its details for inclusion in a network diagram.

#>
function Export-VPNConnection {
    [CmdletBinding()]
    param ([PSCustomObject[]]$connection)

    $name = $connection.Name
    $lgwconnectionname = $name
    $lgconnectionType = $connection.ConnectionType

    if ($connection.VirtualNetworkGateway1) {
        $lgwname = $connection.VirtualNetworkGateway1.id.split("/")[-1]
        $vpngwid = $connection.VirtualNetworkGateway1.id.replace("-", "").replace("/", "").replace(".", "").replace("`"", "").ToLower()
        $data = "    $vpngwid [color = lightgrey;label = `"\n\nLocal GW: $lgwname\nConnection Name: $lgwconnectionname\nConnection Type: $lgconnectionType\n`""
        $lgwid = 0
    }
    else {
        $vpngwid = 0

        if ($connection.LocalNetworkGateway2) {
            $lgwid = $connection.LocalNetworkGateway2.id.replace("-", "").replace("/", "").replace(".", "").replace("`"", "").ToLower()
            $lgwname = $connection.LocalNetworkGateway2.id.split("/")[-1]
            $lgwrg = $connection.LocalNetworkGateway2.id.split("/")[4]
            $lgwobject = (Get-AzLocalNetworkGateway -ResourceGroupName $lgwrg -name $lgwname -ErrorAction Stop)
            $lgwip = $lgwobject.GatewayIpAddress
            $lgwsubnetsarray = $lgwobject.addressSpaceText | ConvertFrom-Json
            $lgwsubnets = ""
            $lgwsubnetsarray.AddressPrefixes | ForEach-Object {
                $prefix = $_
                $lgwsubnets += "$prefix \n"
            }
        }
        elseif ($connection.VirtualNetworkGateway2) {
            $lgwid = $connection.VirtualNetworkGateway2.id.replace("-", "").replace("/", "").replace("`"", "").ToLower()
            $lgwname = $connection.VirtualNetworkGateway2.id.split("/")[-1]
        } else {
            $lgwid = 0
        }
        $data = "    $lgwid [color = lightgrey;label = `"\n\nGateway: $lgwname\nConnection Name: $lgwconnectionname\nConnection Type: $lgconnectionType\n`""
        if ($connection.LocalNetworkGateway2) {
            $data += "Peer IP:$lgwip\n\nStatic remote subnet(s):\n$lgwsubnets`";"
        }
    }

    #DOT
    $data += ";image = `"$OutputPath\icons\VPN-Site.png`";imagepos = `"tc`";labelloc = `"b`";height = 2.0;];"

    if ($connection.Peer -and $vpngwid -ne 0) {
        $peerid = $connection.Peer.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $data += "`n    $vpngwid -> $peerid`n"
    } elseif ($lgwid -ne 0 -and $vpngwid -ne 0) {
        $data += "`n    $vpngwid -> $lgwid`n"
    } else {
        $data += "`n"
    }
    Export-AddToFile -Data $data
}

<#
.SYNOPSIS
Exports details of a Private Endpoint and its associated Private Link Service connections.

.DESCRIPTION
The `Export-PrivateEndpoint` function retrieves information about a specified Private Endpoint, including its name and associated Private Link Service connections. It formats the data for inclusion in a network diagram, displaying the Private Endpoint's details and connections visually.

.PARAMETER pe
Specifies the Private Endpoint object to be processed.

.EXAMPLE
PS> Export-PrivateEndpoint -pe $privateEndpoint

This example processes the specified Private Endpoint and exports its details for inclusion in a network diagram.

#>
function Export-PrivateEndpoint {
    [CmdletBinding()]
    param ([PSCustomObject]$pe)

    try {
        # Get the private link service connection information
        $connections = @()
        $peid = $pe.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        
        # Check for standard service connections
        if ($pe.PrivateLinkServiceConnections) {
            $connections += $pe.PrivateLinkServiceConnections
        }
        
        # Check for manual service connections
        if ($pe.ManualPrivateLinkServiceConnections) {
            $connections += $pe.ManualPrivateLinkServiceConnections
        }
        $pedetails = $pe.name + "\n"
        # Process each connection for this private endpoint
        foreach ($connection in $connections) {
            $pedetails += $connection.PrivateLinkServiceId.Split('/')[-1] + "\n"
        }
        
        $data = "`n                     $peid [label = `"\n$pedetails`" ; color = lightgray;image = `"$OutputPath\icons\private-endpoint.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 
        Export-AddToFile -Data $data
    } catch {
        Write-Error "Can't export Private Endpoint: $($pe.Name)" $_.Exception.Message
    }
}

<#
.SYNOPSIS
Confirms that all prerequisites are met for generating the Azure network diagram.

.DESCRIPTION
The `Confirm-Prerequisites` function ensures that all required tools, modules, and configurations are in place before generating the Azure network diagram. It verifies the presence of Graphviz (`dot.exe`), required PowerShell modules (`Az.Network` and `Az.Accounts`), Azure authentication, and necessary icons for the diagram. If any prerequisites are missing, it provides guidance for resolving the issues.

#>
function Confirm-Prerequisites {
    [CmdletBinding()]
    $ErrorActionPreference = 'Stop'

    if (! (Test-Path $OutputPath)) {}

    # dot.exe executable
    try {
        $dot = (get-command dot.exe).Path
        if ($null -eq $dot) {
            Write-Error "dot.exe executable not found - please install Graphiz (https://graphviz.org), and/or ensure `"dot.exe`" is in `"`$PATH`" !"
        }
    } catch {
        Write-Error "dot.exe executable not found - please install Graphiz (https://graphviz.org), and/or ensure `"dot.exe`" is in `"`$PATH`" !"
    }
    
    # Load Powershell modules
    try {
        import-module az.network -DisableNameChecking
        import-module az.accounts
    } catch {
        Write-Output "Please install the following PowerShell modules, using install-module: Az.Network + Az.Accounts"
        Write-Output ""
        Write-Output "Ie:"
        Write-Output "Install-Module Az.Accounts"
        Write-Error "Install-Module Az.Network"
    }


    # Azure authentication verification
    $context = Get-AzContext  -ErrorAction Stop
    if ($null -eq $context) { 
        Write-Output "Please make sure you are logged in to Azure using Login-AzAccount, and that permissions are granted to resources within scope."
        Write-Output "A login window should appear - hint: they may hide behind active windows!"
        Login-AzAccount
    }

    # Icons available?
    if (! (Test-Path "$OutputPath\icons") ) { Write-Output "Downloading icons to $OutputPath\icons\ ... " ; New-Item -Path "$OutputPath" -Name "icons" -ItemType "directory" | Out-null }
    $icons = @(
        "acr.png",
        "afw.png",
        "agw.png",
        "aks-service.png",
        "aks-node-pool.png",
        "firewallpolicy.png",
        "asp.png",
        "bas.png",
        "Connections.png",
        "ercircuit.png",
        "erport.png",
        "peerings.png",
        "private-endpoint.png",
        "dnspr.png",
        "ergw.png",
        "lgw.png",
        "ipgroup.png",
        "LICENSE",
        "ng.png",
        "snet.png",
        "sqlmi.png",
        "vgw.png",
        "vnet.png",
        "VPN-Site.png",
        "VPN-User.png",
        "vWAN.png",
        "vWAN-Hub.png"
    )
    
    $icons | ForEach-Object {
        if (! (Test-Path "$OutputPath\icons\$_") ) { Invoke-WebRequest "https://github.com/dan-madsen/AzNetworkDiagram/raw/refs/heads/main/icons/$_" -OutFile "$OutputPath\icons\$_" }
    }
}

<#
.SYNOPSIS
Generates a detailed network diagram of Azure resources for specified subscriptions.

.DESCRIPTION
The `Get-AzNetworkDiagram` function collects and visualizes Azure networking resources, including VNets, subnets, firewalls, gateways, Virtual WANs, ExpressRoute circuits, private endpoints, and more. It uses Graphviz to create a DOT-based diagram and outputs it in PDF, PNG, and SVG formats. The diagram includes relationships and dependencies between resources, providing a comprehensive view of the Azure network infrastructure.

.PARAMETER OutputPath
Specifies the directory where the output files (DOT, PDF, PNG, SVG) will be saved. Defaults to the current working directory.

.PARAMETER Subscriptions
A list of Azure subscription IDs to include in the diagram. If not specified, all accessible subscriptions are used.

.PARAMETER EnableRanking
Enables ranking of certain resource types in the diagram for better visualization. Defaults to `$true`.

.PARAMETER TenantId
Specifies the Azure tenant ID to scope the subscriptions. If not provided, the default tenant is used.

.EXAMPLE
PS> Get-AzNetworkDiagram -Subscriptions "subid1","subid2" -OutputPath "C:\Diagrams" -EnableRanking $true

#>
function Get-AzNetworkDiagram {
    [CmdletBinding()]
    # Parameters
    param (
        [Parameter(Mandatory = $false)] [string]$OutputPath = $pwd,
        [Parameter(Mandatory = $false)] [string[]]$Subscriptions,
        [Parameter(Mandatory = $false)] [bool]$EnableRanking = $true,
        [Parameter(Mandatory = $false)] [string]$TenantId = $null,
        [Parameter(Mandatory = $false)] [bool]$OnlyCoreNetwork = $false
    )

    # Remove trailing "\" from path
    $OutputPath = $OutputPath.TrimEnd('\')

    Write-Output "Checking prerequisites ..."
    Confirm-Prerequisites

    ##### Global runtime vars #####
    #Rank (visual) in diagram
    $script:rankrts = @()
    $script:ranksubnets = @()
    $script:rankvnetaddressspaces = @()
    $script:rankvwans = @()
    $script:rankvwanhubs = @()
    $script:rankercircuits = @()
    $script:rankvpnsites = @()
    $script:rankipgroups = @()
    $script:PDNSREpIp = $null
    $script:PDNSRId = $null
    $script:AllInScopevNetIds = @()

    ##### Data collection / Execution #####

    # Run program and collect data through powershell commands
    Export-dotHeader

    # Set subscriptions to every accessible subscription, if unset
    try {
        if ($TenantId) {
            if ( $null -eq $Subscriptions ) { $Subscriptions = (Get-AzSubscription -TenantId $TenantId -ErrorAction Stop | Where-Object -Property State -eq "Enabled").Id }
        } else {
            if ( $null -eq $Subscriptions ) { $Subscriptions = (Get-AzSubscription -ErrorAction Stop | Where-Object -Property State -eq "Enabled").Id }
        }
    } catch {
        Write-Error "No available subscriptions within active AzContext - missing permissions? " $_.Exception.Message
        return
    } 
    
    Write-Output "Gathering information ..."

    try {
        # Collect all vNet ID's in scope otherwise we can end up with 1 vNet peered to 1000 other vNets which are not in scope
        # Errors will appear like: dot: graph is too large for cairo-renderer bitmaps. Scaling by 0.324583 to fit

        $Subscriptions | ForEach-Object {
            # Set Context
            $subid = $_
            if ($TenantId) {
                $context = Set-AzContext -Subscription $subid -Tenant $TenantId -ErrorAction Stop
            }
            else {
                $context = Set-AzContext -Subscription $subid -ErrorAction Stop
            }
            $subname = $context.Subscription.Name
            Write-Output "`nCollecting data from subscription: $subname ($subid)"
            Export-AddToFile "`n    ##########################################################################################################"
            Export-AddToFile "    ##### $subname "
            Export-AddToFile "    ##########################################################################################################`n"

            ### RTs
            Write-Output "Collecting Route Tables..."
            Export-AddToFile "    ##### $subname - Route Tables #####"
            $routetables = Get-AzRouteTable -ErrorAction Stop | Where-Object { ($_.SubnetsText -ne "[]") }
            $routetables | ForEach-Object {
                $routetable = $_
                Export-RouteTable $routetable
            }

            ### Ip Groups
            Write-Output "Collecting IP Groups..."
            Export-AddToFile "    ##### $subname - IP Groups #####"
            $ipGroups = Get-AzIpGroup -ErrorAction Stop
            if ($null -ne $ipGroups) {
                $cluster = "subgraph cluster_ipgroups {
                    style = solid;
                    color = black;
                "
                Export-AddToFile -Data $cluster
                $ipGroups | ForEach-Object {
                    $ipGroup = $_
                    Export-IpGroup -IpGroup $ipGroup
                }
                $footer = "
                    label = `"IP Groups`";
                }"
                Export-AddToFile -Data $footer
            }

            ### vNets (incl. subnets)
            Write-Output "Collecting vNets..."
            Export-AddToFile "    ##### $subname - Virtual Networks #####"
            $vnets = Get-AzVirtualNetwork -ErrorAction Stop
            if ($null -ne $vnets.id) {
                $script:AllInScopevNetIds += $vnets.id

                $vnets | ForEach-Object {
                    $vnet = $_
                    Export-vnet $vnet
                }
            }

            ### Private Endpoints
            if ( -not $OnlyCoreNetwork ) {
                # Get all private endpoints in the subscription
                $privateEndpoints = Get-AzPrivateEndpoint

                # Display results in a table format
                $results = @()
                foreach ($pe in $privateEndpoints) {
                    Export-PrivateEndpoint $pe
                }
            }

            # Application Gateways
            if ( -not $OnlyCoreNetwork ) {
                Write-Output "Collecting Application Gateways..."
                Export-AddToFile "    ##### $subname - Application Gateways #####"
                $agws = Get-AzApplicationGateway -ErrorAction Stop
                foreach ($agw in $agws) {
                    Export-ApplicationGateway $agw
                }
            }
        
            #Express Route Circuits
            Write-Output "Collecting Express Route Circuits..."
            Export-AddToFile "    ##### $subname - Express Route Circuits #####"
            $er = Get-AzExpressRouteCircuit -ErrorAction Stop
            $er | ForEach-Object {
                $er = $_
                Export-ExpressRouteCircuit $er
            }

            #Virtual WANs
            Write-Output "Collecting vWANs..."
            Export-AddToFile "    ##### $subname - Virtual WANs #####"
            $vWANs = Get-AzVirtualWan -ErrorAction Stop
            $vWANs | ForEach-Object {
                $vWAN = $_
                Export-vWAN $vWAN
            }

            #ACRs
            if ( -not $OnlyCoreNetwork ) {
                Write-Output "Collecting Azure Contiainer Registries..."
                Export-AddToFile "    ##### $subname - Azure Contiainer Registries #####"
                $acrs = Get-AzContainerRegistry -ErrorAction Stop
                foreach ($acr in $acrs) {
                    Export-ACR $acr
                }   
            }

            #AKS
            if ( -not $OnlyCoreNetwork ) {
                Write-Output "Collecting AKS Clusters..."
                Export-AddToFile "    ##### $subname - AKS Clusters #####"
                $aksclusters = Get-AzAksCluster -ErrorAction Stop
                foreach ($akscluster in $aksclusters) {
                    Export-AKSCluster $akscluster
                }   
            }

            #VPN Connections
            Write-Output "Collecting VPN Connections..."
            Export-AddToFile "    ##### $subname - VPN Connections #####"
            $VPNConnections = Get-AzResource | Where-Object { $_.ResourceType -eq "Microsoft.Network/connections" }
            $VPNConnections | ForEach-Object {
                $connection = $_
                $resname = $connection.Name
                $rgname = $connection.ResourceGroupName
                $connection = Get-AzVirtualNetworkGatewayConnection -name $resname -ResourceGroupName $rgname -ErrorAction Stop
                Export-VPNConnection $connection
            }

            Export-AddToFile "`n    ##########################################################################################################"
            Export-AddToFile "    ##### $subname "
            Export-AddToFile "    ##### END"
            Export-AddToFile "    ##########################################################################################################`n"
        }
        
        # vNet Peerings
        Write-Output "`nConnecting in-scope peered vNets..."
        foreach ($InScopevNetId in $script:AllInScopevNetIds) {
            $vnetname = $InScopevNetId.split("/")[-1]
            $vnetsub = $InScopevNetId.split("/")[2]
            $vnetrg = $InScopevNetId.split("/")[4]
            #
            # The Hub is in another "managed" subscription, so we cannot use the context of that subscription
            # So we're filtering it out here. We do't have access to it.
            #
            if ($Subscriptions.IndexOf($vnetsub) -ge 0) {
                if ($TenantId) {
                    $context = Set-AzContext -Subscription $vnetsub -Tenant $TenantId -ErrorAction Stop
                }
                else {
                    $context = Set-AzContext -Subscription $vnetsub -ErrorAction Stop
                }
                $vnet = Get-AzVirtualNetwork -name $vnetname -ResourceGroupName $vnetrg -ErrorAction Stop
                $vnetId = $vnet.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
                $vnetPeerings = $vnet.VirtualNetworkPeerings.RemoteVirtualNetwork.id
                foreach ($peering in $vnetPeerings) {
                    if ($script:AllInScopevNetIds.IndexOf($peering) -ge 0) {
                        $peeringId = $peering.replace("-", "").replace("/", "").replace(".", "").ToLower()
                        # DOT
                        $data = "    $vnetId -> $peeringId [ltail = cluster_$vnetId; lhead = cluster_$peeringId; weight = 10;];"

                        Export-AddToFile -Data $data
                    }
                }
            }
        }
    } catch {
        Write-Error "Error while collecting data from subscription: $subid" $_.Exception.Message
        return
    }
    if ( $EnableRanking ) { Export-dotFooterRanking }
    Export-dotFooter

    ##### Generate diagram #####
    # Generate diagram using Graphviz
    Write-Output "`nGenerating $OutputPath\AzNetworkDiagram.pdf ..."
    dot -Tpdf $OutputPath\AzNetworkDiagram.dot -o $OutputPath\AzNetworkDiagram.pdf
    Write-Output "Generating $OutputPath\AzNetworkDiagram.png ..."
    dot -Tpng $OutputPath\AzNetworkDiagram.dot -o $OutputPath\AzNetworkDiagram.png
    Write-Output "Generating $OutputPath\AzNetworkDiagram.svg ..."
    dot -Tsvg $OutputPath\AzNetworkDiagram.dot -o $OutputPath\AzNetworkDiagram.svg
} 

Export-ModuleMember -Function Get-AzNetworkDiagram
