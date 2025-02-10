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

##### Global runtime vars #####
#Rank (visual) in diagram
$global:rankrts = @()
#$global:ranksubnets = @()
$global:rankvnetaddressspaces = @()


##### Functions for standard definitions #####
function Export-dotHeader {
    $Data = "digraph G {
    fontname=`"Arial,sans-serif`"
    node [fontname=`"Arial,sans-serif`"]
    edge [fontname=`"Arial,sans-serif`"]
    
    # Ability fot peerings arrows/connections to end at border
    compound = true;
    
    # Rank (height in picture) support
    newrank = true;
    rankdir = TB;
    "
    Export-CreateFile -Data $Data
}

function Export-dotFooterRanking {
    Export-AddToFile -Data "`n    ##########################################################################################################"
    Export-AddToFile -Data "    ##### RANKS"
    Export-AddToFile -Data "    ##########################################################################################################`n"
    Export-AddToFile -Data "    ### AddressSpace ranks"
    $rankvnetaddressspacesdata = "    { rank=same; "
    
    $global:rankvnetaddressspaces | ForEach-Object {
        $vnetaddresspacename = $_
        $rankvnetaddressspacesdata += $vnetaddresspacename + "; ";
    }

    Export-AddToFile -Data "$rankvnetaddressspacesdata }"

    Export-AddToFile -Data "`n    ### Subnets ranks (TODO!)"
    Export-AddToFile -Data "`n    ### Route table ranks"
    $rankroutedata = "    { rank=same; "
    
    $rankrts | ForEach-Object {
        $routename = $_
        $rankroutedata += $routename + "; ";
    }
    Export-AddToFile -Data "$rankroutedata }"
}

function Export-dotFooter {
    Export-AddToFile -Data "}" #EOF
}

function Export-CreateFile {
    param([string]$Data)
    $Data | Out-File -Encoding ASCII $OutputPath\AzNetworkDiagram.dot
}

function Export-AddToFile {
    param([string]$Data)
    $Data | Out-File -Encoding ASCII  -Append $OutputPath\AzNetworkDiagram.dot
}

function Export-SubnetConfig {
    Param
    (
        [Parameter(Mandatory = $true, Position = 0)]
        [PSCustomObject[]] $subnetconfig
    )

    $data = ""

    #Loop over subnets
    $subnetconfig | ForEach-Object {
        $subnetconfigobject = $_
        $id = $_.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $name = $_.Name
        $AddressPrefix = $_.AddressPrefix

        # vNet      
        $vnetid = $_.id
        $vnetid = $vnetid -split "/subnets/"
        $vnetid = $vnetid[0].replace("-", "").replace("/", "").replace(".", "").ToLower()
     
        ##########################################
        ##### Special subnet characteristics #####
        ##########################################
                
        ### NSG ###
        $nsgid = $_.NetworkSecurityGroupText.ToLower()
        if ($nsgid -ne "null") { $nsgid = ($_.NetworkSecurityGroupText | ConvertFrom-Json).id.replace("-", "").replace("/", "").replace(".", "").ToLower() }
        if ($nsgid -ne "null") { $name += " #" }
        
        ### Route Table ###
        $routetableid = $_.RouteTableText.ToLower()
        if ($routetableid -ne "null" ) { $routetableid = (($_.RouteTableText | ConvertFrom-Json).id).replace("-", "").replace("/", "").replace(".", "").ToLower() }
        if ($routetableid -ne "null" ) { $data += "        $id -> $routetableid" + "`n" }
        # Moved route table association from just before NATGW

        ### Private subnet - ie. no default outbound internet access ###
        $subnetDefaultOutBoundAccess = $subnetconfigobject.DefaultOutboundAccess #(false if activated)
        if ($subnetDefaultOutBoundAccess -eq $false ) { $name += " *" }


        ##############################################
        ##### Special subnet characteristics END #####
        ##############################################
        
        # Support for different types of subnets (AzFW, Bastion etc.)
        # DOT
        switch ($name) {
            "AzureFirewallSubnet" { 
                $AzFW = $subnetconfigobject.IpConfigurationsText | ConvertFrom-Json
                if ($AzFW -ne "[]") {
                    $AzFWid = (($AzFW.id -split ("/azureFirewallIpConfigurations/"))[0]).replace("-", "").replace("/", "").replace(".", "").ToLower()
                    $AzFWname = $AzFW.id.split("/")[8].ToLower()
                    $AzFWrg = $AzFW.id.split("/")[4]
                    $AzFWobject = Get-AzFirewall -Name $AzFWname -ResourceGroupName $AzFWrg
                    $AzFWpolicyName = $AzFWobject.FirewallPolicy.id.split("/")[8]
                
                    #Private IPs
                    $AzFWPrivateIP = ($AzFWobject.IpConfigurationsText | ConvertFrom-Json).privateIPaddress

                    #Public IPs
                    $AzFWPublicIPsArray = ($AzFWobject.IpConfigurationsText | ConvertFrom-Json).PublicIpAddress
                    $AzFWPublicIPs = ""
                    $AzFWPublicIPsArray.id | ForEach-Object {
                        $rgname = $_.split("/")[4]
                        $ipname = $_.split("/")[8]
                        $publicip = (Get-AzPublicIpAddress -ResourceName $ipname -ResourceGroupName $rgname).IpAddress
                        $AzFWPublicIPs += "$ipname : $publicip \n"
                    }
                    
                    $data = $data + "        $id [label = `"\n$name\n$AddressPrefix\n\nName: $AzFWname\nPolicy name: $AzFWpolicyName\n\nPrivate IP : $AzFWPrivateIP\n\nPublic IP(s):\n$AzFWPublicIPs`" ; color = lightgray;image = `"$OutputPath\icons\afw.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];"
                } else { 
                    $data = $data + "        $id [label = `"\n$name\n$AddressPrefix`" ; color = lightgray;image = `"$OutputPath\icons\afw.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];"
                }
                
            }
            "AzureBastionSubnet" { 
                $AzBastionName = $subnetconfigobject.IpConfigurationsText | ConvertFrom-Json
                if ($AzBastionName -ne "[]") { 
                    $AzBastionName = ($subnetconfigobject.IpConfigurationsText | ConvertFrom-Json).id.split("/")[8]
                }
                $AzBastionName = $AzBastionName.ToLower()
                $data = $data + "        $id [label = `"\n\n$name\n$AddressPrefix\nName: $AzBastionName`" ; color = lightgray;image = `"$OutputPath\icons\bas.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 
            }
            "GatewaySubnet" { 
                $data = $data + "        $id [label = `"\n\n$name\n$AddressPrefix`" ; color = lightgray;image = `"$OutputPath\icons\vgw.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 
                $data += "`n"
                
                #GW DOT
                if ($subnetconfigobject.IpConfigurationsText -ne "[]" ) {
                    $gws = $subnetconfigobject.IpConfigurationsText | ConvertFrom-Json
                    
                    #Multi GW scenearios
                    $gws | ForEach-Object {
                        $gwid = (($_.id -split ("/ipConfigurations/"))[0]).replace("-", "").replace("/", "").replace(".", "").ToLower()
                        $gwname = ($_.id-split "/").split("/")[8].ToLower()
                        $gwrg = ($_.id -split "/").split("/")[4]
                        $gw = Get-AzVirtualNetworkGateway -ResourceGroupName $gwrg -ResourceName $gwname
                        $gwtype = $gw.Gatewaytype

                        # ER vs VPN GWs are handled differently
                        if ($gwtype -eq "Vpn" ) {
                            $gwipobjetcs = $gw.IpConfigurations.PublicIpAddress
                            $gwips = ""
                            $gwipobjetcs.id | ForEach-Object {
                                $rgname = $_.split("/")[4]
                                $ipname = $_.split("/")[8]
                                $publicip = (Get-AzPublicIpAddress -ResourceName $ipname -ResourceGroupName $rgname).IpAddress
                                $gwips += "$ipname : $publicip \n"
                            
                            }
                            $data += "        $gwid [color = lightgray;label = `"\n\nName: $gwname`\n\nPublic IP(s):\n$gwips`";image = `"$OutputPath\icons\vgw.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];"
                        } elseif ($gwtype -eq "ExpressRoute") {
                            $data += "        $gwid [color = lightgray;label = `"\nName: $gwname`";image = `"$OutputPath\icons\ergw.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];"
                        }
                        $data += "`n"
                        $data += "        $id -> $gwid"
                        $data += "`n"
                    }
                }
            }
            default { 
                ##### Subnet delegations #####
                # Might be moved to subnet switch "default" ???
                # Just change the icon, or maybe a line with "Delegation info" ?
                # ((get-azvirtualNetwork| Get-AzVirtualNetworkSubnetConfig).Delegations).Name
                $subnetDelegationName = $subnetconfigobject.Delegations.Name
                
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
                } else {
                    # No Delegation
                    $data = $data + "        $id [label = `"\n$name\n$AddressPrefix`" ; color = lightgray;image = `"$OutputPath\icons\snet.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 
                }
            }
        }
        
        $data += "`n"
        
        # DOT VNET->Subnet
        $data = $data + "        $vnetid -> $id"
        $data += "`n"
    
        #NATGW
        if ( $null -ne $subnetconfigobject.NatGateway ) {
            #Define NAT GW
            $NATGWID = $subnetconfigobject.NatGateway.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            
            $name = $subnetconfigobject.NatGateway.id.split("/")[8]
            $rg = $subnetconfigobject.NatGateway.id.split("/")[4]
            $NATGWobject = Get-AzNatGateway -Name $name -ResourceGroupName $rg
            
            #Public IPs associated
            $ips = $NATGWobject.PublicIpAddresses
            $ipsstring = ""
            $ips.id | ForEach-Object {
                $rgname = $_.split("/")[4]
                $ipname = $_.split("/")[8]
                $publicip = (Get-AzPublicIpAddress -ResourceName $ipname -ResourceGroupName $rgname).IpAddress
                $ipsstring += "$ipname : $publicip \n"
            }

            #Public IP prefixes associated
            $ipprefixes = $NATGWobject.PublicIpPrefixes
            $ipprefixesstring = ""
            $ipprefixes.id | ForEach-Object {
                $rgname = $_.split("/")[4]
                $ipname = $_.split("/")[8]
                $prefix = (Get-AzPublicIpPrefix -ResourceName $ipname -ResourceGroupName $rgname).IPPrefix
                $ipprefixesstring += "$ipname : $prefix \n"
            }
        
            $data += "        $NATGWID [color = lightgrey;label = `"\n\nName: $name\n\nPublic IP(s):\n$ipsstring\nPublic IP Prefix(es):\n$ipprefixesstring`";image = `"$OutputPath\icons\ng.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];"
            $data += "        $id -> $NATGWID" + "`n"

        }
    }

    return $data
}

function Export-vnet {
    param ([PSCustomObject[]]$vnet)
    $vnetname = $vnet.Name
    
    $id = $vnet.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
    
    $vnetAddressSpaces = $vnet.AddressSpace.AddressPrefixes
    $subnetconfig = $vnet | Get-AzVirtualNetworkSubnetConfig
    
    $global:rankvnetaddressspaces += $id

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
    if ($subnetconfig) {
        $subnetdata = Export-SubnetConfig $subnetconfig
    }
    $footer = "
        label = `"$vnetname`";
    }
    "

    $alldata = $header + $vnetdata + $subnetdata + $footer
    Export-AddToFile -Data $alldata

    # Peerings
    $vnetPeerings = $vnet.VirtualNetworkPeerings.RemoteVirtualNetworkText
    if ($vnetPeerings) {
        $vnetPeerings = $vnet.VirtualNetworkPeerings.RemoteVirtualNetworkText  | ConvertFrom-Json
    
        $vnetPeerings | ForEach-Object {
            $peering = $_.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            # DOT
            $data = "    $id -> $peering [ltail = cluster_$id; lhead = cluster_$peering;];"
            Export-AddToFile -Data $data
        }
    }
}

function Export-RouteTable {
    param ([PSCustomObject[]]$routetable)
    $routetableName = $routetable.Name
    $id = $routetable.id.replace("-", "").replace("/", "").replace(".", "").ToLower()

    $global:rankrts += $id

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

function Export-VPNConnection {
    param ([PSCustomObject[]]$connection)
    $name = $connection.Name
    $lgwid = $connection.LocalNetworkGateway2Text.replace("-", "").replace("/", "").replace(".", "").replace("`"", "").ToLower()
    $vpngwid = $connection.VirtualNetworkGateway1Text.replace("-", "").replace("/", "").replace(".", "").replace("`"", "").ToLower()
    
    $data = ""
    $lgwname = $connection.LocalNetworkGateway2Text.split("/")[8].replace("/", "").replace(".", "").replace("`"", "").ToLower()
    $lgwrg = $connection.LocalNetworkGateway2Text.split("/")[4].replace("/", "").replace(".", "").replace("`"", "").ToLower()
    $lgwconnectionname = $name
    $lgwobject = (Get-AzLocalNetworkGateway -ResourceGroupName $lgwrg -name $lgwname)
    $lgwip = $lgwobject.GatewayIpAddress
    $lgwsubnetsarray = $lgwobject.addressSpaceText | ConvertFrom-Json
    $lgwsubnets = ""
    $lgwsubnetsarray.AddressPrefixes | ForEach-Object {
        $prefix = $_
        $lgwsubnets += "$prefix \n"
    }

    #DOT
    $data += "    $lgwid [color = lightgrey;label = `"\n\nLocal GW: $lgwname\nConnection Name: $lgwconnectionname\nPeer IP:$lgwip\n\nStatic remote subnet(s):\n$lgwsubnets`";image = `"$OutputPath\icons\lgw.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];"
    $data += "    $vpngwid -> $lgwid"
    Export-AddToFile -Data $data
}

function Confirm-Prerequisites {
    $ErrorActionPreference = "Stop"

    if (! (Test-Path $OutputPath)) {}

    # dot.exe executable
    try {
        $dot = (get-command dot.exe -errorAction SilentlyContinue).Path
        if ($null -eq $dot) {
            Write-Output "dot.exe executable not found - please install Graphiz (https://graphviz.org), and/or ensure `"dot.exe` is in `"`$PATH`" !"
            return
        }
    }
    catch {
        Write-Output "dot.exe executable not found - please install Graphiz (https://graphviz.org), and/or ensure `"dot.exe` is in `"`$PATH`" !"
        return
    }
    
    # Load Powershell modules
    try {
        import-module az.network -DisableNameChecking
        import-module az.accounts
    }
    catch {
        Write-Output "Please install the following PowerShell modules, using install-module: Az.Network + Az.Accounts"
        return
    }


    # Azure authentication verification
    $context = Get-AzContext 
    if ($null -eq $context) { 
        Write-Output "Please make sure you are logged in to Azure using Login-AzAccount, and that permissions are granted to resources within scope."
        Write-Output "A login window should appear - hint: they may hide behind active windows!"
        Login-AzAccount
        return
    }

    # Icons available?
    if (! (Test-Path "$OutputPath\icons") ) { Write-Output "Downloading icons to $OutputPath\icons\ ... " ; New-Item -Path "$OutputPath" -Name "icons" -ItemType "directory" | Out-null }
    $icons =  @(
        "afw.png",
        "asp.png",
        "bas.png",
        "dnspr.png",
        "ergw.png",
        "lgw.png",
        "LICENSE",
        "ng.png",
        "snet.png",
        "sqlmi.png",
        "vgw.png",
        "vnet.png"
    )
    
    $icons | ForEach-Object {
        if (! (Test-Path "$OutputPath\icons\$_") ) { Invoke-WebRequest "https://github.com/dan-madsen/AzNetworkDiagram/raw/refs/heads/main/icons/$_" -OutFile "$OutputPath\icons\$_" }
    }
}

function Get-AzNetworkDiagram {
    # Parameters
    param (
        [string]$OutputPath = $pwd,
        [string[]]$Subscriptions,
        [bool]$EnableRanking = $true
    )

    # Reset global vars
    $global:rankrts = @()
    #$global:ranksubnets = @()
    $global:rankvnetaddressspaces = @()

    Write-Output "Checking prerequisites ..."
    Confirm-Prerequisites

    Write-Output "Gathering information ..."

    ##### Data collection / Execution #####

    # Run program and collect data through powershell commands
    Export-dotHeader

    # Set subscriptions to every accessible subscription, if unset
    if ( $null -eq $Subscriptions ) { $Subscriptions = (Get-AzSubscription).Id } 

    $Subscriptions | ForEach-Object {
        # Set Context
        $context = $_
        Set-AzContext $context | Out-null
        $subname = (Get-AzContext).Subscription.Name
        Export-AddToFile "`n    ##########################################################################################################"
        Export-AddToFile "    ##### $subname "
        Export-AddToFile "    ##########################################################################################################`n"

        ### RTs
        Export-AddToFile "    ##### $subname - Route Tables #####"
        $routetables = Get-AzRouteTable | Where-Object { ($_.SubnetsText -ne "[]") }
        $routetables | ForEach-Object {
            $routetable = $_
            Export-RouteTable $routetable
        }

        ### vNets (incl. subnets)
        Export-AddToFile "    ##### $subname - Virtual Networks #####"
        $vnets = Get-AzVirtualNetwork
        $vnets | ForEach-Object {
            $vnet = $_
            Export-vnet $vnet
        }

        #VPN Connections
        Export-AddToFile "    ##### $subname - VPN Connections #####"
        $VPNConnections = Get-AzResource | Where-Object { $_.ResourceType -eq "Microsoft.Network/connections" }
        $VPNConnections | ForEach-Object {
            $connection = $_
            $resname = $connection.Name
            $rgname = $connection.ResourceGroupName
            $connection = Get-AzVirtualNetworkGatewayConnection -name $resname -ResourceGroupName $rgname
            Export-VPNConnection $connection
        }

        Export-AddToFile "`n    ##########################################################################################################"
        Export-AddToFile "    ##### $subname "
        Export-AddToFile "    ##### END"
        Export-AddToFile "    ##########################################################################################################`n"
    }

    if ( $EnableRanking ) { Export-dotFooterRanking }
    Export-dotFooter

    ##### Generate diagram #####
    # Generate diagram using Graphviz
    Write-Output "Generating $OutputPath\AzNetworkDiagram.pdf ..."
    dot -Tpdf $OutputPath\AzNetworkDiagram.dot -o $OutputPath\AzNetworkDiagram.pdf
    Write-Output "Generating $OutputPath\AzNetworkDiagram.png ..."
    dot -Tpng $OutputPath\AzNetworkDiagram.dot -o $OutputPath\AzNetworkDiagram.png
} 

Export-ModuleMember -Function Get-AzNetworkDiagram