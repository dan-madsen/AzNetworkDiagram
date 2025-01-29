<#
  .SYNOPSIS
  Creates a Network Diagram of your Azure networking infrastructure.

  .DESCRIPTION
  The Get-AzNetworkDiagram.ps1 visualizes Azure networking utilizing GraphViz and the "DOT", diagram-as-code language to export a PNG and PDF with a network digram containing:
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
  
  .PARAMETER OutputPath
  Specifies the path for the DOT-based output file. If unset - current working directory will be used.

  .INPUTS
  None. It will however require previous authentication to Azure

  .OUTPUTS
  None. .\Get-AzNetworkDiagram.psm1 doesn't generate any output (Powershell-wise). FIle based out will be save in the OutputPath

  .EXAMPLE
  # Import module (will be available on PSGallary shortly)
  PS> Import-Module .\AzNetworkDiagram.psm1

  # Run
  PS> .\Get-AzNetworkDiagram [-outputPath C:\temp\]
  PS> .\Get-AzNetworkDiagram 
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
    newrank=true; #Needed for 
    rankdir = TB;
    "
    Export-CreateFile -Data $Data
}

function Export-dotFooter {
    Export-AddToFile -Data "##### RANKS #####"
    Export-AddToFile -Data "### AddressSpace ranks"
    $rankvnetaddressspacesdata = "{ rank=same; "
    
    $global:rankvnetaddressspaces | ForEach-Object {
        $vnetaddresspacename = $_
        $rankvnetaddressspacesdata += $vnetaddresspacename + "; ";
    }

    Export-AddToFile -Data "$rankvnetaddressspacesdata }"

    Export-AddToFile -Data "### Subnets ranks (TODO!)"
    Export-AddToFile -Data "### Route table ranks"
    $rankroutedata = "{ rank=same; "
    
    $rankrts | ForEach-Object {
        $routename = $_
        $rankroutedata += $routename + "; ";
    }
    Export-AddToFile -Data "$rankroutedata }"
    Export-AddToFile -Data "}" #EOF
}

function Export-CreateFile {
    param([string]$Data)
    $Data | Out-File -Encoding ASCII $OutputPath\Visualize-AzureNetwork.dot
}

function Export-AddToFile {
    param([string]$Data)
    $Data | Out-File -Encoding ASCII  -Append $OutputPath\Visualize-AzureNetwork.dot
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
        
        # NSG
        $nsgid = $_.NetworkSecurityGroupText.ToLower()
        if ($nsgid -ne "null") { $nsgid = ($_.NetworkSecurityGroupText | ConvertFrom-Json).id.replace("-", "").replace("/", "").replace(".", "").ToLower() }
        
        # Route Table
        $routetableid = $_.RouteTableText.ToLower()
        if ($routetableid -ne "null" ) { $routetableid = (($_.RouteTableText | ConvertFrom-Json).id).replace("-", "").replace("/", "").replace(".", "").ToLower() }
       
        # Name
        $name = $_.Name
        if ( $nsgid -ne "null") { $name += " #" }

        # vNet      
        $vnetid = $_.id
        $vnetid = $vnetid -split "/subnets/"
        $vnetid = $vnetid[0].replace("-", "").replace("/", "").replace(".", "").ToLower()

        # AddressPrefix
        $AddressPrefix = $_.AddressPrefix
        
        
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
                    
                    $data = $data + "$id [label = `"\n$name\n$AddressPrefix\n\nName: $AzFWname\nPolicy name: $AzFWpolicyName\n\nPrivate IP:$AzFWPrivateIP\n\nPublic IP(s):\n$AzFWPublicIPs`" ; color = lightgray;image = `"icons\afw.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];"
                } else { 
                    $data = $data + "$id [label = `"\n$name\n$AddressPrefix`" ; color = lightgray;image = `"icons\afw.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];"
                    #Write-Output $data
                }
                
            }
            "AzureBastionSubnet" { 
                $AzBastionName = $subnetconfigobject.IpConfigurationsText | ConvertFrom-Json
                if ($AzBastionName -ne "[]") { 
                    $AzBastionName = ($subnetconfigobject.IpConfigurationsText | ConvertFrom-Json).id.split("/")[8]
                }
                $AzBastionName = $AzBastionName.ToLower()
                $data = $data + "$id [label = `"\n\n$name\n$AddressPrefix\nName: $AzBastionName`" ; color = lightgray;image = `"icons\bas.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 
            }
            "GatewaySubnet" { 
                $data = $data + "$id [label = `"\n\n$name\n$AddressPrefix`" ; color = lightgray;image = `"icons\vgw.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 
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
                            $data += "$gwid [color = lightgray;label = `"\n\nName: $gwname`\n\nPublic IP(s):\n$gwips`";image = `"icons\vgw.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];"
                        } elseif ($gwtype -eq "ExpressRoute") {
                            $data += "$gwid [color = lightgray;label = `"\nName: $gwname`";image = `"icons\ergw.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];"
                        }
                        $data += "`n"
                        $data += "$id -> $gwid"
                        $data += "`n"
                    }
                }
            }
            default { $data = $data + "$id [label = `"\n$name\n$AddressPrefix`" ; color = lightgray;image = `"icons\snet.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" }
        }
        
        $data += "`n"
        # DOT
        $data = $data + "$vnetid -> $id"
        $data += "`n"
    
        if ($routetableid -ne "null" ) {
            # DOT
            $data += "$id -> $routetableid" + "`n"
        }
        
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
        
            $data += "$NATGWID [color = lightgrey;label = `"\n\nName: $name\n\nPublic IP(s):\n$ipsstring\nPublic IP Prefix(es):\n$ipprefixesstring`";image = `"icons\ng.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];"
            $data += "$id -> $NATGWID" + "`n"

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

    $vnetdata = "$id [color = lightgray;label = `"\nAddress Space(s):\n$vnetAddressSpacesString`";image = `"icons\vnet.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];"

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
            $data = "$id -> $peering [ltail = cluster_$id; lhead = cluster_$peering;];"
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
    $data += "$lgwid [color = lightgrey;label = `"\n\nLocal GW: $lgwname\nConnection Name: $lgwconnectionname\nPeer IP:$lgwip\n\nStatic remote subnet(s):\n$lgwsubnets`";image = `"icons\lgw.png`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];"
    $data += "$vpngwid -> $lgwid"
    Export-AddToFile -Data $data
}

function Confirm-Prerequisites {
    $ErrorActionPreference = "Stop"

    # dot.exe executable
    try {
        $dot = (get-command dot.exe).Path
    }
    catch {
        Write-Output "dot executable not found - please install Graphiz (https://graphviz.org), and/or ensure `"dot.exe` is in `"`$PATH`" !"
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
}

function Get-AzNetworkDiagram {
    # Parameters
    param (
    [string]$OutputPath = $pwd
    )

    Confirm-Prerequisites

    ##### Data collection / Execution #####
    # Run program and collect data through powershell commands
    Export-dotHeader

    $subscriptions = Get-AzSubscription
    $subscriptions | ForEach-Object {
        # Set Context
        Set-AzContext $_.Id | Out-null

        ### RTs
        Export-AddToFile "##### " + Get-AzContext.id + " Route Tables #####"
        $routetables = Get-AzRouteTable | Where-Object { ($_.SubnetsText -ne "[]") }
        $routetables | ForEach-Object {
            $routetable = $_
            Export-RouteTable $routetable
        }

        ### vNets (incl. subnets)
        Export-AddToFile "#####  " + Get-AzContext.id + " Virtual Networks #####"
        $vnets = Get-AzVirtualNetwork
        $vnets | ForEach-Object {
            $vnet = $_
            Export-vnet $vnet
        }

        #VPN Connections
        Export-AddToFile "#####  " + Get-AzContext.id + " Route Tables #####"
        $VPNConnections = Get-AzResource | Where-Object { $_.ResourceType -eq "Microsoft.Network/connections" }
        #$VPNConnections = Get- | Where-Object { ($_. -ne "[]")}
        $VPNConnections | ForEach-Object {
            $connection = $_
            $resname = $connection.Name
            $rgname = $connection.ResourceGroupName
            $connection = Get-AzVirtualNetworkGatewayConnection -name $resname -ResourceGroupName $rgname
            Export-VPNConnection $connection
        }
    }
    Export-dotFooter

    ##### Generate diagram #####
    # Generate diagram using GraphViz
    dot -Tpdf $OutputPath\Visualize-AzureNetwork.dot -o $OutputPath\Visualize-AzureNetwork.pdf
    dot -Tpng $OutputPath\Visualize-AzureNetwork.dot -o $OutputPath\Visualize-AzureNetwork.png

    # Open Result
    # $outputPNG
} 

Export-ModuleMember -Function Get-AzNetworkDiagram