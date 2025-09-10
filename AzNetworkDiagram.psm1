#Requires -Version 7.1
#Requires -Modules Az.Accounts, Az.Network, Az.Compute, Az.KeyVault, Az.Storage, Az.MySql, Az.PostgreSql, Az.CosmosDB, Az.RedisCache, Az.Sql, Az.EventHub, Az.Websites, Az.ApiManagement, Az.ContainerRegistry, Az.ManagedServiceIdentity, Az.Resources

<#
  .SYNOPSIS
  Creates a Network Diagram of your Azure networking infrastructure.

  .DESCRIPTION
  The Get-AzNetworkDiagram (Powershell)Cmdlet visualizes Azure resources utilizing Graphviz and the "DOT", diagram-as-code language to export a PDF and PNG with an infrastructure digram containing the supported resource and relevant information.

  IMPORTANT:
  Icons in the .\icons\ folder is necessary in order to generate the diagram. If not present, they will be downloaded to the output directory during runtime.
  
  .PARAMETER OutputPath
  -OutputPath specifies the path for the DOT-based output file. If unset - current working directory will be used.

  .PARAMETER Tenant
  -Tenant "tenantId" Specifies the tenant Id to be used in all subscription authentication. Handy when you have multiple tenants to work with. Default: current tenant

  .PARAMETER Subscriptions
  -Subscriptions "subid1","subid2","..."** - a list of subscriptions in scope for the digram. Default is all available subscriptions.

  .PARAMETER EnableRanking
  -EnableRanking $true ($true/$false) - enable ranking (equal hight in the output) of certain resource types. For larger environments, this might be worth a shot. **Default: $true**

  .PARAMETER Sanitize
  -Sanitize $bool ($true/$false) - Sanitizes all names, locations, IP addresses and CIDR blocks. Default: $false

  .PARAMETER Prefix
  -Prefix "string" - Adds a prefix to the output file name. For example is cases where you want to do multiple automated runs then the file names will have the prefix per run that you specify. Default: No Prefix

  .PARAMETER OnlyCoreNetwork
  -OnlyCoreNetwork ($true/$false) - if $true/enabled, only cores network resources are processed - ie. non-network resources are skipped for a cleaner diagram.

  .PARAMETER EnableLinks
  -EnableLinks ($true/$false) - if $true/enabled Azure resource in the PDF output will become links, taking you to the Azure portal. **Default: $false**

  .PARAMETER -KeepDotFile
  -KeepDotFile ($true/$false) - if $true/enabled the DOT file will be preserved

  .PARAMETER -OutputFormat
  -OutputFormat (pdf, svg, png) - One or more output files get generated with the specified formats. Default is PDF.

  .PARAMETER OnlyMgmtGroups
  -OnlyMgmtGroups ($true/$false) - Creates a Management Group and Subscription overview diagram - everything else is skipped. Default is $false.

  .INPUTS
  None. It will however require previous authentication to Azure

  .OUTPUTS
  None. .\Get-AzNetworkDiagram.psm1 doesn't generate any output (Powershell-wise). File based output will be save in the OutputPath, if set - otherwise to current working directory

  .EXAMPLE
  PS> Get-AzNetworkDiagram [-Tenant tenantId] [-Subscriptions "subid1","subid2","..."] [-OutputPath C:\temp\] [-EnableRanking $true] [-OnlyCoreNetwork $true] [-Sanitize $true] [-Prefix prefixstring]
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

<#
.SYNOPSIS
Sanitizes a given string by replacing sensitive or identifiable information with randomized or predefined values.

.DESCRIPTION
The `SanitizeString` function processes an input string and replaces sensitive or identifiable information such as IP addresses, CIDR blocks, numerical strings, and alphanumeric strings with randomized or predefined values. It is designed to anonymize data for use in diagrams or reports. The function also handles specific patterns like dashes, dots, and alphanumerical strings, ensuring consistent sanitization.

.PARAMETER InputString
The string to be sanitized. This can include IP addresses, CIDR blocks, numerical strings, or alphanumeric strings.

.EXAMPLE
PS> $sanitizedString = SanitizeString -InputString "192.168.1.1"
PS> Write-Output $sanitizedString
10.0.0.1

This example sanitizes the input IP address "192.168.1.1" and replaces it with a randomized private IP address.

.EXAMPLE
PS> $sanitizedString = SanitizeString -InputString "my-sensitive-data"
PS> Write-Output $sanitizedString
apple

This example sanitizes the input string "my-sensitive-data" and replaces it with a random word.
#>
function SanitizeLocation {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Location
    )
    # Array of known planets, major moons, stars, and star systems (all lowercase, spaces replaced with dash)
    $celestialBodies = @(
        # Planets (Solar System)
        "mercury", "venus", "earth", "mars", "jupiter", "saturn", "uranus", "neptune",

        # Dwarf Planets (Solar System)
        "pluto", "eris", "haumea", "makemake", "ceres",

        # Major Moons (Solar System)
        "moon", "phobos", "deimos", "io", "europa", "ganymede", "callisto",
        "amalthea", "himalia", "elara", "pasiphae", "sinope", "lysithea", "carme", "ananke", "leda",
        "mimas", "enceladus", "tethys", "dione", "rhea", "titan", "hyperion", "iapetus", "phoebe",
        "miranda", "ariel", "umbriel", "titania", "oberon", "triton", "nereid", "charon", "hydra", "nix", "kerberos", "styx",

        # Notable Stars
        "sun", "sirius", "canopus", "arcturus", "alpha-centauri", "vega", "capella", "rigel", "procyon",
        "achernar", "betelgeuse", "hadar", "altair", "aldebaran", "antares", "spica", "pollux", "fomalhaut",
        "deneb", "mimosa", "regulus", "adhara", "castor", "gacrux", "shaula", "bellatrix", "elnath", "miaplacidus",

        # Notable Star Systems
        "alpha-centauri", "proxima-centauri", "barnard's-star", "luyten's-star", "wolf-359", "lalande-21185",
        "sirius-system", "epsilon-eridani", "tau-ceti", "61-cygni", "altair-system", "vega-system", "trappist-1",

        # Famous Exoplanets (selected)
        "proxima-centauri-b", "kepler-22b", "kepler-452b", "hd-209458-b", "51-pegasi-b", "gliese-581g", "trappist-1e", "trappist-1f", "trappist-1g"
    )
    return $script:DoSanitize ? ($celestialBodies | Get-Random) : $Location
}
<#
.SYNOPSIS
Sanitizes a given string by replacing sensitive or identifiable information with randomized or predefined values.

.DESCRIPTION
The `SanitizeString` function processes an input string and replaces sensitive or identifiable information such as IP addresses, CIDR blocks, numerical strings, and alphanumeric strings with randomized or predefined values. It is designed to anonymize data for use in diagrams or reports. The function also handles specific patterns like dashes, dots, and alphanumerical strings, ensuring consistent sanitization.

.PARAMETER InputString
The string to be sanitized. This can include IP addresses, CIDR blocks, numerical strings, or alphanumeric strings.

.EXAMPLE
PS> $sanitizedString = SanitizeString -InputString "192.168.1.1"
PS> Write-Output $sanitizedString
10.0.0.1

This example sanitizes the input IP address "192.168.1.1" and replaces it with a randomized private IP address.

.EXAMPLE
PS> $sanitizedString = SanitizeString -InputString "my-sensitive-data"
PS> Write-Output $sanitizedString
apple

This example sanitizes the input string "my-sensitive-data" and replaces it with a random word.
#>
function SanitizeString {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$InputString
    )
    $Ignore = @("true", "false", "enabled", "disabled", "yes", "no", "on", "off")

    # Example usage:
    # $randomIP = Get-RandomPrivateIPAddress
    # Write-Output $randomIP
    function Get-RandomPrivateIPAddress {
        # Define private IP ranges
        $privateRanges = @(
            @{ Base = "10"; Min2 = 0; Max2 = 255; Min3 = 0; Max3 = 255; Min4 = 1; Max4 = 254 },
            @{ Base = "172"; Min2 = 16; Max2 = 31; Min3 = 0; Max3 = 255; Min4 = 1; Max4 = 254 },
            @{ Base = "192.168"; Min2 = 0; Max2 = 0; Min3 = 1; Max3 = 254; Min4 = 1; Max4 = 254 }
        )

        $range = Get-Random -InputObject $privateRanges
        if ($range.Base -eq "10") {
            return "$($range.Base).$((Get-Random -Min $range.Min2 -Max ($range.Max2+1))).$((Get-Random -Min $range.Min3 -Max ($range.Max3+1))).$((Get-Random -Min $range.Min4 -Max ($range.Max4+1)))"
        }
        elseif ($range.Base -eq "172") {
            return "$($range.Base).$((Get-Random -Min $range.Min2 -Max ($range.Max2+1))).$((Get-Random -Min $range.Min3 -Max ($range.Max3+1))).$((Get-Random -Min $range.Min4 -Max ($range.Max4+1)))"
        }
        else {
            return "$($range.Base).$((Get-Random -Min 1 -Max 255)).$((Get-Random -Min 1 -Max 255))"
        }
    }

    if ($null -eq $InputString) {
        return ""
    }
    elseif ($InputString -eq "") {
        return $InputString
    }   
    elseif (-not $script:DoSanitize -or ($Ignore -contains $InputString.ToLower())) {
        return $InputString
    }
    # Regex: match 'label =' not preceded by '[' and followed by quoted string
    # Check for IPv4 address
    elseif ($InputString -match '^(?:\d{1,3}\.){3}\d{1,3}$') {
        return Get-RandomPrivateIPAddress
    }
    # Check for CIDR notation
    elseif ($InputString -match '^(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}$') {
        # Extract mask
        $mask = $InputString.Split('/')[1]
        $ip = Get-RandomPrivateIPAddress
        return "$ip/$mask"
    }
    # Test if a string is only digits
    elseif ($InputString -match '^\d+$') {
        $length = $InputString.Length
        return -join (1..$length | ForEach-Object { Get-Random -Minimum 0 -Maximum 10 })

    }
    # TenantId
    elseif ($InputString -match '(\w{8}-\w{4}-\w{4}-\w{4}-\w{12})') {
        return "xxxxxxxx-yyyy-zzzz-cccc-vvvvvvvvvvvv" 
    }
    # Check for dashes and dots
    elseif ($InputString -match '[-.]') {
        # List of 3-letter lowercase words
        $shortwords = @(
            'cat', 'dog', 'sun', 'sky', 'red', 'fox', 'owl', 'bee', 'ant', 'bat', 'cow', 'pig', 'rat', 'hen', 'elk', 'ape', 'yak', 'emu', 'gnu', 'eel', 'ram', 'cod', 'jay', 'kit', 'lob', 'man', 'nut', 'owl', 'pan', 'qua', 'rob', 'sow', 'tan', 'urn', 'vet', 'was', 'yak', 'zip'
        )

        # Split the string by dashes and dots
        $parts = $InputString -split '[-.]'
        if ($parts.Count -le 2) {
            $first = ($shortwords | Get-Random)
            $last = ($shortwords | Get-Random)
        }
        else {
            $first = $parts[0]
            $last = $parts[-1]
        }
        $middleCount = $parts.Count - 2
        $middle = @()
        for ($i = 0; $i -lt $middleCount; $i++) {
            $middle += ($shortwords | Get-Random)
        }
        return ($first + '-' + ($middle -join '-') + '-' + $last)
    }
    # Check for alphanumerical only (no spaces, no dashes, no special chars)
    elseif ($InputString -match '^[a-zA-Z0-9]+$') {
        # Array of known car brands (major global brands, all lowercase, spaces replaced with dash)
        $carBrands = @(
            "acura", "alfa-romeo", "aston-martin", "audi", "bentley", "bmw", "bugatti", "buick", "cadillac", "chevrolet",
            "chrysler", "citroen", "dacia", "daewoo", "daihatsu", "dodge", "ds-automobiles", "ferrari", "fiat", "fisker",
            "ford", "genesis", "gmc", "great-wall", "haval", "holden", "honda", "hummer", "hyundai", "infiniti", "isuzu",
            "jaguar", "jeep", "kia", "koenigsegg", "lada", "lamborghini", "lancia", "land-rover", "lexus", "lincoln",
            "lotus", "lucid", "maserati", "mazda", "mclaren", "mercedes-benz", "mercury", "mini", "mitsubishi", "nissan",
            "opel", "pagani", "peugeot", "polestar", "pontiac", "porsche", "proton", "ram", "renault", "rivian", "rolls-royce",
            "saab", "saturn", "scion", "seat", "skoda", "smart", "ssangyong", "subaru", "suzuki", "tata", "tesla", "toyota",
            "vauxhall", "volkswagen", "volvo", "wuling", "zotye"
        )        
        return $carBrands | Get-Random
    }
    else {
        # List of random words to choose from
        $fruits = @(
            "apple", "apricot", "avocado", "banana", "blackberry", "blueberry", "cantaloupe", "cherry", "coconut", "cranberry",
            "currant", "date", "dragonfruit", "durian", "elderberry", "fig", "gooseberry", "grape", "grapefruit", "guava",
            "honeydew", "jackfruit", "kiwi", "kumquat", "lemon", "lime", "lychee", "mango", "melon", "mulberry",
            "nectarine", "orange", "papaya", "passionfruit", "peach", "pear", "persimmon", "pineapple", "plum", "pomegranate",
            "quince", "raspberry", "starfruit", "strawberry", "tangerine", "watermelon"
        )
        $words = @('alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf', 'hotel', 'india', 'juliet', 'kilo', 'lima', 'mike', 'november', 'oscar', 'papa', 'quebec', 'romeo', 'sierra', 'tango', 'uniform', 'victor', 'whiskey', 'xray', 'yankee', 'zulu')
        return ($fruits + $words) | Get-Random
    }
}

<#
.SYNOPSIS
Takes an Azure PS object and returns a deeplink to the Azure portal, in DOT format.

.DESCRIPTION
The `Generate-DOTURL` function processes an Azure resource object and returns a deeplink to the Azure portal, in DOT format.

.PARAMETER resource
The resource you want a link to
#>
function Generate-DOTURL {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$resource
    )
    
    if ( $EnableLinks -and $script:DoSanitize -eq $false ) {
        $tenantDisplayName = SanitizeString (Get-AzTenant -TenantId (Get-AzContext).Tenant.Id).DefaultDomain
        $linkbase = "https://portal.azure.com/#@$tenantDisplayName/resource"
        $linkend = $resource.id
        if ( $null -eq $linkend ) { $linkend = $resource.ResourceID }
        $doturl = "URL=`"$($linkbase + $linkend)`";"
        return $doturl
    }
    else {
        return ""
    }
}

##### Functions for standard definitions #####
<#
.SYNOPSIS
Exports the DOT file header for the infrastructure diagram.
.DESCRIPTION
This function writes the initial DOT syntax and global graph settings for the Azure infrastructure diagram.
.PARAMETER None
This function does not take any parameters.
.EXAMPLE
Export-dotHeader
#>
function Export-dotHeader {
    [CmdletBinding()]

    $Data = "digraph AzNetworkDiagram {  
    # Colors
    colorscheme=pastel19;
    bgcolor=9;

    fontname=`"Arial,sans-serif`"
    node [colorscheme=x11; fontname=`"Arial,sans-serif`"]
    edge [fontname=`"Arial,sans-serif`"]
    
    # Ability for peerings arrows/connections to end at border
    compound = true;
    #concentrate = true;
    clusterrank = local;
    
    # Rank (height in picture) support
    newrank = true;
    rankdir = TB;
    nodesep=`"1.0`"
    "
    Export-CreateFile -Data $Data
}

<#
.SYNOPSIS
Exports the DOT file footer with resource ranking for the infrastructure diagram.
.DESCRIPTION
This function writes the closing DOT syntax and resource ranking information for the Azure infrastructure diagram.
.PARAMETER None
This function does not take any parameters.
.EXAMPLE
Export-dotFooterRanking
#>
function Export-dotFooterRanking {
    Export-AddToFile -Data "`n    ##########################################################################################################"
    Export-AddToFile -Data "    ##### RANKS"
    Export-AddToFile -Data "    ##########################################################################################################`n"
    if ($script:rankvnetaddressspaces) {
        Export-AddToFile -Data "    ### AddressSpace ranks"
        Export-AddToFile "    { rank=min; $($script:rankvnetaddressspaces -join '; ') }`n "
    }
    if ($script:ranksubnets) {
        Export-AddToFile -Data "`n    ### Subnets ranks"
        Export-AddToFile "    { rank=same; $($script:ranksubnets -join '; ') }`n "
    }
    if ($script:rankvgws) {
        Export-AddToFile -Data "`n    ### Virtual Network Gateways ranks"
        Export-AddToFile "    { rank=same; $($script:rankvgws -join '; ') }`n "
    }
    if ($script:rankrts) {
        Export-AddToFile -Data "`n    ### Route table ranks"
        Export-AddToFile "    { rank=same; $($script:rankrts -join '; ') }`n "
    }
    if ($script:rankvwans) {
        Export-AddToFile -Data "`n    ### vWAN ranks"
        Export-AddToFile "    { rank=same; $($script:rankvwans -join '; ') }`n "
    }
    if ($script:rankvwanhubs) {
        Export-AddToFile -Data "`n    ### vWAN Hub ranks"
        Export-AddToFile "    { rank=same; $($script:rankvwanhubs -join '; ') }`n "
    }
    if ($script:rankercircuits) {
        Export-AddToFile -Data "`n    ### ER Circuit ranks"
        Export-AddToFile "    { rank=same; $($script:rankercircuits -join '; ') }`n "
    }
    if ($script:rankvpnsites) {
        Export-AddToFile -Data "`n    ### VPN Site ranks"
        Export-AddToFile "    { rank=same; $($script:rankvpnsites -join '; ') }`n "        
    }
    if ($script:rankipgroups) {
        Export-AddToFile -Data "`n    ### IP Groups ranks"
        Export-AddToFile "    { rank=max; $($script:rankipgroups -join '; ') }`n "        
    }
}

<#
.SYNOPSIS
Exports the DOT file footer for the infrastructure diagram.
.DESCRIPTION
This function writes the closing DOT syntax for the Azure infrastructure diagram.
.PARAMETER None
This function does not take any parameters.
.EXAMPLE
Export-dotFooter
#>
function Export-dotFooter {
    $Script:Legend = $Script:Legend | Sort-Object -Unique
    $Global:MyLegend = $Script:Legend

    $date = Get-Date -Format 'yyyy-MM-dd'

    $context = Get-AzContext -ErrorAction SilentlyContinue
    $TenantId = $context.Tenant.Id
    $Tenant = Get-AzTenant -TenantId $TenantId -ErrorAction SilentlyContinue
    $TenantName = $Tenant.Name

    $tenantDisplayName = SanitizeString $TenantName

    #$tenantDisplayId = SanitizeString (Get-AzContext).Tenant.Id

    Export-AddToFile -Data "`n    ##########################################################################################################"
    Export-AddToFile -Data "    ##### Legend"
    Export-AddToFile -Data "    ##########################################################################################################`n"
    
    $data = "    subgraph clusterLegend {
                    style = solid;
                    margin = 0;
                    colorscheme = rdpu7;
                    bgcolor = 1;
                    node [colorscheme = rdpu7;color = 1; margin = 0; ];
                    labelloc=b;
                    label = `"Tenant:\n$tenantDisplayName\n\nCreated on $date by:\nAzNetworkDiagram $ver`";
                    URL = `"https://github.com/dan-madsen/AzNetworkDiagram`"

                    l1 [color = 1; label = < <TABLE border=`"0`" style=`"rounded`">
                                <TR><TD colspan=`"2`" border=`"0`"><FONT POINT-SIZE=`"25`"><B>Legend</B></FONT></TD></TR>
            "

    foreach ($Item in $Script:Legend) {
        $icon = Join-Path $OutputPath "icons" $Item[1]
        $data += "                <TR><TD align=`"left`"><IMG SCALE=`"TRUE`" SRC=`"$icon`"/></TD><TD align=`"left`">$($Item[0])</TD></TR>`n"
    }
    #$data += "                <TR><TD colspan=`"2`" align=`"center`"><IMG SCALE=`"TRUE`" SRC=`"c:/temp/logo.png`"/></TD></TR>`n"
    $data += "                </TABLE>>]; 
            }
            { rank=max; l1; }
    }"
    Export-AddToFile -Data $data #EOF
}

<#
.SYNOPSIS
Creates a new file for outputting the infrastructure diagram data.
.DESCRIPTION
This function creates a new output file for the Azure infrastructure diagram, overwriting any existing file with the same name.
.PARAMETER None
This function does not take any parameters.
.EXAMPLE
Export-CreateFile
#>
function Export-CreateFile {
    [CmdletBinding()]
    param([string]$Data)

    $Data | Out-File -Encoding ASCII $OutputPath\AzNetworkDiagram.dot
}

<#
.SYNOPSIS
Appends data to the output file for the infrastructure diagram.
.DESCRIPTION
This function appends a string of data to the output file for the Azure infrastructure diagram.
.PARAMETER Data
The string data to append to the output file.
.EXAMPLE
Export-AddToFile -Data $data
#>
function Export-AddToFile {
    [CmdletBinding()]
    param([string]$Data)

    $Data | Out-File -Encoding ASCII -Append $OutputPath\AzNetworkDiagram.dot
}

<#
.SYNOPSIS
Exports details of an AKS Cluster for inclusion in an infrastructure diagram.
.DESCRIPTION
This function processes an AKS Cluster object and formats its details for the Azure infrastructure diagram.
.PARAMETER Aks
The AKS Cluster object to process.
.EXAMPLE
Export-AKSCluster -Aks $Aks
#>
function Export-AKSCluster {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$Aks
    )
    try {
        # Check if ACR integration is enabled and which ACRs are attached
        #$Aks.IdentityProfile.kubeletidentity.ClientId
        if ($null -eq $Aks.IdentityProfile.kubeletidentity.ObjectId) {
            # No kubelet identity found for AKS cluster $($Aks.Name). Skipping ACR role assignment check.
            $aksacr = "None"
            $aksacrid = ""
        } else {
            # Get role assignments for the AKS cluster's kubelet identity
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
            }
            else {
                $aksacr = "None"
                $aksacrid = ""
            }
        }
        $aksid = $Aks.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $Name = SanitizeString $Aks.Name
        $data = "
        # $Name - $aksid
        subgraph cluster_$aksid {
            style = solid;
            bgcolor = 8;
            
            node [color = 8;];
        "
        $ServiceCidr = $Aks.NetworkProfile.ServiceCidr ? $(SanitizeString $Aks.NetworkProfile.ServiceCidr) : "None"
        $PodCidr = $Aks.NetworkProfile.PodCidr ? $(SanitizeString $Aks.NetworkProfile.PodCidr) : "None"
        $Location = SanitizeLocation $Aks.Location
        $ImagePath = Join-Path $OutputPath "icons" "aks-service.png"
        $data += "        $aksid [label = `"\nLocation: $Location\nVersion: $($Aks.KubernetesVersion)\nSKU Tier: $($Aks.Sku.Tier)\nPrivate Cluster: $($Aks.ApiServerAccessProfile.EnablePrivateCluster)\nDNS Service IP: $($Aks.DnsServiceIP)\nMax Agent Pools: $($Aks.MaxAgentPools)\nContainer Registry: $aksacr\nPod CIDR: $PodCidr\nService CIDR: $ServiceCidr\n`" ; color = 8;image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 3.0;$(Generate-DotURL -resource $Aks)];"
        
        #$Aks.PrivateLinkResources.PrivateLinkServiceId
        $ImagePath = Join-Path $OutputPath "icons" "aks-node-pool.png"
        foreach ($agentpool in $Aks.AgentPoolProfiles) {
            $agentpoolid = $aksid + $agentpool.Name.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "        $($agentpoolid) [label = `"\nName: $($agentpool.Name ? (SanitizeString $agentpool.Name) : '')\nMode: $($agentpool.Mode)\nZones: $($agentpool.AvailabilityZones)\nVM Size: $($agentpool.VmSize)\nMax Pods: $($agentpool.MaxPods)\nOS SKU: $($agentpool.OsSKU)\nAgent Pools: $($agentpool.MinCount) >= Pod Count <=  $($agentpool.MaxCount)\nEnable AutoScaling: $($agentpool.EnableAutoScaling)\nPublic IP: $($agentpool.EnableNodePublicIP ? (SanitizeString $agentpool.EnableNodePublicIP) : '')\n`" ; color = 7;image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 3.0;];`n" 
            $data += "        $aksid -> $agentpoolid [label = `"Node Pool`"];`n"
            if ($agentpool.VnetSubnetId) {
                $agentpoolsubnetid = $agentpool.VnetSubnetId.replace("-", "").replace("/", "").replace(".", "").ToLower()
                $data += "        $agentpoolid -> $agentpoolsubnetid;`n"
            }
        }

        if ($aksacr -ne "None") {
            $data += "        $aksid -> $aksacrid [label = `"Container Registry`"];`n"
        }   
        $sshid = (Get-AzSshKey | Where-Object { $_.publickey -eq $Aks.LinuxProfile.Ssh.Publickeys.Keydata }).Id
        if ($sshid) {
            $sshid = $sshid.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "        $aksid -> $sshid;`n"
        }
        # Check for User Assign Identity
        if ($aks.Identity.UserAssignedIdentities.Keys) {
            foreach ($identity in $aks.Identity.UserAssignedIdentities.Keys) { 
                $managedIdentityId = $identity.replace("-", "").replace("/", "").replace(".", "").ToLower() 
                $data += "        $aksid -> $managedIdentityId;`n"
            } 
        }
        # Check for Private Endpoints
        $pvtendpoints = get-azprivateEndpointConnection -PrivateLinkResourceId $aks.id -ErrorAction SilentlyContinue
        if ($pvtendpoints) {
            foreach ($pe in $($pvtendpoints.PrivateEndpoint)) {
                $peid = $pe.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
                $data += "        $aksid -> $peid [label = `"Private Endpoint`"; ];`n"
            }
        }
        # Match VMSS to node pools
        $vmssResources = Get-AzVmss 
        
        if ($vmssResources) {
            foreach ($vmss in $vmssResources) {
                # Extract node pool name from the VMSS name/tags
                
                # Method 1: Check in VMSS tags
                if ($vmss.Tags -and $vmss.Tags.ContainsKey("aks-managed-poolName")) {
                    $nodePoolName = $vmss.Tags["aks-managed-poolName"]
                }
                # Method 2: Extract from VMSS name (aks-[poolname]-[random])
                elseif ($vmss.Name -match "^aks-(.+?)-\d+-vmss$") {
                    $nodePoolName = $matches[1]
                }
                else {
                    # This VMSS is not an AKS VMSS
                    $nodePoolName = $null
                }
                if ($null -ne $nodePoolName) {
                    # Try to find matching node pool in the AKS cluster
                    $matchingPool = $aks.AgentPoolProfiles | Where-Object { $_.Name -eq $nodePoolName }
                    $agentpoolid = $aksid + $nodePoolName.replace("-", "").replace("/", "").replace(".", "").ToLower()
                    $vmssid = $vmss.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()

                    $data += "        $agentpoolid -> $vmssid [label = `"VM Scale Set`"];`n"
                }
            }
        }
        $data += "   label = `"$Name`";
                }`n"
        Export-AddToFile -Data $data
    }
    catch {
        Write-Host "Can't export AKS Cluster: $($Aks.Name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of an Azure Application Gateway for inclusion in an infrastructure diagram.

.DESCRIPTION
The `Export-ApplicationGateway` function processes a specified Azure Application Gateway object, retrieves its details, and formats the data for inclusion in an infrastructure diagram. It visualizes the gateway's name, SKU, zones, SSL certificates, frontend IP configurations, and associated firewall policies.

.PARAMETER agw
Specifies the Azure Application Gateway object to be processed.

.EXAMPLE
PS> Export-ApplicationGateway -agw $applicationGateway

This example processes the specified Azure Application Gateway and exports its details for inclusion in an infrastructure diagram.

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
        $Name = SanitizeString $agw.Name
        $Location = SanitizeLocation $agw.Location
        $data = "
        # $Name - $agwid
        subgraph cluster_$agwid {
            style = solid;
            colorscheme = gnbu9;
            bgcolor = 5;
            margin = 0;
            node [colorscheme = gnbu9; margin = 0;];
        "

        $skuname = $agw.Sku.Name
        if ($agw.SslCertificates) {
            $sslcerts = ($agw.SslCertificates.Name | ForEach-Object { SanitizeString   $_ }) -join ", "
        }
        else {
            $sslcerts = "None"
        }
        if ($agw.FrontendIPConfigurations) {
            $pvtips = ""
            foreach ($ipconfig in $agw.FrontendIPConfigurations) {
                if ($pvtips -ne "") {
                    $pvtips += ", "
                }
                if ($ipconfig.PrivateIPAllocationMethod -eq "Dynamic") {
                    if ($ipconfig.PublicIPAddress.Id) {
                        $pip = Get-AzPublicIpAddress -ResourceGroupName $agw.ResourceGroupName -Name $ipconfig.PublicIPAddress.Id.split("/")[-1] -ErrorAction SilentlyContinue
                        $pvtips += $(SanitizeString $pip.IPAddress) + " (Public)"
                    }
                }
                elseif ($ipconfig.PrivateIPAllocationMethod -eq "Static") {
                    $pvtips += $(SanitizeString $ipconfig.PrivateIPAddress) + " (Private)"
                }
            }
        }
        else {
            $pvtips = "None"
        }
        if ($agw.FirewallPolicy.Id) {
            $polname = SanitizeString $agw.FirewallPolicy.Id.split("/")[-1]
        }
        else {
            $polname = "None"
        }
        if ($agw.Zones) {
            $zones = $agw.Zones -join ","
        }
        else {
            $zones = "None"
        }
        if ($agw.FrontendPorts) {
            $feports = $agw.FrontendPorts.Port -join ", "
        }
        else {
            $feports = "None"
        }
        $ImagePath = Join-Path $OutputPath "icons" "agw.png"
        $data += "        $agwid [label = `"\nLocation: $Location\nPolicy name: $polname\nIPs: $pvtips\nSKU: $skuname\nZones: $zones\nSSL Certificates: $sslcerts\nFrontend ports: $feports\n`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 3.0;$(Generate-DotURL -resource $agw)];"
        $data += "`n"
        $data += "        $agwid -> $agwSubnetId;`n"

        if ($agw.Identity.UserAssignedIdentities.Keys) {
            foreach ($identity in $agw.Identity.UserAssignedIdentities.Keys) { 
                $managedIdentityId = $identity.replace("-", "").replace("/", "").replace(".", "").ToLower()
                $data += "        $agwid -> $managedIdentityId;`n"
            }
        }
        $data += "   label = `"$Name`";
                }`n"

        Export-AddToFile $data

    }
    catch {
        Write-Host "Can't export Application Gateway: $($agw.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of a managed identity for inclusion in an infrastructure diagram.
.DESCRIPTION
This function processes a managed identity object and formats its details for the Azure infrastructure diagram.
.PARAMETER managedIdentity
The managed identity object to process.
.EXAMPLE
Export-ManagedIdentity -managedIdentity $identity
#>
function Export-ManagedIdentity {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$managedIdentity
    )   
    
    try {
        $id = $managedIdentity.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $Location = SanitizeLocation $managedIdentity.Location
        $Name = SanitizeString $managedIdentity.Name
        $ImagePath = Join-Path $OutputPath "icons" "managed-identity.png"
        $data = "
        # $Name - $managedIdentityId
        subgraph cluster_$id {
            style = solid;
            colorscheme = blues9;
            bgcolor = 3;
            margin = 0;
            node [colorscheme = blues9; color = 3; margin = 0;];

            $id [label = `"\n$Name\nLocation: $Location`"; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;$(Generate-DotURL -resource $managedIdentity)];
            label = `"$Name`";
        }
        "
        Export-AddToFile -Data $data
    }
    catch {
        Write-Host "Can't export Managed Identity: $($managedIdentity.Name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of a Network Security Group (NSG) for inclusion in a network diagram.
.DESCRIPTION
This function processes a Network Security Group object and formats its details for the Azure network diagram.
.PARAMETER nsg
The Network Security Group object to process.
.EXAMPLE
Export-NSG -nsg $nsg
#>
function Export-NSG {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$nsg
    )   
    
    try {
        $id = $nsg.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $Location = SanitizeLocation $nsg.Location
        $Name = SanitizeString $nsg.Name
        $ImagePath = Join-Path $OutputPath "icons" "nsg.png"
        $data = "
        # $($nsg.Name) - $id
        subgraph cluster_$id {
            style = solid;
            bgcolor = 8;
            node [colorscheme = rdylgn11; style = filled;];

            $id [label = `"\n$Name\nLocation: $Location`" ; fillcolor = 8;image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;$(Generate-DotURL -resource $nsg)];
            label = `"$Name`";
        }
        "
        Export-AddToFile -Data $data
    }
    catch {
        Write-Host "Can't export NSG: $($nsg.Name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of an SSH key for inclusion in an infrastructure diagram.
.DESCRIPTION
This function processes an SSH key object and formats its details for the Azure infrastructure diagram.
.PARAMETER sshKey
The SSH key object to process.
.EXAMPLE
Export-SSHKey -sshKey $sshKey
#>
function Export-SSHKey {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$sshkey
    )   
    
    try {
        $id = $sshkey.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $Location = SanitizeLocation $sshkey.Location
        $Name = SanitizeString $sshkey.Name
        $ImagePath = Join-Path $OutputPath "icons" "ssh-key.png"
        $data = "
        # $Name - $id
        subgraph cluster_$id {
            style = solid;
            margin = 0;
            colorscheme = blues9;
            bgcolor = 4;
            node [colorscheme = blues9; color = 4; margin = 0;];

            $id [label = `"\n$Name\nLocation: $Location`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;$(Generate-DotURL -resource $sshkey)];
            label = `"$Name`";
        }
        "
        Export-AddToFile -Data $data
    }
    catch {
        Write-Host "Can't export SSH Key: $($sshkey.Name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

function Export-ComputeGallery {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$computeGallery
    )   
    
    try {
        $id = $computeGallery.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $sharing = $computeGallery.SharingProfile.Permissions ? "Shared" : "Private"
        $Location = SanitizeLocation $computeGallery.Location
        $Name = SanitizeString $computeGallery.Name
        $ImagePath = Join-Path $OutputPath "icons" "computegalleries.png"
        $data = "
        # $Name - $id
        subgraph cluster_$id {
            style = solid;
            margin = 0;
            colorscheme = purd9;
            bgcolor = 3;
            color = black;
            node [colorscheme = purd9; fillcolor = 4; margin = 0; style = `"filled`";];

            $id [fillcolor = 5; label = `"\nName: $Name\nLocation: $Location\nSharing Profile: $sharing`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.0;$(Generate-DotURL -resource $computeGallery)];`n"
        
        # Get all image definitions in the gallery
        $imageDefinitions = Get-AzGalleryImageDefinition -ResourceGroupName $computeGallery.ResourceGroupName -GalleryName $computeGallery.Name -ErrorAction Stop
        $ImagePath = Join-Path $OutputPath "icons" "imagedef.png"
        foreach ($imageDef in $imageDefinitions) {
            # Get all image versions for the image definition
            $imageVersions = Get-AzGalleryImageVersion -ResourceGroupName $computeGallery.ResourceGroupName -GalleryName $computeGallery.Name -GalleryImageDefinitionName $imageDef.Name -ErrorAction Stop
            $versions = $imageVersions | Select-Object @{Name = "Version"; Expression = { $_.Name } }, @{Name = "TargetRegions"; Expression = { $_.PublishingProfile.TargetRegions.Name -join ", " } } | Format-Table -AutoSize | Out-String

            $imageDefId = $imageDef.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "        $imageDefId [label = < 
                                        <TABLE border=`"0`" style=`"rounded`">
                                        <TR><TD align=`"left`">Name</TD><TD align=`"left`">$($imageDef.Name)</TD></TR>
                                        <TR><TD align=`"left`">OS Type</TD><TD align=`"left`">$($imageDef.OsType)</TD></TR>
                                        <TR><TD align=`"left`">OS State</TD><TD align=`"left`">$($imageDef.OsState)</TD></TR>
                                        <TR><TD align=`"left`">VM Generation</TD><TD align=`"left`">$($imageDef.HyperVGeneration)</TD></TR>
                                        <TR><TD><BR/><BR/></TD></TR>
                                        <TR><TD><B>Version</B></TD><TD><B>Target Regions</B></TD></TR>
                                        "
            foreach ($imageVersion in $imageVersions) {
                $version = $imageVersion.Name
                $targetRegions = $imageVersion.PublishingProfile.TargetRegions.Name -join ", "
                $data += "<TR><TD>$version</TD><TD>$targetRegions</TD></TR>`n"
            }                                        
            $data += "                  </TABLE>>; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 3.5;];`n"
            $data += "        $id -> $imageDefId;`n"
        }
        $data += "`n
            label = `"$Name`";
        }
        "
    
        Export-AddToFile -Data $data
    }
    catch {
        Write-Host "Can't export Compute Gallery: $($computeGallery.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }

}
<#
.SYNOPSIS
Exports details of an Azure Key Vault for inclusion in an infrastructure diagram.
.DESCRIPTION
This function processes a Key Vault object and formats its details for the Azure infrastructure diagram.
.PARAMETER keyvault
The Key Vault object to process.
.EXAMPLE
Export-Keyvault -keyvault $keyvault
#>
function Export-Keyvault {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$keyvault
    )   
    
    try {
        $properties = Get-AzResource -ResourceId $keyvault.ResourceId -ErrorAction Stop
        $Location = SanitizeLocation $keyvault.Location
        $id = $keyvault.ResourceId.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $Name = SanitizeString $keyvault.VaultName
        $ImagePath = Join-Path $OutputPath "icons" "keyvault.png"
        $data = "
        # $Name - $id
        subgraph cluster_$id {
            style = solid;
            colorscheme = brbg11;
            bgcolor = 8;
            margin = 0;
            node [colorscheme = brbg11; color = 8; margin = 0;];

            $id [label = `"\nLocation: $Location\nSKU: $($properties.Properties.Sku.Name)\nSoft Delete Enabled: $($properties.Properties.enableSoftDelete)\nRBAC Authorization Enabled: $($properties.Properties.enableRbacAuthorization)\nPublic Network Access: $($properties.Properties.publicNetworkAccess)\nPurge Protection Enabled: $($properties.Properties.enablePurgeProtection)`"; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.5;$(Generate-DotURL -resource $keyvault)];
        "
        if ($properties.Properties.privateEndpointConnections.properties.PrivateEndpoint.Id) {
            $peid = $properties.Properties.privateEndpointConnections.properties.PrivateEndpoint.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "        $id -> $peid [label = `"Private Endpoint`"; ];`n"
        }
        $data += "
            label = `"$Name`";
        }
        "
        Export-AddToFile -Data $data
    }
    catch {
        Write-Host "Can't export Key Vault: $($keyvault.VaultName) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of a Virtual Machine Scale Set (VMSS) for inclusion in an infrastructure diagram.
.DESCRIPTION
This function processes a VMSS object and formats its details for the Azure infrastructure diagram.
.PARAMETER vmss
The Virtual Machine Scale Set object to process.
.EXAMPLE
Export-VMSS -vmss $vmss
#>
function Export-VMSS {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$vmss
    )   
    
    try {
        $vmssid = $vmss.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $Location = SanitizeLocation $vmss.Location
        $Name = SanitizeString $vmss.Name
        $data = "
        # $Name - $vmssid
        subgraph cluster_$vmssid {
            style = solid;
            colorscheme = blues9;
            bgcolor = 2;
            node [colorscheme = blues9; color = 2;];
        "
        $extensions = $vmss.VirtualMachineProfile.ExtensionProfile.Extensions | ForEach-Object { $_.Name } | Join-String -Separator ", "
        $ImagePath = Join-Path $OutputPath "icons" "vmss.png"
        $data += "        $vmssid [label = `"\nLocation: $Location\nSKU: $($vmss.Sku.Name)\nCapacity: $($vmss.Sku.Capacity)\nZones: $($vmss.Zones)\nOS Type: $($vmss.StorageProfile.OsDisk.OsType)\nOrchestration Mode: $($vmss.OrchestrationMode)\nUpgrade Policy: $($vmss.UpgradePolicy)\nExtensions: $extensions`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 3.0;$(Generate-DotURL -resource $vmss)];"
        $data += "`n"

        $sshid = (Get-AzSshKey | Where-Object { $_.publickey -eq $vmss.VirtualMachineProfile.OsProfile.LinuxConfiguration.Ssh.PublicKeys.KeyData }).Id
        if ($sshid) {
            $sshid = $sshid.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "        $vmssid -> $sshid;`n"
        }
        if ($vmss.Identity.UserAssignedIdentities.Keys) {
            foreach ($identity in $vmss.Identity.UserAssignedIdentities.Keys) { 
                $managedIdentityId = $identity.replace("-", "").replace("/", "").replace(".", "").ToLower() 
                $data += "        $vmssid -> $managedIdentityId;`n"
            } 
        }
        if ($vmss.VirtualMachineProfile.NetworkProfile.NetworkInterfaceConfigurations.IpConfigurations.Subnet.Id) {
            $subnetid = $vmss.VirtualMachineProfile.NetworkProfile.NetworkInterfaceConfigurations.IpConfigurations.Subnet.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "        $vmssid -> $subnetid;`n"
        }
        if ($vmss.VirtualMachineProfile.NetworkProfile.NetworkInterfaceConfigurations.NetworkSecurityGroup.Id) {
            $nsgid = $vmss.VirtualMachineProfile.NetworkProfile.NetworkInterfaceConfigurations.NetworkSecurityGroup.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "        $vmssid -> $nsgid;`n"
        }
        $data += "   label = `"$Name`";
        }`n"

        Export-AddToFile -Data $data

    }
    catch {
        Write-Host "Can't export VMSS: $($vmss.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of a Virtual Machine (VM) for inclusion in an infrastructure diagram.
.DESCRIPTION
This function processes a VM object and formats its details for the Azure infrastructure diagram.
.PARAMETER vm
The Virtual Machine object to process.
.EXAMPLE
Export-VM -vm $vm
#>
function Export-VM {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$vm
    )   
    
    try {
        $vmid = $vm.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $Location = SanitizeLocation $vm.Location
        $Name = SanitizeString $vm.Name
        $data = "
        # $Name - $vmid
        subgraph cluster_$vmid {
            style = solid;
            colorscheme = blues9;
            bgcolor = 3;
            node [colorscheme = blues9; ];
        "
        $extensions = $vm.Extensions | ForEach-Object { $_.Id.split("/")[-1] } | Join-String -Separator ", "

        # NIC loop for private + public IPs
        $NICs = $vm.NetworkProfile.NetworkInterfaces.id
        $PublicIPAddresses = @()
        $PrivateIPAddresses = @()
        $NICs | Foreach-Object {
            #NIC
            #$nic = Get-AzNetworkInterface -ResourceId $vm.NetworkProfile.NetworkInterfaces[0].Id -ErrorAction Stop
            $nicref = $_
            $nic = Get-AzNetworkInterface -ResourceId $nicref -ErrorAction Stop

            # Public IP
            if ( $null -ne $nic.IpConfigurations[0].PublicIpAddress ) {
                #$PublicIpAddress = $nic.IpConfigurations[0].PublicIpAddress ? $(SanitizeString $nic.IpConfigurations[0].PublicIpAddress) : ""
                $PublicIPID = $nic.IpConfigurations[0].PublicIpAddress.Id
                $PublicIPRG = $PublicIPID.Split("/")[4]
                $PublicIPName = $PublicIPID.Split("/")[8]
                $PublicIpAddresses += SanitizeString (Get-AzPublicIpAddress -name $PublicIPName -ResourceGroupName $PublicIPRG).Ipaddress
            }
            
            $PrivateIpAddresses += $nic.IpConfigurations[0].PrivateIpAddress ? $(SanitizeString $nic.IpConfigurations[0].PrivateIpAddress) : ""
        }
        $PrivateIpAddresses = $PrivateIpAddresses | Sort-Object -Unique
        $PublicIPAddresses = $PublicIPAddresses | Sort-Object -Unique
        if ( $null -eq $PublicIPAddresses ) { $PublicIPAddresses = "None" }

        $ImagePath = Join-Path $OutputPath "icons" "vm.png"
        $data += "        $vmid [label = `"\nLocation: $Location\nSKU: $($vm.HardwareProfile.VmSize)\nZones: $($vm.Zones)\nOS Type: $($vm.StorageProfile.OsDisk.OsType)\nPublic IP(s): $($PublicIpAddresses -Join ", ")\nPrivate IP(s): $($PrivateIpAddresses -Join ", ")\nExtensions: $extensions`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 3.0;$(Generate-DotURL -resource $vm)];"
        $data += "`n"
        $subnetid = $nic.IpConfigurations[0].Subnet.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $data += "        $vmid -> $subnetid;`n"
        if ($vm.Identity.UserAssignedIdentities.Keys) {
            foreach ($identity in $vm.Identity.UserAssignedIdentities.Keys) { 
                $managedIdentityId = $identity.replace("-", "").replace("/", "").replace(".", "").ToLower()
                $data += "        $vmid -> $managedIdentityId;`n"
            }
        }

        # VM (NIC) -> NSG
        $NetworkProfiles = $vm.NetworkProfile.networkinterfaces
        $NetworkProfiles | Foreach-Object {
            $NetworkProfile = $_
            $NICId = $NetworkProfile.id
            $NICrg = $NICId.split("/")[4]
            $NICname = $NICId.split("/")[8]
            $NIC = Get-AzNetworkInterface -ResourceGroupName $NICrg -name $NICname
            if ( $null -ne $nic.NetworkSecurityGroup.id ) {
                $NSGid = ($nic.NetworkSecurityGroup.id).replace("-", "").replace("/", "").replace(".", "").ToLower()
                #$data += "        $vmid -> $NSGid [label = `"NIC: $NICName`"];`n"
                $data += "        $vmid -> $NSGid`n"
            }
        }
        $data += "   label = `"$Name`";
                }`n"

        Export-AddToFile -Data $data
    }
    catch {
        Write-Host "Can't export VM: $($vm.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of a MySQL Flexible Server for inclusion in an infrastructure diagram.
.DESCRIPTION
This function processes a MySQL Flexible Server object and formats its details for the Azure infrastructure diagram.
.PARAMETER mysql
The MySQL Flexible Server object to process.
.EXAMPLE
Export-MySQLServer -mysql $mysql
#>
function Export-MySQLServer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$mysql
    )   
    
    try {
        # Get Entra ID Admin
        $subid = $mysql.id.split("/")[2]
        $resourceGroupName = $mysql.id.split("/")[4]
        
        <#
        $uri = "https://management.azure.com/subscriptions/$subid/resourceGroups/$resourceGroupName/providers/Microsoft.DBforMySQL/flexibleServers/$($mysql.Name)/administrators?api-version=2023-06-01-preview"
        $token = (ConvertFrom-SecureString (Get-AzAccessToken -ResourceUrl 'https://management.azure.com' -AsSecureString).Token -AsPlainText)
        $headers = @{
            Accept        = '*/*'
            Authorization = "bearer $token"
        }

        $response = Invoke-RestMethod -ContentType "application/json" -Method Get -Uri $uri -Headers $headers -ErrorAction SilentlyContinue
        $sqladmins = $response.value.properties.login
        #>
        $sqladmins = $mysql.AdministratorLogin

        # Get other server properties
        $mysqlid = $mysql.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $properties = Get-AzResource -ResourceId $mysql.id -ErrorAction Stop      
        $Name = SanitizeString $mysql.Name
        $Location = SanitizeLocation $mysql.Location
        $data = "
        # $Name - $mysqlid
        subgraph cluster_$mysqlid {
            style = solid;
            
            bgcolor = 4;
        "
        $ImagePath = Join-Path $OutputPath "icons" "mysql.png"
        $data += "        $mysqlid [label = `"\n\n\nLocation: $Location\nSKU: $($mysql.SkuName)\nTier: $($mysql.SkuTier.ToString())\nVersion: $($mysql.Version)\nLogin Admins:$(SanitizeString $sqladmins)\nVM Size: $($properties.Sku.Name)\nAvailability Zone: $($mysql.AvailabilityZone)\nStandby Zone: $($mysql.HighAvailabilityStandbyAvailabilityZone)\nPublic Network Access: $($mysql.NetworkPublicNetworkAccess)`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 3.5;$(Generate-DotURL -resource $mysql)];"
        $data += "`n"
        
        $dbs = Get-AzMySqlFlexibleServerDatabase -ResourceGroupName $mysql.id.split("/")[4] -ServerName $mysql.Name -ErrorAction Stop
        $ImagePath = Join-Path $OutputPath "icons" "db.png"
        foreach ($db in $dbs) {
            $dbid = $db.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "        $($dbid) [label = `"\n\nName: $(SanitizeString $db.Name)\n`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];`n" 
            $data += "        $mysqlid -> $($dbid);`n"
        }

        if ($properties.properties.network.delegatedSubnetResourceId  ) {
            $mysqlsubnetid = $properties.properties.network.delegatedSubnetResourceId.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "        $mysqlid -> $($mysqlsubnetid);`n"
        }
        if ($properties.Identity.UserAssignedIdentities.Keys) {
            foreach ($identity in $properties.Identity.UserAssignedIdentities.Keys) { 
                $managedIdentityId = $identity.replace("-", "").replace("/", "").replace(".", "").ToLower() 
                $data += "        $mysqlid -> $managedIdentityId;`n"
            }
        }
        $data += "   label = `"$Name`";
                }`n"

        Export-AddToFile -Data $data

    }
    catch {
        Write-Host "Can't export MySQL Server: $($mysql.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

function Invoke-TableWriter {
    #    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [scriptblock]$GetDatabases,
        [Parameter(Mandatory = $true)]
        [scriptblock]$GetDBThroughput,
        [Parameter(Mandatory = $true)]
        [scriptblock]$GetCollections,
        [Parameter(Mandatory = $true)]
        [scriptblock]$GetColThrouput,
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$cosmosdbact,
        [Parameter(Mandatory = $true)]
        [string]$TypeName,
        [Parameter(Mandatory = $true)]
        [string]$iconname
    )
    $resourceGroupName = $cosmosdbact.Id.split("/")[4]
    $data = ""
    $dbs = & $GetDatabases -ResourceGroupName $resourceGroupName -AccountName $cosmosdbact.Name -ErrorAction Stop
    foreach ($db in $dbs) {
        $dbthroughput = & $GetDBThroughput -ResourceGroupName $resourceGroupName -AccountName $cosmosdbact.Name -Name $db.Name -ErrorAction SilentlyContinue
        if ($null -eq $dbthroughput) {
            $dbthroughput = "Unknown"
        }   
        else {
            $dbthroughput = $dbthroughput.Throughput
        }
        $table = "<TABLE border=`"0`" style=`"rounded`">`n"
        $table += "<TR><TD><BR/><BR/></TD></TR>`n"
        $table += "<TR><TD align=`"left`">Name</TD><TD align=`"left`">$(SanitizeString $db.Name)</TD></TR>`n"
        $table += "<TR><TD align=`"left`">Database Throughput</TD><TD align=`"left`">$dbthroughput</TD></TR>`n"
        $table += "<TR><TD><BR/><BR/></TD></TR>`n"
        $table += "<TR><TD align=`"left`"><B>$TypeName</B></TD><TD align=`"left`"><B>RU</B></TD></TR>"
        $collection = & $GetCollections -ResourceGroupName $resourceGroupName -AccountName $cosmosdbact.Name -DatabaseName $db.Name -ErrorAction SilentlyContinue
        if ($collection.count -gt 0) {
            $table += "<HR/>`n"
        }
        $colthroughputs = $collection | ForEach-Object {
            $collection = SanitizeString $_.Name
            $RU = (& $GetColThrouput  `
                    -ResourceGroupName $resourceGroupName `
                    -AccountName      $cosmosdbact.Name `
                    -DatabaseName     $db.Name `
                    -Name             $_.Name `
                    -ErrorAction      SilentlyContinue
            ).Throughput
            $table += "<TR><TD align=`"left`">$collection</TD><TD align=`"left`">$RU</TD></TR>`n"
        }
        $table += "</TABLE>`n"
        $dbid = $db.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $ImagePath = Join-Path $OutputPath "icons" "$iconname.png"
        $data += "        $dbid [shape = box; label = < $table > ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 3.0;];`n"
        $data += "        $cosmosdbactid -> $($dbid);`n"
    }
    return $data
}

<#
.SYNOPSIS
Exports details of a Cosmos DB account for inclusion in an infrastructure diagram.
.DESCRIPTION
This function processes a Cosmos DB account object and formats its details for the Azure infrastructure diagram.
.PARAMETER cosmosdbact
The Cosmos DB account object to process.
.EXAMPLE
Export-CosmosDBAccount -cosmosdbact $cosmosdbact
#>
function Export-CosmosDBAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$cosmosdbact
    )   
    
    try {
        $cosmosdbactid = $cosmosdbact.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $Locations = ($cosmosdbact.Locations.LocationName | ForEach-Object { SanitizeLocation $_ }) -join ", "
        $Name = SanitizeString $cosmosdbact.Name
        $data = "
        # $Name - $cosmosdbactid
        subgraph cluster_$cosmosdbactid {
            style = solid;
            bgcolor = 4;
            node [color = black;];
        "
        $ImagePath = Join-Path $OutputPath "icons" "cosmosdb.png"
        $data += "        $cosmosdbactid [label = `"Version: $($cosmosdbact.ApiProperties.ServerVersion)\nLocations: $Locations\nDefault Consistency Level: $($cosmosdbact.ConsistencyPolicy.DefaultConsistencyLevel)\nKind: $($cosmosdbact.Kind)\nDatabase Account Offer Type: $($cosmosdbact.DatabaseAccountOfferType)\nEnable Analytical Storage: $($cosmosdbact.EnableAnalyticalStorage)\nVirtual Network Filter Enabled: $($cosmosdbact.IsVirtualNetworkFilterEnabled)`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 3.0;$(Generate-DotURL -resource $cosmosdbact)];"
        $data += "`n"
        $resourceGroupName = $cosmosdbact.Id.split("/")[4]
        switch ($cosmosdbact.Kind) {
            #MongoDB
            "MongoDB" {  
                $data += Invoke-TableWriter `
                    -GetDatabases { param($ResourceGroupName, $AccountName) Get-AzCosmosDBMongoDBDatabase -ResourceGroupName $ResourceGroupName -AccountName $AccountName -ErrorAction Stop } `
                    -GetDBThroughput { param($ResourceGroupName, $AccountName, $Name) Get-AzCosmosDBMongoDBDatabaseThroughput -ResourceGroupName $ResourceGroupName -AccountName $AccountName -Name $Name -ErrorAction SilentlyContinue } `
                    -GetCollections { param($ResourceGroupName, $AccountName, $DatabaseName) Get-AzCosmosDBMongoDBCollection -ResourceGroupName $ResourceGroupName -AccountName $AccountName -DatabaseName $DatabaseName -ErrorAction SilentlyContinue } `
                    -GetColThrouput { param($ResourceGroupName, $AccountName, $DatabaseName, $Name) Get-AzCosmosDBMongoDBCollectionThroughput -ResourceGroupName $ResourceGroupName -AccountName $AccountName -DatabaseName $DatabaseName -Name $Name -ErrorAction SilentlyContinue } `
                    -CosmosDbAct $cosmosdbact `
                    -TypeName "Collection" `
                    -IconName "mongodb"
            }
            # NoSQL
            "GlobalDocumentDB" { 
                $data += Invoke-TableWriter `
                    -GetDatabases { param($ResourceGroupName, $AccountName) Get-AzCosmosDBSqlDatabase -ResourceGroupName $ResourceGroupName -AccountName $AccountName -ErrorAction Stop } `
                    -GetDBThroughput { param($ResourceGroupName, $AccountName, $Name) Get-AzCosmosDBSqlDatabaseThroughput -ResourceGroupName $ResourceGroupName -AccountName $AccountName -Name $Name -ErrorAction SilentlyContinue } `
                    -GetCollections { param($ResourceGroupName, $AccountName, $DatabaseName) Get-AzCosmosDBSqlContainer -ResourceGroupName $ResourceGroupName -AccountName $AccountName -DatabaseName $DatabaseName -ErrorAction SilentlyContinue } `
                    -GetColThrouput { param($ResourceGroupName, $AccountName, $DatabaseName, $Name) Get-AzCosmosDBSqlContainerThroughput -ResourceGroupName $ResourceGroupName -AccountName $AccountName -DatabaseName $DatabaseName -Name $Name -ErrorAction SilentlyContinue } `
                    -CosmosDbAct $cosmosdbact `
                    -TypeName "Container" `
                    -IconName "documentdb"
            }
            #Gremlin
            "Gremlin" {  
                $data += Invoke-TableWriter `
                    -GetDatabases { param($ResourceGroupName, $AccountName) Get-AzCosmosDBGremlinDatabase -ResourceGroupName $ResourceGroupName -AccountName $AccountName -ErrorAction Stop } `
                    -GetDBThroughput { param($ResourceGroupName, $AccountName, $Name) Get-AzCosmosDBGremlinDatabaseThroughput -ResourceGroupName $ResourceGroupName -AccountName $AccountName -Name $Name -ErrorAction SilentlyContinue } `
                    -GetCollections { param($ResourceGroupName, $AccountName, $DatabaseName) Get-AzCosmosDBGremlinGraph -ResourceGroupName $ResourceGroupName -AccountName $AccountName -DatabaseName $DatabaseName -ErrorAction SilentlyContinue } `
                    -GetColThrouput { param($ResourceGroupName, $AccountName, $DatabaseName, $Name) Get-AzCosmosDBGremlinGraphThroughput -ResourceGroupName $ResourceGroupName -AccountName $AccountName -DatabaseName $DatabaseName -Name $Name -ErrorAction SilentlyContinue } `
                    -CosmosDbAct $cosmosdbact `
                    -TypeName "Graph" `
                    -IconName "gremlin"
            }
            #Table
            "Table" {  
                $dbs = Get-AzCosmosDBTable -ResourceGroupName $$resourceGroupName -AccountName $cosmosdbact.Name -ErrorAction Stop
                $iconname = "table"
                foreach ($db in $dbs) {
                    $throughput = Get-AzCosmosDBTableThroughput -ResourceGroupName $resourceGroupName -AccountName $cosmosdbact.Name -Name $db.Name -ErrorAction SilentlyContinue
                    if ($null -eq $dbthroughput) {
                        $dbthroughput = "Unknown"
                    }   
                    else {
                        $dbthroughput = $dbthroughput.Throughput
                    }
                    $ImagePath = Join-Path $OutputPath "icons" "$iconname.png"
                    $dbid = $db.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
                    $data += "        $($dbid) [shape = box; label = `"\n\nName: $(SanitizeString $db.Name)\nTable Throughput: $dbthroughput\n`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 3.0;];`n" 
                    $data += "        $cosmosdbactid -> $($dbid);`n"
                }
            }   
            #Cassandra
            "Cassandra" { 
                $data += Invoke-TableWriter `
                    -GetDatabases { param($ResourceGroupName, $AccountName) Get-AzCosmosDBCassandraKeyspace -ResourceGroupName $ResourceGroupName -AccountName $AccountName -ErrorAction Stop } `
                    -GetDBThroughput { param($ResourceGroupName, $AccountName, $Name) Get-AzCosmosDBCassandraKeyspaceThroughput -ResourceGroupName $ResourceGroupName -AccountName $AccountName -Name $Name -ErrorAction SilentlyContinue } `
                    -GetCollections { param($ResourceGroupName, $AccountName, $DatabaseName) Get-AzCosmosDBCassandraTable -ResourceGroupName $ResourceGroupName -AccountName $AccountName -DatabaseName $DatabaseName -ErrorAction SilentlyContinue } `
                    -GetColThrouput { param($ResourceGroupName, $AccountName, $DatabaseName, $Name) Get-AzCosmosDBCassandraTableThroughput -ResourceGroupName $ResourceGroupName -AccountName $AccountName -DatabaseName $DatabaseName -Name $Name -ErrorAction SilentlyContinue } `
                    -CosmosDbAct $cosmosdbact `
                    -TypeName "Table" `
                    -IconName "cassandra"
            }

            default { 
                Write-Output "Unknown CosmosDB type: $($cosmosdbact.Kind)" 
                $iconname = $null
                $dbs = $null
            }
        }   
        # Add links to Virtual Network Rules, Private Endpoints, and Managed Identities
        foreach ($vnRule in $cosmosdbact.VirtualNetworkRules) {
            $vnRuleid = $vnRule.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "        $cosmosdbactid -> $($vnRuleid) [label = `"Virtual Network Rule`"; ];`n"
        }
        if ($cosmosdbact.PrivateEndpointConnections.PrivateEndpoint.Id) {
            $peid = $cosmosdbact.PrivateEndpointConnections.PrivateEndpoint.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "        $cosmosdbactid -> $peid [label = `"Private Endpoint`"; ];`n"
        }
        if ($cosmosdbact.Identity.UserAssignedIdentities.Keys) {
            foreach ($identity in $cosmosdbact.Identity.UserAssignedIdentities.Keys) { 
                $managedIdentityId = $identity.replace("-", "").replace("/", "").replace(".", "").ToLower() 
                $data += "        $cosmosdbactid -> $managedIdentityId;`n"
            } 
        }
        $data += "   label = `"$Name`";
                }`n"

        Export-AddToFile -Data $data
    }
    catch {
        Write-Host "Can't export Cosmos DB Account: $($cosmosdbact.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of a PostgreSQL Flexible Server for inclusion in an infrastructure diagram.
.DESCRIPTION
This function processes a PostgreSQL Flexible Server object and formats its details for the Azure infrastructure diagram.
.PARAMETER postgresql
The PostgreSQL Flexible Server object to process.
.EXAMPLE
Export-PostgreSQLServer -postgresql $postgresql
#>
function Export-PostgreSQLServer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$postgresql
    )
    try {
        $postgresqlid = $postgresql.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $Name = SanitizeString $postgresql.Name
        $data = "
        # $Name - $postgresqlid
        subgraph cluster_$postgresqlid {
            style = solid;
            bgcolor = 4;
            
            node [color = black;];
        "

        $resource = Get-AzResource -ResourceId $postgresql.Id -ErrorAction Stop
        # General Purpose, D4ds_v5 (SkuName), 4 vCores, 16 GiB RAM, 128 GiB storage $postgresql.StorageSizeGb
        $Location = SanitizeLocation (Get-AzLocation | Where-Object DisplayName -eq $postgresql.Location).Location 
        $SkuName = $postgresql.SkuName
        $SkuCaps = Get-AzComputeResourceSku -Location $postgresql.Location | Where-Object { $_.Name -eq $skuName }
        $iops = ($SkuCaps.Capabilities | Where-Object Name -eq "UncachedDiskIOPS").Value
        $vCPUs = ($SkuCaps.Capabilities | Where-Object Name -eq "vCPUs").Value
        $MemoryGB = ($SkuCaps.Capabilities | Where-Object Name -eq "MemoryGB").Value
        $config = $postgresql.SkuTier.ToString() + ", " + $postgresql.SkuName + ", " + $vCPUs + " vCores, " + $MemoryGB + " GiB RAM, " + $postgresql.StorageSizeGb + " GiB storage"
        $ImagePath = Join-Path $OutputPath "icons" "postgresql.png"
        $data += "        $postgresqlid [label = `"\nLocation: $Location\nVersion: $($postgresql.Version.ToString()).$($postgresql.MinorVersion)\nAvailability Zone: $($postgresql.AvailabilityZone)\nConfiguration: $config\nMax IOPS: $iops\nPublic Network Access: $($postgresql.NetworkPublicNetworkAccess.ToString())`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.5;$(Generate-DotURL -resource $postgresql)];"
        $data += "`n"

        $dbs = Get-AzPostgreSqlFlexibleServerDatabase -ResourceGroupName $postgresqlserver.id.split("/")[4] -ServerName $postgresqlserver.Name -ErrorAction Stop
        $ImagePath = Join-Path $OutputPath "icons" "db.png"
        foreach ($db in $dbs) {
            $dbid = $db.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "        $($dbid) [label = `"\n\nName: $(SanitizeString $db.Name)\n`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];`n" 
            $data += "        $postgresqlid -> $($dbid);`n"
        }
        if ($postgresql.NetworkDelegatedSubnetResourceId) {
            $postgresqlsubnetid = $postgresql.NetworkDelegatedSubnetResourceId.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "        $postgresqlid -> $($postgresqlsubnetid);`n"
        }
        if ($resource.Identity.UserAssignedIdentities.Keys) {
            foreach ($identity in $resource.Identity.UserAssignedIdentities.Keys) { 
                $managedIdentityId = $identity.replace("-", "").replace("/", "").replace(".", "").ToLower() 
                $data += "        $postgresqlid -> $managedIdentityId;`n"
            } 
        }
        $data += "   label = `"$Name`";
                }`n"

        Export-AddToFile -Data $data

    }
    catch {
        Write-Host "Can't export PostgreSQL Server: $($postgresql.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of a Redis server for inclusion in an infrastructure diagram.
.DESCRIPTION
This function processes a Redis server object and formats its details for the Azure infrastructure diagram.
.PARAMETER redis
The Redis server object to process.
.EXAMPLE
Export-RedisServer -redis $redis
#>
function Export-RedisServer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$redis
    )
    try {
        $redisid = $redis.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $Location = SanitizeLocation $redis.Location
        $Name = SanitizeString $redis.Name
        $data = "
        # $Name - $redisid
        subgraph cluster_$redisid {
            style = solid;
            colorscheme = puor9;
            bgcolor = 2;
            margin = 0;
            node [colorscheme = puor9; color = 2; margin = 0;]
        "
        $ImagePath = Join-Path $OutputPath "icons" "redis.png"
        $data += "        $redisid [label = `"\nLocation: $Location\nSKU: $($redis.Sku)\nRedis Version: $($redis.RedisVersion)\nZones: $($redis.Zone -join ", ")\nShard Count: $($redis.ShardCount)\n`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.5;$(Generate-DotURL -resource $redis)];"
        $data += "`n"
        if ($redis.PrivateEndpointConnection.PrivateEndpoint.Id) {
            $peid = $redis.PrivateEndpointConnection.PrivateEndpoint.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "        $redisid -> $peid [label = `"Private Endpoint`"; ];`n"
        }
        if ($redis.Identity.UserAssignedIdentities.Keys) {
            foreach ($identity in $redis.Identity.UserAssignedIdentities.Keys) { 
                $managedIdentityId = $identity.replace("-", "").replace("/", "").replace(".", "").ToLower() 
                $data += "        $redisid -> $managedIdentityId;`n"
            } 
        }
        $data += "   label = `"$Name`";
                }`n"

        Export-AddToFile -Data $data
    }
    catch {
        Write-Host "Can't export Redis Cache: $($redis.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of a SQL Managed Instance for inclusion in an infrastructure diagram.
.DESCRIPTION
This function processes a SQL Managed Instance object and formats its details for the Azure infrastructure diagram.
.PARAMETER sqlmi
The SQL Managed Instance object to process.
.EXAMPLE
Export-SQLManagedInstance -sqlmi $sqlmi
#>
function Export-SQLManagedInstance {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$sqlmi
    )
    try {
        $sqlmiid = $sqlmi.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $Location = SanitizeLocation $sqlmi.Location
        $Name = SanitizeString $sqlmi.ManagedInstanceName
        $data = "
        # $Name - $sqlmiid
        subgraph cluster_$sqlmiid {
            style = solid;
            bgcolor = 4;
           
        "
        $ImagePath = Join-Path $OutputPath "icons" "sqlmi.png"
        $data += "        $sqlmiid [label = `"\n\nLocation: $Location\nSKU: $($sqlmi.Sku.Tier) $($sqlmi.Sku.Family)\nVersion: $($sqlmi.DatabaseFormat)\nEntra Id Admin: $(SanitizeString $sqlmi.Administrators.Login)\nvCores: $($sqlmi.VCores)\nStorage Size: $($sqlmi.StorageSizeInGB) GB\nZone Redundant: $($sqlmi.ZoneRedundant)\nPublic endpoint (data): $($sqlmi.PublicDataEndpointEnabled)`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 3.5;$(Generate-DotURL -resource $sqlmi)];"
        $data += "`n"
        $ImagePath = Join-Path $OutputPath "icons" "sqlmidb.png"
        Get-AzSqlInstanceDatabase -InstanceResourceId $sqlmi.Id -ErrorAction SilentlyContinue |
        ForEach-Object {
            $db = $_
            $dbid = $_.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $Location = SanitizeLocation $db.Location
            $retention = Get-AzSqlInstanceDatabaseBackupShortTermRetentionPolicy -ResourceGroupName $db.ResourceGroupName -InstanceName $db.ManagedInstanceName -DatabaseName $db.Name -ErrorAction SilentlyContinue
            $data += "        $($dbid) [label = `"\n\nLocation: $Location\nName: $($db.DatabaseName)\nBackup retention: $($retention.RetentionDays) Days`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.0;$(Generate-DotURL -resource $_)];`n" 
            $data += "        $sqlmiid -> $($dbid);`n"
        }

        if ($sqlmi.SubnetId) {
            $sqlmisubnetid = $sqlmi.SubnetId.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "        $sqlmiid -> $($sqlmisubnetid);`n"
        }
        $data += "   label = `"$Name`";
                }`n"

        Export-AddToFile -Data $data
    }
    catch {
        Write-Host "Can't export SQL Managed Instance: $($sqlmi.ManagedInstanceName) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of a SQL Server for inclusion in an infrastructure diagram.
.DESCRIPTION
This function processes a SQL Server object and formats its details for the Azure infrastructure diagram.
.PARAMETER sqlserver
The SQL Server object to process.
.EXAMPLE
Export-SQLServer -sqlserver $sqlserver
#>
function Export-SQLServer {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$sqlserver
    )
    try {
        $sqlserverid = $sqlserver.ResourceId.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $Location = SanitizeLocation $sqlserver.Location
        $Name = SanitizeString $sqlserver.ServerName
        $data = "
        # $Name - $sqlserverid
        subgraph cluster_$sqlserverid {
            style = solid;
            bgcolor = 4;
            
        "
        $ImagePath = Join-Path $OutputPath "icons" "sqlserver.png"
        $data += "        $sqlserverid [label = `"\nLocation: $Location\nVersion: $($sqlserver.ServerVersion)\nEntra ID Admin: $(SanitizeString $sqlserver.Administrators.Login)`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.0;$(Generate-DotURL -resource $sqlserver)];"
        $data += "`n"

        # Iterate through all SQL databases hosted on that server
        Get-AzSqlDatabase -ServerName $sqlserver.ServerName -ResourceGroupName $sqlserver.ResourceGroupName -ErrorAction SilentlyContinue |
        ForEach-Object {
            $db = $_
            $dbid = $_.ResourceId.replace("-", "").replace("/", "").replace(".", "").ToLower()

            if ($db.Edition -ne "System" -and $db.SkuName -ne "System") {
                # Master databases
                # pricing tier , vCore-based DBs expose Family
                if ($db.Family) {
                    $pricingTier = $db.Edition + " " + $db.Family + " " + $db.Capacity + " vCores"
                }
                else {
                    $pricingTier = $db.Edition + " " + $db.ServiceObjectiveName + " " + $db.Capacity + " DTUs"
                }

                #Max storage size
                $gb = [math]::Round($db.MaxSizeBytes / 1GB, 2)   # 1 GB = 1 073 741 824 bytes
                $Location = SanitizeLocation $db.Location
                $ImagePath = Join-Path $OutputPath "icons" "sqldb.png"
                $data += "        $($dbid) [label = `"\n\nLocation: $Location\nName: $(SanitizeString $db.DatabaseName)\nPricing Tier: $pricingTier\nMax Size: $gb GB\nZone Redundant: $($db.ZoneRedundant)\nElastic Pool Name: $($db.ElasticPoolName ? (SanitizeString $db.ElasticPoolName) : 'N/A')`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.0;$(Generate-DotURL -resource $_)];`n" 
                $data += "        $sqlserverid -> $($dbid);`n"
            }
        }

        $data += "   label = `"$Name`";
                }`n"

        Export-AddToFile -Data $data
    }
    catch {
        Write-Host "Can't export SQL Server: $($sqlserver.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of an Event Hub namespace for inclusion in an infrastructure diagram.
.DESCRIPTION
This function processes an Event Hub namespace object and formats its details for the Azure infrastructure diagram.
.PARAMETER namespace
The Event Hub namespace object to process.
.EXAMPLE
Export-EventHub -namespace $namespace
#>
function Export-EventHub {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$namespace
    )
    try {
        $namespaceid = $namespace.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $Location = SanitizeLocation $namespace.Location
        $Name = SanitizeString $namespace.Name
        $data = "
        # $Name - $namespaceid
        subgraph cluster_$namespaceid {
            style = solid;
            bgcolor = 5;
        "
        $ImagePath = Join-Path $OutputPath "icons" "eventhub.png"
        $data += "        $namespaceid [label = `"\nLocation: $Location\nSKU: $($namespace.SkuName)\nTier: $($namespace.SkuTier)\nCapacity: $($namespace.SkuCapacity)\nZone Redundant: $($namespace.ZoneRedundant)`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.5;$(Generate-DotURL -resource $namespace)];"
        $data += "`n"
        
        # iterate through all event hubs hosted on that namespace
        Get-AzEventHub -NamespaceName $namespace.Name -ResourceGroupName $namespace.ResourceGroupName -ErrorAction SilentlyContinue |
        ForEach-Object {
            $eventhub = $_
            $eventhubid = $_.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $Location = SanitizeLocation $eventhub.Location
            $data += "        $($eventhubid) [label = `"\n\nLocation: $Location\nName: $(SanitizeString $eventhub.Name)\nMessage Retention: $($eventhub.MessageRetentionInDays)\nPartition Count: $($eventhub.PartitionCount)\n`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.0;$(Generate-DotURL -resource $_)];`n" 
            $data += "        $namespaceid -> $eventhubid;`n"
        }
        if ($namespace.PrivateEndpointConnection.PrivateEndpointId) {
            $peid = $namespace.PrivateEndpointConnection.PrivateEndpointId.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "        $namespaceid -> $peid [label = `"Private Endpoint`"; ];`n"
        }
        $data += "   label = `"$Name`";
                }`n"    
        Export-AddToFile -Data $data
    }
    catch {
        Write-Host "Can't export Event Hub Namespace: $($namespace.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of an App Service Plan for inclusion in an infrastructure diagram.
.DESCRIPTION
This function processes an App Service Plan object and formats its details for the Azure infrastructure diagram.
.PARAMETER plan
The App Service Plan object to process.
.EXAMPLE
Export-AppServicePlan -plan $plan
#>
function Export-AppServicePlan {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$plan
    )

    try {
        $resourceGroupName = $plan.Id.split("/")[4]
        $planid = $plan.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $Location = SanitizeLocation $plan.Location
        $Name = SanitizeString $plan.Name
        $data = "
        # $Name - $planid
        subgraph cluster_$planid {
            style = solid;
            bgcolor = 1;
            
            node [color = black;];
        "
        $ImagePath = Join-Path $OutputPath "icons" "appplan.png"
        $data += "        $planid [label = `"\nLocation: $Location\nSKU: $($plan.Sku.Name)\nTier: $($plan.Sku.Tier)\nKind: $($plan.Kind)\nCapacity: $($plan.Sku.Capacity)\nNumber of Apps: $($plan.NumberOfSites)\n`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.5;$(Generate-DotURL -resource $plan)];"
        $data += "`n"

        $ImagePath = Join-Path $OutputPath "icons" "appservices.png"
        # iterate through all web apps hosted on that plan
        Get-AzWebApp -ResourceGroupName $resourceGroupName -ErrorAction SilentlyContinue |
        Where-Object { $_.ServerFarmId -eq $plan.Id } |
        ForEach-Object {
            $app = $_
            $appid = $_.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $Location = SanitizeLocation $app.Location

            $data += "        $($appid) [label = `"\n\nLocation: $Location\nName: $(SanitizeString $app.Name)\nKind: $($app.Kind)\nHost Name: $(SanitizeString $app.DefaultHostName)\n`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.0;$(Generate-DotURL -resource $_)];`n" 
            $data += "        $planid -> $appid;`n"

            # Add links to Private Endpoints and Managed Identities
            if ($app.Identity.UserAssignedIdentities.Keys) {
                foreach ($identity in $app.Identity.UserAssignedIdentities.Keys) { 
                    $managedIdentityId = $identity.replace("-", "").replace("/", "").replace(".", "").ToLower() 
                    $data += "        $appid -> $managedIdentityId;`n"
                } 
            }
        }
        $data += "   label = `"$Name`";
                }`n"
        Export-AddToFile -Data $data
    }
    catch {
        Write-Host "Can't export AppService Plan: $($plan.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }

}

<#
.SYNOPSIS
Exports details of an API Management (APIM) instance for inclusion in an infrastructure diagram.
.DESCRIPTION
This function processes an APIM object and formats its details for the Azure infrastructure diagram.
.PARAMETER apim
The API Management object to process.
.EXAMPLE
Export-APIM -apim $apim
#>
function Export-APIM {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$apim
    )
    try {
        $apimid = $apim.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $Location = SanitizeLocation $apim.Location
        $Name = SanitizeString $apim.Name
        $data = "
        # $Name - $apimidexport-
        subgraph cluster_$apimid {
            style = solid;
            colorscheme = ylgnbu9;
            bgcolor = 4;
            node [colorscheme = ylgnbu9; color = 4;];
        "
        $apimCtx = New-AzApiManagementContext -ResourceGroupName $apim.ResourceGroupName -ServiceName $apim.name
        $prodCount = (Get-AzApiManagementProduct -Context $apimCtx -ErrorAction SilentlyContinue).Count
        $apiCount = (Get-AzApiManagementApi     -Context $apimCtx -ErrorAction SilentlyContinue).Count
        if ($null -eq $apim.PublicIPAddresses) {
            $PublicIPAddresses = "None"
        }
        else {
            $PublicIPAddresses = $apim.PublicIPAddresses
        }
        if ($null -eq $apim.PrivateIPAddresses) {
            $PrivateIPAddresses = "None"
        }
        else {
            $PrivateIPAddresses = $apim.PrivateIPAddresses
        }
        $ImagePath = Join-Path $OutputPath "icons" "apim.png"
        $data += "        $apimid [label = `"\nLocation: $Location\nSKU: $($apim.Sku)\nPlatform Version: $($apim.PlatformVersion)\nPublic IP Addresses: $PublicIPAddresses\nPrivate IP Addresses: $PrivateIPAddresses\nCapacity: $($apim.Capacity)\nZone: $($apim.Zone)\nPublic Network Access: $($apim.PublicNetworkAccess)\nProducts: $prodCount\nAPI's: $apiCount\nVirtual Network: $($apim.VpnType)`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.5;$(Generate-DotURL -resource $apim)];"
        $data += "`n"
        if ($apim.VirtualNetwork.SubnetResourceId) {
            $subnetid = $apim.VirtualNetwork.SubnetResourceId.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "        $apimid -> $subnetid;`n"
        }
        if ($apim.PrivateEndpointConnections.Id) {
            $peid = $apim.PrivateEndpointConnections.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "        $apimid -> $peid [label = `"Private Endpoint`"; ];`n"
        }
        $data += "   label = `"$Name`";
                }`n"

        Export-AddToFile -Data $data
    }
    catch {
        Write-Host "Can't export APIM: $($apim.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of an Azure Container Registry (ACR) for inclusion in an infrastructure diagram.
.DESCRIPTION
This function processes an Azure Container Registry object and formats its details for the Azure infrastructure diagram.
.PARAMETER acr
The Azure Container Registry object to process.
.EXAMPLE
Export-ACR -acr $acr
#>
function Export-ACR {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$acr
    )   
    
    try {
        $acrid = $acr.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $Location = SanitizeLocation $acr.Location
        $Name = SanitizeString $acr.Name
        $data = "
        # $Name - $acrid
        subgraph cluster_$acrid {
            style = solid;
            margin = 0;
            colorscheme = orrd9;
            bgcolor = 2;
            node [colorscheme = orrd9; color = 2; margin = 0;];
        "
        $ImagePath = Join-Path $OutputPath "icons" "acr.png"
        $data += "        $acrid [label = `"\nACR Name: $Name\nLocation: $Location\nSKU: $($acr.SkuName.ToString())\nZone Redundancy: $($acr.ZoneRedundancy.ToString())\nPublic Network Access: $($acr.PublicNetworkAccess.ToString())\n`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.5;$(Generate-DotURL -resource $acr)];"
        $data += "`n"

        #Repositories
        $acrid = $acr.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $repos = Get-AzContainerRegistryRepository -RegistryName $acr.name
        $repos | ForEach-Object {
            $reponame = SanitizeString $_
            $repo = $_.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $ImagePath = Join-Path $OutputPath "icons" "imagedefversions.png"
            $data += "              $acrid$repo [label = `"Repository: $reponame`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];"
            $data += "              $acrid -> $acrid$repo`n" #Repos do not have IDs

            #$tags = Get-AzContainerRegistryTag -RepositoryName $repo -RegistryName $acr.name
        }


        if ($acr.PrivateEndpointConnection.PrivateEndpointId) {
            $acrpeid = $acr.PrivateEndpointConnection.PrivateEndpointId.ToString().replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "        $acrid -> $($acrpeid) [label = `"Private Endpoint`"; ];`n"
        }
        $data += "   label = `"$Name`";
                }`n"

        Export-AddToFile $data

    }
    catch {
        Write-Host "Can't export ACR: $($acr.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of a Storage Account for inclusion in an infrastructure diagram.
.DESCRIPTION
This function processes a Storage Account object and formats its details for the Azure infrastructure diagram.
.PARAMETER storageaccount
The Storage Account object to process.
.EXAMPLE
Export-StorageAccount -storageaccount $storageaccount
#>
function Export-StorageAccount {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$storageaccount
    )   
    
    try {
        $staid = $storageaccount.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $Location = SanitizeLocation $storageaccount.Location
        $Name = SanitizeString $storageaccount.StorageAccountName
        $data = "
        # $Name - $staid
        subgraph cluster_$staid {
            style = solid;
            margin = 0;
            colorscheme = bugn9;
            bgcolor = 2;
            node [colorscheme = bugn9; color = 2; margin = 0;];

        "
        if ($storageaccount.PublicNetworkAccess -eq "Disabled") {
            $PublicNetworkAccess = "Disabled"
        }   
        elseif ($storageaccount.NetworkRuleSet.DefaultAction -eq "Allow") {
            $PublicNetworkAccess = "Enabled from all networks"
        }
        else {
            $PublicNetworkAccess = "Enabled from selected virtual`nnetworks and IP addresses"
        }
        $HierarchicalNamespace = $storageaccount.EnableHierarchicalNamespace ? "Enabled" : "Disabled"
        $ImagePath = Join-Path $OutputPath "icons" "storage-account.png"
        $data += "        $staid [label = `"\n\nLocation: $Location\nSKU: $($storageaccount.Sku.Name)\nKind: $($storageaccount.Kind)\nPublic Network Access: $PublicNetworkAccess\nAccess Tier: $($storageaccount.AccessTier)\nHierarchical Namespace: $HierarchicalNamespace\n`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 3.0;$(Generate-DotURL -resource $storageaccount)];"
        $data += "`n"
        
        #File Shares
        try {
            #Shares that are not snapshots
            $shares = $storageaccount | Get-AzStorageShare | Where-Object {$_.IsSnapshot -eq $false}

            if ( $null -ne $shares ) {
                $shares | ForEach-Object {
                    $share = $_
                    $sharename = SanitizeString $share.Name
                    $shareid = ("$staid$sharename").replace("-", "").replace("/", "").replace(".", "").ToLower()
                    $sharequota = $share.Quota
                    $shareaccesstier = $share.ListShareProperties.Properties.AccessTier

                    $Script:Legend += ,@("Azure File Share", "azurefileshare.png")
                    $ImagePath = Join-Path $OutputPath "icons" "azurefileshare.png"

                    $data += "        $shareid [label = `"Name: $sharename\nQuota in GiB: $sharequota\nAccess tier: $shareaccesstier`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.0;];`n"
                    $data += "      $staid -> $shareid`n"
                }
            }
        } catch {
            # No access to shares
            $Script:Legend += ,@("Azure File Share", "azurefileshare.png")
            $ImagePath = Join-Path $OutputPath "icons" "azurefileshare.png"
            $data += "        $($staid)sharenoaccess [label = `"Unknown\nPermission denied when looking look up File Shares`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.0;];`n"
            $data += "      $staid -> $($staid)sharenoaccess`n"
        }

        #Containers
        try {    
            $containers =  $storageaccount | Get-AzStorageContainer

            if ( $null -ne $containers ) {
                $containers | ForEach-Object {
                    $container = $_
                    $containername = SanitizeString $container.Name
                    $containerid = ("$staid$containername").replace("-", "").replace("/", "").replace(".", "").ToLower()
                    #$sharequota = $share.Quota
                    #$shareaccesstier = $share.ListShareProperties.Properties.AccessTier

                    $Script:Legend += ,@("Azure Storage Account Container", "storage-account-container.png")
                    $ImagePath = Join-Path $OutputPath "icons" "storage-account-container.png"

                    $data += "        $containerid [label = `"Name: $containername`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.0;];`n"
                    $data += "      $staid -> $containerid`n"
                }
            }
        } catch {
            # No access to Containers
            $Script:Legend += ,@("Azure Storage Account Container", "storage-account-container.png")
            $ImagePath = Join-Path $OutputPath "icons" "storage-account-container.png"
            $data += "        $($staid)containernoaccess [label = `"Unknown\nPermission denied when looking look up containers`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.0;];`n"
            $data += "      $staid -> $($staid)containernoaccess`n"
        }
        
        
        $peids = Get-AzPrivateEndpointConnection -PrivateLinkResourceId $storageaccount.Id -ErrorAction Stop
        
        if ($peids) {
            foreach ($peid in $peids) {
                $stapeid = $peid.PrivateEndpoint.Id.ToString().replace("-", "").replace("/", "").replace(".", "").ToLower()
                $data += "        $staid -> $($stapeid) [label = `"Private Endpoint`"; ];`n"
            }
        }
        $data += "   label = `"$Name`";
                }`n"

        Export-AddToFile $data

    }
    catch {
        Write-Host "Can't export Storage Account: $($storageaccount.StorageAccountName) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of an Azure Firewall and its associated policies for inclusion in an infrastructure diagram.

.DESCRIPTION
The `Export-AzureFirewall` function processes a specified Azure Firewall object, retrieves its details, and formats the data for inclusion in an infrastructure diagram. It visualizes the firewall's name, private and public IP addresses, SKU tier, zones, and associated firewall policies, including DNS settings and IP groups.

.PARAMETER FirewallId
Specifies the unique identifier of the Azure Firewall to be processed.

.PARAMETER ResourceGroupName
Specifies the resource group of the Azure Firewall.

.EXAMPLE
PS> Export-AzureFirewall -FirewallId "/subscriptions/xxxx/resourceGroups/rg1/providers/Microsoft.Network/azureFirewalls/fw1" -ResourceGroupName "rg1"

This example processes the specified Azure Firewall and exports its details for inclusion in an infrastructure diagram.

#>
function Export-AzureFirewall {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$FirewallId,
        [Parameter(Mandatory = $true)]
        [string]$ResourceGroupName
    )

    try {
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
                    
                    $PublicIps += SanitizeString (Get-AzPublicIpAddress -ResourceGroupName $publicIpRG -Name $publicIpName -ErrorAction Stop).IpAddress
                }
            }
        }
        else {
            # Hub Integrated Azure Firewall
            $PrivateIPAddress = $azFW.HubIPAddresses.PrivateIPAddress
            $PublicIPs = ""
            foreach ($publicIP in $azFW.HubIPAddresses.PublicIPs.Addresses) { $PublicIPs += ((SanitizeString $publicIP.Address) + "\n") }
        }
        $ImagePath = Join-Path $OutputPath "icons" "afw.png"
        $data = "`n"
        $data += "          $azFWId [label = `"\n\n$(SanitizeString $azFWName)\nPrivate IP Address: $(SanitizeString $PrivateIPAddress)\nSKU Tier: $($azfw.Sku.Tier)\nZones: $($azfw.zones -join "," )\nPublic IP(s):\n$($PublicIPs -join "\n")`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;$(Generate-DotURL -resource $azfw)];" 

        # Get the Azure Firewall policy
        if ($null -ne $azfw.FirewallPolicy.id) {
            $firewallPolicyName = $azfw.FirewallPolicy.id.split("/")[-1]
            $firewallPolicy = Get-AzFirewallPolicy -ResourceGroupName $ResourceGroupName -Name $firewallPolicyName -ErrorAction Stop
            $fwpolid = $firewallPolicy.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()

            $dnsservers = $firewallPolicy.DnsSettings.Servers
            if ( $null -eq $dnsserver) { $dnsservers = "None"}

            $ImagePath = Join-Path $OutputPath "icons" "firewallpolicy.png"
            $data += "`n"
            $data += "          $fwpolid [label = `"\n\n$(SanitizeString $firewallPolicyName)\nSKU Tier: $($firewallPolicy.sku.tier)\nThreat Intel Mode: $($firewallPolicy.ThreatIntelMode)\nDNS Servers: $(($dnsservers|ForEach-Object {SanitizeString $_}) -join '; ')\nProxy Enabled: $($firewallPolicy.DnsSettings.EnableProxy)`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;$(Generate-DotURL -resource $firewallPolicy)];" 
            $data += "`n        $azFWId -> $fwpolid;"

            for ($i = 0; $i -lt $firewallPolicy.DnsSettings.Servers.Count; $i++) {
                $index = [array]::indexof($script:PDNSREpIp, $firewallPolicy.DnsSettings.Servers[$i])
                if ($index -ge 0) {
                    $data += "        $fwpolid -> $($script:PDNSRId[$index]) [label = `"DNS Query`"; ];`n" 
                }
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
            if ( $ipGroupIds.count -ne 0 ) {
                $ipGroupIds = $ipGroupIds.replace("-", "").replace("/", "").replace(".", "").ToLower()
                foreach ($ipGroupId in $ipGroupIds) {
                    $data += "`n    $fwpolid -> $ipGroupId;"
                }
            }
        }
        return $data
    }
    catch {
        Write-Host "Can't export Azure Firewall: $($azFWName) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of a Virtual WAN Hub for inclusion in an infrastructure diagram.

.DESCRIPTION
The `Export-Hub` function processes a specified Virtual WAN Hub object, retrieves its details, and formats the data for inclusion in an infrastructure diagram. It visualizes the hub's name, location, SKU, address prefix, routing preference, and associated resources such as VPN gateways, ExpressRoute gateways, and Azure Firewalls.

.PARAMETER hub
Specifies the Virtual WAN Hub object to be processed.

.EXAMPLE
PS> Export-Hub -hub $vwanHub

This example processes the specified Virtual WAN Hub and exports its details for inclusion in an infrastructure diagram.

#>
function Export-Hub {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$hub
    )
    $vwanname = $hub.VirtualWan.id.Split("/")[-1]
    $hubname = $hub.Name
    $hubrgname = $hub.ResourceGroupName
    $Name = SanitizeString $hubname
    $id = $hub.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
    $location = SanitizeLocation $hub.Location
    $sku = $hub.Sku
    $AddressPrefix = $hub.AddressPrefix
    $HubRoutingPreference = $hub.HubRoutingPreference
    $Script:Legend += ,@("vWAN Hub", "vWAN-Hub.png")

    try {
        Write-Host "Collecting vWAN Hub info: $vwanname/$hubname"
        # DOT
        # Hub details
        $data = "
            # $Name - $id
            subgraph cluster_$id {
                style = solid;
                bgcolor = 7;   
                node [ color = black; ];             
            "

        $ImagePath = Join-Path $OutputPath "icons" "vWAN-Hub.png"
        # Find out the Hub's own vNet
        if ($null -ne $hub.VirtualNetworkConnections) {
            $vnetname = ($hub.VirtualNetworkConnections[0].RemoteVirtualNetwork.id).Split("/")[-1]
            $vnetrg = ($hub.VirtualNetworkConnections[0].RemoteVirtualNetwork.id).Split("/")[4]
            
            # In cases where first VNet connection is from another subscription - changing context is necessary, temporarily
            $currentcontext = (Get-AzContext).Subscription.Id
            $tempcontext = ($hub.VirtualNetworkConnections[0].RemoteVirtualNetwork.id).Split("/")[2]
            $null = Set-AzContext $tempcontext
            $vnet = Get-AzVirtualNetwork -name $vnetname -ResourceGroupName $vnetrg -ErrorAction Stop
            $null = Set-AzContext $currentcontext
                        
            $HubvNetID = $vnet.VirtualNetworkPeerings.RemoteVirtualNetwork.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $headid = $HubvNetID
            $script:AllInScopevNetIds += $vnet.VirtualNetworkPeerings.RemoteVirtualNetwork.id

            $data += "    $HubvNetID [label = `"\n\n$Name\nLocation: $location\nSKU: $sku\nAddress Prefix: $(SanitizeString $AddressPrefix)\nHub Routing Preference: $HubRoutingPreference`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.5;];"
        }
        else {
            $data += "        $id [label = `"\n$Name\nLocation: $location\nSKU: $sku\nAddress Prefix: $(SanitizeString $AddressPrefix)\nHub Routing Preference: $HubRoutingPreference`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.5;];"
            $headid = $id
        }
        $script:rankvwanhubs += $headid

        # Hub Items
        if ($null -ne $hub.VpnGateway) {
            $Script:Legend += ,@("vWAN-VPN-Gateway", "vgw.png")
            $vgwId = $hub.VpnGateway.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $vgwName = $hub.VpnGateway.id.split("/")[-1]
            $vgwNameShort = $vgwName.split("-")[1, 2, 3] -join ("-")
            $vpngw = Get-AzVpnGateway -ResourceGroupName $hub.ResourceGroupName -Name $vgwName -ErrorAction Stop
            $ImagePath = Join-Path $OutputPath "icons" "vgw.png"
            $data += "`n"
            $data += "        $vgwId [label = `"\n\n$(SanitizeString $vgwNameShort)\nScale Units: $($vpngw.VpnGatewayScaleUnit)\nPublic IP(s):\n$(($vpngw.IpConfigurations.PublicIpAddress | ForEach-Object {SanitizeString $_}) -join ",")\n`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 
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
                    $vpnsiteName = SanitizeString $VpnSite.Name
                    $peerip = $vpnSite.VpnSiteLinks.IpAddress
                    $ImagePath = Join-Path $OutputPath "icons" "VPN-Site.png"
                    $data += "`n"
                    $data += "        $vpnsiteId [label = `"\n\n$(SanitizeString $vpnsiteName)\nDevice Vendor: $($VpnSite.DeviceProperties.DeviceVendor)\nLink Speed: $($VpnSite.VpnSiteLinks.LinkProperties.LinkSpeedInMbps) Mbps\nLinks: $($VpnSite.VpnSiteLinks.count)\n\nPeer : $(SanitizeString $peerip)\nAddressPrefixes: $(($VpnSite.AddressSpace.AddressPrefixes | ForEach-Object {SanitizeString $_}) -join ",")\n`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 
                    $data += "`n    $vgwId -> $vpnsiteId;"
                }
            }
        }

        if ($null -ne $hub.ExpressRouteGateway) {
            $Script:Legend += ,@("ER Gateway", "ergw.png")
            $ergwId = $hub.ExpressRouteGateway.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $ergwName = $hub.ExpressRouteGateway.id.split("/")[-1]
            $ergwshortname = $ergwName.split("-")[1, 2, 3] -join ("-")
            $ergw = Get-AzExpressRouteGateway -ResourceGroupName $hub.ResourceGroupName -Name $ergwName -ErrorAction Stop
            $ImagePath = Join-Path $OutputPath "icons" "ergw.png"
            $data += "`n"
            $data += "        $ergwId [label = `"\n\n\n$(SanitizeString $ergwshortname)\nAuto Scale Configuration: $($ergw.AutoScaleConfiguration.Bounds.min)-$($ergw.AutoScaleConfiguration.Bounds.max)`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 
            $data += "`n    $headid -> $ergwId;"
            $peerings = $ergw.ExpressRouteConnections.ExpressRouteCircuitPeering.id
            foreach ($peering in $peerings) {
                $peeringId = $peering.replace("-", "").replace("/", "").replace(".", "").replace("peeringsAzurePrivatePeering", "").ToLower()
                $data += "`n    $ergwId -> $peeringId ;"
            }
        }
        if ($null -ne $hub.P2SVpnGateway) {
            $Script:Legend += ,@("P2S VPN Gateway", "VPN-User.png")
            $p2sgwId = $hub.P2SVpnGateway.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $p2sgwName = $hub.P2SVpnGateway.id.split("/")[-1]
            $p2sgwNameShort = $p2sgwName.split("-")[1, 2, 3] -join ("-")
            $p2sgw = Get-AzP2sVpnGateway -ResourceName $p2sgwName
            $cidr = $p2sgw.P2SConnectionConfigurations.VpnClientAddressPool.AddressPrefixes

            $configname = $p2sgw.P2SConnectionConfigurations.Name
            $configid = $p2sgw.P2SConnectionConfigurations.Id
            
            $vpnserverconfigs = Get-AzVpnServerConfiguration -ResourceGroupName $hubrgname
            $vpnserverconfig = ''
            foreach ( $config in $vpnserverconfigs ) { 
                if ( $config.P2SVpnGateways.id -eq $p2sgw.id ) { $vpnserverconfig = $config }
            }
                     
            $protocol = $vpnserverconfig.VpnProtocols
            $auth = $vpnserverconfig.VpnAuthenticationTypes
            $ImagePath = Join-Path $OutputPath "icons" "VPN-User.png"
            $data += "`n"
            $data += "        $p2sgwId [label = `"\n\n$(SanitizeString $p2sgwNameShort)\nProtocol: $protocol, Auth: $auth\nP2S Address Prefixes: $(($cidr | ForEach-Object {SanitizeString $_}) -join ", ")`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];" 
            $data += "`n    $headid -> $p2sgwId;"
        }
        if ($null -ne $hub.AzureFirewall) {
            $data += Export-AzureFirewall -FirewallId $hub.AzureFirewall.id -ResourceGroupName $hub.ResourceGroupName
            $azFWId = $hub.AzureFirewall.id.replace("-", "").replace("/", "").replace(".", "").ToLower()

            $data += "`n                $headid -> $azFWId [label = `"Secure Hub`"];"
        }
        $vWANId = $hub.VirtualWAN.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $data += "`n                $vWANId -> $headid [label = `"vWAN Hub`"];"
        $footer = "
                label = `"$Name`";
                }
        "
        $data += $footer

        return $data
    }
    catch {
        Write-Error "Can't export Hub: $($hub.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
        return $null
    }
}

<#
.SYNOPSIS
Exports details of a Virtual Network Gateway for inclusion in an infrastructure diagram.

.DESCRIPTION
The `Export-VirtualGateway` function processes a specified Virtual Network Gateway object, retrieves its details, and formats the data for inclusion in an infrastructure diagram. It visualizes the gateway's name, type (VPN or ExpressRoute), and associated public IP addresses.

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

This example processes the specified Virtual Network Gateway and exports its details for inclusion in an infrastructure diagram.

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

    $script:rankvgws += $GatewayId

    # ER vs VPN GWs are handled differently
    if ($gwtype -eq "Vpn" ) {
        $gwipobjetcs = $gw.IpConfigurations.PublicIpAddress
        $gwips = ""
        $gwipobjetcs.id | ForEach-Object {
            $rgname = $_.split("/")[4]
            $ipname = $_.split("/")[8]
            $publicip = SanitizeString (Get-AzPublicIpAddress -ResourceName $ipname -ResourceGroupName $rgname -ErrorAction Stop).IpAddress
            $gwips += "$(SanitizeString $ipname) : $publicip \n"
        
        }
        $ImagePath = Join-Path $OutputPath "icons" "vgw.png"
        $data += "            $GatewayId [fillcolor = 7;label = `"\n\nName: $(SanitizeString $GatewayName)`\n\nPublic IP(s):\n$gwips`";image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;$(Generate-DotURL -resource $gw)];"

        # Get P2S conf, if configured
        $protocol = $gw.VpnClientConfiguration.VpnClientProtocols
        $cidr = $gw.VpnClientConfiguration.VpnClientAddressPool.AddressPrefixes
        $auth = $gw.VpnClientConfiguration.VpnAuthenticationTypes
        $customroutes = $gw.CustomRoutes.AddressPrefixes

        if ($null -ne $auth) {
            $Script:Legend += ,@("P2S VPN Gateway", "VPN-User.png")
            #P2S config present
            $ImagePath = Join-Path $OutputPath "icons" "VPN-User.png"
            $data += "            ${GatewayId}P2S [fillcolor = 8;label = `"\n\nProtocol: $protocol, Auth: $auth\nP2S Address Prefix: $(SanitizeString $cidr)\nCustom routes: $(($customroutes | ForEach-Object {SanitizeString $_}) -join ",")`"; image = `"$ImagePath`"; imagepos = `"tc`"; labelloc = `"b`"; height = 1.5;]; "
            $data += "            $GatewayId -> ${GatewayId}P2S"
        } 
    }
    elseif ($gwtype -eq "ExpressRoute") {
        $Script:Legend += ,@("ER Gateway", "ergw.png")
        $ImagePath = Join-Path $OutputPath "icons" "ergw.png"
        $data += "        $GatewayId [fillcolor = 3; label = `"\nName: $(SanitizeString $GatewayName)`"; image = `"$ImagePath`"; imagepos = `"tc`"; labelloc = `"b`"; height = 1.5;$(Generate-DotURL -resource $gw)]; "
    }
    $data += "`n"
    $data += "            $HeadId -> $GatewayId"
    $data += "`n"

    return $data

}

<#
.SYNOPSIS
Exports details of a subnet configuration for inclusion in an infrastructure diagram.

.DESCRIPTION
The `Export-SubnetConfig` function processes a list of subnet objects, retrieves their details, and formats the data for inclusion in an infrastructure diagram. It visualizes subnet properties such as name, address prefix, associated NSGs, route tables, NAT gateways, and special configurations like Azure Firewall, Bastion, and Gateway subnets.

.PARAMETER subnets
Specifies the list of subnet objects to be processed.

.EXAMPLE
PS> Export-SubnetConfig -subnets $subnetList

This example processes the specified list of subnets and exports their details for inclusion in an infrastructure diagram.

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
            $AddressPrefix = SanitizeString $subnet.AddressPrefix
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
                $nsgid = $subnet.NetworkSecurityGroup.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
                if ($nsgid -ne "null") { 
                    $data += "`n        $id -> $nsgid`n"
                }
            }

            ### Route Table ###
            $routetableid = $subnet.RouteTableText.ToLower()
            if ($routetableid -ne "null" ) { $routetableid = (($subnet.RouteTableText | ConvertFrom-Json).id).replace("-", "").replace("/", "").replace(".", "").ToLower() }
            if ($routetableid -ne "null" ) { $data += "        $id -> $routetableid" + "`n" }

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
                    $ImagePath = Join-Path $OutputPath "icons" "afw.png"
                    $Script:Legend += ,@("Azure Firewall", "afw.png") 
                    if ( $null -ne $subnet.IpConfigurations.Id ) {
                        #Firewall deployed
                        $AzFWid = $subnet.IpConfigurations.Id.ToLower().split("/azurefirewallipconfigurations/")[0]
                        $AzFWrg = $subnet.IpConfigurations.id.split("/")[4]

                        $data += "            $id [label = `"\n\n$name\n$AddressPrefix`" ; fillcolor = 9; image = `"$ImagePath`"; imagepos = `"tc`"; labelloc = `"b`"; height = 1.5; ]; " 

                        $data += Export-AzureFirewall -FirewallId $AzFWid -ResourceGroupName $AzFWrg
                        $AzFWDotId = $AzFWid.replace("-", "").replace("/", "").replace(".", "").ToLower()
                        $data += "`n            $id -> $azFWDotId"
                    }
                    else {
                        # No firewall deployed
                        $data += "            $id [label = `"\n\n$name\n$AddressPrefix\nName: Firewall not deployed`" ; fillcolor = 9; image = `"$ImagePath`"; imagepos = `"tc`"; labelloc = `"b`"; height = 1.5; ]; "
                    }
                }
                "AzureBastionSubnet" { 
                    if ( $null -ne $subnet.IpConfigurations.Id ) { 
                        $AzBastionName = SanitizeString $subnet.IpConfigurations.Id.split("/")[8].ToLower()
                        $AzBastionRGName = $subnet.IpConfigurations.Id.split("/")[4].ToLower()
                        $AzBastion = Get-AzBastion -ResourceGroupName $AzBastionRGName -Name $subnet.IpConfigurations.Id.split("/")[8].ToLower()
                        $AzBastionSKU = ($AzBastion.SkuText | ConvertFrom-JSON).Name
                        $AzBastionLink = $(Generate-DotURL -resource $AzBastion)
                    }
                    else {
                        $AzBastionName = "Bastion not deployed" 
                        $AzBastionSKU = "None"
                    }

                    $ImagePath = Join-Path $OutputPath "icons" "bas.png"
                    $Script:Legend += ,@("Azure Bastion", "bas.png")
                    
                    $data += "            $id [label = `"\n\n$name\n$AddressPrefix\nName: $AzBastionName`\nSKU: $AzBastionSKU`" ; fillcolor = 6; image = `"$ImagePath`"; imagepos = `"tc`"; labelloc = `"b`"; height = 1.5;$AzBastionLink]; " 
                }
                "AppGatewaySubnet" { 
                    if ( $null -ne $subnet.IpConfigurations.Id ) { 
                        $AppGatewayName = SanitizeString $subnet.IpConfigurations.Id.split("/")[8].ToLower()
                        #$AppGatewayRGName = $subnet.IpConfigurations.Id.split("/")[4].ToLower()
                        #$AppGateway = Get-
                        $ImagePath = Join-Path $OutputPath "icons" "agw.png"
                        $Script:Legend += ,@("Application Gateway", "agw.png")
                    
                        $data += "            $id [label = `"\n\n$name\n$AddressPrefix\nName: $AppGatewayName`" ; fillcolor = 5; image = `"$ImagePath`"; imagepos = `"tc`"; labelloc = `"b`"; height = 1.5; ]; " 
                    }
                }
                "GatewaySubnet" { 
                    $ImagePath = Join-Path $OutputPath "icons" "vgw.png"
                    $Script:Legend += ,@("Virtual Network Gateway", "vgw.png")
                    $data += "            $id [label = `"\n\n$name\n$AddressPrefix`"; fillcolor = 4; image = `"$ImagePath`"; imagepos = `"tc`"; labelloc = `"b`"; height = 1.5; ]; " 
                    $data += "`n"
                    
                    #GW DOT
                    if ( $null -ne $subnet.IpConfigurations.Id ) {
                        foreach ($subnet in $subnet.IpConfigurations.Id) {
                            $gwid = $subnet.split("/ipConfigurations/")[0].replace("-", "").replace("/", "").replace(".", "").ToLower()
                            $gwname = $subnet.split("/")[8].ToLower()
                            $gwrg = $subnet.split("/")[4].ToLower()
                            $data += Export-VirtualGateway -GatewayName $gwname -ResourceGroupName $gwrg -GatewayId $gwid -HeadId $id
                        }
                    }
                }
                default { 
                    ##### Subnet delegations #####
                    $subnetDelegationName = $subnet.Delegations.Name
                    
                    if ( $null -ne $subnetDelegationName ) {
                        # Delegated
                        $iconname = ""
                        switch ($subnetDelegationName) {
                            "Microsoft.Web/serverFarms" { $iconname = "appplan" }
                            "Microsoft.Sql/managedInstances" { $iconname = "sqlmi" } 
                            "Microsoft.Network/dnsResolvers" { $iconname = "dnspr" }
                            Default { $iconname = "snet" }
                        }
                        $ImagePath = Join-Path $OutputPath "icons" "$iconname.png"
                        $data = $data + "            $id [label = `"\n\n$(SanitizeString $name)\n$AddressPrefix\n\nDelegated to:\n$subnetDelegationName`" ; fillcolor = 3; image = `"$ImagePath`"; imagepos = `"tc`"; labelloc = `"b`"; height = 1.5; ]; " 
                    }
                    else {
                        # No Delegation
                        $ImagePath = Join-Path $OutputPath "icons" "snet.png"
                        $data = $data + "            $id [label = `"\n\n$(SanitizeString $name)\n$AddressPrefix`" ; fillcolor = 9; image = `"$ImagePath`"; imagepos = `"tc`"; labelloc = `"b`"; height = 1.5; ]; " 
                    }
                    $data += "`n"
                    foreach ($pe in $subnet.PrivateEndpoints) {
                        $peid = $pe.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
                        $data += "            $id -> $peid [label = `"Private Endpoint`"; ] ; `n"
                    }
                }
            }
            $data += "`n"
            
            # DOT VNET->Subnet
            $data = $data + "            $vnetid -> $id"
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
                if ($ips.id) {
                    $ips.id | ForEach-Object {
                        $rgname = $_.split("/")[4]
                        $ipname = $_.split("/")[8]
                        $publicip = SanitizeString (Get-AzPublicIpAddress -ResourceName $ipname -ResourceGroupName $rgname -ErrorAction Stop).IpAddress
                        $ipsstring += "$ipname : $publicip \n"
                    }
                }
                #Public IP prefixes associated
                $ipprefixes = $NATGWobject.PublicIpPrefixes
                $ipprefixesstring = ""
                if ( $ipprefixes.id -ne "" -and $null -ne $ipprefixes.id ) {
                    $ipprefixes.id | ForEach-Object {
                        $rgname = $_.split("/")[4]
                        $ipname = $_.split("/")[8]
                        $ipprefix = SanitizeString (Get-AzPublicIpPrefix -Name $ipname -ResourceGroupName $rgname -ErrorAction Stop).IpPrefix
                        $ipprefixesstring += "$ipname : $ipprefix \n"
                    }
                }
                if ( $ipsstring -eq "" ) { $ipsstring = "None" }
                if ( $ipprefixesstring -eq "" ) { $ipprefixesstring = "None" }
                
                $ImagePath = Join-Path $OutputPath "icons" "ng.png" 
                $data += "            $NATGWID [fillcolor = 9; label = `"\n\nName: $(SanitizeString $name)\n\nPublic IP(s):\n$ipsstring\nPublic IP Prefix(es):\n$ipprefixesstring`"; image = `"$ImagePath`"; imagepos = `"tc`"; labelloc = `"b`"; height = 1.5;$(Generate-DotURL -resource $NATGWobject)]; `n"
                $data += "            $id -> $NATGWID" + "`n"

            }
        }
    }
    catch {
        Write-Host "Can't export Subnet: $($subnet.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
    return $data
}

<#
.SYNOPSIS
Exports details of a virtual network (VNet) for inclusion in an infrastructure diagram.

.DESCRIPTION
The `Export-vnet` function processes a specified virtual network object, retrieves its details, and formats the data for inclusion in an infrastructure diagram. It visualizes the VNet's name, address spaces, subnets, associated private DNS resolvers, and other configurations.

.PARAMETER vnet
Specifies the virtual network object to be processed.

.EXAMPLE
PS> Export-vnet -vnet $vnet

This example processes the specified virtual network and exports its details for inclusion in an infrastructure diagram.

#>
function Export-vnet {
    [CmdletBinding()]
    param ([PSCustomObject[]]$vnet)

    try {
        $vnetname = SanitizeString $vnet.Name
        $Location = SanitizeLocation $vnet.Location
        $id = $vnet.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $vnetAddressSpaces = $vnet.AddressSpace.AddressPrefixes
        $script:rankvnetaddressspaces += $id

        $header = "
        # $vnetname - $id
        subgraph cluster_$id {
            style = solid;
            colorscheme = pastel19 ;
            bgcolor = 3;
            node [colorscheme = rdylgn11 ; style = filled;];
        "

        # Convert addressSpace prefixes from array to string
        $vnetAddressSpacesString = ""
        $vnetAddressSpaces | ForEach-Object {
            $vnetAddressSpacesString += $(SanitizeString $_) + "\n"
        }
        $ImagePath = Join-Path $OutputPath "icons" "vnet.png"
        $vnetdata = "    $id [fillcolor = 10; fontcolor = white; label = `"\nLocation: $Location\nAddress Space(s):\n$vnetAddressSpacesString`";image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;$(Generate-DotURL -resource $vnet)];`n"

        # Subnets
        if ($vnet.Subnets) {
            $Script:Legend += ,@("Subnet", "snet.png")
            $subnetdata = Export-SubnetConfig $vnet.Subnets
        }
        # Retrieve all Private DNS Resolvers in a specific resource group
        $dnsResolvers = Get-AzDnsResolver | Where-Object { $_.VirtualNetworkId -eq $vnet.id } -ErrorAction Stop
        $dnsprdata = ""
        if ($dnsResolvers) {
            $Script:Legend += ,@("Private DNS Resolver", "dnspr.png")
            # Display details of each Private DNS Resolver
            foreach ($resolver in $dnsResolvers) {
                $resolverName = $resolver.Name
                $Location = SanitizeLocation $resolver.Location
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
                        colorscheme = pastel19;
                        bgcolor = 2;
                        node [colorscheme = pastel19; color = 2; shape = box]
                            
                        $pdnsrId [label = <
                                        <TABLE border=`"0`" style=`"rounded`" align=`"left`">
                                        <TR><TD align=`"left`">Name</TD><TD align=`"left`">$(SanitizeString $resolverName)</TD></TR>
                                        <TR><TD align=`"left`">Location</TD><TD align=`"left`">$(SanitizeString $Location)</TD></TR>
                                        <TR><TD align=`"left`">Inbound IP Address</TD><TD align=`"left`">$(SanitizeString $inboundEpIp)</TD></TR>
                                        <TR><TD><BR/><BR/></TD></TR>
                                        <TR><TD colspan=`"3`" border=`"0`"><B>$(SanitizeString $dnsFrs.Name)</B></TD></TR>
                                        <TR><TD align=`"left`">Name</TD><TD align=`"left`">Domain Name</TD><TD align=`"left`">Target DNS</TD></TR>
                    "

                    foreach ($rule in $frsRules) {
                        $dnsprdata += "                <TR><TD align=`"left`">$(SanitizeString $rule.Name)</TD><TD align=`"left`">$(SanitizeString $rule.DomainName)</TD><TD align=`"left`">$(($rule.TargetDnsServer.IPAddress | ForEach-Object {SanitizeString $_}) -join ', ')</TD></TR>`n"                    
                    }
                    # End table                     $pdnsrId -> $dnsFrsId;     
                    $ImagePath = Join-Path $OutputPath "icons" "dnspr.png"
                    $dnsprdata += "</TABLE>>; image = `"$ImagePath`";imagepos = `"tr`";labelloc = `"b`";height = 3.0;]; 
                        label = `"$(SanitizeString $resolverName)`";
                    }
                    "
                    $script:PDNSRepIP += $inboundEpIp
                    $script:PDNSRId += $pdnsrId
                }
            }
        }                            

        $footer = "
            label = `"$vnetname`";
        }
        "
        $alldata = $header + $vnetdata + $subnetdata + $footer + $dnsprdata
        Export-AddToFile -Data $alldata
    }
    catch {
        Write-Error "Can't export VNet: $($vnet.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of a Virtual WAN (vWAN) for inclusion in an infrastructure diagram.

.DESCRIPTION
The `Export-vWAN` function processes a specified Virtual WAN object, retrieves its details, and formats the data for inclusion in an infrastructure diagram. It visualizes the vWAN's name, type, location, and associated hubs, along with their configurations.

.PARAMETER vwan
Specifies the Virtual WAN object to be processed.

.EXAMPLE
PS> Export-vWAN -vwan $vWAN

This example processes the specified Virtual WAN and exports its details for inclusion in an infrastructure diagram.

#>
function Export-vWAN {
    [CmdletBinding()]
    param ([PSCustomObject[]]$vwan)

    $vwanname = $vwan.Name
    $Name = SanitizeString $vwanname
    $id = $vwan.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
    $VirtualWANType = $vwan.VirtualWANType
    $ResourceGroupName = $vwan.ResourceGroupName
    $AllowVnetToVnetTraffic = $vwan.AllowVnetToVnetTraffic
    $AllowBranchToBranchTraffic = $vwan.AllowBranchToBranchTraffic
    $Location = SanitizeLocation $vwan.Location

    try {
        Write-Host "Collecting vWAN info: $vwanname"
        $hubs = Get-AzVirtualHub -ResourceGroupName $ResourceGroupName -ErrorAction Stop | Where-Object { $($_.VirtualWAN.id) -eq $($vwan.id) }
        if ($null -ne $hubs) {
            $script:rankvwans += $id
            $header = "
            # $Name - $id
            subgraph cluster_$id {
                style = solid;
                bgcolor = 6;
                node [color = black;];
            "
        
            # Convert addressSpace prefixes from array to string
            $vWANDetails = "Virtual WAN Type: $VirtualWANType\nLocation: $Location\nAllow Vnet to Vnet Traffic: $AllowVnetToVnetTraffic\nAllow Branch to Branch Traffic: $AllowBranchToBranchTraffic"
            $ImagePath = Join-Path $OutputPath "icons" "vWAN.png"
            $vwandata = "    $id [label = `"\n$vWANDetails`";image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.0;$(Generate-DotURL -resource $vwan)];`n"
            $footer = "
                label = `"$Name`";
            }
            "
        
            # Hubs
            $hubdata = ""
            foreach ($hub in $hubs) {
                $hubdata += Export-Hub -Hub $hub
            }
            $alldata = $header + $vwandata + $hubdata + $footer
        
            Export-AddToFile -Data $alldata
        }            
    }
    catch {
        Write-Error "Can't export Hub: $($hub.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of an ExpressRoute Circuit for inclusion in an infrastructure diagram.

.DESCRIPTION
The `Export-ExpressRouteCircuit` function processes a specified ExpressRoute Circuit object, retrieves its details, and formats the data for inclusion in an infrastructure diagram. It visualizes the circuit's name, SKU, bandwidth, provider, peering details, and associated ExpressRoute Direct ports if applicable.

.PARAMETER er
Specifies the ExpressRoute Circuit object to be processed.

.EXAMPLE
PS> Export-ExpressRouteCircuit -er $expressRouteCircuit

This example processes the specified ExpressRoute Circuit and exports its details for inclusion in an infrastructure diagram.

#>
function Export-ExpressRouteCircuit {
    [CmdletBinding()]
    param ([PSCustomObject[]]$er)

    $ername = SanitizeString $er.Name
    $id = $er.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
    if ($er.ServiceProviderProperties) {
        $ServiceProviderName = $er.ServiceProviderProperties.ServiceProviderName
        $Peeringlocation = SanitizeLocation $er.ServiceProviderProperties.PeeringLocation
        $Bandwidth = $er.ServiceProviderProperties.BandwidthInMbps.ToString() + " Mbps"
        $BillingType = "N/A"
        $Encapsulation = "N/A"
    }
    else {
        # ExpressRoute Direct
        $erport = Get-AzExpressRoutePort -ResourceId $er.ExpressRoutePort.Id -ErrorAction Stop
        $erportid = $erport.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $erportname = SanitizeString $erport.Name.ToLower()
        $ServiceProviderName = "N/A"
        $Peeringlocation = SanitizeLocation $erport.PeeringLocation
        $Bandwidth = $erport.ProvisionedBandwidthInGbps.ToString() + " Gbps"
        $BillingType = $erport.BillingType
        $Encapsulation = $erport.Encapsulation
        $Location = SanitizeLocation $erport.Location
        $ImagePath = Join-Path $OutputPath "icons" "erport.png"

        $erportdata = "
        # $erportname - $erportid
        subgraph cluster_$erportid {
            style = solid;
            colorscheme = rdpu9 ;
            bgcolor = 3;
            node [colorscheme = rdpu9 ; color = 3; ];
    
            $erportid [label = `"\nName: $erportname\nLocation: $Location\n`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;$(Generate-DotURL -resource $erport)];
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
                            $linkid [shape = none; label = <
                                <TABLE cellborder=`"0`" color=`"black`" border=`"1`" style=`"rounded`">
                                <TR><TD colspan=`"2`" border=`"0`"><B>$linkname</B></TD></TR><HR/>
                                <TR><TD align=`"left`">Router Name</TD><VR/><TD align=`"left`">$($link.RouterName)</TD></TR><HR/>
                                <TR><TD align=`"left`">Interface Name</TD><VR/><TD align=`"left`">$($link.InterfaceName)</TD></TR><HR/>
                                <TR><TD align=`"left`">Patch Panel Id</TD><VR/><TD align=`"left`">$($link.PatchPanelId)</TD></TR><HR/>
                                <TR><TD align=`"left`">Rack Id</TD><VR/><TD align=`"left`">$($link.RackId)</TD></TR><HR/>
                                <TR><TD align=`"left`">Connector Type</TD><VR/><TD align=`"left`">$($link.ConnectorType)</TD></TR><HR/>
                                <TR><TD align=`"left`">Encapsulation</TD><VR/><TD align=`"left`">$Encapsulation</TD></TR><HR/>
                                <TR><TD align=`"left`">MACSEC</TD><VR/><TD align=`"left`">$macsec</TD></TR>
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
    $Location = SanitizeLocation $er.Location
    $ImagePath = Join-Path $OutputPath "icons" "ercircuit.png"

    $header = "
    # $ername - $id
    subgraph cluster_$id {
        style = solid;
        colorscheme = rdpu9 ;
        bgcolor = 2;
        node [colorscheme = rdpu9 ; color = 2; ];

        $id [label = `"\nName: $ername\nLocation: $Location`" ; image = `"$ImagePath`";imagepos = `"tc`"; labelloc = `"b`";height = 3.5;$(Generate-DotURL -resource $er)];
        $id [shape = none;label = <
            <TABLE cellborder=`"0`" color=`"black`" border=`"1`"  style=`"rounded`">
            <TR><TD>SKU Tier</TD><VR/><TD>$skuTier</TD></TR><HR/>
            <TR><TD>SKU Family</TD><VR/><TD>$skuFamily</TD></TR><HR/>
            <TR><TD>Billing Type</TD><VR/><TD>$BillingType</TD></TR><HR/>
            <TR><TD>Provider</TD><VR/><TD>$ServiceProviderName</TD></TR><HR/>
            <TR><TD>Location</TD><VR/><TD>$Peeringlocation</TD></TR><HR/>
            <TR><TD>Bandwidth</TD><VR/><TD>$Bandwidth</TD></TR>
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
        $peeringName = SanitizeString $peering.Name
        $peeringId = $peering.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $peeringType = $peering.PeeringType
        $AzureASN = SanitizeString $peering.AzureASN
        $PeerASN = SanitizeString $peering.PeerASN
        $PrimaryPeerAddressPrefix = SanitizeString $peering.PrimaryPeerAddressPrefix
        $SecondaryPeerAddressPrefix = SanitizeString $peering.SecondaryPeerAddressPrefix
        $VlanId = SanitizeString $peering.VlanId
        $ImagePath = Join-Path $OutputPath "icons" "peerings.png"

        # DOT
        $PeeringData = $PeeringData + "
            # $peeringName - $peeringId
            subgraph cluster_$peeringId {
                style = solid;
                colorscheme = rdpu9;
                bgcolor = 4;
                node [colorscheme = rdpu9 ; color = 4; ];
        
                $peeringId [label = `"\n$peeringName`" ; image = `"$ImagePath`";imagepos = `"tc`"; labelloc = `"b`";height = 2.5;];
                $peeringId [shape = none;label = <
                    <TABLE cellborder=`"0`" color=`"black`" border=`"1`" style=`"rounded`" align=`"left`">
                    <TR><TD>Peering Type</TD><VR/><TD COLSPAN=`"2`">$peeringType</TD></TR><HR/>
                    <TR><TD>Address Prefixes</TD><VR/><TD>$PrimaryPeerAddressPrefix</TD><VR/><TD>$SecondaryPeerAddressPrefix</TD></TR><HR/>
                    <TR><TD>ASN Azure/Peer</TD><VR/><TD>$AzureASN</TD><VR/><TD>$PeerASN</TD></TR><HR/>
                    <TR><TD>VlanId</TD><VR/><TD colspan=`"2`">$VlanId</TD></TR>
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
Exports details of a route table for inclusion in an infrastructure diagram.

.DESCRIPTION
The `Export-RouteTable` function processes a specified route table object, retrieves its routes, and formats the data for inclusion in an infrastructure diagram. It visualizes the route table name, address prefixes, next hop types, and next hop IP addresses.

.PARAMETER routetable
Specifies the route table object to be processed.

.EXAMPLE
PS> Export-RouteTable -routetable $routeTable

This example processes the specified route table and exports its details for inclusion in an infrastructure diagram.

#>
function Export-RouteTable {
    [CmdletBinding()]
    param ([PSCustomObject[]]$routetable)

    try {
        $routetableName = SanitizeString $routetable.Name
        $Location = SanitizeLocation $routetable.Location
        $id = $routetable.id.replace("-", "").replace("/", "").replace(".", "").ToLower()

        $script:rankrts += $id

        $header = "
        subgraph cluster_$id {
            style = solid;
            colorscheme = purples9;
            bgcolor = 5;
            margin = 0;
            node [colorscheme = purples9; shape = box; color = 5; margin = 0;];
            
            $id [label = <
                <TABLE border=`"0`" style=`"rounded`">
                <TR><TD border=`"0`" align=`"left`"><BR/><BR/><B>$routetableName</B></TD></TR>
                <TR><TD border=`"0`" align=`"left`">Location: $Location<BR/><BR/></TD></TR>
                <TR><TD><B>Route</B></TD><TD><B>Name</B></TD><TD><B>NextHopType</B></TD><TD><B>NextHopIpAddress</B></TD></TR>
                <HR/>"
        
        # Individual Routes        
        $data = ""

        #Sort routes for easier reading
        $routesSorted = $routetable.Routes | Sort-Object -Property AddressPrefix
        ForEach ($route in $routesSorted ) {
            if ($route.AddressPrefix -match '^[a-zA-Z]+$') {
                # Only letters, not IP address or CIDR
                $addressprefix = $route.AddressPrefix
            }
            else {
                $addressprefix = $route.AddressPrefix ? $(SanitizeString $route.AddressPrefix) : ""
            }
            $name = $route.Name
            $nexthoptype = $route.NextHopType
            $nexthopip = $route.NextHopIpAddress ? $(SanitizeString $route.NextHopIpAddress) : ""
            $data = $data + "<TR><TD align=`"left`">$addressprefix</TD><TD align=`"left`">$name</TD><TD align=`"left`">$nexthoptype</TD><TD align=`"left`">$nexthopip</TD></TR>"
        }
        if ($data -eq "") {
            $data = "<TR><TD align=`"left`">No routes found</TD><TD align=`"left`">N/A</TD><TD align=`"left`">N/A</TD><TD align=`"left`">N/A</TD></TR>"
        }
        # End table
        $ImagePath = Join-Path $OutputPath "icons" "RouteTable.png"
        $footer = "
                </TABLE>>;
                image = `"$ImagePath`";imagepos = `"tr`"; labelloc = `"b`";height = 2.5;$(Generate-DotURL -resource $routetable)];
        }
                "
        $alldata = $header + $data + $footer
        Export-AddToFile -Data $alldata
    }
    catch {   
        Write-Host "Can't export Route Table: $($routetable.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of an IP Group for inclusion in an infrastructure diagram.

.DESCRIPTION
The `Export-IpGroup` function processes a specified IP Group object, retrieves its details, and formats the data for inclusion in an infrastructure diagram. It visualizes the IP Group name and associated IP addresses.

.PARAMETER IpGroup
Specifies the IP Group object to be processed.

.EXAMPLE
PS> Export-IpGroup -IpGroup $ipGroup

This example processes the specified IP Group and exports its details for inclusion in an infrastructure diagram.

#>
function Export-IpGroup {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]$IpGroup
    )

    $id = $ipGroup.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
    $Location = SanitizeLocation $ipGroup.Location
    $script:rankipgroups += $id
    if ($ipGroup.IpAddresses) {
        $IpAddresses = ($ipGroup.IpAddresses | ForEach-Object { SanitizeString $_ }) -join "\n"
    }
    else {
        $IpAddresses = "None"
    }

    $ImagePath = Join-Path $OutputPath "icons" "ipgroup.png"
    $alldata = "
    subgraph cluster_$id {
        style = invis;
        
        $id [shape = box; label = `"\n\n\nName: $(SanitizeString $ipGroup.Name)\nLocation: $Location\n\n$IpAddresses`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;$(Generate-DotURL -resource $IpGroup)];
    }
    "
    Export-AddToFile -Data $alldata
}

<#
.SYNOPSIS
Exports details of a VPN connection and its associated gateways.

.DESCRIPTION
The `Export-Connection` function processes a specified VPN/ER connection object, retrieves details about the associated virtual network gateway or local network gateway, and formats the data for inclusion in an infrastructure diagram. It visualizes the connection type, peer information, and static remote subnets if applicable.

.PARAMETER connection
Specifies the VPN/ER connection object to be processed.

.EXAMPLE
PS> Export-Connection -connection $vpnConnection

This example processes the specified VPN connection and exports its details for inclusion in an infrastructure diagram.

#>
function Export-Connection {
    [CmdletBinding()]
    param ([PSCustomObject[]]$connection)

    $name = $connection.Name
    $lgwconnectionname = $name
    $lgconnectionType = $connection.ConnectionType

    ### Logic description
    # VirtualNetworkGateway1 - always set
    # VirtualNetworkGateway2 - if set = VNET2VNET
    # $connection.LocalNetworkGateway2 - if set = Site2Site VPN
    # $connection.Peer - if set = ER Circuit connection

    if ($connection.VirtualNetworkGateway2) { $VNET2VNET=$true }
    if ($connection.LocalNetworkGateway2) { $S2S=$true }
    if ($connection.Peer) { $ER=$true }

    # VPN GW 1, connection source endpoint, always set - Not added to DOT, as it is defined in VNet definition
    if ($connection.VirtualNetworkGateway1) {
        $lgwname = $connection.VirtualNetworkGateway1.id.split("/")[-1]
        $vpngwid = $connection.VirtualNetworkGateway1.id.replace("-", "").replace("/", "").replace(".", "").replace("`"", "").ToLower()
        #$data = "    $vpngwid [color = lightgrey;label = `"\n\nLocal GW: $(SanitizeString $lgwname)\nConnection Name: $(SanitizeString $lgwconnectionname)\nConnection Type: $lgconnectionType\n`""
        $lgwid = 0
    }
    else {
        $vpngwid = 0
    }
    
    # LGW set - S2S
    if ($S2S) {
        $Script:Legend += ,@("Site-to-Site VPN", "VPN-Site.png")
        $lgwid = $connection.LocalNetworkGateway2.id.replace("-", "").replace("/", "").replace(".", "").replace("`"", "").ToLower()
        $lgwname = $connection.LocalNetworkGateway2.id.split("/")[-1]
        $lgwrg = $connection.LocalNetworkGateway2.id.split("/")[4]
        $lgwobject = (Get-AzLocalNetworkGateway -ResourceGroupName $lgwrg -name $lgwname -ErrorAction Stop)
        $lgwip = $lgwobject.GatewayIpAddress
        $lgwFQDN = $lgwobject.Fqdn

        $lgwPeerInfo = ''
        if ( $null -eq $lgwip ) { $lgwPeerInfo = $lgwFQDN } else { $lgwPeerInfo = $lgwip }

        $lgwsubnetsarray = $lgwobject.addressSpaceText | ConvertFrom-Json
        $lgwsubnets = ""
        $lgwsubnetsarray.AddressPrefixes | ForEach-Object {
            $prefix = SanitizeString $_
            $lgwsubnets += "$prefix \n"
        }
        $data = "    $lgwid [color = lightgrey;label = `"\n\nGateway: $(SanitizeString $lgwname)\nConnection Name: $(SanitizeString $lgwconnectionname)\nConnection Type: $lgconnectionType\n"

        $data += "Peer : $(SanitizeString $lgwPeerInfo)\n\nStatic remote subnet(s):\n$lgwsubnets"
        $ImagePath = Join-Path $OutputPath "icons" "VPN-Site.png"
        $data += "`";image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.0;$(Generate-DotURL -resource $connection)];"
    } 
    elseif ($VNET2VNET) {
        $lgwid = $connection.VirtualNetworkGateway2.id.replace("-", "").replace("/", "").replace("`"", "").replace(".", "").ToLower()
        $lgwname = $connection.VirtualNetworkGateway2.id.split("/")[-1]
    }
    else {
        #ER
        $lgwid = 0
    }
  
    # ER (Peer set = ER Circuit - circuit defined seperately)
    if ($ER -and $vpngwid -ne 0) {
        $peerid = $connection.Peer.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        
        # Validate ER Circuit access
        $peerSub = $connection.Peer.id.Split("/")[2]
        $peerRG = $connection.Peer.id.Split("/")[4]
        $peerName = $connection.Peer.id.Split("/")[8]
        
        $currentcontext = (Get-AzContext).Subscription.Id
        $tempcontext = $peerSub
        $null = Set-AzContext $tempcontext -ErrorAction SilentlyContinue
        $circiut = Get-azexpressRouteCircuit -ResourceName $peerName -ResourceGroupName $peerRG -ErrorAction SilentlyContinue
        $null = Set-AzContext $currentcontext
        
        if ( $null -eq $circiut ) {
            #Define unknown ER Cicuit here as unknown, if not found.
            $Script:Legend += ,@("Express Route Circuit","ercircuit.png")
            $ImagePath = Join-Path $OutputPath "icons" "ercircuit.png"
            $data += "$peerid [label = `"\nName:$peerName\n(Unknown Express route circuit)`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;];"
        }

        $data += "`n    $vpngwid -> $peerid`n"
    }
    # VPN or VNet2VNet
    elseif ($lgwid -ne 0 -and $vpngwid -ne 0) {
        $data += "`n    $vpngwid -> $lgwid`n"
    }
    else {
        $data += "`n"
    }
    Export-AddToFile -Data $data
}

<#
.SYNOPSIS
Exports details of a Private Endpoint and its associated Private Link Service connections.

.DESCRIPTION
The `Export-PrivateEndpoint` function retrieves information about a specified Private Endpoint, including its name and associated Private Link Service connections. It formats the data for inclusion in an infrastructure diagram, displaying the Private Endpoint's details and connections visually.

.PARAMETER pe
Specifies the Private Endpoint object to be processed.

.EXAMPLE
PS> Export-PrivateEndpoint -pe $privateEndpoint

This example processes the specified Private Endpoint and exports its details for inclusion in an infrastructure diagram.

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

        $pedetails = $(SanitizeString $pe.name) + "\n"
        # Process each connection for this private endpoint
        foreach ($connection in $connections) {
            if ($connection.PrivateLinkServiceId) {
                $pedetails += $(SanitizeString $connection.PrivateLinkServiceId.Split('/')[-1]) + "\n"
            }
        }
        $ImagePath = Join-Path $OutputPath "icons" "private-endpoint.png"
        $data = "`n                     $peid [colorscheme = rdylgn11; color = 1; fontcolor = white; label = `"\n$pedetails`" ; image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;$(Generate-DotURL -resource $pe)];" 
        Export-AddToFile -Data $data
    }
    catch {
        Write-Error "Can't export Private Endpoint: $($pe.Name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of an Azure Container Group for inclusion in an infrastructure diagram.

.DESCRIPTION
The `Export-ContainerGroup` function processes a specified Azure Container Group object, retrieves its details, and formats the data for inclusion in an infrastructure diagram. It visualizes the container group's name, location, OS type, IP address, zone, SKU, and associated containers with their configurations.

.PARAMETER containerGroup
Specifies the Azure Container Group object to be processed. This parameter is mandatory.

.EXAMPLE
PS> $containerGroup = Get-AzContainerGroup -Name "MyContainerGroup" -ResourceGroupName "MyResourceGroup"
PS> Export-ContainerGroup -containerGroup $containerGroup

This example retrieves an Azure Container Group object and exports its details for inclusion in an infrastructure diagram.
#>
function Export-ContainerGroup
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$containerGroup
    )

    $name = SanitizeString $containerGroup.Name
    $id = $containerGroup.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
    $location = SanitizeLocation $containerGroup.Location
    $script:rankcontainergroups += $id

    try {
        $header = "
        # $name - $id
        subgraph cluster_$id {
            style = solid;
            colorscheme = bupu9;
            bgcolor = 2;
            node [colorscheme = bupu9; style = filled;];
        "
        
        if ( $null -ne $containerGroup.IPAddress.IP ) { $instanceIP = (SanitizeString $containerGroup.IPAddress.IP) + " ($($containerGroup.IPAddressType.ToString()))"
        } else { $instanceIP = "Instance stopped, unavailable" }
        
        $instanceOS = $containerGroup.OSType.ToString()
        $instanceZone = $null -eq $containerGroup.Zone ? "None" : $containerGroup.Zone
        $instanceSku = $containerGroup.sku.ToString()
        $ImagePath = Join-Path $OutputPath "icons" "containerinstance.png"

        $data = "    $id [fillcolor = 3; fontcolor = black; label = `"\nName: $name\nLocation: $location\nOS Type: $instanceOS\nIP Address: $instanceIP\nZone: $instanceZone\nSKU: $instanceSku`";image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.5;$(Generate-DotURL -resource $containerGroup)];`n"
        
        $contId = 0;
        foreach($container in $containerGroup.Container) {
            $containerName = SanitizeString $container.Name
            $containerImage = SanitizeString $container.Image
            $containerCpu = $container.RequestCpu
            $containerMemory = $container.RequestMemoryInGb
            $containerGpu = $null -eq $container.RequestGpuCount ? "0" : $container.RequestGpuCount 
            $containerPorts = ($container.Port | ForEach-Object { "$($_.Port)/$($_.Protocol)" }) -join ', '     
            
            # DOT
            $ImagePath = Join-Path $OutputPath "icons" "containers.png"
            $data += "    $id$contId [fillcolor = 4; label = `"\n\nName: $containerName\nImage: $containerImage\nCPU: $containerCpu Cores\nMemory: $containerMemory Gb\nGPU's: $containerGpu\nPorts: $containerPorts`";image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.5;];`n"
            $data += "    $id -> $id$contId [ltail = cluster_$id; lhead = cluster_$id$contId;];`n"
            $contId += 1;
        }
        # DOT
        if ($null -ne $containerGroup.SubnetId) {
            $subnetid = $containerGroup.SubnetId.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $data += "    $id -> $subnetId;`n"
        }
        Export-AddToFile -Data ($header + $data + "label = `"$name`";}")
    }
    catch {
        Write-Error "Can't export Container Group: $($containerGroup.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of an Azure Container App Environment for inclusion in an infrastructure diagram.

.DESCRIPTION
The `Export-ContainerAppEnv` function processes a specified Azure Container App Environment object, retrieves its details, and formats the data for inclusion in an infrastructure diagram. It visualizes the environment's name, location, static IP, zone redundancy, environment type, and associated container apps.

.PARAMETER containerAppEnvironment
Specifies the Azure Container App Environment object to be processed. This parameter is mandatory.

.EXAMPLE
PS> $containerAppEnv = Get-AzContainerAppEnvironment -Name "MyEnvironment" -ResourceGroupName "MyResourceGroup"
PS> Export-ContainerAppEnv -containerAppEnvironment $containerAppEnv

This example retrieves an Azure Container App Environment object and exports its details for inclusion in an infrastructure diagram.
#>
function Export-ContainerAppEnv
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$containerAppEnvironment
    )

    $envName = SanitizeString $containerAppEnvironment.Name
    $id = $containerAppEnvironment.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
    $location = SanitizeLocation $containerAppEnvironment.Location
    $staticIP = $containerAppEnvironment.StaticIp ? $(SanitizeString $containerAppEnvironment.StaticIp) : "N/A"
    $EnvironmentType = $null -eq $containerAppEnvironment.WorkloadProfile? "Consumption Only" : "Unknown"

    try {
        $script:rankcontainerappenv += $id

        $header = "
        # $envName - $id
        subgraph cluster_$id {
            style = solid;
            colorscheme = blues9 ;
            bgcolor = 2;
            node [colorscheme = blues9 ; style = filled;];
        "
        $ImagePath = Join-Path $OutputPath "icons" "containerappenv.png"
        $envdata = "    $id [fillcolor = 3; fontcolor = black; label = `"\nName: $envname\nLocation: $location\nZone Redundant: $($containerAppEnvironment.ZoneRedundant)\nEnvironment Type: $EnvironmentType\nStatic IP: $staticIP`";image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.5;$(Generate-DotURL -resource $containerAppEnvironment)];`n"
        $acas =  Get-AzContainerApp | where-object { $_.EnvironmentId -eq $containerAppEnvironment.id }
        if ($acas) {
            $script:rankcontainerapps += $id
            # Export each Container App in the environment
            foreach ($aca in $acas) {
                $acaName = SanitizeString $aca.Name
                $acaId = $aca.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
                $acaLocation = SanitizeLocation $aca.Location
                $AppEnvironmentType = $null -eq $aca.WorkloadProfileName? "Consumption Only" : "Unknown"
                if ($nul -ne $aca.TemplateContainer) {
                    $acaImage = $aca.TemplateContainer.Image
                    $acaAppName = $aca.TemplateContainer.Name
                    $acaCpu = $aca.TemplateContainer.ResourceCpu
                    $acaMemory = $aca.TemplateContainer.ResourceMemory
                    $acaStorage = $aca.TemplateContainer.ResourceEphemeralStorage
                }
                else {
                    $acaImage = "Unknown"
                    $acaAppName = "Unknown"
                    $acaCpu = "Unknown"
                    $acaMemory = "Unknown"
                    $acaStorage = "Unknown"
                }

                $acaDetails = "Name: $acaName\nLocation: $acaLocation\nEnvironment Type: $AppEnvironmentType\nApp Name: $acaAppName\nApp Image: $acaImage\nApp CPU: $acaCpu Cores\nApp Memory: $acaMemory\nApp Storage: $acaStorage\nOutbound IP Address: $($aca.OutboundIPAddress -join ', ')\n"
                
                # DOT
                $ImagePath = Join-Path $OutputPath "icons" "containerapp.png"
                $envdata += "    $acaId [fillcolor = 4; label = `"\n$acaDetails`";image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.0;$(Generate-DotURL -resource $aca)];`n"
                $envdata += "    $id -> $acaId [ltail = cluster_$id; lhead = cluster_$acaId;];`n"
            }
        }

        # End subgraph
        $footer = "
            label = `"$envName`";
        }
        "
        
        Export-AddToFile -Data ($header + $envdata + $footer)
    }
    catch {
        Write-Error "Can't export Container App Environment: $($containerAppEnvironment.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of an Azure Static Web App for inclusion in an infrastructure diagram.

.DESCRIPTION
The `Export-StaticWebApp` function processes a specified Azure Static Web App Environment object, retrieves its details, and formats the data for inclusion in an infrastructure diagram. It visualizes the Web App's name, location, SKU, custom domain name.

.PARAMETER containerAppEnvironment
Specifies the Azure Static Web App object to be processed. This parameter is mandatory.

.EXAMPLE
PS> $StaticWebApp = Get-AzStaticWebApp -Name "MyStaticWebApp" -ResourceGroupName "MyResourceGroup"
PS> Export-StaticWebApp -StaticWebApp $StaticWebApp

This example retrieves an Azure Static Web App object and exports its details for inclusion in an infrastructure diagram.
#>
function Export-StaticWebApp
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$StaticWebApp
    )

    try {
        $id = $StaticWebApp.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $script:rankstaticwebapp += $id
        
        $header = "
        # $($StaticWebApp.Name) - $id
        subgraph cluster_$id {
            style = solid;
            colorscheme = blues9 ;
            bgcolor = 2;
            node [colorscheme = blues9 ; style = filled;];
        "
        $ImagePath = Join-Path $OutputPath "icons" "swa.png"
        $swaName = SanitizeString $StaticWebApp.Name
        $swaLocation = SanitizeLocation $StaticWebApp.Location
        $swaSKU = $StaticWebApp.SkuName

        $swaCustomDomainTemp  = $StaticWebApp.CustomDomain
        if ($null -eq $swaCustomDomainTemp ){ $swaCustomDomain = SanitizeString $($StaticWebApp.CustomDomain) } else { $swaCustomDomain = "None" }

        $swaDefaultDomain = SanitizeString "$($StaticWebApp.DefaultHostName)"
        #$swaProvider = $StaticWebApp.Provider

        $swadata += "    $id [fillcolor = 4; label = `"\n\nLocation: $swaLocation\nSKU: $swaSKU\n\nDefault Domain:\n$swaDefaultDomain\n\nCustom Domain:\n$swaCustomDomain`";image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.0;$(Generate-DotURL -resource $StaticWebApp)];`n"
        #$swadata += "    $id -> $swaId [ltail = cluster_$id; lhead = cluster_$swaId;];`n"

        # End subgraph
        $footer = "
            label = `"$swaName`";
        }
        "
        
        Export-AddToFile -Data ($header + $swadata + $footer)
    }
    catch {
        Write-Error "Can't export Static Web App: $($StaticWebApp.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of a Recovery Service Vault for inclusion in an infrastructure diagram.

.DESCRIPTION
The `Export-RecoveryServiceVault` function processes a specified Recovery Service Vault object, retrieves its details, and formats the data for inclusion in the diagram. It visualizes the Vault's name, location, policies, storage redundancy and softdelete state.

.PARAMETER RecoveryServiceVault
Specifies the Recovery Service Vault object to be processed. This parameter is mandatory.

.EXAMPLE
PS> $RecoveryServiceVault = Get-AzRecoveryServicesVault -Name "RSV" -ResourceGroupName "MyResourceGroup"
PS> Export-RecoveryServiceVault $RecoveryServiceVault 

This example retrieves a Recovery Service Vault object and exports its details for inclusion in the diagram.
#>
function Export-RecoveryServiceVault
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$RecoveryServiceVault
    )

    try {
        $id = $RecoveryServiceVault.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $script:rankrecoveryservicevault += $id
        
        $header = "
        # $($RecoveryServiceVault.Name) - $id
        subgraph cluster_$id {
            style = solid;
            colorscheme = blues9 ;
            bgcolor = 2;
            node [colorscheme = blues9 ; style = filled;];
        "
        
        $rsvdata = ""
        
        $vaultname = SanitizeString $RecoveryServiceVault.Name
        $vaultid = $RecoveryServiceVault.ID.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $softdeletestate = (Get-AzRecoveryServicesVaultProperty -VaultId $RecoveryServiceVault.id -WarningAction SilentlyContinue).SoftDeleteFeatureState
        $softdeletedays = (Get-AzRecoveryServicesVaultProperty -VaultId $RecoveryServiceVault.id -WarningAction SilentlyContinue).SoftDeleteRetentionPeriodInDays
        $redundancy = (Get-AzRecoveryServicesBackupProperties -Vault $RecoveryServiceVault).BackupStorageRedundancy
        
        $ImagePath = Join-Path $OutputPath "icons" "rsv.png"

        #DOT - add image and other metadata
        $rsvdata += "    $vaultid [fillcolor = 3; label=`"$vaultname\nRedundancy: $redundancy\nSoft delete: $softdeletestate\nSoft delete day(s): $softdeletedays`";image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.0;$(Generate-DotURL -resource $RecoveryServiceVault)]`n"
                
        $policies = Get-AzRecoveryServicesBackupProtectionPolicy -VaultId $RecoveryServiceVault.id
        $policies | ForEach-Object {
            $policy = $_
            $policyname = SanitizeString $policy.Name
            $policyid = $policy.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            
            #$containertype = $item.containertype
            $workloadtype = $policy.WorkloadType
            $policysubtype = $policy.PolicySubType ? $policy.PolicySubType : "N/A"
            
            $items = Get-AzRecoveryServicesBackupItem -Policy $policy -VaultId $RecoveryServiceVault.id
            $policyProtectedItemsCount = $items.count
            
            #DOT
            $rsvdata += "$vaultid -> $policyid`n"
            $rsvdata += "$policyid [fillcolor = 4; label=`"$policyname\nWorkload type: $workloadtype\nPolicy subtype: $policysubtype\nProtected Items: $policyProtectedItemsCount`";image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.0;]`n"

            $items | ForEach-Object {
                $item = $_
                $resid = $item.SourceResourceId.replace("-", "").replace("/", "").replace(".", "").ToLower()
                
                $resobject = $null
                $rgname = $item.SourceResourceId.split("/")[4]
                $resname = $item.SourceResourceId.split("/")[8]

                #Validate existance prior to creating reference in DOT
                switch ($workloadtype) {
                    "AzureVM" {
                        $vm = Get-AzVM -ResourceGroupName $rgname -Name $resname -ErrorAction SilentlyContinue
                        if ( $null -ne $vm ) { $resobject = $vm } #else {
                            #$VMImagePath = Join-Path $OutputPath "icons" "vm.png"
                            #$rsvdata += "$resid [label = `"\nNon-existent VM: $(SanitizeString $resname)`" ; image = `"$VMImagePath`";fillcolor = 7;imagepos = `"tc`";labelloc = `"b`";height = 1.0;];"
                        #}
                    }
                    "AzureFiles" {
                        $sa = Get-AzStorageAccount -ResourceGroupName $rgname -Name $resname -ErrorAction SilentlyContinue
                        $filesharename = $item.FriendlyName
                        if ( $null -ne $sa ) { 
                            $resobject = $sa 
                            $resid = "$($resid)$filesharename" #move pointer to fileshare instead of SA
                        } #else {
                            #$SAImagePath = Join-Path $OutputPath "icons" "sa.png"
                            #$rsvdata += "$resid [label = `"\nNon-existent storage account: $(SanitizeString $resname)`" ; image = `"$SAImagePath`";fillcolor = 7;imagepos = `"tc`";labelloc = `"b`";height = 1.0;];"
                        #}
                    }
                    "AzureSQL" { #Not implemented 
                    }
                    "AzureVMAppContainer"  { #Not implemented
                    }
                    #SQL DB in VM
                    "MSSQL" {
                        $sqlvm = Get-AzSQLVM -ResourceGroupName $rgname -Name $resname -ErrorAction SilentlyContinue
                        if ( $null -ne $sqlvm ) { $resobject = $sqlvm } # else {
                        #    $SQLVMImagePath = Join-Path $OutputPath "icons" "vm.png"
                        #    $rsvdata += "$resid [label = `"\nNon-existent SQLVM: $(SanitizeString $resname)`" ; image = `"$SQLVMImagePath`";fillcolor = 7;imagepos = `"tc`";labelloc = `"b`";height = 1.0;];"
                        #}
                    }
                    #"Windows" # Requires "-BackupManagementType MAB" in the next sted. But MARS agents/backups are out of scope
                }
            
                #DOT
                if ( $null -ne $resobject ) {
                    $rsvdata += "$resid -> $policyid`n"
                }
            }
        }

        # End subgraph
        $footer = "
            label = `"$vaultName`";
        }
        "
        
        Export-AddToFile -Data ($header + $rsvdata + $footer)
    }
    catch {
        Write-Error "Can't export Recovery Service Vault: $($RecoveryServiceVault.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of a Backup Vault for inclusion in an infrastructure diagram.

.DESCRIPTION
The `Export-BackupVault` function processes a specified Backup Vault object, retrieves its details, and formats the data for inclusion in the diagram. It visualizes the Vault's name, location, policies, storage redundancy and softdelete state.

.PARAMETER BackupVault
Specifies the Backup Vaultobject to be processed. This parameter is mandatory.

.EXAMPLE
PS> $BackupVault = Get-AzDataProtectionBackupVault -Name "RSV" -ResourceGroupName "MyResourceGroup"
PS> Export-BackupVault $BackupVault 

This example retrieves a Backup Vault object and exports its details for inclusion in the diagram.
#>
function Export-BackupVault
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$BackupVault
    )

    try {
        $id = $BackupVault.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $script:rankbackupvault += $id
        
        $header = "
        # $($BackupVault.Name) - $id
        subgraph cluster_$id {
            style = solid;
            colorscheme = blues9 ;
            bgcolor = 2;
            node [colorscheme = blues9 ; style = filled;];
        "

        $bvdata = ""
        
        $vaultname = SanitizeString $BackupVault.Name
        $vaultrgname = $BackupVault.id.split("/")[4]
        $vaultid = $BackupVault.ID.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $softdeletestate = $backupvault.SoftDeleteState
        $softdeletedays = $backupvault.SoftDeleteRetentionDurationInDay
        $redundancy = $backupvault.StorageSetting.type
        
        $ImagePath = Join-Path $OutputPath "icons" "backupvault.png"

        #DOT - add image and other metadata
        $bvdata += "    $vaultid [fillcolor = 3; label=`"$vaultname\nRedundancy: $redundancy\nSoft delete: $softdeletestate\nSoft delete day(s): $softdeletedays`";image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 2.0;$(Generate-DotURL -resource $BackupVault)]`n"
        
        #All policies
        $policies = Get-AzDataProtectionBackupPolicy -VaultName $vaultname -ResourceGroupName $vaultrgname
        $policies | ForEach-Object {
            $policy = $_
            $policyname = SanitizeString $policy.Name
            $policyid = $policy.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
            $policydatasource = $policy.Property.DatasourceType
            
            #DOT
            $bvdata += "$policyid [fillcolor = 4; label=`"Policy Name: $policyname\nData source type=$policydatasource`";image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 1.5;]`n"
            $bvdata += "$vaultid -> $policyid`n"
        }

        #Instances/items
        $instances = Get-AzDataProtectionBackupInstance -VaultName $vaultname -ResourceGroupName $vaultrgname
        $instances | ForEach-Object {
            $instance = $_
            #$policyname = $instance.Property.PolicyInfo.policyid.Split("/")[10]
            $policyid = $instance.Property.POlicyInfo.policyid.replace("-", "").replace("/", "").replace(".", "").ToLower()

            $resid = ($instance.Property.DataSourceInfo.ResourceId).replace("-", "").replace("/", "").replace(".", "").ToLower()
            $containers = $instance.Property.PolicyInfo.PolicyParameter.BackupDatasourceParametersList.ContainersList
            
            $containers | ForEach-Object {
                $container = $_
                $bvdata += "$resid$container -> $policyid`n"
            }
        }

        # End subgraph
        $footer = "
            label = `"$vaultName`";
        }
        "
        
        Export-AddToFile -Data ($header + $bvdata + $footer)
    }
    catch {
        Write-Error "Can't export Backup Vault: $($BackupVault.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of a Mangement Group for inclusion in an infrastructure diagram.

.DESCRIPTION
The `Export-MgmtGroups function processes a specified Azure Management Groups, retrieves its details, and formats the data for inclusion in an infrastructure diagram.
#>
function Export-MgmtGroups
{
    [CmdletBinding()]
    param(
    )

    try {
        Export-AddToFile "`n    ##########################################################################################################"
        Export-AddToFile "    ##### Management Group overview "
        Export-AddToFile "    ##########################################################################################################`n"

        $header = "
    # Management Group overview
    subgraph cluster_mgmtgroups {
        style = solid;
        colorscheme = blues9 ;
        bgcolor = 2;
        node [colorscheme = blues9 ; style = filled;];
    "

        $MgmtGroupsEntityObjects = Get-AzManagementGroupEntity -ErrorAction Stop 
        $mgmtgroupdata = ""
        if ($null -ne $MgmtGroupsEntityObjects) {
            $Script:Legend += ,@("Management Group","mgmtgroup.png")
            $MgmtGroupsEntityObjects | ForEach-Object {
                $MgmtGroupEntityObject = $_
                $mgmtgroupdata += Export-MgmtGroupEntityObject -MgmtGroupEntityObject $MgmtGroupEntityObject
            }
        }

        # End subgraph
        $footer = "
            label = `"Mangement Groups`";
        }
        "
        
        Export-AddToFile -Data ($header + $mgmtgroupdata + $footer)
    }
    catch {
        Write-Error "Can't export Management Groups at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}

<#
.SYNOPSIS
Exports details of a Mangement Group for inclusion in an infrastructure diagram.

.DESCRIPTION
The `Export-MgmtGroupEntityObject` function processes a specified Azure Management Group object, retrieves its details, and formats the data for inclusion in an infrastructure diagram.

.PARAMETER mgmtGroup
Specifies the Azure Management Group object to be processed. This parameter is mandatory.

.EXAMPLE
PS> $MgmtGroupEntityObject = Get-AzManagementGroupEntity
PS> $MgmtGroupEntityObject | Foreach-Object { Export-MgmtGroupEntityObject -MgmtGroupEntityObject $MgmtGroupEntityObject }

This example retrieves specified Azure Management Group object, retrieves its details, and formats the data for inclusion in an infrastructure diagram.
#>
function Export-MgmtGroupEntityObject
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$MgmtGroupEntityObject
    )

    try {
        $data = ""
        $id = $MgmtGroupEntityObject.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        if ( $MgmtGroupEntityObject.Type -eq "Microsoft.Management/managementGroups" ) {
            $MgmtGroup = $_
            $script:rankmgmtgroup += $id
            $ImagePath = Join-Path $OutputPath "icons" "mgmtgroup.png"
            $name = SanitizeString $MgmtGroup.DisplayName
            $descendants = $MgmtGroupEntityObject.NumberOfDescendants
            
            $data += "      $id [fillcolor = 4; label = `"\nName: $name\nDescendants: $descendants`";image = `"$ImagePath`";imagepos = `"tc`";height = 2.0;];`n"
            
        } 
        elseif ( $MgmtGroupEntityObject.Type -eq "/subscriptions" ) {
        
            $sub = $_
            $script:ranksubs += $id
            $ImagePath = Join-Path $OutputPath "icons" "sub.png"
            $name = SanitizeString $sub.DisplayName

            $Script:Legend += ,@("Subscription","sub.png")
            
            $data += "      $id [fillcolor = 4; label = `"\nName: $name`";image = `"$ImagePath`";imagepos = `"tc`";height = 2.0;$(Generate-DotURL -resource $sub)];`n"
            
        }    
        $parent = $MgmtGroupEntityObject.parent
        if ( $null -ne $parent) { 
            # Tenant Root Group has no parent
            $parent = $parent.replace("-", "").replace("/", "").replace(".", "").ToLower() 
            $data += "      $parent -> $id ;`n"
        }

        return $data

    }
    catch {
        Write-Error "Can't export Management Groups Entity Object at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
  
}

<#
.SYNOPSIS
Confirms that all prerequisites are met for generating the Azure infrastructure diagram.

.DESCRIPTION
The `Confirm-Prerequisites` function ensures that all required tools, modules, and configurations are in place before generating the Azure infrastructure diagram. It verifies the presence of Graphviz (`dot.exe`), required PowerShell modules (`Az.Network` and `Az.Accounts`), Azure authentication, and necessary icons for the diagram. If any prerequisites are missing, it provides guidance for resolving the issues.

#>
function Confirm-Prerequisites {
    [CmdletBinding()]
    $ErrorActionPreference = 'Stop'

    if (! (Test-Path $OutputPath)) {}
    # dot.exe executable
    try {
        $dot = (Get-DOTExecutable).Fullname
        if ($null -eq $dot) {
            Write-Error "dot application executable not found - please install Graphiz (https://graphviz.org), and/or ensure `"dot`" is in `"`$PATH`" !"
        }
    }
    catch {
        Write-Error "dot application executable not found - please install Graphiz (https://graphviz.org), and/or ensure `"dot`" is in `"`$PATH`" !"
    }
    
    # Azure authentication verification
    $context = Get-AzContext  -ErrorAction Stop
    if ($null -eq $context) { 
        Write-Output "Please make sure you are logged in to Azure using Login-AzAccount, and that permissions are granted to resources within scope."
        Write-Output "A login window should appear - hint: it may hide behind active windows!"
        Login-AzAccount
    }
    # Icons available?
    $ImagePath = Join-Path $OutputPath "icons" 
    if (! (Test-Path "$ImagePath") ) { Write-Output "Downloading icons to $ImagePath ... " ; New-Item -Path "$OutputPath" -Name "icons" -ItemType "directory" | Out-null }
    $icons = @(
        "LICENSE",
        "acr.png",
        "afw.png",
        "agw.png",
        "aks-node-pool.png",
        "aks-service.png",
        "apim.png",
        "appplan.png",
        #"appserviceplan.png",
        "appservices.png",
        "azurefileshare.png",
        #"azuresql.png",
        "bas.png",
        "cassandra.png",
        "computegalleries.png",
        "containerapp.png",
        "containerappenv.png",
        "containerapps.png",
        "containerinstance.png",
        "containers.png",
        #"Connections.png",
        "cosmosdb.png",
        "db.png",
        #"DNSforwardingruleset.png",
        "dnspr.png",
        "documentdb.png",
        "ercircuit.png",
        "ergw.png",
        "erport.png",
        "eventhub.png",
        "firewallpolicy.png",
        "gremlin.png",
        "imagedef.png",
        "imagedefversions.png",
        "ipgroup.png",
        "keyvault.png",
        #"lgw.png",
        "managed-identity.png",
        #"mariadb.png",
        "mgmtgroup.png"
        "mongodb.png",
        "mysql.png",
        "ng.png",
        "nsg.png",
        "peerings.png",
        "postgresql.png",
        "private-endpoint.png",
        #"privatednszone.png",
        "redis.png",
        "RouteTable.png",
        "rsv.png",
        "snet.png",
        "sqldb.png",
        "sqlmi.png",
        "sqlmidb.png",
        "sqlserver.png",
        "ssh-key.png",
        "storage-account.png",
        "storage-account-container.png",
        "sub.png"
        "swa.png",
        "table.png",
        "vWAN-Hub.png",
        "vWAN.png",
        "vgw.png",
        "vm.png",
        "vmss.png",
        "vnet.png",
        "VPN-Site.png",
        "VPN-User.png"
    )
    
    $icons | ForEach-Object {
        $ImagePath = Join-Path $OutputPath "icons" $_
        if (! (Test-Path $ImagePath) ) { Invoke-WebRequest "https://github.com/dan-madsen/AzNetworkDiagram/raw/refs/heads/main/icons/$_" -OutFile $ImagePath }
    }
    
}

<#
.SYNOPSIS
Retrieves the path to the Graphviz `dot` executable.

.DESCRIPTION
The `Get-DOTExecutable` function searches for the Graphviz `dot` executable in common installation paths across Windows, Linux, and macOS. It also checks the system's PATH environment variable for the executable. If found, the function returns the full path to the `dot` executable; otherwise, it returns `$null`.

.PARAMETER None
This function does not take any parameters.

.EXAMPLE
PS> $dotPath = Get-DOTExecutable
PS> if ($null -eq $dotPath) { Write-Host "Graphviz 'dot' executable not found." } else { Write-Host "Graphviz 'dot' found at: $dotPath" }

This example retrieves the path to the Graphviz `dot` executable and prints a message indicating whether it was found.
#>
function Get-DOTExecutable {
    try {
        $PossibleGraphVizPaths = @(
            'C:\Program Files\NuGet\Packages\Graphviz*\dot.exe',
            'C:\program files*\GraphViz*\bin\dot.exe',
            '/usr/local/bin/dot',
            '/usr/bin/dot',
            '/opt/homebrew/bin/dot'
        )
        $PossibleGraphVizPaths += (Get-Command -Type Application -Name dot).Source

        $GraphViz = Resolve-Path -path $PossibleGraphVizPaths -ErrorAction SilentlyContinue | Get-Item | Where-Object BaseName -eq 'dot' | Select-Object -First 1
    }
    catch {
        $GraphViz = $null
    }
    return $GraphViz
}

<#
.SYNOPSIS
Generates a detailed infrastructure diagram of Azure resources for specified subscriptions.

.DESCRIPTION
The `Get-AzNetworkDiagram` function collects and visualizes Azure resources, including networking, infrastructure and more. It uses Graphviz to create a DOT-based diagram and outputs it in PDF, PNG, and SVG formats. The diagram includes relationships and dependencies between resources, providing a comprehensive view of the Azure network infrastructure.

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
        [Parameter(Mandatory = $false)]
        [string]$OutputPath = $pwd,
        [Parameter(Mandatory = $false)]
        [string[]]$Subscriptions,
        [Parameter(Mandatory = $false)]
        [bool]$EnableRanking = $true,
        [Parameter(Mandatory = $false)]
        [bool]$EnableLinks = $false,
        [Parameter(Mandatory = $false)]
        [string]$TenantId = $null,
        [Parameter(Mandatory = $false)]
        [string]$Prefix = $null,
        [Parameter(Mandatory = $false)]
        [bool]$Sanitize = $false,
        [Parameter(Mandatory = $false)] 
        [bool]$OnlyCoreNetwork = $false,
        [Parameter(Mandatory = $false)] 
        [bool]$OnlyMgmtGroups = $false,
        [Parameter(Mandatory = $false)] 
        [bool]$KeepDotFile = $false,
        [Parameter(Mandatory = $false)] 
        [ValidateSet('pdf','svg','png')]
        [string[]]$OutputFormat = "pdf"
    )

    # Remove trailing "\" from path
    $OutputPath = $OutputPath.TrimEnd('\')

    #Version info
    $module = Get-Module AzNetworkDiagram 
    $vermajor = $module.Version.Major
    $verminor = $module.Version.Minor
    $verbuild = $module.Version.Build
    $ver = "${vermajor}.${verminor}.${verbuild}"

    if ( $ver -eq "0.0.-1" ) { $ver = "(Non-PSGallery version)" } # Module loaded from file - not from PSGallery
    elseif ( $ver -eq ".." ) { $ver = "(Non-PSGallery version)" } # Module not imported - ran directly from .psm1 file ?
    else { $ver = "v$($ver)" }
    
    Write-Output "##############################################################################################"
    Write-Output "    ___        _   __     __                      __   ____  _                                "
    Write-output "   /   |____  / | / /__  / /__      ______  _____/ /__/ __ \(_)___ _____ __________ _____ ___ "
    Write-Output "  / /| /_  / /  |/ / _ \/ __/ | /| / / __ \/ ___/ //_/ / / / / __ ``/ __ ``/ ___/ __ ``/ __ ``__ \"
    Write-output " / ___ |/ /_/ /|  /  __/ /_ | |/ |/ / /_/ / /  / ,< / /_/ / / /_/ / /_/ / /  / /_/ / / / / / /" 
    Write-Output "/_/  |_/___/_/ |_/\___/\__/ |__/|__/\____/_/  /_/|_/_____/_/\__,_/\__, /_/   \__,_/_/ /_/ /_/ "
    write-output "                                                                 /____/                       "
    Write-Output "$ver"
    Write-Output "##############################################################################################`n"


    Write-Output "Checking prerequisites ..."
    Confirm-Prerequisites
    ##### Global runtime vars #####
    #Rank (visual) in diagram
    $script:rankrts = @()
    $script:ranksubnets = @()
    $script:rankvgws = @()
    $script:rankvnetaddressspaces = @()
    $script:rankvwans = @()
    $script:rankvwanhubs = @()
    $script:rankercircuits = @()
    $script:rankvpnsites = @()
    $script:rankipgroups = @()
    $script:PDNSREpIp = @()
    $script:PDNSRId = @()
    $script:AllInScopevNetIds = @()
    $script:DoSanitize = $Sanitize
    $script:Legend = @()

    ##### Data collection / Execution #####

    # Run program and collect data through powershell commands
    Export-dotHeader
    # Set subscriptions to every accessible subscription, if unset
    try {
        if ($TenantId) {
            if ( $null -eq $Subscriptions ) { $Subscriptions = (Get-AzSubscription -TenantId $TenantId -ErrorAction Stop | Where-Object -Property State -eq "Enabled").Id }
        }
        else {
            if ( $null -eq $Subscriptions ) { $Subscriptions = (Get-AzSubscription -ErrorAction Stop | Where-Object -Property State -eq "Enabled").Id }
        }
    }
    catch {
        Write-Error "No available subscriptions within active AzContext - missing permissions? " $_.Exception.Message
        return
    } 
    Write-Output "Gathering information ..."
    Update-AzConfig -DisplaySecretsWarning $false -Scope process | Out-Null
    Update-AzConfig -DisplayBreakingChangeWarning $false -Scope process | Out-Null

    # No subscriptions available?
    if ( $null -eq $Subscriptions ) {
        throw  "No available subscriptions within active AzContext - missing permissions?"
    }

    try {
        if ( $OnlyMgmtGroups ) {
            Write-Output "`nCollecting management groups and subscriptions..."
            Export-MgmtGroups
        }
        if ( $false -eq $OnlyMgmtGroups ) {
            # Collect all vNet ID's in scope otherwise we can end up with 1 vNet peered to 1000 other vNets which are not in scope
            # Errors will appear like: dot: graph is too large for cairo-renderer bitmaps. Scaling by 0.324583 to fit
            
            #$AzureRegions = Get-AzLocation | Select-Object DisplayName, Location | Sort-Object DisplayName
            $Subscriptions | ForEach-Object {
                # Set Context
                if ($TenantId) {
                    # If TenantId is specified, use it to set the context               
                    $context = Set-AzContext -Subscription $_ -Tenant $TenantId -Force -ErrorAction Stop
                }
                else {
                    $context = Set-AzContext -Subscription $_ -Force -ErrorAction Stop
                    $TenantId = $context.Tenant.Id
                }
                $subid = $context.Subscription.Id
                $subname = $context.Subscription.Name
                
                Write-Output "`nCollecting data from subscription: $subname ($subid)"
                Export-AddToFile "`n    ##########################################################################################################"
                Export-AddToFile "    ##### $subname "
                Export-AddToFile "    ##########################################################################################################`n"

                ### RTs
                Write-Output "Collecting Route Tables..."
                Export-AddToFile "    ##### $subname - Route Tables #####"
                $routetables = Get-AzRouteTable -ErrorAction Stop 
                if ($null -ne $routetables) {
                    $Script:Legend += ,@("Route Table","RouteTable.png")
                    $routetables | ForEach-Object {
                        $routetable = $_
                        Export-RouteTable $routetable
                    }
                }

                ### Ip Groups
                Write-Output "Collecting IP Groups..."
                Export-AddToFile "    ##### $subname - IP Groups #####"
                $ipGroups = Get-AzIpGroup -ErrorAction Stop
                if ($null -ne $ipGroups) {
                    $Script:Legend += ,@("IP Group","ipgroup.png")
                    $cluster = "subgraph cluster_ipgroups {
                        style = solid;
                        bgcolor = 5;
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
                Write-Output "Collecting vNets, and associated information..."
                Export-AddToFile "    ##### $subname - Virtual Networks #####"
                $vnets = Get-AzVirtualNetwork -ErrorAction Stop
                if ($null -ne $vnets.id) {
                    $Script:Legend += ,@("Virtual Network","vnet.png")
                    $script:AllInScopevNetIds += $vnets.id

                    $vnets | ForEach-Object {
                        $vnet = $_
                        Export-vnet $vnet
                    }
                }

                #NSGs
                Write-Output "Collecting NSG's..."
                Export-AddToFile "    ##### $subname - NSG's #####"
                $nsgs = Get-AzNetworkSecurityGroup -ErrorAction Stop
                if ($null -ne $nsgs) {
                    $Script:Legend += ,@("Network Security Group","nsg.png")
                    foreach ($nsg in $nsgs) {
                        Export-NSG $nsg
                    }
                }

                #VPN Connections
                Write-Output "Collecting VPN/ER Connections..."
                Export-AddToFile "    ##### $subname - VPN/ER Connections #####"
                $VPNConnections = Get-AzResource | Where-Object { $_.ResourceType -eq "Microsoft.Network/connections" }
                if ($null -ne $VPNConnections) {
                    $Script:Legend += ,@("VPN Connection","VPN-Site.png")
                    $VPNConnections | ForEach-Object {
                        $connection = $_
                        $resname = $connection.Name
                        $rgname = $connection.ResourceGroupName
                        $connection = Get-AzVirtualNetworkGatewayConnection -name $resname -ResourceGroupName $rgname -ErrorAction Stop
                        Export-Connection $connection
                    }
                }

                #Express Route Circuits
                Write-Output "Collecting Express Route Circuits..."
                Export-AddToFile "    ##### $subname - Express Route Circuits #####"
                $er = Get-AzExpressRouteCircuit -ErrorAction Stop
                if ($null -ne $er) {
                    $Script:Legend += ,@("Express Route Circuit","ercircuit.png")
                    $er | ForEach-Object {
                        $er = $_
                        Export-ExpressRouteCircuit $er
                    }
                }

                #Virtual WANs
                Write-Output "Collecting vWANs..."
                Export-AddToFile "    ##### $subname - Virtual WANs #####"
                $vWANs = Get-AzVirtualWan -ErrorAction Stop
                if ($null -ne $vWANs) {
                    $Script:Legend += ,@("Virtual WAN","vWAN.png")
                    $vWANs | ForEach-Object {
                        $vWAN = $_
                        Export-vWAN $vWAN
                    }
                }

                ### Private Endpoints
                Write-Output "Collecting Private Endpoints..."
                Export-AddToFile "    ##### $subname - Private Endpoints #####"
                $privateEndpoints = Get-AzPrivateEndpoint -ErrorAction Stop
                if ($null -ne $privateEndpoints) {
                    $Script:Legend += ,@("Private Endpoint","private-endpoint.png")
                    foreach ($pe in $privateEndpoints) {
                        Export-PrivateEndpoint $pe
                    }
                }

                # Skip the rest of the resource types, if -OnlyCoreNetwork was set to true, at runtime
                if ( -not $OnlyCoreNetwork ) {
                    #Container Instances
                    Write-Output "Collecting Container Instances..."
                    Export-AddToFile "    ##### $subname - Container Instances #####"
                    $containerGroups = Get-AzContainerGroup -ErrorAction Stop
                    if ($null -ne $containerGroups) {   
                        $Script:Legend += ,@("Containers","containers.png")
                        $Script:Legend += ,@("Container Instance","containerinstance.png")
                        foreach ($containerGroup in $containerGroups) {
                            Export-ContainerGroup $containerGroup
                        }
                    }
                    ### VMs
                    Write-Output "Collecting VMs..."
                    Export-AddToFile "    ##### $subname - VMs #####"
                    $VMs = Get-AzVM -ErrorAction Stop
                    if ($null -ne $VMs) {
                        $Script:Legend += ,@("Virtual Machine","vm.png")
                        foreach ($vm in $VMs) {
                            Export-VM $VM
                        }
                    }

                    ### Keyvaults
                    Write-Output "Collecting Keyvaults..."
                    Export-AddToFile "    ##### $subname - Keyvaults #####"
                    $Keyvaults = Get-AzKeyVault -ErrorAction Stop
                    if ($null -ne $Keyvaults) {
                        $Script:Legend += ,@("Key Vault","keyvault.png")
                        foreach ($keyvault in $Keyvaults) {
                            Export-Keyvault $Keyvault
                        }
                    }

                    ### Storage Accounts
                    Write-Output "Collecting Storage Accounts..."
                    Export-AddToFile "    ##### $subname - Storage Accounts #####"
                    $storageaccounts = Get-AzStorageAccount -ErrorAction Stop
                    if ($null -ne $storageaccounts) {
                        $Script:Legend += ,@("Storage Account","storage-account.png")
                        foreach ($storageaccount in $storageaccounts) {
                            Export-StorageAccount $storageaccount
                        }
                    }

                    # Application Gateways
                    Write-Output "Collecting Application Gateways..."
                    Export-AddToFile "    ##### $subname - Application Gateways #####"
                    $agws = Get-AzApplicationGateway -ErrorAction Stop
                    if ($null -ne $agws) {
                        $Script:Legend += ,@("Application Gateway","agw.png")
                        foreach ($agw in $agws) {
                            Export-ApplicationGateway $agw
                        }
                    }

                    #MySQL Servers
                    Write-Output "Collecting MySQL Flexible Servers..."
                    Export-AddToFile "    ##### $subname - MySQL Flexible Servers #####"
                    $mysqlservers = Get-AzMySqlFlexibleServer -ErrorAction Stop
                    if ($null -ne $mysqlservers) {
                        $Script:Legend += ,@("MySQL Server","mysql.png")
                        foreach ($mysqlserver in $mysqlservers) {
                            Export-MySQLServer $mysqlserver 
                        }
                    }

                    #PostgreSQL Servers
                    Write-Output "Collecting PostgreSQL Servers..."
                    Export-AddToFile "    ##### $subname - PostgreSQL Servers #####"
                    $postgresqlservers = Get-AzPostgreSqlFlexibleServer -ErrorAction Stop
                    if ($null -ne $postgresqlservers) {
                        $Script:Legend += ,@("PostgreSQL Server","postgresql.png")
                        foreach ($postgresqlserver in $postgresqlservers) {
                            Export-PostgreSQLServer $postgresqlserver 
                        }
                    }

                    #CosmosDB Servers
                    Write-Output "Collecting CosmosDB Servers..."
                    Export-AddToFile "    ##### $subname - CosmosDB Servers #####"
                    $resourceGroups = Get-AzResourceGroup -ErrorAction Stop
                    $GotAzCosmosDBAccounts = $false
                    foreach ($rg in $resourceGroups) {
                        $dbaccts = Get-AzCosmosDBAccount -ResourceGroupName $rg.ResourceGroupName -ErrorAction Stop
                        foreach ($dbaact in $dbaccts) {
                            $GotAzCosmosDBAccounts = $true
                            Export-CosmosDBAccount $dbaact
                        }
                    }
                    if ($GotAzCosmosDBAccounts) {
                        $Script:Legend += ,@("CosmosDB Account","cosmosdb.png")
                    }

                    #Redis Servers
                    Write-Output "Collecting Redis Servers..."
                    Export-AddToFile "    ##### $subname - Redis Servers #####"
                    $redisservers = Get-AzRedisCache -ErrorAction Stop
                    if ($null -ne $redisservers) {
                        $Script:Legend += ,@("Redis Cache","redis.png")
                        foreach ($redisserver in $redisservers) {
                            Export-RedisServer $redisserver 
                        }
                    }

                    #SQL Managed Instances
                    Write-Output "Collecting SQL Managed Instances..."
                    Export-AddToFile "    ##### $subname - SQL Managed Instances #####"
                    $sqlmanagedinstances = Get-AzSqlInstance -ErrorAction Stop
                    if ($null -ne $sqlmanagedinstances) {
                        $Script:Legend += ,@("SQL Managed Instance","sqlmi.png")
                        foreach ($sqlmanagedinstance in $sqlmanagedinstances) {
                            Export-SQLManagedInstance $sqlmanagedinstance 
                        }
                    }

                    #Azure SQL logical servers
                    Write-Output "Collecting SQL Servers..."
                    Export-AddToFile "    ##### $subname - SQL Servers #####"
                    $sqlservers = Get-AzSqlServer -ErrorAction Stop
                    if ($null -ne $sqlservers) {
                        $Script:Legend += ,@("SQL Server","sqlserver.png")
                        foreach ($sqlserver in $sqlservers) {
                            Export-SQLServer $sqlserver 
                        }
                    }

                    #EventHubs
                    Write-Output "Collecting Event Hubs..."
                    Export-AddToFile "    ##### $subname - Event Hubs #####"
                    $namespaces = Get-AzEventHubNamespace -ErrorAction Stop
                    if ($null -ne $namespaces) {
                        $Script:Legend += ,@("Event Hub","eventhub.png")
                        foreach ($namespace in $namespaces) {
                            Export-EventHub $namespace 
                        }
                    }

                    #App Service Plans
                    Write-Output "Collecting App Service Plans..."
                    Export-AddToFile "    ##### $subname - App Service Plans #####"
                    $appserviceplans = Get-AzAppServicePlan -ErrorAction Stop   
                    if ($null -ne $appserviceplans) {
                        $Script:Legend += ,@("App Service Plan","appplan.png")
                        foreach ($appserviceplan in $appserviceplans) {
                            Export-AppServicePlan $appserviceplan 
                        }
                    }

                    #APIMs
                    Write-Output "Collecting API Management Services..."
                    Export-AddToFile "    ##### $subname - API Management Services #####"
                    $apims = Get-AzApiManagement -ErrorAction Stop
                    if ($null -ne $apims) {
                        $Script:Legend += ,@("API Management","apim.png")
                        foreach ($apim in $apims) {
                            Export-APIM $apim 
                        }
                    }

                    #AKS
                    Write-Output "Collecting AKS Clusters..."
                    Export-AddToFile "    ##### $subname - AKS Clusters #####"
                    $aksclusters = Get-AzAksCluster -ErrorAction Stop
                    if ($null -ne $aksclusters) {
                        $Script:Legend += ,@("AKS Cluster","aks-service.png")
                        foreach ($akscluster in $aksclusters) {
                            Export-AKSCluster $akscluster
                        }   
                    }

                    #Compute Galleries
                    Write-Output "Collecting Compute Galleries..."
                    Export-AddToFile "    ##### $subname - Compute Galleries #####"
                    $computeGalleries = Get-AzGallery -ErrorAction Stop
                    if ($null -ne $computeGalleries) {
                        $Script:Legend += ,@("Compute Gallery","computegalleries.png")
                        foreach ($computeGallery in $computeGalleries) {
                            Export-ComputeGallery $computeGallery
                        }
                    }

                    #VMSSs
                    Write-Output "Collecting VMSS..."
                    Export-AddToFile "    ##### $subname - VMSS #####"
                    $VMSSs = Get-AzVMSS -ErrorAction Stop
                    if ($null -ne $VMSSs) {
                        $Script:Legend += ,@("Virtual Machine Scale Set","vmss.png")
                        foreach ($vmss in $VMSSs) {
                            Export-VMSS $vmss
                        }
                    }

                    #Managed Identities
                    Write-Output "Collecting Managed Identities..."
                    Export-AddToFile "    ##### $subname - User Assigned Managed Identities #####"
                    $managedIdentities = Get-AzUserAssignedIdentity -ErrorAction Stop
                    if ($null -ne $managedIdentities) {
                        $Script:Legend += ,@("Managed Identity","managed-identity.png")
                        foreach ($managedIdentity in $managedIdentities) {
                            Export-ManagedIdentity $managedIdentity
                        }
                    }

                    #ACRs
                    Write-Output "Collecting Azure Container Registries..."
                    Export-AddToFile "    ##### $subname - Azure Container Registries #####"
                    $acrs = Get-AzContainerRegistry -ErrorAction Stop
                    if ($null -ne $acrs) {
                        $Script:Legend += ,@("Azure Container Registry","acr.png")
                        foreach ($acr in $acrs) {
                            Export-ACR $acr
                        }   
                    }

                    #SSH Keys
                    Write-Output "Collecting SSH Keys..."
                    Export-AddToFile "    ##### $subname - SSH Keys #####"
                    $sshkeys = Get-AzSshKey -ErrorAction Stop
                    if ($null -ne $sshkeys) {
                        $Script:Legend += ,@("SSH Key","ssh-key.png")
                        foreach ($sshkey in $sshkeys) {
                            Export-SSHKey $sshkey
                        }
                    }

                    #Container App Environments
                    Write-Output "Collecting Container App Environments..."
                    Export-AddToFile "    ##### $subname - Container App Environments #####"
                    $containerAppEnvironments = Get-AzContainerAppManagedEnv -ErrorAction Stop
                    if ($null -ne $containerAppEnvironments) {
                        $Script:Legend += ,@("Container App Environment","containerappenv.png")
                        foreach ($containerAppEnvironment in $containerAppEnvironments) {
                            Export-ContainerAppEnv $containerAppEnvironment
                        }
                    }
                    
                    #Static Web Apps
                    Write-Output "Collecting Static Web Apps..."
                    Export-AddToFile "    ##### $subname - Static Web Apps #####"
                    $StaticWebApps = Get-AzStaticWebApp
                    if ( $null -ne $StaticWebApps ) {
                        $Script:Legend += ,@("Static Web App","swa.png")
                        foreach ( $swa in $StaticWebApps ) {
                            Export-StaticWebApp -StaticWebApp $swa
                        }
                    }

                    #Recovery Service Vaults (RSV)
                    Write-Output "Collecting Recovery Service Vaults..."
                    Export-AddToFile "    ##### $subname - Recovery Service Vaults #####"
                    $RecoveryServiceVaults = Get-AzRecoveryServicesVault
                    if ( $null -ne $RecoveryServiceVaults ) {
                        $Script:Legend += ,@("Recovery Service Vault","rsv.png")
                        foreach ( $rsv in $RecoveryServiceVaults ) {
                            Export-RecoveryServiceVault -RecoveryServiceVault $rsv
                        }
                    }

                    #Backup Vaults (BV)
                    Write-Output "Collecting Backup Vaults..."
                    Export-AddToFile "    ##### $subname - Backup Vaults #####"
                    $BackupVaults = Get-AzDataProtectionBackupVault
                    if ( $null -ne $BackupVaults ) {
                        $Script:Legend += ,@("Backup Vault","backupvault.png")
                        foreach ( $bv in $BackupVaults ) {
                            Export-BackupVault -BackupVault $bv
                        }
                    }
                    
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

                try {
                    $vnetsubName = (Get-AzSubscription -SubscriptionId $vnetsub -Tenant $TenantId -ErrorAction Stop).Name
                } catch {
                    $vnetsubName = ""
                }

                #
                # The Hub is in another "managed" subscription, so we cannot use the context of that subscription
                # So we're filtering it out here. We do't have access to it.
                #
                if (($Subscriptions.IndexOf($vnetsub) -ge 0) -or ($Subscriptions.IndexOf($vnetsubName) -ge 0)) {
                    $context = Set-AzContext -Subscription $vnetsub -Tenant $TenantId -ErrorAction Stop
                    $vnet = Get-AzVirtualNetwork -name $vnetname -ResourceGroupName $vnetrg -ErrorAction Stop
                    $vnetId = $vnet.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
                    $vnetPeerings = $vnet.VirtualNetworkPeerings.RemoteVirtualNetwork.id
                    foreach ($peering in $vnetPeerings) {
                        if ($script:AllInScopevNetIds.IndexOf($peering) -ge 0) {
                            $peeringId = $peering.replace("-", "").replace("/", "").replace(".", "").ToLower()
                            # DOT
                            $data = "    $vnetId -> $peeringId [label = `"Peered to`"; ltail = cluster_$vnetId; lhead = cluster_$peeringId; weight = 10;];"

                            Export-AddToFile -Data $data
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-Error "Error while collecting data from subscription: $subid" $_.Exception.Message
        return
    }
    
    try {
        if ( $EnableRanking ) { Export-dotFooterRanking }
        Export-dotFooter

        ##### Generate diagram #####
        # Generate diagram using Graphviz
        $OutputFileName = "AzNetworkDiagram"
        if ($Prefix) {
            $OutputFileName = $Prefix + "-" + $OutputFileName
        }
        $OutputFileName = Join-Path $OutputPath -ChildPath $OutputFileName  # OS-safe, works on Linux as well as Windows

    #    dot -q1 -Tpdf $OutputPath\AzNetworkDiagram.dot -o "$OutputFileName.pdf"

        $DOT = (Get-DOTExecutable).Fullname
        $esc = '--%'
        foreach ($format in $OutputFormat) {
            Write-Output "`nGenerating $OutputFileName.$format ..."
            #GenerateDotFile -OutputPath $OutputPath -OutputFileName $OutputFileName -Format $OutputFormat
            $DOTFileName = Join-Path $OutputPath -ChildPath "AzNetworkDiagram.dot"
            $arguments = "-v -T$format $DOTFileName -o $OutputFileName.$format"
            $errorOutput = $( $output = & $DOT $esc $arguments) 2>&1
            # Check the exit code and error output
            if ($LastExitCode -ne 0) {
                Write-Host "The executable failed with exit code: $LastExitCode"
                Write-Host "Error details: $errorOutput"
                Write-Host "Output: $output"
            }
        }
    } catch {
        Write-Error "Error while generating diagram: $OutputFileName at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
    finally {
        if (-not $KeepDotFile) {
            Remove-Item "$OutputPath\AzNetworkDiagram.dot" -Force
        }
    }
} 

Export-ModuleMember -Function Get-AzNetworkDiagram
