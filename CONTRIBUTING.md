# Table of contents
* [How to contribute](#How-to-contribute)
* [Issues, bugs, comments and ideas](#issues-bugs-comments-and-ideas)
* [New resource type](#New-resource-type)

# How to contribute
Let us know if you would like to contribute - pull request and good ideas are welcome. Have a lot at the current issues, ideas, etc. in the "Issues" sections in Github.

# Issues, bugs, comments and ideas
Please submit these using the issues option in GitHub. Remember to supply at least version information, error description and error message from the command line. If the Azure resource/object in question have a "special/exotic/rarely used" configuration that you are aware of, please include that is well, to ease troubleshooting.

# New resource type
New resource types are added from time to time. This section describes guidelines on how to added a new resource type

## Runtime switches
All non-core resource types have commandline switches to enable and disable them, in the "Get-AzNetworkDiagram" function.

``` Powershell
        [Parameter(Mandatory = $false)][switch]$EnableSA,
        [Parameter(Mandatory = $false)][switch]$SkipSA,
```

And some debug output:
``` Powershell
        write-host "-EnableSA : $EnableSA"
        write-host "-SkipSA : $SkipSA"
```

### Runtime enablement
Here is an example of the Storage account runtime enablement, in the "Get-AzNetworkDiagram" function. Almost all lines contains refence to the resource type - please change variables names, function names and output to match the new resource type.

``` Powershell
                ### Storage Accounts
                if ( $EnableSA -OR (-not $SkipNonCoreNetwork -AND -not $SkipSA ) ) {
                    Write-Output "Collecting Storage Accounts..."
                    Export-AddToFile "    ##### $subname - Storage Accounts #####"
                    $storageaccounts = Get-AzStorageAccount -ErrorAction Stop
                    if ($null -ne $storageaccounts) {
                        $Script:Legend += ,@("Storage Account","storage-account.png")
                        foreach ($storageaccount in $storageaccounts) {
                            Export-StorageAccount $storageaccount
                        }
                    }
                }
```

## Ranking
Consider reference to other resource types when you decide on the ranking level (1-10).

Variables are defined, in the "Get-AzNetworkDiagram", like this:
``` Powershell
    $script:ranksa = @()
```

``` Powershell
        $staid = $storageaccount.Id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $script:ranksa = @()
```

With the function for the resource type, the varible is populated with IDs (DOT ID - ie. the Azure resource id, stripped for not-supported characters) for all instance of the resource type, like this:
``` Powershell
        $script:ranksa += $staid
```

In the "Export-dotFooterRanking" function, the ranking is set for all resource types, under the relevant (DOT subgraph. Rank 1-10 is already defined - add the new resource type in an appropriate place.

``` Powershell
        ### Storage Account
        $($script:ranksa -join '; ')
```

## Icon
- Add icon the the icons folder
- Add file name in the (alphabetical) array of icons, ini the "Confirm-Prerequisites" functioni

## Export-XXX function template
Search and replace (IN ORDER)
- Replace "RESOURCE TYPE" with resource type name
- Replace "RES" with resource abbreviation
  - Ensure the Generate-URL switch is set to "-resource"
  
``` Powershell
<#
.SYNOPSIS
Exports details of a RESOURCE TYPE instance for inclusion in an infrastructure diagram.

.DESCRIPTION
The `Export-RES` function processes a specified RESOURCE TYPE object, retrieves its details, and formats the data for inclusion in the diagram.

.PARAMETER RES
Specifies the RESOURCE TYPE object to be processed. This parameter is mandatory.

.EXAMPLE
PS> Export-RES -RES $RES

This example retrieves an LB instance and exports its details for inclusion in the diagram.
#>
function Export-RES
{
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSCustomObject]$RES
    )

    try {
        $RESid = $RES.id.replace("-", "").replace("/", "").replace(".", "").ToLower()
        $script:rankRES += $RESid

        # Collect information about RES
        $RESname = SanitizeString $RES.name
        $location = SanitizeLocation $RES.location

        $header = "
        # $($name) - $RESid
        subgraph cluster_$RESid {
            style = solid;
            colorscheme = blues9 ;
            bgcolor = 2;
            node [colorscheme = blues9 ; style = filled;];
        "

        #RES DOT
        $ImagePath = Join-Path $OutputPath "icons" "ICONNAME.png"
        $RESdata += "            $RESid [fillcolor = 3; label=`"Location: $location`";image = `"$ImagePath`";imagepos = `"tc`";labelloc = `"b`";height = 3.0;$(Generate-DotURL -resource $RES)]`n"


        # End subgraph
        $footer = "
            label = `"$(SanitizeString $RESname)`";
        }
        "

        Export-AddToFile -Data ($header + $RESdata + $footer)
    }
    catch {
        Write-Error "Can't export RES: $($RES.name) at line $($_.InvocationInfo.ScriptLineNumber) " $_.Exception.Message
    }
}
```

## Sanitize
Utilizie the "SanitizeString" and "SanitizeLocation" for all potetial confidential data that should have the OPTION to be anonymized int the digram.

## (Additional) Powershell module needed?
- At the top of the psm1 file - add the module to the array
- In the psd1 flie, add the module to the "RequiredModules" array