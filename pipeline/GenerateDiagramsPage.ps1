
param (
    [Parameter(Mandatory=$true)]
    [String]$destPath,
    [Parameter(Mandatory=$true)]
    [String]$buildDirectory
)

# https://github.com/microsoft/PSDocs
# https://github.com/microsoft/PSDocs/blob/main/docs/commands/PSDocs/en-US/Invoke-PSDocument.md

# Connect-AzAccount -Tenant c9b9cb50-3644-4db4-a267-fa84df2f4ceb
$cwd = Get-Location
Write-Output "Current working directory: $cwd"
Write-Output "Destination path: $destPath"
Write-Output "Build directory: $buildDirectory"
Import-Module "$buildDirectory/AzNetworkDiagram/AzNetworkDiagram.psm1" -Force
$OutputPath = "$destPath/Azure-Landing-Zone-Architecture-Design-and-Implementation/ALZ-Networking/media"
Copy-Item -Path "$buildDirectory/AzNetworkDiagram/icons" -Destination "$OutputPath/icons" -Recurse -Force

$TargetSet = @(
    ,@("ZA", "Contoso South Africa", @("za-con-prd-1","za-id-prd-1","za-mgt-prd-1" ))
    ,@("GP", "Contoso Group", @("gp-con-prd-1","gp-id-prd-1","gp-mgt-prd-1" ))
    ,@("CM", "Contoso Cameroon", @("cm-con-prd-1","cm-id-prd-1","cm-mgt-prd-1" ))
    ,@("FT", "Contoso Group Fintech", @("ft-con-prd-1","ft-id-prd-1","ft-mgt-prd-1" ))
    ,@("BB", "Contoso Bayobab", @("bb-con-prd-1","bb-id-prd-1","bb-mgt-prd-1" ))
    ,@("UG", "Contoso Uganda", @("ug-con-prd-1","ug-id-prd-1","ug-mgt-prd-1" ))
    ,@("GH", "Contoso Ghana", @("gh-con-prd-1","gh-id-prd-1","gh-mgt-prd-1" ))
    ,@("NG", "Contoso Nigeria", @("ng-con-prd-1","ng-id-prd-1","ng-mgt-prd-1" ))
)

$Environments = @()
ForEach ($target in $TargetSet) {
    $Row = "" | Select Prefix, Name, Subscriptions
    $Row.Prefix = $target[0]
    $Row.Name = $target[1]
    $Row.Subscriptions = $target[2]
    $Environments += $Row
}
$PSDocsInputObject = New-Object PSObject -property @{
    'Environments' = $Environments | Sort-Object -Property Name
}

$PSDocsInputObject.Environments | ForEach-Object { 
                                        $prefix = $_.Prefix
                                        Write-Host "Using PS version $($PSVersionTable.PSVersion) - Edition: $($PSVersionTable.PSEdition)"
                                        Get-AzNetworkDiagram -Subscriptions $_.Subscriptions -Prefix $prefix -OutputPath $OutputPath -OutputFormat pdf,svg,png
                                        cd "$destPath"
                                        git add "$OutputPath/$prefix*.png"
                                        git add "$OutputPath/$prefix*.svg"
                                        git add "$OutputPath/$prefix*.pdf"
                                    }

$PSDocsInputObject | Export-Clixml -Path "$buildDirectory/PSDocsInputObject.xml"

# https://github.com/microsoft/PSDocs/blob/main/docs/commands/PSDocs/en-US/Invoke-PSDocument.md


