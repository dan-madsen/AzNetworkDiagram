// az deployment group create --resource-group RGNAME --name 'AzNetworkDiagram-demo' --template-file IaaS.bicep -c

// Deploy everything to the same RG
targetScope = 'resourceGroup'

param location string = 'swedencentral'
param locationshort string = 'sdc'
param environment string = 'dev'

// Network
param enableGallery bool = true
param enableAVD bool = true
param enableBackup bool = true
param enableESAN bool = true
param enableSSHKey bool = true


///////////////////////////////////////////////
//// Network core
///////////////////////////////////////////////
module hub 'br/public:avm/res/network/virtual-network:0.9.0' = {
  params: {
    name: 'vnet-hub-${environment}-${locationshort}-01'
    location: location
    addressPrefixes: ['10.0.0.0/23']
    subnets: [
      {
        name: 'default'
        addressPrefix: '10.0.0.0/26'
        routeTableResourceId: rt02.outputs.resourceId
      }
      {
        name: 'AzureFirewallSubnet'
        addressPrefix: '10.0.0.64/26'
      }
      {
        name: 'AzureBastionSubnet'
        addressPrefix: '10.0.0.128/26'
      }
      {
        name: 'GatewaySubnet'
        addressPrefix: '10.0.0.192/26'
      }
      {
        name: 'RouteServerSubnet'
        addressPrefix: '10.0.1.0/26'
      }
    ]
  }
}

module spoke 'br/public:avm/res/network/virtual-network:0.9.0' = {
  params: {
    name: 'vnet-spoke-${environment}-${locationshort}-01'
    location: location
    addressPrefixes: ['10.0.2.0/24']
    subnets: [
      {
        name: 'default'
        addressPrefix: '10.0.2.0/24'
        networkSecurityGroupResourceId: nsg2.outputs.resourceId
        routeTableResourceId: rt02.outputs.resourceId
      }
    ]
  }
}

module rt02 'br/public:avm/res/network/route-table:0.5.0' = {
  params: {
    location: location
    name: 'rt-aznetworkdiagram-${environment}-${locationshort}-01'
    routes: [
      {
        name: 'r01'
        properties: {
          nextHopType: 'VirtualAppliance'
          addressPrefix: '172.16.0.0/24'
          nextHopIpAddress: '10.0.0.68'
        }
      }
    ]
  }
}

module peering1 'br/public:avm/res/network/virtual-network/virtual-network-peering:0.2.0' = {
  params: {
    localVnetName: hub.outputs.name
    remoteVirtualNetworkResourceId: spoke.outputs.resourceId
  }
}

module peering2 'br/public:avm/res/network/virtual-network/virtual-network-peering:0.2.0' = {
  params: {
    localVnetName: spoke.outputs.name
    remoteVirtualNetworkResourceId: hub.outputs.resourceId
  }
}

module nsg2 'br/public:avm/res/network/network-security-group:0.5.3' = {
  params: {
    name: 'nsg-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
  }
}

///////////////////////////////////////////////
//// VM VMSS
///////////////////////////////////////////////
module vm01 'br/public:avm/res/compute/virtual-machine:0.22.1' = {
  params: {
    name: 'vm-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    backupVaultName: enableBackup ? rsv.outputs.name : null
    backupVaultResourceGroup: enableBackup ? resourceGroup().name : null
    backupPolicyName: enableBackup ? 'DefaultPolicy' : null
    computerName: 'TestVM'
    availabilityZone: 1
    nicConfigurations: [
      {
        ipConfigurations: [
          {
            subnetResourceId: '${spoke.outputs.resourceId}/subnets/default'
          }
        ]
        nicSuffix: '-nic-01'
        networkSecurityGroupResourceId: nsg2.outputs.resourceId
      }
    ]
    osDisk: {
      createOption: 'FromImage'
      managedDisk: {}
    }
    osType: 'Windows'

    imageReference: {
      publisher: 'MicrosoftWindowsServer'
      offer: 'WindowsServer'
      sku: '2025-datacenter-azure-edition'
      version: 'latest'
    }

    vmSize: 'Standard_B2ats_v2'
    adminUsername: 'InitialUser'
    adminPassword: '!2Hj${uniqueString('gsughs3gusoghpo!shIYGiygsgiu', location, 'vm')}'
  }
}

// module vmss01 'br/public:avm/res/compute/virtual-machine-scale-set:0.11.1' = {
//     params: {
//         name: 'vmss-aznetworkdiagram-${environment}-${locationshort}-01'
//         adminPassword: uniqueString('igYGgoygYgoyugouyfgyuf')
//         adminUsername: 'InitialAccount'
//         imageReference: {}
//         nicConfigurations: [
//             {
//                 ipConfigurations: [
//                     {
//                         subnetResourceId: spoke.outputs.resourceId
//                     }
//                 ]
//                 nicSuffix: '-nic-01'
//             }
//         ]
//         osDisk: {
//             createOption: 'FromImage'
//         }
//         osType: 'Windows'
//         skuName: 'Standard_B2s_v2'
//     }
// }


module sshkey 'br/public:avm/res/compute/ssh-public-key:0.4.4' = if(enableSSHKey) {
  params: {
    name: 'sshkey-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    // publicKey:  // ??
  }
}

module computegallery 'br/public:avm/res/compute/gallery:0.9.5' = if (enableGallery) {
  params: {
    name: 'galaznetworkdiagram${environment}${locationshort}01'
    location: location
  }
}

module rsv 'br/public:avm/res/recovery-services/vault:0.11.3' = if(enableBackup) {
  params: {
    name: 'rsv-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
  }
}

module bv 'br/public:avm/res/data-protection/backup-vault:0.13.1' = if(enableBackup) {
  params: {
    name: 'bv-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
  }
}

module avdhp 'br/public:avm/res/desktop-virtualization/host-pool:0.8.1' = if (enableAVD) {
  params: {
    name: 'avdhp-azdiagram-${environment}-${locationshort}-01'
    friendlyName: 'Hostpool-01'
    hostPoolType: 'Pooled'
    location: 'westeurope' // Not available in all regions
    loadBalancerType: 'DepthFirst'
    personalDesktopAssignmentType: 'Automatic'
  }
}

module avdappgroup 'br/public:avm/res/desktop-virtualization/application-group:0.4.2' = if (enableAVD) {
  params: {
    name: 'avdhp-azdiagram-${environment}-${locationshort}-01'
    location: 'westeurope' // Not available in all regions
    applicationGroupType: 'RemoteApp'
    hostpoolName: avdhp.outputs.name
  }
}

module avdworkspace 'br/public:avm/res/desktop-virtualization/workspace:0.9.2' = if (enableAVD) {
  params: {
    name: 'Workspace01'
    location: 'westeurope' // Not available in all regions
    friendlyName: 'Workspace 01'
    applicationGroupReferences: [
      '${avdappgroup.outputs.resourceId}'
    ]
  }
}

module avdapp1 'br/public:avm/res/desktop-virtualization/application-group/application:0.1.0' = if (enableAVD) {
  params: {
    name: 'Notepad'
    applicationGroupName: avdappgroup.outputs.name
    filePath: 'c:\\windows\\notepad.exe'
    friendlyName: 'Notepad'
  }
}

module avdapp2 'br/public:avm/res/desktop-virtualization/application-group/application:0.1.0' = if (enableAVD) {
  params: {
    name: 'Calc'
    applicationGroupName: avdappgroup.outputs.name
    filePath: 'c:\\windows\\calc.exe'
    friendlyName: 'Calc'
  }
}

module esan 'br/public:avm/res/elastic-san/elastic-san:0.5.1' = if(enableESAN) {
  params: {
    name: 'esan-azdiagram-${environment}-${locationshort}-01'
    availabilityZone: -1
    baseSizeTiB: 1
    location: location
    volumeGroups: [
      {
        name: 'vg1'
        volumes: [
          {
            name: 'vol1'
            sizeGiB: 1
          }
        ]
      }
    ]
  }
}
