// az deployment group create --resource-group RGNAME --name 'AzNetworkDiagram-demo' --template-file Demo.bicep -c

// Deploy everything to the same RG
targetScope = 'resourceGroup'

param location string = 'swedencentral'
param locationshort string = 'sdc'
param environment string = 'dev'

// Network
// param enableCoreNetwork bool = true
param enableAzFW bool = false
param enableRS bool = true
param enableVPN bool = false
param enableBastion bool = false

// Other
param enableVM bool = true
param enableASP bool = true
param enableSWA bool = true
param enableKV bool = true
param enableUMI bool = true
param enableSSH bool = true
param enableST bool = true
param enableGallery bool = true

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
        natGatewayResourceId: natgw2.outputs.resourceId
        networkSecurityGroupResourceId: nsg2.outputs.resourceId
        routeTableResourceId: rt02.outputs.resourceId
      }
    ]
  }
}

// Coupling to vnet/subnet missing !?
resource rs01 'Microsoft.Network/virtualHubs@2025-05-01' = if (enableRS) {
  name: 'rs-aznetworkdiagram-${environment}-${locationshort}-01'
  location: location
  properties: {
    sku: 'Standard'
  }
}

module rspip 'br/public:avm/res/network/public-ip-address:0.12.0' = {
  params: {
    name: '${rs01.name}-pip-01'
  }
}

resource rs01b 'Microsoft.Network/virtualHubs/ipConfigurations@2025-05-01' = if (enableRS) {
  name: 'rs-testConfiga-znetworkdiagram-${environment}-${locationshort}-01'
  parent: rs01
  properties: {
    subnet: {
      id: '${hub.outputs.resourceId}/subnets/RouteServerSubnet'
    }
    publicIPAddress: rspip
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

module natgw2 'br/public:avm/res/network/nat-gateway:2.1.0' = {
  params: {
    name: 'natgw-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    availabilityZone: -1
    natGatewaySku: 'StandardV2'
    publicIpResourceIds: [natgw2pip.outputs.resourceId]
  }
}

module natgw2pip 'br/public:avm/res/network/public-ip-address:0.12.0' = {
  params: {
    name: 'natgw-aznetworkdiagram-${environment}-${locationshort}-01-pip-01'
    location: location
    skuName: 'StandardV2'
  }
}

module vgw 'br/public:avm/res/network/virtual-network-gateway:0.11.0' = if (enableVPN) {
  params: {
    name: 'vgw-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    clusterSettings: {
      clusterMode: 'activePassiveBgp'
    }
    gatewayType: 'Vpn'
    virtualNetworkResourceId: hub.outputs.resourceId
  }
}

module lgw01 'br/public:avm/res/network/local-network-gateway:0.4.0' = if (enableVPN) {
  params: {
    name: 'lgw-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    localGatewayPublicIpAddress: '127.0.0.2'
    localNetworkAddressSpace: {
      addressPrefixes: ['192.168.0.0/24', '172.16.0.0/24']
    }
  }
}

module con01 'br/public:avm/res/network/connection:0.1.7' = if (enableVPN) {
  params: {
    name: 'con-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    virtualNetworkGateway1: {
      id: vgw.outputs.resourceId
    }
    localNetworkGateway2ResourceId: lgw01.outputs.resourceId
    connectionType: 'IPsec'
    vpnSharedKey: 'N/A'
    connectionProtocol: 'IKEv2'
  }
}

module AzFW 'br/public:avm/res/network/azure-firewall:0.10.1' = if (enableAzFW) {
  params: {
    name: 'afw-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    azureSkuTier: 'Standard'
    virtualNetworkResourceId: hub.outputs.resourceId
    firewallPolicyId: AzFWPol.outputs.resourceId
  }
}

module AzFWPol 'br/public:avm/res/network/firewall-policy:0.3.5' = if (enableAzFW) {
  params: {
    name: 'afwp-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    // ruleCollectionGroups: []
  }
}

module rcg01 'br/public:avm/res/network/firewall-policy/rule-collection-group:0.1.0' = if (enableAzFW) {
  params: {
    name: 'rcg-test'
    firewallPolicyName: AzFWPol.outputs.name
    priority: 100
    ruleCollections: [
      // {
      //     name: 'RG-Test'
      //     priority: 100
      //     ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
      //     action: {
      //       type: 'Allow'
      //     }
      //     rules: [
      //       {
      //         name: 'ACL-Test'
      //         ruleType: 'NetworkRule'
      //         sourceAddresses: [
      //           '10.0.0.0/16'
      //         ]
      //         destinationIpGroups: [
      //           '${ipg01.outputs.resourceId}'
      //           '${ipg02.outputs.resourceId}'
      //         ]
      //         destinationPorts: [
      //           '443'
      //         ]
      //         ipProtocols: [
      //           'TCP'
      //         ]
      //       }
      //     ]
      //   }
    ]
  }
}

module ipg01 'br/public:avm/res/network/ip-group:0.4.0' = if (enableAzFW) {
  params: {
    name: 'ipg-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    ipAddresses: ['10.0.0.4']
  }
}

module ipg02 'br/public:avm/res/network/ip-group:0.4.0' = if (enableAzFW) {
  params: {
    name: 'ipg-aznetworkdiagram-${environment}-${locationshort}-02'
    location: location
    ipAddresses: ['10.0.0.5']
  }
}

module bas01 'br/public:avm/res/network/bastion-host:0.8.2' = if (enableBastion) {
  params: {
    name: 'bas-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    virtualNetworkResourceId: hub.outputs.resourceId
    skuName: 'Basic'
  }
}

///////////////////////////////////////////////
//// vWAN
///////////////////////////////////////////////

///////////////////////////////////////////////
//// VM VMSS
///////////////////////////////////////////////
module vm01 'br/public:avm/res/compute/virtual-machine:0.22.1' = if (enableVM) {
  params: {
    name: 'vm-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
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

    vmSize: 'Standard_B2ms'
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

///////////////////////////////////////////////
//// AKS
///////////////////////////////////////////////
// module aks01 'br/public:avm/res/kubernetes-configuration/extension:0.3.8' = {
//     params: {
//         name: 
//         clusterName: 
//         extensionType: 
//     }
// }

///////////////////////////////////////////////
//// App Service
///////////////////////////////////////////////
module asp01 'br/public:avm/res/web/serverfarm:0.7.0' = if (enableASP) {
  params: {
    name: 'asp-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
  }
}

module web01 'br/public:avm/res/web/site:0.23.0' = if (enableASP) {
  params: {
    name: 'app-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    kind: 'app,container,windows'
    serverFarmResourceId: asp01.outputs.resourceId
  }
}

module pe01 'br/public:avm/res/network/private-endpoint:0.12.1' = if (enableASP) {
  params: {
    name: '${web01.name}-pe-01'
    location: location
    subnetResourceId: '${spoke.outputs.resourceId}/subnets/default'
    privateLinkServiceConnections: [
      {
        // id: web01.outputs.resourceId
        name: 'pe01Test'
        properties: {
          privateLinkServiceId: web01.outputs.resourceId
          groupIds: [
            'sites'
          ]
        }
      }
    ]
  }
}

//---------------------------------------------
// Storage account
//---------------------------------------------
module st 'br/public:avm/res/storage/storage-account:0.32.0' = if (enableST) {
  params: {
    name: 'stazdiagram${uniqueString(location, resourceGroup().name)}'
    location: location
    accessTier: 'Hot'
    skuName: 'Standard_LRS'
  }
}

//---------------------------------------------
// SWA
//---------------------------------------------
module swa 'br/public:avm/res/web/static-site:0.9.5' = if (enableSWA) {
  params: {
    name: 'swa-aznetworkdiagram-${environment}-${locationshort}-01'
    sku: 'Free'
    location: 'westeurope' // Not available in all regions - hardcoded
  }
}

module umi 'br/public:avm/res/managed-identity/user-assigned-identity:0.5.1' = if (enableUMI) {
  params: {
    name: 'mi-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
  }
}

module sshkey 'br/public:avm/res/compute/ssh-public-key:0.4.4' = if (enableSSH) {
  params: {
    name: 'sshkey-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    // publicKey:  // ??
  }
}

// module computegallery 'br/public:avm/res/compute/gallery:0.9.5' = if (enableGallery) {
//   params: {
//     name: 'galaznetworkdiagram${environment}${locationshort}01'
//     location: location
//   }
// }

module kv 'br/public:avm/res/key-vault/vault:0.13.3' = if (enableKV) {
  params: {
    name: 'kv-azdiagram-${environment}-${locationshort}' // Length restriction
    location: location
    sku: 'standard'
    softDeleteRetentionInDays: 7
    enableSoftDelete: false
  }
}

module mysql 'br/public:avm/res/db-for-my-sql/flexible-server:0.10.3' = {
  params: {
    name: 'mysql-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    availabilityZone: -1
    highAvailability: 'Disabled'
    skuName: 'Standard_B1ms'
    tier: 'Burstable'
    administratorLogin: 'sqlsa'
    administratorLoginPassword: '!2Hj${uniqueString('gsughs3gusoghpo!shIYGiygsgiu', location, 'mysql')}'
  }
}

module mysqldb 'br/public:avm/res/db-for-my-sql/flexible-server/database:0.1.0' = {
  params: {
    name: 'mysqldb-aznetworkdiagram-${environment}-${locationshort}-01'
    flexibleServerName: mysql.outputs.name
  }
}

module sqlmi 'br/public:avm/res/sql/managed-instance:0.4.1' = {
  params: {
    name: 'sqlmi-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    skuName: 'GP_Gen5'
    storageSizeInGB: 32
    vCores: 1
    subnetResourceId: spoke.outputs.subnetResourceIds[0]
    zoneRedundant: false

    databases: [
      {
        name: 'sqlmidb-aznetworkdiagram-${environment}-${locationshort}-01'
      }
    ]
  }
}

module sqlserver 'br/public:avm/res/sql/server:0.21.2' = {
  params: {
    name: 'sql-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    administratorLogin: 'sqlsa'
    administratorLoginPassword: '!2Hj${uniqueString('gsughs3gusoghpo!shIYGiygsgiu', location, 'mysql')}'
  }
}

module sqldb 'br/public:avm/res/sql/server/database:0.2.1' = {
  params: {
    name: 'sqldb-aznetworkdiagram-${environment}-${locationshort}-01'
    availabilityZone: 1
    serverName: sqlserver.outputs.name
    sku: {
      name: 'S0' // S0 = 10 DTU
      tier: 'Standard'
    }
  }
}

module pgsql 'br/public:avm/res/db-for-postgre-sql/flexible-server:0.15.4' = {
  params: {
    name: 'pgsql-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    availabilityZone: -1
    skuName: 'Standard_B1ms'
    tier: 'Burstable'
    geoRedundantBackup: 'Disabled'
    highAvailability: 'Disabled'
  }
}

module pgsqldb 'br/public:avm/res/db-for-postgre-sql/flexible-server/database:0.1.1' = {
  params: {
    name: 'pgsqldb-aznetworkdiagram-${environment}-${locationshort}-01'
    flexibleServerName: pgsql.outputs.name
  }
}

module cosmosdbact 'br/public:avm/res/document-db/database-account:0.19.0' = {
  params: {
    name: 'cosmosact-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    zoneRedundant: false
  }
}

//module cosmosdb 'br/public:cosmos'

module redis 'br/public:avm/res/cache/redis:0.17.1' = {
  params: {
    name: 'redis-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    skuName: 'Basic'
  }
}

module acr 'br/public:avm/res/container-registry/registry:0.12.1' = {
  params: {
    name: 'acraznetworkdiagram${environment}${locationshort}01'
    location: location
    acrSku: 'Basic'
  }
}

module apim 'br/public:avm/res/api-management/service:0.14.4' = {
  params: {
    name: 'apim-aznetworkdiagram-${environment}-${locationshort}-01'
    publisherEmail: 'no-one@nowhere.com'
    publisherName: 'No one'
    sku: 'Developer'
    location: location
  }
}

module relay 'br/public:avm/res/relay/namespace:0.7.4' = {
  params: {
    name: 'relay-aznetworkdiagram-${environment}-${locationshort}-01'
    skuName: 'Standard'
    location: location
  }
}

module cae 'br/public:avm/res/app/managed-environment:0.13.3' = {
  params: {
    name: 'cae-aznetworkdiagram-${environment}-${locationshort}-01'
    zoneRedundant: false
    location: location
  }
}

module rsv 'br/public:avm/res/recovery-services/vault:0.11.3' = {
  params: {
    name: 'rsv-aznetworkdiagram-${environment}-${locationshort}-01'
  }
}

module bv 'br/public:avm/res/data-protection/backup-vault:0.13.1' = {
  params: {
    name: 'bv-aznetworkdiagram-${environment}-${locationshort}-01'
  }
}

module aci 'br/public:avm/res/container-instance/container-group:0.7.0' = {
  name: 'aciDeployment'
  params: {
    name: 'aci-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    availabilityZone: -1
    osType: 'Linux'

    containers: [
      {
        name: 'hello-container'
        properties: {
          image: 'mcr.microsoft.com/azuredocs/aci-helloworld'
          resources: {
            requests: {
              cpu: 1
              memoryInGB: '1'
            }
          }
          ports: [
            {
              port: 80
            }
          ]
        }
      }
    ]

    ipAddress: {
      type: 'Public'
      dnsNameLabel: 'aznetworkdiagram${uniqueString(subscription().subscriptionId)}'
      ports: [
        {
          protocol: 'TCP'
          port: 80
        }
      ]
    }

    restartPolicy: 'Always'
  }
}

module sb 'br/public:avm/res/service-bus/namespace:0.16.2' = {
  params: {
    name: 'sb-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
  }
}

module eh 'br/public:avm/res/event-hub/namespace:0.14.2' = {
  params: {
    name: 'eh-aznetworkdiagram-${environment}-${locationshort}-01'
    skuName: 'Basic'
    location: location
  }
}

module egn 'br/public:avm/res/event-grid/namespace:0.7.4' = {
  params: {
    name: 'egn-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    topicSpaces: []
  }
}

module egd 'br/public:avm/res/event-grid/domain:0.8.4' = {
  params: {
    name: 'egd-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    eventSubscriptions: []
    topics: []
  }
}

module egt 'br/public:avm/res/event-grid/topic:0.9.3' = {
  params: {
    name: 'egt-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    kind: 'Azure'
    eventSubscriptions: [
      {
        name: 'egt-sub-01'
      }
    ]
  }
}

// module egst 'br/public:avm/res/event-grid/system-topic:0.6.5' = {
//   params: {
//     name: 
//     source: 
//     topicType: 
//   }
// }

//AKS
module aks 'br/public:avm/res/container-service/managed-cluster:0.13.1' = {
  name: 'aks-aznetworkdiagram-${environment}-${locationshort}-01'
  params: {
    name: 'aks-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location

    dnsPrefix: 'aks-aznetworkdiagram${uniqueString(subscription().subscriptionId)}-${environment}-${locationshort}-01'

    primaryAgentPoolProfiles: [
      {
        name: 'nodepool1'
        count: 1
        vmSize: 'Standard_B2s'
        osType: 'Linux'
        mode: 'System'
      }
    ]

    enableRBAC: true
  }
}

//ACS
module acs 'br/public:avm/res/communication/communication-service:0.4.3' = {
  params: {
    name: 'acs-aznetworkdiagram-${environment}-${locationshort}-01'
    location: 'global' // Only supported location
    dataLocation: 'Europe'
  }
}

module acsmail 'br/public:avm/res/communication/email-service:0.4.5' = {
  params: {
    name: 'acsmail-aznetworkdiagram-${environment}-${locationshort}-01'
    location: 'global'
    dataLocation: 'Europe'
  }
}

module esan 'br/public:avm/res/elastic-san/elastic-san:0.5.1' = {
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

module avdhp 'br/public:avm/res/desktop-virtualization/host-pool:0.8.1' = {
  params: {
    name: 'avdhp-azdiagram-${environment}-${locationshort}-01'
    friendlyName: 'Hostpool-01'
    hostPoolType: 'Pooled'
    location: 'westeurope' // Not available in all regions
    loadBalancerType: 'DepthFirst'
  }
}

module avdappgroup 'br/public:avm/res/desktop-virtualization/application-group:0.4.2' = {
  params: {
    name: 'avdhp-azdiagram-${environment}-${locationshort}-01'
    location: location
    applicationGroupType: 'Desktop'
    hostpoolName: avdhp.outputs.name
  }
}

module avdworkspace 'br/public:avm/res/desktop-virtualization/workspace:0.9.2' = {
  params: {
    name: 'Workspace01'
    location: 'westeurope' // Not available in all regions
    friendlyName: 'Workspace 01'
    applicationGroupReferences: [
      '${avdappgroup.outputs.resourceId}'
    ]
  }
}

module avdapp 'br/public:avm/res/desktop-virtualization/application-group/application:0.1.0' = {
  params: {
    name: 'Notepad'
    applicationGroupName: avdappgroup.outputs.name
    filePath: 'c:\\windows\\notepad.exe'
    friendlyName: 'Notepad'
  }
}

module vwan 'br/public:avm/res/network/virtual-wan:0.4.3' = {
  params: {
    name: 'vwan-azdiagram-${environment}-${locationshort}-01'
    allowBranchToBranchTraffic: true
    location: location
    type: 'Standard'
  }
}

module vwanhub 'br/public:avm/res/network/virtual-hub:0.4.4' = {
  params: {
    name: 'vhub-azdiagram-${environment}-${locationshort}-01'
    addressPrefix: '10.1.0.0/24'
    virtualWanResourceId: vwan.outputs.resourceId
    sku: 'Standard'
    hubVirtualNetworkConnections: [
      {
        name: 'hub1vnet1'
        remoteVirtualNetworkResourceId: spoke.outputs.resourceId
      }
    ]
  }
}

// ERGW
