// az deployment group create --resource-group RGNAME --name 'AzNetworkDiagram-demo' --template-file Demo.bicep -c

// Deploy everything to the same RG
targetScope = 'resourceGroup'

param location string = 'swedencentral'
param locationshort string = 'sdc'
param environment string = 'dev'

// PaaS
param enableASP bool = true
param enableSWA bool = true
param enableKV bool = true
param enableUMI bool = true
param enableSSH bool = true
param enableST bool = true
param enableSQL bool = true
param enableSQLMI bool = true
param enablePGSQL bool = true
param enableMySQL bool = true
param enableCosmos bool = true
param enableRedis bool = true
param enableAPIM bool = true
param enableRelay bool = true
param enableServiceBus bool = true
param enableEventGrid bool = true
param enableEventHub bool = true

///////////////////////////////////////////////
//// Network base
///////////////////////////////////////////////
module spoke 'br/public:avm/res/network/virtual-network:0.9.0' = {
  params: {
    name: 'vnet-spoke-${environment}-${locationshort}-01'
    location: location
    addressPrefixes: ['10.0.2.0/24']
    subnets: [
      {
        name: 'default'
        addressPrefix: '10.0.2.0/24'
      }
    ]
  }
}

///////////////////////////////////////////////
//// PaaS
///////////////////////////////////////////////
module asp01 'br/public:avm/res/web/serverfarm:0.7.0' = if (enableASP) {
  params: {
    name: 'asp-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    skuName: 'P0v3'
    skuCapacity: 1
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

module st 'br/public:avm/res/storage/storage-account:0.32.0' = if (enableST) {
  params: {
    name: 'stazdiagram${uniqueString(location, resourceGroup().name)}'
    location: location
    accessTier: 'Hot'
    skuName: 'Standard_LRS'
  }
}

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

module kv 'br/public:avm/res/key-vault/vault:0.13.3' = if (enableKV) {
  params: {
    name: 'kv-azdiagram-${environment}-${locationshort}' // Length restriction
    location: location
    sku: 'standard'
    softDeleteRetentionInDays: 7
    enableSoftDelete: false
  }
}

module mysql 'br/public:avm/res/db-for-my-sql/flexible-server:0.10.3' = if(enableMySQL) {
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

module mysqldb 'br/public:avm/res/db-for-my-sql/flexible-server/database:0.1.0' = if(enableMySQL) {
  params: {
    name: 'mysqldb-aznetworkdiagram-${environment}-${locationshort}-01'
    flexibleServerName: mysql.outputs.name
  }
}

module sqlmi 'br/public:avm/res/sql/managed-instance:0.4.1' = if(enableSQLMI) {
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

module sqlserver 'br/public:avm/res/sql/server:0.21.2' = if(enableSQL) {
  params: {
    name: 'sql-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    administratorLogin: 'sqlsa'
    administratorLoginPassword: '!2Hj${uniqueString('gsughs3gusoghpo!shIYGiygsgiu', location, 'mysql')}'
  }
}

module sqldb 'br/public:avm/res/sql/server/database:0.2.1' = if(enableSQL) {
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

module pgsql 'br/public:avm/res/db-for-postgre-sql/flexible-server:0.15.4' = if(enablePGSQL) {
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

module pgsqldb 'br/public:avm/res/db-for-postgre-sql/flexible-server/database:0.1.1' = if(enablePGSQL) {
  params: {
    name: 'pgsqldb-aznetworkdiagram-${environment}-${locationshort}-01'
    flexibleServerName: pgsql.outputs.name
  }
}

module cosmosdbact 'br/public:avm/res/document-db/database-account:0.19.0' = if(enableCosmos) {
  params: {
    name: 'cosmosact-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    zoneRedundant: false
  }
}

//module cosmosdb 'br/public:cosmos'

module redis 'br/public:avm/res/cache/redis:0.17.1' = if(enableRedis) {
  params: {
    name: 'redis-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    skuName: 'Basic'
  }
}

module apim 'br/public:avm/res/api-management/service:0.14.4' = if(enableAPIM) {
  params: {
    name: 'apim-aznetworkdiagram-${environment}-${locationshort}-01'
    publisherEmail: 'no-one@nowhere.com'
    publisherName: 'No one'
    sku: 'Developer'
    location: location
  }
}

module relay 'br/public:avm/res/relay/namespace:0.7.4' = if(enableRelay) {
  params: {
    name: 'relay-aznetworkdiagram-${environment}-${locationshort}-01'
    skuName: 'Standard'
    location: location
  }
}

module sb 'br/public:avm/res/service-bus/namespace:0.16.2' = if(enableServiceBus) {
  params: {
    name: 'sb-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    skuObject: {
      name: 'Basic'
    }
  }
}

module eh 'br/public:avm/res/event-hub/namespace:0.14.2' = if(enableEventHub) {
  params: {
    name: 'eh-aznetworkdiagram-${environment}-${locationshort}-01'
    skuName: 'Basic'
    location: location
  }
}

module egn 'br/public:avm/res/event-grid/namespace:0.7.4' = if(enableEventGrid) {
  params: {
    name: 'egn-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    topicSpaces: []
  }
}

module egd 'br/public:avm/res/event-grid/domain:0.8.4' = if(enableEventGrid) {
  params: {
    name: 'egd-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    eventSubscriptions: []
    topics: []
  }
}

module egt 'br/public:avm/res/event-grid/topic:0.9.3' = if(enableEventGrid) {
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
//     name: 'evst-aznetworkdiagram-${environment}-${locationshort}-01'
//     source: 
//     topicType: 
//   }
// }
