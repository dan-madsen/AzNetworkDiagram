// az deployment group create --resource-group RGNAME --name 'AzNetworkDiagram-Contains-demo' --template-file Containers.bicep -c

// Deploy everything to the same RG
targetScope = 'resourceGroup'

param location string = 'swedencentral'
param locationshort string = 'sdc'
param environment string = 'dev'

param enableACR bool = true
param enableCAE bool = true
param enableACI bool = true
param enableAKS bool = false // Not working, yet
param enableACS bool = true

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

module acr 'br/public:avm/res/container-registry/registry:0.12.1' = if(enableACR) {
  params: {
    name: 'acraznetworkdiagram${environment}${locationshort}01'
    location: location
    acrSku: 'Basic'
  }
}


module cae 'br/public:avm/res/app/managed-environment:0.13.3' = if(enableCAE) {
  params: {
    name: 'cae-aznetworkdiagram-${environment}-${locationshort}-01'
    zoneRedundant: false
    location: location
  }
}

module aci 'br/public:avm/res/container-instance/container-group:0.7.0' = if(enableACI) {
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

module aks 'br/public:avm/res/container-service/managed-cluster:0.13.1' = if(enableAKS) {
  name: 'aks-aznetworkdiagram-${environment}-${locationshort}-01'
  params: {
    name: 'aks-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    aksServicePrincipalProfile: { // MISSING INFO !
      clientId: ''
    }
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
module acs 'br/public:avm/res/communication/communication-service:0.4.3' = if(enableACS) {
  params: {
    name: 'acs-aznetworkdiagram-${environment}-${locationshort}-01'
    location: 'global' // Only supported location
    dataLocation: 'Europe'
  }
}

module acsmail 'br/public:avm/res/communication/email-service:0.4.5' = if(enableACS) {
  params: {
    name: 'acsmail-aznetworkdiagram-${environment}-${locationshort}-01'
    location: 'global'
    dataLocation: 'Europe'
  }
}
