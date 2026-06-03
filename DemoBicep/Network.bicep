// az deployment group create --resource-group RGNAME --name 'AzNetworkDiagram-demo' --template-file Demo.bicep -c

// Deploy everything to the same RG
targetScope = 'resourceGroup'

param location string = 'swedencentral'
param locationshort string = 'sdc'
param environment string = 'dev'

param enableAzFW bool = true
param enableRS bool = true
param enableVPN bool = true
param enableBastion bool = true
param enableDNSPR bool = true
param enableVWAN bool = true

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
      {
        name: 'DNSPRin'
        addressPrefix: '10.0.1.64/26'
        delegation: 'Microsoft.Network/dnsResolvers'
      }
      {
        name: 'DNSPROut'
        addressPrefix: '10.0.1.128/26'
        delegation: 'Microsoft.Network/dnsResolvers'
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
    location: location
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
      {
        name: 'RG-Test'
        priority: 100
        ruleCollectionType: 'FirewallPolicyFilterRuleCollection'
        action: {
          type: 'Allow'
        }
        rules: [
          {
            name: 'ACL-Test'
            ruleType: 'NetworkRule'
            sourceAddresses: [
              '10.0.0.0/16'
            ]
            destinationIpGroups: [
              '${ipg01.outputs.resourceId}'
              '${ipg02.outputs.resourceId}'
            ]
            destinationPorts: [
              '443'
            ]
            ipProtocols: [
              'TCP'
            ]
          }
        ]
      }
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

module dnspr 'br/public:avm/res/network/dns-resolver:0.5.7' = if (enableDNSPR) {
  params: {
    name: 'dnspr-aznetworkdiagram-${environment}-${locationshort}-01'
    location: location
    virtualNetworkResourceId: hub.outputs.resourceId
    inboundEndpoints: [
      {
        name: 'dnspr-in'
        subnetResourceId: hub.outputs.subnetResourceIds[5]
      }
    ]
    outboundEndpoints: [
      {
        name: 'dnspr-out'
        subnetResourceId: hub.outputs.subnetResourceIds[6]
      }
    ]
  }
}

module dnsprrs 'br/public:avm/res/network/dns-forwarding-ruleset:0.5.4' = {
  params: {
    name: 'dnsprrs-test-t-01'
    dnsForwardingRulesetOutboundEndpointResourceIds: [ dnspr.outputs.outboundEndpointsObject[0].resourceId ]
    forwardingRules: [
      {
        name: 'r1'
        domainName: 'google.com.'
        targetDnsServers: [
          {
            ipAddress: '8.8.8.8'
            port: 53
          }
        ]
      }
    ]
  }
}

///////////////////////////////////////////////
//// vWAN
///////////////////////////////////////////////
module vwan 'br/public:avm/res/network/virtual-wan:0.4.3' = if (enableVWAN) {
  params: {
    name: 'vwan-azdiagram-${environment}-${locationshort}-01'
    allowBranchToBranchTraffic: true
    location: location
    type: 'Standard'
  }
}

module vwanhub 'br/public:avm/res/network/virtual-hub:0.4.4' = if (enableVWAN) {
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
