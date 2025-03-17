# Checks Priorities

## Summary of Ranges

| **Range Start - End** | **Category**                       | **Description**                                  |
|-----------------------|------------------------------------|--------------------------------------------------|
| 0 - 999               | Foundation and system-level checks | Core system, device, and network foundations.    |
| 1000 - 1999           | Protocol checks                    | Protocol-related checks like BGP, OSPF, etc.     |
| 2000 - 2999           | Routing Table Checks               | Dataplane-related checks.                        |
| 3000 - 3999           | Application checks                 | Application-level checks like DNS and HTTP.      |
| 4000 - 4999           | Miscellaneous or custom checks     | Other/custom checks not part of core categories. |

## Current Priorities Table

| Check Name                  | Check Priority |
|-----------------------------|----------------|
| DeviceExistenceCheck        | 0              |  # Foundation and system-level checks
| CollisionDomainCheck        | 10             |  
| StartupExistenceCheck       | 20             |  
| IPv6EnabledCheck            | 30             |  
| SysctlCheck                 | 40             |  
| InterfaceIPCheck            | 50             |  
| BridgeCheck                 | 60             |  
| ReachabilityCheck           | 70             |  
| DaemonCheck                 | 80             |  
| BGPNeighborCheck            | 1010           |  # Protocol Checks
| BGPRoutesCheck              | 1020           |  
| EVPNSessionCheck            | 1030           |  
| VTEPCheck                   | 1040           |  
| AnnouncedVNICheck           | 1050           |  
| OSPFNeighborCheck           | 1060           |  
| OSPFRoutesCheck             | 1070           |  
| OSPFInterfaceCheck          | 1080           |  
| SCIONAddressCheck           | 1090           |  
| SCIONPathsCheck             | 1100           |  
| AnnouncedNetworkCheck       | 1110           |  
| ProtocolRedistributionCheck | 1120           |  
| KernelRouteCheck            | 2000           |  # Routing Table Checks
| DNSAuthorityCheck           | 3010           |  # Application Checks
| LocalNSCheck                | 3020           |  
| DNSRecordCheck              | 3030           |  
| HTTPCheck                   | 3040           |  
| CustomCommandCheck          | 4010           |  # Miscellaneous/Custom Checks