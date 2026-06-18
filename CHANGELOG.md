# Changelog

All notable changes to Muninn are documented in this file.

<!-- towncrier release notes start -->

## 0.4.0 - 2026-06-17

### Added Parsers

- Added parser support for `show boot system` on Cisco IOS-XE. ([#985](https://github.com/ChartinoLabs/Muninn/pull/985))
- Added parser support for `show cdp interface` on Cisco IOS-XE. ([#986](https://github.com/ChartinoLabs/Muninn/pull/986))
- Added parser support for `show crypto ipsec profile` on Cisco IOS-XE. ([#987](https://github.com/ChartinoLabs/Muninn/pull/987))
- Added parser support for `show crypto ipsec sa count` on Cisco IOS-XE. ([#988](https://github.com/ChartinoLabs/Muninn/pull/988))
- Added parser support for `show crypto isakmp key` on Cisco IOS-XE. ([#989](https://github.com/ChartinoLabs/Muninn/pull/989))
- Added parser support for `show crypto isakmp policy` on Cisco IOS-XE. ([#990](https://github.com/ChartinoLabs/Muninn/pull/990))
- Added parser support for `show crypto isakmp sa` on Cisco IOS-XE. ([#991](https://github.com/ChartinoLabs/Muninn/pull/991))
- Added parser support for `show crypto isakmp sa count` on Cisco IOS-XE. ([#992](https://github.com/ChartinoLabs/Muninn/pull/992))
- Added parser support for `show crypto key mypubkey rsa` on Cisco IOS-XE. ([#993](https://github.com/ChartinoLabs/Muninn/pull/993))
- Added parser support for `show errdisable detect` on Cisco IOS-XE. ([#994](https://github.com/ChartinoLabs/Muninn/pull/994))
- Added parser support for `show etherchannel summary` on Cisco IOS-XE. ([#995](https://github.com/ChartinoLabs/Muninn/pull/995))
- Added parser support for `show hosts summary` on Cisco IOS-XE. ([#996](https://github.com/ChartinoLabs/Muninn/pull/996))
- Added parser support for `show interfaces counters` on Cisco IOS-XE. ([#997](https://github.com/ChartinoLabs/Muninn/pull/997))
- Added parser support for `show interfaces status` on Cisco IOS-XE. ([#998](https://github.com/ChartinoLabs/Muninn/pull/998))
- Added parser support for `show ip http server status` on Cisco IOS-XE. ([#999](https://github.com/ChartinoLabs/Muninn/pull/999))
- Added parser support for `show ip route summary` on Cisco IOS-XE. ([#1000](https://github.com/ChartinoLabs/Muninn/pull/1000))
- Added parser support for `show ip route vrf * summary` on Cisco IOS-XE. ([#1001](https://github.com/ChartinoLabs/Muninn/pull/1001))
- Added parser support for `show ip sla authentication` on Cisco IOS-XE. ([#1002](https://github.com/ChartinoLabs/Muninn/pull/1002))
- Added parser support for `show ip sla responder` on Cisco IOS-XE. ([#1003](https://github.com/ChartinoLabs/Muninn/pull/1003))
- Added parser support for `show ip sla statistics` on Cisco IOS-XE. ([#1004](https://github.com/ChartinoLabs/Muninn/pull/1004))
- Added parser support for `show ip sla summary` on Cisco IOS-XE. ([#1005](https://github.com/ChartinoLabs/Muninn/pull/1005))
- Added parser support for `show ip ssh` on Cisco IOS-XE. ([#1006](https://github.com/ChartinoLabs/Muninn/pull/1006))
- Added parser support for `show license summary` on Cisco IOS-XE. ([#1007](https://github.com/ChartinoLabs/Muninn/pull/1007))
- Added parser support for `show line` on Cisco IOS-XE. ([#1008](https://github.com/ChartinoLabs/Muninn/pull/1008))
- Added parser support for `show lldp` on Cisco IOS-XE. ([#1009](https://github.com/ChartinoLabs/Muninn/pull/1009))
- Added parser support for `show lldp interface` on Cisco IOS-XE. ([#1010](https://github.com/ChartinoLabs/Muninn/pull/1010))
- Added parser support for `show mac address-table count` on Cisco IOS-XE. ([#1011](https://github.com/ChartinoLabs/Muninn/pull/1011))
- Added parser support for `show macdb summary` on Cisco IOS-XE. ([#1012](https://github.com/ChartinoLabs/Muninn/pull/1012))
- Added parser support for `show memory platform` on Cisco IOS-XE. ([#1013](https://github.com/ChartinoLabs/Muninn/pull/1013))
- Added parser support for `show mka policy` on Cisco IOS-XE. ([#1014](https://github.com/ChartinoLabs/Muninn/pull/1014))
- Added parser support for `show mka sessions` on Cisco IOS-XE. ([#1015](https://github.com/ChartinoLabs/Muninn/pull/1015))
- Added parser support for `show mka statistics` on Cisco IOS-XE. ([#1016](https://github.com/ChartinoLabs/Muninn/pull/1016))
- Added parser support for `show ntp associations` on Cisco IOS-XE. ([#1017](https://github.com/ChartinoLabs/Muninn/pull/1017))
- Added parser support for `show platform hardware qfp active datapath utilization summary` on Cisco IOS-XE. ([#1018](https://github.com/ChartinoLabs/Muninn/pull/1018))
- Added parser support for `show processes memory platform sorted` on Cisco IOS-XE. ([#1019](https://github.com/ChartinoLabs/Muninn/pull/1019))
- Added parser support for `show spanning-tree detail` on Cisco IOS-XE. ([#1020](https://github.com/ChartinoLabs/Muninn/pull/1020))
- Added parser support for `show spanning-tree summary` on Cisco IOS-XE. ([#1021](https://github.com/ChartinoLabs/Muninn/pull/1021))
- Added parser support for `show users` on Cisco IOS-XE. ([#1022](https://github.com/ChartinoLabs/Muninn/pull/1022))
- Added parser support for `show users wide` on Cisco IOS-XE. ([#1023](https://github.com/ChartinoLabs/Muninn/pull/1023))
- Added parser support for `show vlan brief` on Cisco IOS-XE. ([#1024](https://github.com/ChartinoLabs/Muninn/pull/1024))
- Added parser support for `show vlans` on Cisco IOS-XE. ([#1025](https://github.com/ChartinoLabs/Muninn/pull/1025))
- Added parser support for `show vtp counters` on Cisco IOS-XE. ([#1026](https://github.com/ChartinoLabs/Muninn/pull/1026))
- Added parser support for `show vtp status` on Cisco IOS-XE. ([#1027](https://github.com/ChartinoLabs/Muninn/pull/1027))
- Added parser support for `show controllers ethernet-controller` on Cisco IOS-XE. ([#1028](https://github.com/ChartinoLabs/Muninn/pull/1028))
- Added parser support for `show processes cpu sorted` on Cisco IOS-XE. ([#1029](https://github.com/ChartinoLabs/Muninn/pull/1029))
- Added parser support for `dir` and `dir <filesystem>` on Cisco IOS. ([#1030](https://github.com/ChartinoLabs/Muninn/pull/1030))
- Added parser support for `dir flash:` on Cisco IOS (covered by stacked `dir <filesystem>` registration). ([#1031](https://github.com/ChartinoLabs/Muninn/pull/1031))
- Added parser support for `show aaa method-lists accounting` on Cisco IOS. ([#1032](https://github.com/ChartinoLabs/Muninn/pull/1032))
- Added parser support for `show aaa method-lists authentication` on Cisco IOS. ([#1033](https://github.com/ChartinoLabs/Muninn/pull/1033))
- Added parser support for `show aaa method-lists authorization` on Cisco IOS. ([#1034](https://github.com/ChartinoLabs/Muninn/pull/1034))
- Added parser support for `show boot` on Cisco IOS. ([#1035](https://github.com/ChartinoLabs/Muninn/pull/1035))
- Added parser support for `show cdp` on Cisco IOS. ([#1036](https://github.com/ChartinoLabs/Muninn/pull/1036))
- Added parser support for `show cdp interface` on Cisco IOS. ([#1037](https://github.com/ChartinoLabs/Muninn/pull/1037))
- Added parser support for `show class-map` on Cisco IOS. ([#1038](https://github.com/ChartinoLabs/Muninn/pull/1038))
- Added parser support for `show crypto key mypubkey rsa` on Cisco IOS. ([#1039](https://github.com/ChartinoLabs/Muninn/pull/1039))
- Added parser support for `show debug condition` on Cisco IOS. ([#1040](https://github.com/ChartinoLabs/Muninn/pull/1040))
- Added parser support for `show errdisable detect` on Cisco IOS. ([#1041](https://github.com/ChartinoLabs/Muninn/pull/1041))
- Added parser support for `show errdisable flap-values` on Cisco IOS. ([#1042](https://github.com/ChartinoLabs/Muninn/pull/1042))
- Added parser support for `show errdisable recovery` on Cisco IOS. ([#1043](https://github.com/ChartinoLabs/Muninn/pull/1043))
- Added parser support for `show hosts` on Cisco IOS. ([#1044](https://github.com/ChartinoLabs/Muninn/pull/1044))
- Added parser support for `show interfaces status` on Cisco IOS. ([#1045](https://github.com/ChartinoLabs/Muninn/pull/1045))
- Added parser support for `show interfaces switchport` on Cisco IOS. ([#1046](https://github.com/ChartinoLabs/Muninn/pull/1046))
- Added parser support for `show ip default-gateway` on Cisco IOS. ([#1047](https://github.com/ChartinoLabs/Muninn/pull/1047))
- Added parser support for `show ip ssh` on Cisco IOS. ([#1048](https://github.com/ChartinoLabs/Muninn/pull/1048))
- Added parser support for `show line` on Cisco IOS. ([#1049](https://github.com/ChartinoLabs/Muninn/pull/1049))
- Added parser support for `show line console 0` on Cisco IOS. ([#1050](https://github.com/ChartinoLabs/Muninn/pull/1050))
- Added parser support for `show lldp` on Cisco IOS. ([#1051](https://github.com/ChartinoLabs/Muninn/pull/1051))
- Added parser support for `show lldp interface` on Cisco IOS. ([#1052](https://github.com/ChartinoLabs/Muninn/pull/1052))
- Added parser support for `show mac address-table count` on Cisco IOS. ([#1053](https://github.com/ChartinoLabs/Muninn/pull/1053))
- Added parser support for `show ntp associations` on Cisco IOS. ([#1054](https://github.com/ChartinoLabs/Muninn/pull/1054))
- Added parser support for `show processes cpu sorted` on Cisco IOS. ([#1055](https://github.com/ChartinoLabs/Muninn/pull/1055))
- Added parser support for `show snmp view` on Cisco IOS. ([#1056](https://github.com/ChartinoLabs/Muninn/pull/1056))
- Added parser support for `show spanning-tree inconsistentports` on Cisco IOS. ([#1058](https://github.com/ChartinoLabs/Muninn/pull/1058))
- Added parser support for `show spanning-tree summary` on Cisco IOS. ([#1059](https://github.com/ChartinoLabs/Muninn/pull/1059))
- Added parser support for `show users wide` on Cisco IOS. ([#1060](https://github.com/ChartinoLabs/Muninn/pull/1060))
- Added parser support for `show vtp counters` on Cisco IOS. ([#1061](https://github.com/ChartinoLabs/Muninn/pull/1061))
- Added parser support for `show vtp interface` on Cisco IOS. ([#1062](https://github.com/ChartinoLabs/Muninn/pull/1062))
- Added parser support for `show arp summary` on Cisco IOS-XE. ([#1144](https://github.com/ChartinoLabs/Muninn/pull/1144))

### Internal

- Relax mainline dependency version floors to true minimums, pin dev dependencies to exact versions, and add CI job to test lowest dependency bounds. ([#1161](https://github.com/ChartinoLabs/Muninn/pull/1161))
- Centralized user-facing OS display names on each `OperatingSystem` subclass via a new `display_name` ClassVar. The docs site catalog now sources display names from these declarations instead of a hardcoded JS map, ensuring new platforms render with proper names (e.g. "Palo Alto PAN-OS") rather than internal slugs.
- Parser library page now opens parser details in a modal dialog instead of an inline row expansion. Eliminates cursor-lag caused by table-layer recompositing on a 349-row table, and adds search input debouncing, batched row insertion, and a delegated click handler for additional responsiveness.
- Updated Supported Platforms table and parser library OS labels to include Arista EOS, Juniper Junos, Palo Alto PAN-OS, Nokia SR OS, and Linux.


## 0.3.0 - 2026-05-09

### Added Parsers

- Added parser for `show version` on Cisco IOS-XR. ([#698](https://github.com/ChartinoLabs/Muninn/pull/698))
- Added parser for `show version` on Arista EOS. ([#699](https://github.com/ChartinoLabs/Muninn/pull/699))
- Added parser for `show version` on Juniper Junos. ([#700](https://github.com/ChartinoLabs/Muninn/pull/700))
- Added parser for `show system info` on Palo Alto PAN-OS. ([#701](https://github.com/ChartinoLabs/Muninn/pull/701))
- Added parser for `show port` on Nokia SR OS. ([#702](https://github.com/ChartinoLabs/Muninn/pull/702))
- Added parser for `ip address show` on Linux. ([#703](https://github.com/ChartinoLabs/Muninn/pull/703))
- Added parser for `show interfaces brief` on Cisco IOS-XR. ([#710](https://github.com/ChartinoLabs/Muninn/pull/710))
- Added parser for `show ip route` on Cisco IOS-XR. ([#711](https://github.com/ChartinoLabs/Muninn/pull/711))
- Added parser for `show interfaces status` on Arista EOS. ([#712](https://github.com/ChartinoLabs/Muninn/pull/712))
- Added parser for `show ip route` on Arista EOS. ([#713](https://github.com/ChartinoLabs/Muninn/pull/713))
- Added parser for `show interfaces` on Juniper Junos. ([#714](https://github.com/ChartinoLabs/Muninn/pull/714))
- Added parser for `show bgp summary` on Juniper Junos. ([#715](https://github.com/ChartinoLabs/Muninn/pull/715))
- Added parser for `show interface hardware` on Palo Alto PAN-OS. ([#716](https://github.com/ChartinoLabs/Muninn/pull/716))
- Added parser for `show arp all` on Palo Alto PAN-OS. ([#717](https://github.com/ChartinoLabs/Muninn/pull/717))
- Added parser for `show router interface` on Nokia SR OS. ([#718](https://github.com/ChartinoLabs/Muninn/pull/718))
- Added parser for `show lag` on Nokia SR OS. ([#719](https://github.com/ChartinoLabs/Muninn/pull/719))
- Added parser for `ip route show` on Linux. ([#720](https://github.com/ChartinoLabs/Muninn/pull/720))
- Added parser for `ip link show` on Linux. ([#721](https://github.com/ChartinoLabs/Muninn/pull/721))
- Added parser for `show bgp summary` on Cisco IOS-XR. ([#734](https://github.com/ChartinoLabs/Muninn/pull/734))
- Added parser for `show ospf neighbor` on Cisco IOS-XR. ([#735](https://github.com/ChartinoLabs/Muninn/pull/735))
- Added parser for `show ip arp` on Arista EOS. ([#736](https://github.com/ChartinoLabs/Muninn/pull/736))
- Added parser for `show lldp neighbors` on Arista EOS. ([#737](https://github.com/ChartinoLabs/Muninn/pull/737))
- Added parser for `show arp no-resolve` on Juniper Junos. ([#738](https://github.com/ChartinoLabs/Muninn/pull/738))
- Added parser for `show ospf neighbor` on Juniper Junos. ([#739](https://github.com/ChartinoLabs/Muninn/pull/739))
- Added parser for `show routing route` on Palo Alto PAN-OS. ([#740](https://github.com/ChartinoLabs/Muninn/pull/740))
- Added parser for `show routing protocol bgp summary` on Palo Alto PAN-OS. ([#741](https://github.com/ChartinoLabs/Muninn/pull/741))
- Added parser for `show router bgp summary family` on Nokia SR OS. ([#742](https://github.com/ChartinoLabs/Muninn/pull/742))
- Added parser for `show service sap-using` on Nokia SR OS. ([#743](https://github.com/ChartinoLabs/Muninn/pull/743))
- Added parser for `arp -a` on Linux. ([#744](https://github.com/ChartinoLabs/Muninn/pull/744))
- Added parser for `show ip interface` on Cisco IOS and IOS-XE. ([#921](https://github.com/ChartinoLabs/Muninn/pull/921))
- Added ``show bgp instance all summary`` parser for Cisco IOS-XR. Parses BGP process information, speaker table, and neighbor summary across all configured BGP instances, address families, and VRFs.
- Added `cisco_iosxr` parser for `show cdp neighbors detail`.
- Added `show bgp vrf all ipv4 unicast summary` parser for Cisco IOS-XR.
- Added `show ip bgp summary` parser for Arista EOS.
- Added `show task replication` parser for Juniper Junos.
- Added parser for `admin show environment fan` on Cisco IOS-XR.
- Added parser for `admin show environment power` on Cisco IOS-XR.
- Added parser for `admin show inventory` on Cisco IOS-XR.
- Added parser for `admin show platform` on Cisco IOS-XR.
- Added parser for `admin show vm` on Cisco IOS-XR.
- Added parser for `debug swm status` on Palo Alto PAN-OS.
- Added parser for `dir` on Arista EOS.
- Added parser for `dir` on Cisco IOS-XR.
- Added parser for `dmidecode -t bios` on Linux.
- Added parser for `dmidecode -t memory` on Linux.
- Added parser for `dmidecode -t processor` on Linux.
- Added parser for `dmidecode -t system` on Linux.
- Added parser for `docker stats --no-stream` on Linux.
- Added parser for `ifconfig` on Linux.
- Added parser for `ip vrf show` on Linux.
- Added parser for `iwconfig` on Linux.
- Added parser for `nmcli connection show` on Linux.
- Added parser for `ping` on Cisco IOS-XR.
- Added parser for `request license info` on Palo Alto PAN-OS.
- Added parser for `route` on Linux.
- Added parser for `show arp` on Cisco IOS-XR.
- Added parser for `show asic-errors all location` on Cisco IOS-XR.
- Added parser for `show bfd sessions` on Cisco IOS-XR.
- Added parser for `show bgp neighbor` on Juniper Junos.
- Added parser for `show bgp neighbors` on Cisco IOS-XR.
- Added parser for `show bgp vrf all neighbors advertised-routes` on Cisco IOS-XR.
- Added parser for `show call-home` on Cisco IOS and IOS-XE.
- Added parser for `show cef drops location` on Cisco IOS-XR.
- Added parser for `show chassis cluster interfaces` on Juniper Junos.
- Added parser for `show chassis cluster status` on Juniper Junos.
- Added parser for `show chassis firmware` on Juniper Junos.
- Added parser for `show chassis hardware` on Juniper Junos.
- Added parser for `show clock` on Arista EOS.
- Added parser for `show configuration commit list` on Cisco IOS-XR.
- Added parser for `show controller fabric plane all` on Cisco IOS-XR.
- Added parser for `show controllers HundredGigabitEthernet` on Cisco IOS-XR.
- Added parser for `show controllers all phy` on Cisco IOS-XR.
- Added parser for `show controllers fabric fia drops egress location` on Cisco IOS-XR.
- Added parser for `show controllers fabric fia drops ingress location` on Cisco IOS-XR.
- Added parser for `show controllers fabric fia errors egress location` on Cisco IOS-XR.
- Added parser for `show controllers fabric fia errors ingress location` on Cisco IOS-XR.
- Added parser for `show counter global` on Palo Alto PAN-OS.
- Added parser for `show ddos-protection statistics` on Juniper Junos.
- Added parser for `show drops np all` on Cisco IOS-XR.
- Added parser for `show environment cooling` on Arista EOS.
- Added parser for `show environment power` on Arista EOS.
- Added parser for `show environment temperature` on Arista EOS.
- Added parser for `show high-availability all` on Palo Alto PAN-OS.
- Added parser for `show high-availability path-monitoring` on Palo Alto PAN-OS.
- Added parser for `show hostname` on Arista EOS.
- Added parser for `show hsrp` on Cisco IOS-XR.
- Added parser for `show install active` on Cisco IOS-XR.
- Added parser for `show interface logical` on Palo Alto PAN-OS.
- Added parser for `show interface management` on Palo Alto PAN-OS.
- Added parser for `show interfaces description` on Arista EOS.
- Added parser for `show interfaces description` on Cisco IOS-XR.
- Added parser for `show interfaces summary` on Cisco IOS-XR.
- Added parser for `show interfaces transceiver detail` on Arista EOS.
- Added parser for `show interfaces transceiver` on Arista EOS.
- Added parser for `show interfaces` on Arista EOS.
- Added parser for `show interfaces` on Cisco IOS-XR.
- Added parser for `show inventory` on Arista EOS.
- Added parser for `show inventory` on Cisco IOS-XR.
- Added parser for `show ip access-lists` on Arista EOS.
- Added parser for `show ip bgp detail` on Arista EOS.
- Added parser for `show ip bgp` on Arista EOS.
- Added parser for `show ip helper-address` on Arista EOS.
- Added parser for `show ip interface brief` on Arista EOS.
- Added parser for `show ip interface brief` on Cisco IOS-XR.
- Added parser for `show ip mroute vrf all detail` on Arista EOS.
- Added parser for `show ip ospf database` on Arista EOS.
- Added parser for `show ip ospf interface brief` on Arista EOS.
- Added parser for `show ip ospf neighbor` on Arista EOS.
- Added parser for `show ip ospf summary` on Arista EOS.
- Added parser for `show ip ospf` on IOS-XE.
- Added parser for `show ipv4 interface` on Cisco IOS-XR.
- Added parser for `show ipv4 vrf all interface brief` on Cisco IOS-XR.
- Added parser for `show ipv6 bgp summary` on Arista EOS.
- Added parser for `show ipv6 neighbors` on Cisco IOS-XR.
- Added parser for `show ipv6 neighbors` on Juniper Junos.
- Added parser for `show isis adjacency` on Juniper Junos.
- Added parser for `show isis neighbors` on Arista EOS.
- Added parser for `show isis neighbors` on Cisco IOS-XR.
- Added parser for `show jobs all` on Palo Alto PAN-OS.
- Added parser for `show krt queue` on Juniper Junos.
- Added parser for `show lacp interfaces` on Juniper Junos.
- Added parser for `show ldp neighbor` on Juniper Junos.
- Added parser for `show lldp neighbors detail` on Arista EOS.
- Added parser for `show lldp neighbors detail` on Cisco IOS-XR.
- Added parser for `show lldp neighbors` on Cisco IOS-XR.
- Added parser for `show lldp neighbors` on Juniper Junos.
- Added parser for `show logging` on Cisco IOS-XR. Parses syslog configuration (console, monitor, trap, buffer levels and counts) and log buffer entries.
- Added parser for `show lpts pifib hardware police location` on Cisco IOS-XR.
- Added parser for `show mac address-table` on Arista EOS.
- Added parser for `show mac all` on Palo Alto PAN-OS.
- Added parser for `show mac security interface` on Arista EOS.
- Added parser for `show mac security mka counters` on Arista EOS.
- Added parser for `show mac security participants detail` on Arista EOS.
- Added parser for `show mlag` on Arista EOS.
- Added parser for `show mpls ldp neighbor brief` on Cisco IOS-XR.
- Added parser for `show ntp associations` on Juniper Junos.
- Added parser for `show ntp status` on Juniper Junos.
- Added parser for `show ospf vrf all interface brief` on Cisco IOS-XR.
- Added parser for `show ospf vrf all neighbor` on Cisco IOS-XR.
- Added parser for `show ospf3 neighbor` on Juniper Junos.
- Added parser for `show pfe statistics traffic` on Juniper Junos.
- Added parser for `show pim ipv4 group-map` on Cisco IOS-XR.
- Added parser for `show pim ipv4 interface` on Arista EOS.
- Added parser for `show pim ipv4 interface` on Cisco IOS-XR.
- Added parser for `show pim ipv4 neighbor` on Arista EOS.
- Added parser for `show pim ipv4 neighbor` on Cisco IOS-XR.
- Added parser for `show platform` on Cisco IOS-XR.
- Added parser for `show port-channel summary` on Arista EOS.
- Added parser for `show ppm transmissions protocol bfd detail` on Juniper Junos.
- Added parser for `show processes cpu` on Cisco IOS-XR.
- Added parser for `show redundancy summary` on Cisco IOS-XR.
- Added parser for `show reload cause` on Arista EOS.
- Added parser for `show route summary` on Juniper Junos.
- Added parser for `show route` on Juniper Junos.
- Added parser for `show router arp dynamic` on Nokia SR OS.
- Added parser for `show router isis adjacency` on Nokia SR OS.
- Added parser for `show rsvp interface` on Juniper Junos.
- Added parser for `show rsvp neighbors` on Cisco IOS-XR.
- Added parser for `show running nat-policy` on Palo Alto PAN-OS.
- Added parser for `show running security-policy` on Palo Alto PAN-OS.
- Added parser for `show security policies hit-count` on Juniper Junos.
- Added parser for `show service sdp-using` on Nokia SR OS.
- Added parser for `show snmp community` on Arista EOS.
- Added parser for `show system configuration database usage` on Juniper Junos.
- Added parser for `show system ntp all` on Nokia SR OS.
- Added parser for `show system processes brief` on Juniper Junos.
- Added parser for `show system processes summary` on Juniper Junos.
- Added parser for `show system uptime` on Juniper Junos.
- Added parser for `show ted database extensive` on Juniper Junos.
- Added parser for `show version brief` on Cisco IOS-XR.
- Added parser for `show vlan` on Arista EOS.
- Added parser for `show vlans` on Juniper Junos.
- Added parser for `show vrf all detail` on Cisco IOS-XR.
- Added parser for `show vrf` on Arista EOS.
- Added parser for `test security-policy-match` on Palo Alto PAN-OS.
- Added parser for `top` on Linux.

### Updated Parsers

- Added pattern registration `ping <destination>` for IOS and IOS-XE ping parser to support parameterized commands.
- Cross-registered `ping` parser for IOS-XE (previously IOS-only).
- ``show bgp all`` / ``show ip bgp all`` (IOS-XE): ``as_path`` and ``path_type`` fields in BGP path entries are now omitted when empty instead of being set to ``""``.
- ``show cdp neighbors detail`` (IOS/IOS-XE): ``vtp_management_domain`` field is now omitted when the device reports an empty VTP domain instead of being set to ``""``.
- ``show interfaces`` (IOS/IOS-XE): ``duplex`` and ``speed`` fields in port-channel member entries are now omitted when unavailable instead of being set to ``""``.
- ``show inventory`` (IOS/IOS-XE/NX-OS): ``description`` field is now omitted when the device reports an empty description instead of being set to ``""``.
- ``show ip bgp neighbors advertised-routes`` (IOS): ``path`` field in route entries is now omitted when empty instead of being set to ``""``.
- ``show ip bgp`` / ``show bgp vrf all all`` (NX-OS): ``status_codes``, ``as_path``, and ``path_type`` fields in BGP path entries are now omitted when empty instead of being set to ``""``.
- ``show ip bgp`` / ``show ip bgp regexp`` (IOS-XE): ``as_path`` and ``path_type`` fields in BGP path entries are now omitted when empty instead of being set to ``""``.
- ``show port`` (Nokia SR OS): ``link_state`` field is now omitted for connector ports instead of being set to ``""``.
- ``show stackwise-virtual neighbors`` (IOS-XE): ``remote_port`` field is now omitted when the remote port is not reported instead of being set to ``""``.
- ``show vlan`` (IOS/IOS-XE): ``type`` field in VLAN entries is now omitted when not present in the extended table instead of being set to ``""``.

### Fixed Parsers

- Fixed `show lldp neighbors` parser and `canonical_interface_name` to correctly handle FiveGigabitEthernet (`Fi`) interfaces on Catalyst 9000 series switches. ([#928](https://github.com/ChartinoLabs/Muninn/pull/928))
- Fixed `show ip ospf interface` parser to extract `transmit_delay`, `state`, `priority`, and `bfd_enabled` when `, BFD enabled` is appended to the state line on IOS-XE devices.
- Fixed `show version` parser to extract license fields (level, type, next reload level) from C9300, ISR4451, C3945, and C1900 platforms, and `image_type` from C9300 switches.

### Core Features

- Added OS definitions and parser scaffolding for Arista EOS, Juniper Junos, Palo Alto PAN-OS, Nokia SR OS, and Linux platforms.
- Parser library now displays TypedDict schema and test fixture examples (CLI input and parsed output) for each parser, loaded on demand when a row is expanded.

### Core Fixes

- Fixed parser library page not rendering on first visit when using MkDocs Material instant navigation. ([#670](https://github.com/ChartinoLabs/Muninn/pull/670))

### Internal

- Bump ty from 0.0.24 to 0.0.25 and resolve all 229 newly-enforced type-checking violations across the parser codebase. ([#667](https://github.com/ChartinoLabs/Muninn/pull/667))
- Added CI, package, and license badges to the README. ([#689](https://github.com/ChartinoLabs/Muninn/pull/689))
- Bumped the `ty` type checker dev dependency from 0.0.29 to 0.0.34. ([#932](https://github.com/ChartinoLabs/Muninn/pull/932))
- Added Acknowledgments section to README recognizing Cisco GenieParser and NTC Templates projects.
- Added fixture guardrail test that rejects empty string values in ``expected.json`` files, with legacy exemptions for existing fixtures.
- Expanded interface canonicalization guardrail to cover all vendor OS directories and added IOS-XR prefix support (MgmtEth, Null, tunnel-te).
- Removed 13 unused ``type: ignore`` comments flagged by newer ``ty`` releases.


## 0.2.0 - 2026-03-25

### Added Parsers

- Added parser support for `show controller ethernet-controller` on Cisco IOS-XE. ([#282](https://github.com/ChartinoLabs/Muninn/pull/282))
- Added parser support for `show crypto ipsec sa detail` on Cisco IOS. ([#283](https://github.com/ChartinoLabs/Muninn/pull/283))
- Added parser support for `show diagnostic status` on Cisco IOS-XE. ([#284](https://github.com/ChartinoLabs/Muninn/pull/284))
- Added parser support for `show dlep clients` on Cisco IOS-XE. ([#285](https://github.com/ChartinoLabs/Muninn/pull/285))
- Added parser support for `show dlep counters` on Cisco IOS-XE. ([#286](https://github.com/ChartinoLabs/Muninn/pull/286))
- Added parser support for `show dlep neighbor` on Cisco IOS-XE. ([#287](https://github.com/ChartinoLabs/Muninn/pull/287))
- Added parser support for `show dns-lookup cache` on Cisco IOS-XE. ([#288](https://github.com/ChartinoLabs/Muninn/pull/288))
- Added parser support for `show endpoint-tracker records` on Cisco IOS-XE. ([#289](https://github.com/ChartinoLabs/Muninn/pull/289))
- Added parser support for `show endpoint-tracker static-route` on Cisco IOS-XE. ([#290](https://github.com/ChartinoLabs/Muninn/pull/290))
- Added parser support for `show esmc detail` on Cisco IOS-XE. ([#291](https://github.com/ChartinoLabs/Muninn/pull/291))
- Added parser support for `show gnxi state` on Cisco IOS-XE. ([#292](https://github.com/ChartinoLabs/Muninn/pull/292))
- Registered `show ip dhcp snooping binding` for Cisco IOS (shared parser with IOS-XE). ([#293](https://github.com/ChartinoLabs/Muninn/pull/293))
- Added parser support for `show meraki connect` on Cisco IOS-XE. ([#294](https://github.com/ChartinoLabs/Muninn/pull/294))
- Added parser support for `show meraki migration` on Cisco IOS-XE. ([#295](https://github.com/ChartinoLabs/Muninn/pull/295))
- Added IOS-XE parser for `show netconf session`. ([#296](https://github.com/ChartinoLabs/Muninn/pull/296))
- Added IOS-XE parser for `show netconf-yang datastores`. ([#297](https://github.com/ChartinoLabs/Muninn/pull/297))
- Added IOS-XE parser for `show netconf-yang sessions`. ([#298](https://github.com/ChartinoLabs/Muninn/pull/298))
- Added parser support for `show network-clocks synchronization` on Cisco IOS-XE. ([#299](https://github.com/ChartinoLabs/Muninn/pull/299))
- Added parser support for `show ppp all` on Cisco IOS-XE. ([#300](https://github.com/ChartinoLabs/Muninn/pull/300))
- Added IOS-XE parser for `show ppp statistics`. ([#301](https://github.com/ChartinoLabs/Muninn/pull/301))
- Added parser support for `show pppatm session` on Cisco IOS-XE. ([#302](https://github.com/ChartinoLabs/Muninn/pull/302))
- Added parser support for `show pppoe statistics` on Cisco IOS-XE. ([#303](https://github.com/ChartinoLabs/Muninn/pull/303))
- Added parser support for `show radius statistics` on Cisco IOS-XE. ([#304](https://github.com/ChartinoLabs/Muninn/pull/304))
- Added parser support for `show sdwan security-info` on Cisco IOS-XE. ([#309](https://github.com/ChartinoLabs/Muninn/pull/309))
- Added parser support for `show sdwan software` on Cisco IOS-XE. ([#310](https://github.com/ChartinoLabs/Muninn/pull/310))
- Added parser support for `show sdwan tenant-summary` on Cisco IOS-XE. ([#311](https://github.com/ChartinoLabs/Muninn/pull/311))
- Added parser support for `show sdwan version` on Cisco IOS-XE. ([#312](https://github.com/ChartinoLabs/Muninn/pull/312))
- Added IOS-XE parser for `show stack-power budgeting`. ([#313](https://github.com/ChartinoLabs/Muninn/pull/313))
- Added IOS-XE parser for `show stack-power detail`. ([#314](https://github.com/ChartinoLabs/Muninn/pull/314))
- Added IOS-XE parser for `show stackwise-virtual bandwidth`. ([#315](https://github.com/ChartinoLabs/Muninn/pull/315))
- Added IOS-XE parser for `show stackwise-virtual dual-active-detection`. ([#316](https://github.com/ChartinoLabs/Muninn/pull/316))
- Added IOS-XE parser for `show stackwise-virtual link`. ([#317](https://github.com/ChartinoLabs/Muninn/pull/317))
- Added IOS-XE parser for `show stackwise-virtual neighbors`. ([#318](https://github.com/ChartinoLabs/Muninn/pull/318))
- Added parser support for `show subscriber lite-session` on Cisco IOS-XE. ([#319](https://github.com/ChartinoLabs/Muninn/pull/319))
- Added parser support for `show subscriber session` on Cisco IOS-XE. ([#320](https://github.com/ChartinoLabs/Muninn/pull/320))
- Added parser support for `show subscriber statistics` on Cisco IOS-XE. ([#321](https://github.com/ChartinoLabs/Muninn/pull/321))

### Updated Parsers

- IOS-XE ``show ppp all`` now emits canonical interface names for each session row and dict key. ([#573](https://github.com/ChartinoLabs/Muninn/pull/573))
- IOS-XE ``show pppatm session`` now emits canonical interface names for the ATM, VT, and VA columns. ([#574](https://github.com/ChartinoLabs/Muninn/pull/574))
- Omit hyphen placeholder values for privacy protocol (and access-list) in IOS `show snmp user` output. ([#623](https://github.com/ChartinoLabs/Muninn/pull/623))
- Omit `interface` on IOS-XE `show vpdn` sessions when the CLI prints `-` (no interface). ([#624](https://github.com/ChartinoLabs/Muninn/pull/624))
- NX-OS ``show ip arp detail vrf all`` omits ``physical_interface`` when the CLI prints ``-`` (no resolved L2 interface). ([#625](https://github.com/ChartinoLabs/Muninn/pull/625))
- Omit `up_time` on NX-OS `show ip ospf neighbor` when the CLI prints a hyphen placeholder. ([#626](https://github.com/ChartinoLabs/Muninn/pull/626))
- IOS/IOS-XE ``show platform``: omit ``state`` when the device reports ``N/A`` for an empty module bay (unknown or blank slot type). ([#633](https://github.com/ChartinoLabs/Muninn/pull/633))
- IOS-XE `show power inline priority`: omit `admin_priority` when the CLI prints `NA` / `N/A` / `n/a` (unset), instead of passing those strings through. ([#635](https://github.com/ChartinoLabs/Muninn/pull/635))
- IOS-XE ``show pppatm session`` omits ``uniq_id`` and other columns when the CLI used NA-like placeholders with no semantic value. ([#636](https://github.com/ChartinoLabs/Muninn/pull/636))
- IOS-XE `show radius statistics`: omit `auth` / `acct` keys when the device prints `NA` for non-applicable counters (see #637). ([#637](https://github.com/ChartinoLabs/Muninn/pull/637))
- Omit VLAN field in IOS/IOS-XE `show mac address-table` output when the CLI uses dash placeholders instead of a VLAN id.

### Fixed Parsers

- NX-OS ``show vpc`` omits ``dual_active_excluded_vlans`` when the device prints ``-`` (no VLANs excluded). ([#627](https://github.com/ChartinoLabs/Muninn/pull/627))
- IOS ``show authentication sessions`` and ``show access-session`` omit the ``method`` field when the CLI prints ``NA`` / ``N/A`` / ``n/a`` as an empty placeholder (instead of echoing those strings). ([#629](https://github.com/ChartinoLabs/Muninn/pull/629))
- IOS / IOS-XE NAT translation parsers omit ``outside_local`` / ``outside_global`` when the CLI prints ``---`` instead of emitting ``N/A`` string values; hierarchical keys still use ``N/A`` for missing outside-global addressing. ([#630](https://github.com/ChartinoLabs/Muninn/pull/630))
- IOS-XE ``show endpoint-tracker records`` omits ``endpoint_type``, ``threshold_ms``, ``multiplier``, and ``interval_s`` when the CLI prints ``NA`` / ``N/A`` / ``n/a`` as empty placeholders (e.g. tracker-group rows). ([#631](https://github.com/ChartinoLabs/Muninn/pull/631))
- IOS-XE ``show network-clocks synchronization`` omits ``sig_type`` as well as ``esmc_tx`` / ``esmc_rx`` when the CLI prints ``NA`` / ``N/A`` / ``n/a`` as empty placeholders (in addition to ``-``). ([#655](https://github.com/ChartinoLabs/Muninn/pull/655))

### Breaking Changes

- IOS `show lldp neighbors detail` now nests `neighbors` as outer key (canonical local interface, or port id when absent) → chassis id → port id → entry, replacing the prior list-of-dicts shape. ([#587](https://github.com/ChartinoLabs/Muninn/pull/587))
- IOS/IOS-XE ``show interfaces`` parser: ``port_channel.members`` is now a dict keyed by canonical interface name; each value holds ``duplex`` and ``speed`` only (the redundant ``interface`` field is removed). ([#588](https://github.com/ChartinoLabs/Muninn/pull/588))
- IOS `show object-group` replaces flat `entries` lists with nested structures: network groups use `hosts`, `ranges`, `ipv4_networks` (CIDR keys), `ipv6_prefixes`, and `nested_groups`; service groups use a `protocols` tree plus `nested_groups` for `group-object` references. ([#589](https://github.com/ChartinoLabs/Muninn/pull/589))
- IOS `show standby` now returns each group's `tracks` as nested mappings (`track_type` → `track_name` → track details) instead of a list of track objects. ([#590](https://github.com/ChartinoLabs/Muninn/pull/590))
- `show standby brief` on IOS/IOS-XE now returns `interfaces` as a mapping of canonical interface name to `{ "groups": { group_number: HsrpGroupEntry, ... } }`, replacing the prior list of entries. ([#591](https://github.com/ChartinoLabs/Muninn/pull/591))
- `show vlan` on IOS/IOS-XE now returns `private_vlans` as a mapping of secondary VLAN ID (string) to association details instead of a list. ([#592](https://github.com/ChartinoLabs/Muninn/pull/592))
- `show interfaces` on IOS/IOS-XE now returns each port-channel's `members` as a mapping of interface name to duplex/speed details instead of a list. ([#593](https://github.com/ChartinoLabs/Muninn/pull/593))
- IOS and IOS-XE `show mac address-table` now return `mac_table` as `vlan_key -> mac_address -> row`, with each row carrying `kind` (`unicast` or `multicast`) and no top-level `entries` / `multicast_entries` lists. ([#600](https://github.com/ChartinoLabs/Muninn/pull/600))
- NX-OS `show mac address-table` now returns `mac_table` as `vlan_key -> mac_address -> row` (with `kind: unicast` on each row) instead of a flat list of entries. ([#601](https://github.com/ChartinoLabs/Muninn/pull/601))
- IOS `show dot1x all` now maps `clients` by `session_id` (dict) instead of a list; `session_id` is not duplicated inside each client row. ([#602](https://github.com/ChartinoLabs/Muninn/pull/602))
- IOS-XE `show netconf-yang sessions` now returns `sessions` as a dict keyed by session id; `session_id` is not repeated inside each session value. ([#603](https://github.com/ChartinoLabs/Muninn/pull/603))
- IOS-XE `show policy-map interface` now nests `qos_set` as `type -> value -> { table?, packets_marked? }` instead of a list of QoS-set objects. ([#604](https://github.com/ChartinoLabs/Muninn/pull/604))
- IOS-XE `show platform packet-trace statistics` now maps `punt_causes` and `drop_causes` by cause code (string keys); `code` is not repeated inside each cause value. ([#605](https://github.com/ChartinoLabs/Muninn/pull/605))
- IOS-XE `show stackwise-virtual neighbors` parser now returns per-switch `ports` as a mapping of local interface name to `{ "remote_port": ... }` instead of a `port_pairs` list.
- IOS-XE `show track` now nests `tracked_by` as protocol name → group id → interface → entry (replacing the prior list-of-dicts shape).
- IOS/IOS-XE `show cdp neighbors detail` now nests `neighbors` as local interface → CDP device_id → outgoing port_id → entry (replacing both the prior list shape and a flat per-local-interface map). Each neighbor entry no longer repeats `local_interface`; use the top-level key path instead.
- NX-OS `show cdp neighbors detail` now returns per-local-interface neighbors as a mapping keyed by `device_id` (with a `device_id|port_id` suffix when the same device appears twice on one interface) instead of a list.
- NX-OS `show ipv6 interface brief` (including `vrf` variants) now returns per-interface global IPv6 addresses as a mapping of address string to optional metadata (e.g. `flags`) instead of a list of objects.
- `show stackwise-virtual link` parser now returns per-switch `ports` as a mapping of interface name to status instead of a list.

### Internal

- Fixture interface-name checks now include Virtual-Access and Virtual-Template (``Vi``/``Vt`` abbreviations and full names). ([#582](https://github.com/ChartinoLabs/Muninn/pull/582))
- Document nested dict preference for composite keys; CI rejects `|` in parser `expected.json` object keys. ([#620](https://github.com/ChartinoLabs/Muninn/pull/620))
- Add CI tests that discourage placeholder strings (`-`, `---`, `NA`/`N/A`) in parser `expected.json` fixtures, with legacy exemptions. ([#621](https://github.com/ChartinoLabs/Muninn/pull/621))
- Add MkDocs Material documentation site with interactive parser library, design philosophy, and CI/CD integration. ([#668](https://github.com/ChartinoLabs/Muninn/pull/668))
- Link README to the documentation site. ([#669](https://github.com/ChartinoLabs/Muninn/pull/669))
- Added a convention test for ``expected.json`` fixtures (keyed dicts vs list-of-dicts) with full-file exemptions listed in the test module.
- Remove stale list-of-dicts exemption for `show standby brief` (fixture already nested dicts).


## 0.1.0 - 2026-03-19

### Added Parsers

- Added parser support for IOS-XE `dir <filesystem>` commands such as `dir crashinfo:`. ([#225](https://github.com/ChartinoLabs/Muninn/pull/225))
- Added parser support for `show vrf` on IOS-XE. ([#324](https://github.com/ChartinoLabs/Muninn/pull/324))
- Added parser for ``show boot`` on IOS-XE with support for variable and path-list output formats. ([#325](https://github.com/ChartinoLabs/Muninn/pull/325))
- Added parser support for `show module` on IOS-XE (Catalyst 9000 series). ([#326](https://github.com/ChartinoLabs/Muninn/pull/326))
- Added parser for ``show vrf detail`` on IOS-XE. ([#327](https://github.com/ChartinoLabs/Muninn/pull/327))
- Added IOS-XE parser for `show ip bgp` with support for multipath routes, continuation lines, and wrapped long network prefixes. ([#328](https://github.com/ChartinoLabs/Muninn/pull/328))
- Added parser support for 'show ip eigrp neighbors' on IOS-XE. ([#329](https://github.com/ChartinoLabs/Muninn/pull/329))
- Added parser support for 'show vrf' on NX-OS. ([#330](https://github.com/ChartinoLabs/Muninn/pull/330))
- Added parser support for 'show vrrp brief' on IOS-XE. ([#331](https://github.com/ChartinoLabs/Muninn/pull/331))
- Added parser support for 'show vrrp all' on IOS-XE. ([#332](https://github.com/ChartinoLabs/Muninn/pull/332))
- Added parser support for 'show ip bgp neighbors' on IOS-XE. ([#333](https://github.com/ChartinoLabs/Muninn/pull/333))
- Added parser support for 'dir' on IOS-XE. ([#334](https://github.com/ChartinoLabs/Muninn/pull/334))
- Added parser support for 'show ip eigrp neighbors detail' on IOS-XE. ([#335](https://github.com/ChartinoLabs/Muninn/pull/335))
- Added parser support for 'show redundancy' on IOS-XE. ([#336](https://github.com/ChartinoLabs/Muninn/pull/336))
- Added parser support for 'show switch detail' on IOS-XE. ([#337](https://github.com/ChartinoLabs/Muninn/pull/337))
- Added parser support for 'show ip eigrp interfaces detail' on IOS-XE. ([#338](https://github.com/ChartinoLabs/Muninn/pull/338))
- Added parser support for 'show endpoint-tracker tracker-group' on IOS-XE. ([#339](https://github.com/ChartinoLabs/Muninn/pull/339))
- Added parser support for 'show dhcp lease' on IOS-XE. ([#340](https://github.com/ChartinoLabs/Muninn/pull/340))
- Added parser support for 'show file systems' on IOS-XE. ([#341](https://github.com/ChartinoLabs/Muninn/pull/341))
- Added parser support for 'show dmvpn' on IOS-XE. ([#342](https://github.com/ChartinoLabs/Muninn/pull/342))
- Added parser support for 'show stack-power' on IOS-XE. ([#343](https://github.com/ChartinoLabs/Muninn/pull/343))
- Added parser support for 'show nve vni' on IOS-XE. ([#344](https://github.com/ChartinoLabs/Muninn/pull/344))
- Added parser support for 'show sdwan bfd summary' on IOS-XE. ([#345](https://github.com/ChartinoLabs/Muninn/pull/345))
- Added parser support for 'show feature' on NX-OS. ([#346](https://github.com/ChartinoLabs/Muninn/pull/346))
- Added parser support for 'show nve peers' on IOS-XE. ([#347](https://github.com/ChartinoLabs/Muninn/pull/347))
- Added parser support for 'show sdwan control connections' on IOS-XE. ([#348](https://github.com/ChartinoLabs/Muninn/pull/348))
- Added parser support for 'show arp' on IOS. ([#349](https://github.com/ChartinoLabs/Muninn/pull/349))
- Added parser support for 'show sdwan tunnel statistics table' on IOS-XE. ([#350](https://github.com/ChartinoLabs/Muninn/pull/350))
- Added parser support for 'show etherchannel summary' on IOS. ([#351](https://github.com/ChartinoLabs/Muninn/pull/351))
- Added parser support for 'show power' on IOS-XE. ([#352](https://github.com/ChartinoLabs/Muninn/pull/352))
- Added parser support for 'show sdwan omp peers' on IOS-XE. ([#353](https://github.com/ChartinoLabs/Muninn/pull/353))
- Added parser support for 'show clock' on IOS. ([#354](https://github.com/ChartinoLabs/Muninn/pull/354))
- Added parser support for 'show route-map' on IOS. ([#355](https://github.com/ChartinoLabs/Muninn/pull/355))
- Added parser support for 'show access-list' on IOS. ([#356](https://github.com/ChartinoLabs/Muninn/pull/356))
- Added parser support for 'show vrrp' on IOS-XE. ([#357](https://github.com/ChartinoLabs/Muninn/pull/357))
- Added parser support for 'show ip arp detail vrf all' on NX-OS. ([#358](https://github.com/ChartinoLabs/Muninn/pull/358))
- Added parser support for 'show bgp neighbors' on IOS-XE. ([#359](https://github.com/ChartinoLabs/Muninn/pull/359))
- Added parser support for 'show environment all' on IOS-XE. ([#360](https://github.com/ChartinoLabs/Muninn/pull/360))
- Added parser support for 'show bgp summary' on IOS-XE. ([#361](https://github.com/ChartinoLabs/Muninn/pull/361))
- Added parser support for 'show bgp all' on IOS-XE. ([#362](https://github.com/ChartinoLabs/Muninn/pull/362))
- Added parser support for 'show standby' on IOS. ([#363](https://github.com/ChartinoLabs/Muninn/pull/363))
- Added parser support for 'show power detail' on IOS-XE. ([#364](https://github.com/ChartinoLabs/Muninn/pull/364))
- Added parser support for 'show route-map all' on IOS-XE. ([#365](https://github.com/ChartinoLabs/Muninn/pull/365))
- Added parser support for 'show environment status' on IOS-XE. ([#366](https://github.com/ChartinoLabs/Muninn/pull/366))
- Added parser support for 'show standby internal' on IOS-XE. ([#367](https://github.com/ChartinoLabs/Muninn/pull/367))
- Added parser support for 'show standby all' on IOS-XE. ([#368](https://github.com/ChartinoLabs/Muninn/pull/368))
- Added parser support for 'show clock' on NX-OS. ([#369](https://github.com/ChartinoLabs/Muninn/pull/369))
- Added parser support for 'show processes' on NX-OS. ([#370](https://github.com/ChartinoLabs/Muninn/pull/370))
- Added parser support for 'show route-map' on NX-OS. ([#371](https://github.com/ChartinoLabs/Muninn/pull/371))
- Added parser support for 'show vrrp detail' on IOS-XE. ([#372](https://github.com/ChartinoLabs/Muninn/pull/372))
- Added parser support for 'show module' on NX-OS. ([#373](https://github.com/ChartinoLabs/Muninn/pull/373))
- Added parser support for 'show environment temperature' on IOS. ([#374](https://github.com/ChartinoLabs/Muninn/pull/374))
- Added parser support for 'show ip prefix-list' on IOS. ([#375](https://github.com/ChartinoLabs/Muninn/pull/375))
- Added parser support for 'show power available' on IOS. ([#376](https://github.com/ChartinoLabs/Muninn/pull/376))
- Added parser support for 'show module status' on IOS. ([#377](https://github.com/ChartinoLabs/Muninn/pull/377))
- Added parser support for 'show module submodule' on IOS. ([#378](https://github.com/ChartinoLabs/Muninn/pull/378))
- Added parser support for 'show power supplies' on IOS. ([#379](https://github.com/ChartinoLabs/Muninn/pull/379))
- Added parser support for 'show power used' on IOS. ([#380](https://github.com/ChartinoLabs/Muninn/pull/380))
- Added parser support for 'show power status' on IOS. ([#381](https://github.com/ChartinoLabs/Muninn/pull/381))
- Added parser support for 'show snmp community' on IOS. ([#382](https://github.com/ChartinoLabs/Muninn/pull/382))
- Added parser support for 'show snmp group' on IOS. ([#383](https://github.com/ChartinoLabs/Muninn/pull/383))
- Added parser support for 'show snmp user' on IOS. ([#384](https://github.com/ChartinoLabs/Muninn/pull/384))
- Added parser support for 'show ip bgp all' on IOS-XE. ([#385](https://github.com/ChartinoLabs/Muninn/pull/385))
- Added parser support for 'show bgp all neighbors' on IOS-XE. ([#386](https://github.com/ChartinoLabs/Muninn/pull/386))
- Added parser support for 'show bgp all summary' on IOS-XE. ([#387](https://github.com/ChartinoLabs/Muninn/pull/387))
- Added parser support for 'show bgp all detail' on IOS-XE. ([#388](https://github.com/ChartinoLabs/Muninn/pull/388))
- Added parser support for 'show power inline priority' on IOS-XE. ([#389](https://github.com/ChartinoLabs/Muninn/pull/389))
- Added parser support for 'show power inline consumption' on IOS-XE. ([#390](https://github.com/ChartinoLabs/Muninn/pull/390))
- Added parser support for 'show ip eigrp timers' on IOS-XE. ([#391](https://github.com/ChartinoLabs/Muninn/pull/391))
- Added parser support for 'show power inline upoe-plus' on IOS-XE. ([#392](https://github.com/ChartinoLabs/Muninn/pull/392))
- Added parser support for 'show ip eigrp interfaces' on IOS-XE. ([#393](https://github.com/ChartinoLabs/Muninn/pull/393))
- Added parser support for 'show vrrp brief all' on IOS-XE. ([#395](https://github.com/ChartinoLabs/Muninn/pull/395))
- Added parser support for 'show environment temperature' on NX-OS. ([#396](https://github.com/ChartinoLabs/Muninn/pull/396))
- Added parser support for 'show bgp peer-template' on NX-OS. ([#397](https://github.com/ChartinoLabs/Muninn/pull/397))
- Added parser support for 'show hsrp summary' on NX-OS. ([#398](https://github.com/ChartinoLabs/Muninn/pull/398))
- Added parser support for 'show bgp sessions' on NX-OS. ([#399](https://github.com/ChartinoLabs/Muninn/pull/399))
- Added parser support for 'show processes cpu' on NX-OS. ([#400](https://github.com/ChartinoLabs/Muninn/pull/400))
- Added parser support for 'show vrf interface' on NX-OS. ([#401](https://github.com/ChartinoLabs/Muninn/pull/401))
- Added parser support for 'show environment power all' on IOS. ([#402](https://github.com/ChartinoLabs/Muninn/pull/402))
- Added parser support for 'show vrf detail' on NX-OS. ([#403](https://github.com/ChartinoLabs/Muninn/pull/403))
- Added parser support for 'show ip eigrp topology' on IOS. ([#404](https://github.com/ChartinoLabs/Muninn/pull/404))
- Added parser support for 'show module online diag' on IOS. ([#405](https://github.com/ChartinoLabs/Muninn/pull/405))
- Added parser support for 'show ip vrf interfaces' on IOS. ([#406](https://github.com/ChartinoLabs/Muninn/pull/406))
- Added 'show processes memory sorted' as an alias for the existing 'show processes memory' parser on IOS and IOS-XE. ([#407](https://github.com/ChartinoLabs/Muninn/pull/407))
- Added parser support for 'show ip route summary' on IOS. ([#408](https://github.com/ChartinoLabs/Muninn/pull/408))
- Added parser support for 'show ip ospf database' on IOS. ([#409](https://github.com/ChartinoLabs/Muninn/pull/409))
- Added parser support for 'show switch' on IOS-XE. ([#410](https://github.com/ChartinoLabs/Muninn/pull/410))
- Added parser support for 'show ip bgp all summary' on IOS-XE. ([#411](https://github.com/ChartinoLabs/Muninn/pull/411))
- Added parser support for 'show ip bgp all neighbors' on IOS-XE. ([#412](https://github.com/ChartinoLabs/Muninn/pull/412))
- Added parser support for 'show track' on IOS-XE. ([#413](https://github.com/ChartinoLabs/Muninn/pull/413))
- Added parser support for 'show ip bgp all detail' on IOS-XE. ([#414](https://github.com/ChartinoLabs/Muninn/pull/414))
- Added parser support for 'show ip bgp regexp ^$' on Cisco IOS-XE. ([#415](https://github.com/ChartinoLabs/Muninn/pull/415))
- Added parser support for 'show ip eigrp neighbors' on Cisco NX-OS. ([#416](https://github.com/ChartinoLabs/Muninn/pull/416))
- Added parser support for 'show ip ospf neighbor' on Cisco NX-OS. ([#417](https://github.com/ChartinoLabs/Muninn/pull/417))
- Added parser support for 'show bgp all nexthop-database' on Cisco NX-OS. ([#418](https://github.com/ChartinoLabs/Muninn/pull/418))
- Added parser support for 'show ip ospf database' on Cisco NX-OS. ([#419](https://github.com/ChartinoLabs/Muninn/pull/419))
- Added parser support for 'show license' on Cisco IOS. ([#420](https://github.com/ChartinoLabs/Muninn/pull/420))
- Added parser support for 'show ip ospf database network' on Cisco IOS. ([#421](https://github.com/ChartinoLabs/Muninn/pull/421))
- Added parser support for 'show policy-map' on Cisco IOS. ([#422](https://github.com/ChartinoLabs/Muninn/pull/422))
- Added parser support for 'show ip ospf database router' on Cisco IOS. ([#423](https://github.com/ChartinoLabs/Muninn/pull/423))
- Added parser support for 'show ip bgp neighbors advertised-routes' on Cisco IOS. ([#424](https://github.com/ChartinoLabs/Muninn/pull/424))
- Added parser support for 'show ip ospf interface brief' on Cisco IOS. ([#425](https://github.com/ChartinoLabs/Muninn/pull/425))
- Added parser support for 'show platform resources' on Cisco IOS-XE. ([#426](https://github.com/ChartinoLabs/Muninn/pull/426))
- Added parser support for 'show ip ospf neighbor detail' on Cisco IOS. ([#427](https://github.com/ChartinoLabs/Muninn/pull/427))
- Added parser support for 'show policy-map control-plane' on Cisco IOS-XE. ([#428](https://github.com/ChartinoLabs/Muninn/pull/428))
- Added parser support for 'show policy-map interface' on Cisco IOS-XE. ([#429](https://github.com/ChartinoLabs/Muninn/pull/429))
- Added parser support for 'show udld neighbor' on Cisco IOS-XE. ([#430](https://github.com/ChartinoLabs/Muninn/pull/430))
- Added parser support for 'show policy-map multipoint' on Cisco IOS-XE. ([#431](https://github.com/ChartinoLabs/Muninn/pull/431))
- Added parser support for 'show authentication sessions' on Cisco IOS. ([#432](https://github.com/ChartinoLabs/Muninn/pull/432))
- Added parser support for 'show bgp all dampening flap-statistics' on Cisco NX-OS. ([#433](https://github.com/ChartinoLabs/Muninn/pull/433))
- Added parser support for 'show interface' on Cisco NX-OS. ([#434](https://github.com/ChartinoLabs/Muninn/pull/434))
- Added parser support for 'show bgp vrf all all' on Cisco NX-OS. ([#435](https://github.com/ChartinoLabs/Muninn/pull/435))
- Added 'show bgp l2vpn evpn summary' support on Cisco NX-OS by reusing the existing 'show ip bgp summary' parser. ([#436](https://github.com/ChartinoLabs/Muninn/pull/436))
- Added parser support for 'show dot1x all' on Cisco IOS. ([#437](https://github.com/ChartinoLabs/Muninn/pull/437))
- Added parser support for 'show interface link' on Cisco IOS. ([#438](https://github.com/ChartinoLabs/Muninn/pull/438))
- Added parser support for 'show bgp process vrf all' on Cisco NX-OS. ([#439](https://github.com/ChartinoLabs/Muninn/pull/439))
- Added parser support for 'show ip mroute' on Cisco IOS. ([#440](https://github.com/ChartinoLabs/Muninn/pull/440))
- Added parser support for 'show ipv6 neighbors' on Cisco IOS. ([#441](https://github.com/ChartinoLabs/Muninn/pull/441))
- Added parser support for 'show ipv6 access-lists' on Cisco IOS. ([#442](https://github.com/ChartinoLabs/Muninn/pull/442))
- Added parser support for 'show interface transceiver' on Cisco IOS. ([#443](https://github.com/ChartinoLabs/Muninn/pull/443))
- Added parser support for 'show ip ospf interface brief' on Cisco NX-OS. ([#444](https://github.com/ChartinoLabs/Muninn/pull/444))
- Added parser support for 'show isis neighbors' on Cisco IOS. ([#445](https://github.com/ChartinoLabs/Muninn/pull/445))
- Added parser support for `show mpls interfaces` on Cisco IOS. ([#446](https://github.com/ChartinoLabs/Muninn/pull/446))
- Added parser support for 'show license status' on Cisco IOS. ([#447](https://github.com/ChartinoLabs/Muninn/pull/447))
- Added parser support for 'show platform diag' on Cisco IOS. ([#448](https://github.com/ChartinoLabs/Muninn/pull/448))
- Added parser support for 'show spanning-tree root' on Cisco IOS. ([#449](https://github.com/ChartinoLabs/Muninn/pull/449))
- Added parser support for 'show ipv6 eigrp interfaces' on Cisco IOS-XE. ([#450](https://github.com/ChartinoLabs/Muninn/pull/450))
- Added parser support for 'show switch virtual' on Cisco IOS. ([#451](https://github.com/ChartinoLabs/Muninn/pull/451))
- Added parser support for 'show vtp status' on Cisco IOS. ([#452](https://github.com/ChartinoLabs/Muninn/pull/452))
- Added parser support for 'show ipv6 dhcp interface' on Cisco IOS-XE. ([#453](https://github.com/ChartinoLabs/Muninn/pull/453))
- Added parser support for 'show ip bgp vpnv4 all neighbors' on Cisco IOS. ([#454](https://github.com/ChartinoLabs/Muninn/pull/454))
- Added parser support for 'show ipv6 eigrp neighbors' on Cisco IOS-XE. ([#455](https://github.com/ChartinoLabs/Muninn/pull/455))
- Added parser support for 'show platform packet-trace summary' on Cisco IOS-XE. ([#456](https://github.com/ChartinoLabs/Muninn/pull/456))
- Added parser support for 'show platform integrity sign' on Cisco IOS-XE. ([#457](https://github.com/ChartinoLabs/Muninn/pull/457))
- Added parser support for `show platform packet-trace all` on Cisco IOS-XE. ([#458](https://github.com/ChartinoLabs/Muninn/pull/458))
- Added parser support for `show platform packet-trace statistics` on Cisco IOS-XE. ([#459](https://github.com/ChartinoLabs/Muninn/pull/459))
- Added parser support for 'show platform sudi pki' on Cisco IOS-XE. ([#460](https://github.com/ChartinoLabs/Muninn/pull/460))
- Added parser support for 'ping' on Cisco IOS. ([#461](https://github.com/ChartinoLabs/Muninn/pull/461))
- Added parser support for 'show platform software meraki-service' on Cisco IOS-XE. ([#462](https://github.com/ChartinoLabs/Muninn/pull/462))
- Added parser support for 'show bfd neighbors' on Cisco NX-OS. ([#463](https://github.com/ChartinoLabs/Muninn/pull/463))
- Added parser support for 'show interface brief' on Cisco NX-OS. ([#464](https://github.com/ChartinoLabs/Muninn/pull/464))
- Added parser support for 'show interface snmp-ifindex' on Cisco NX-OS. ([#465](https://github.com/ChartinoLabs/Muninn/pull/465))
- Added parser support for 'show interface switchport' on Cisco NX-OS. ([#466](https://github.com/ChartinoLabs/Muninn/pull/466))
- Added parser support for 'show interface capabilities' on Cisco NX-OS. ([#467](https://github.com/ChartinoLabs/Muninn/pull/467))
- Added parser support for 'show interface transceiver' on Cisco NX-OS. ([#468](https://github.com/ChartinoLabs/Muninn/pull/468))
- Added parser support for 'show interface description' on Cisco NX-OS. ([#469](https://github.com/ChartinoLabs/Muninn/pull/469))
- Added parser support for 'show logging onboard rp active message detail' on Cisco IOS-XE. ([#470](https://github.com/ChartinoLabs/Muninn/pull/470))
- Added parser support for 'show license usage' on Cisco NX-OS. ([#471](https://github.com/ChartinoLabs/Muninn/pull/471))
- Added parser support for 'show logging onboard rp active counter detail' on Cisco IOS-XE. ([#472](https://github.com/ChartinoLabs/Muninn/pull/472))
- Added parser support for 'show logging onboard rp active clilog detail' on Cisco IOS-XE. ([#473](https://github.com/ChartinoLabs/Muninn/pull/473))
- Added parser support for 'show logging onboard rp active environment detail' on Cisco IOS-XE. ([#474](https://github.com/ChartinoLabs/Muninn/pull/474))
- Added parser support for 'show spanning-tree root' on Cisco NX-OS. ([#475](https://github.com/ChartinoLabs/Muninn/pull/475))
- Added parser support for 'show bgp vrf all all neighbors' on Cisco NX-OS. ([#477](https://github.com/ChartinoLabs/Muninn/pull/477))
- Added parser support for 'traceroute' on Cisco IOS. ([#478](https://github.com/ChartinoLabs/Muninn/pull/478))
- Added parser support for 'show bfd neighbors details' on Cisco IOS. ([#479](https://github.com/ChartinoLabs/Muninn/pull/479))
- Added parser support for 'show bootvar' on Cisco IOS-XE. ([#480](https://github.com/ChartinoLabs/Muninn/pull/480))
- Added parser support for 'show cdp' on Cisco IOS-XE. ([#481](https://github.com/ChartinoLabs/Muninn/pull/481))
- Added parser support for 'show cloud-mgmt' on Cisco IOS-XE. ([#482](https://github.com/ChartinoLabs/Muninn/pull/482))
- Added parser support for 'show bgp vrf all all nexthop-database' on Cisco NX-OS. ([#483](https://github.com/ChartinoLabs/Muninn/pull/483))
- Added parser support for 'show crypto pki certificates' on Cisco IOS. ([#484](https://github.com/ChartinoLabs/Muninn/pull/484))
- Added parser support for 'show esmc' on Cisco IOS-XE. ([#485](https://github.com/ChartinoLabs/Muninn/pull/485))
- Added parser support for 'show graceful-reload' on Cisco IOS-XE. ([#486](https://github.com/ChartinoLabs/Muninn/pull/486))
- Added parser support for 'show ip nat translations' on Cisco IOS. ([#487](https://github.com/ChartinoLabs/Muninn/pull/487))
- Added parser support for 'show ip dhcp binding' on Cisco IOS. ([#488](https://github.com/ChartinoLabs/Muninn/pull/488))
- Added parser support for 'show crypto session detail' on Cisco IOS. ([#489](https://github.com/ChartinoLabs/Muninn/pull/489))
- Added parser support for 'show mpls l2transport vc' on Cisco IOS. ([#490](https://github.com/ChartinoLabs/Muninn/pull/490))
- Added parser support for 'show ipv6 interface brief' on Cisco IOS. ([#491](https://github.com/ChartinoLabs/Muninn/pull/491))
- Added parser support for 'show meraki' on Cisco IOS-XE. ([#492](https://github.com/ChartinoLabs/Muninn/pull/492))
- Added parser support for 'show port-security interface' on Cisco IOS. ([#493](https://github.com/ChartinoLabs/Muninn/pull/493))
- Added parser support for 'show stackwise-virtual' on Cisco IOS-XE. ([#494](https://github.com/ChartinoLabs/Muninn/pull/494))
- Added parser support for 'show vtemplate' on Cisco IOS-XE. ([#495](https://github.com/ChartinoLabs/Muninn/pull/495))
- Added parser support for 'dir' on Cisco NX-OS. ([#496](https://github.com/ChartinoLabs/Muninn/pull/496))
- Added parser support for 'show vpdn' on Cisco IOS-XE. ([#497](https://github.com/ChartinoLabs/Muninn/pull/497))
- Added parser support for 'show table-map' on Cisco IOS-XE. ([#498](https://github.com/ChartinoLabs/Muninn/pull/498))
- Added parser support for 'show ip dhcp snooping statistics' on Cisco IOS-XE. ([#499](https://github.com/ChartinoLabs/Muninn/pull/499))
- Added parser support for 'show ipv6 eigrp interfaces detail' on Cisco IOS-XE (reuses existing IPv4 EIGRP interfaces detail parser). ([#500](https://github.com/ChartinoLabs/Muninn/pull/500))
- Added parser support for 'show platform hardware throughput level' on Cisco IOS-XE. ([#501](https://github.com/ChartinoLabs/Muninn/pull/501))
- Added parser support for 'show platform hardware authentication status' on Cisco IOS-XE. ([#502](https://github.com/ChartinoLabs/Muninn/pull/502))
- Added parser support for 'show ipv6 eigrp neighbors detail' on Cisco IOS-XE. ([#503](https://github.com/ChartinoLabs/Muninn/pull/503))
- Added parser support for 'show platform hardware throughput crypto' on Cisco IOS-XE. ([#504](https://github.com/ChartinoLabs/Muninn/pull/504))
- Added parser support for 'show platform software dns-umbrella statistics' on Cisco IOS-XE. ([#505](https://github.com/ChartinoLabs/Muninn/pull/505))
- Added parser support for 'show platform software dpidb index' on Cisco IOS-XE. ([#506](https://github.com/ChartinoLabs/Muninn/pull/506))
- Added parser support for 'show platform nat translations active' on Cisco IOS-XE. ([#507](https://github.com/ChartinoLabs/Muninn/pull/507))
- Added parser support for 'show platform software audit ruleset' on Cisco IOS-XE. ([#508](https://github.com/ChartinoLabs/Muninn/pull/508))
- Added parser support for 'show platform software nat ipalias' on Cisco IOS-XE. ([#511](https://github.com/ChartinoLabs/Muninn/pull/511))
- Added parser support for 'show platform software audit summary' on Cisco IOS-XE. ([#512](https://github.com/ChartinoLabs/Muninn/pull/512))
- Added parser support for 'show platform software infractructure inject' on Cisco IOS-XE. ([#513](https://github.com/ChartinoLabs/Muninn/pull/513))
- Added parser support for 'show platform software yang-management process' on Cisco IOS-XE. ([#514](https://github.com/ChartinoLabs/Muninn/pull/514))
- Added parser support for 'show platform software multicast stats' on Cisco IOS-XE. ([#515](https://github.com/ChartinoLabs/Muninn/pull/515))
- Added parser support for `show aliases` on IOS. ([#516](https://github.com/ChartinoLabs/Muninn/pull/516))
- Added parser for `show redundancy config-sync failures mcl` on IOS-XE. ([#517](https://github.com/ChartinoLabs/Muninn/pull/517))
- [#518](https://github.com/ChartinoLabs/Muninn/pull/518), [#531](https://github.com/ChartinoLabs/Muninn/pull/531), [#534](https://github.com/ChartinoLabs/Muninn/pull/534)
- Added parser support for `show access-session` on IOS. ([#519](https://github.com/ChartinoLabs/Muninn/pull/519))
- Added parser support for 'show platform sudi certificate sign' on Cisco IOS-XE. ([#520](https://github.com/ChartinoLabs/Muninn/pull/520))
- Added parser support for `show endpoint-tracker` on IOS with results grouped by interface and tracker. ([#521](https://github.com/ChartinoLabs/Muninn/pull/521))
- Added parser for `show ipv6 interface brief` on NX-OS. ([#522](https://github.com/ChartinoLabs/Muninn/pull/522))
- Added parser support for `show archive` on IOS. ([#523](https://github.com/ChartinoLabs/Muninn/pull/523))
- Added `show mac-address-table` command alias for IOS and IOS-XE. ([#524](https://github.com/ChartinoLabs/Muninn/pull/524))
- Added parser for `show interface transceiver details` on NX-OS with transceiver identification and DOM diagnostic readings. ([#525](https://github.com/ChartinoLabs/Muninn/pull/525))
- Added parser support for `show tacacs` on IOS. ([#526](https://github.com/ChartinoLabs/Muninn/pull/526))
- Added parser support for 'show users' on Cisco IOS. ([#527](https://github.com/ChartinoLabs/Muninn/pull/527))
- Added parser support for 'show object-group' on Cisco IOS. ([#528](https://github.com/ChartinoLabs/Muninn/pull/528))
- Added parser support for IOS `show authentication sessions method details`. ([#529](https://github.com/ChartinoLabs/Muninn/pull/529))
- Added parser support for `show vlans` on IOS. ([#530](https://github.com/ChartinoLabs/Muninn/pull/530))
- Added parser support for 'show caller summary' on Cisco IOS-XE. ([#532](https://github.com/ChartinoLabs/Muninn/pull/532))
- Added parser for `show avb domain` on IOS-XE. ([#533](https://github.com/ChartinoLabs/Muninn/pull/533))
- Added parser for `show bgp vrf all ipv4 unicast detail` on NX-OS. ([#535](https://github.com/ChartinoLabs/Muninn/pull/535))
- Added parser for `show interface status` on IOS-XE and IOS. ([#539](https://github.com/ChartinoLabs/Muninn/pull/539))
- Added parser support for IOS-XE `show ip ospf database`. ([#540](https://github.com/ChartinoLabs/Muninn/pull/540))
- Added IOS-XE parser coverage for control-plane, access-layer, and hardware telemetry workflows, including `show ip interface brief`, `show ip vrf`, `show ip ospf neighbor`, `show ip dhcp snooping binding`, `show mac address-table dynamic`, `show macsec summary`, `show mpls forwarding-table summary`, and platform-focused commands such as `show platform software fed ip mfib count`, `show platform usb status`, `show standby delay`, and `show privilege`.
- Added broad NX-OS parser coverage across L2/L3 operations, neighbor discovery, and data-center feature sets, including `show ip route`, `show ipv6 route`, `show ip arp`, `show ip bgp`, `show ip bgp summary`, `show ip bgp neighbors`, `show cdp neighbors`, `show lldp neighbors`, `show interface status`, `show port-channel summary`, `show vpc`, `show hsrp all`, and additional operational commands such as `show environment`, `show version`, `show track`, and `show vlan` variants.
- Added foundational IOS parser coverage for switching, routing, and platform visibility commands, including `show interfaces`, `show ip route`, `show ip arp`, `show ip ospf interface`, `show ipv6 route`, `show mac address-table`, `show spanning-tree`, `show cdp neighbors`, `show lldp neighbors`, and core operational outputs such as `show version`, `show inventory`, `show logging`, and `show platform`.

### Fixed Parsers

- Fixed duplicate registration of 'show bgp vrf all all nexthop-database' on Cisco NX-OS that caused test collection to fail. ([#538](https://github.com/ChartinoLabs/Muninn/pull/538))
- Fixed 'show ip vrf' parser on IOS-XE failing on live device output due to leading whitespace in VRF name column. ([#542](https://github.com/ChartinoLabs/Muninn/pull/542))

### Core Features

- Added local parser overlays with configurable execution policy and fallback behavior, including local-first, centralized-first, and local-only modes. ([#1](https://github.com/ChartinoLabs/Muninn/pull/1))
- Added a centralized configuration system that loads from API overrides, environment variables, and `pyproject.toml` with deterministic source precedence. ([#68](https://github.com/ChartinoLabs/Muninn/pull/68))
- Added pattern-aware parser routing with literal-first lookup, regex command matching, and ambiguity reporting for overlapping same-source patterns. ([#322](https://github.com/ChartinoLabs/Muninn/pull/322))
- Added metadata tags to parsers via `BaseParser.tags` for feature-based filtering and documentation. Built-in parsers must declare tags; local parsers may omit them. New `ParserInfo` dataclass and `RuntimeRegistry.list_parser_catalog()` method for aggregating parser metadata. ([#537](https://github.com/ChartinoLabs/Muninn/pull/537))

### Breaking Changes

- Replaced module-level parsing and configuration globals with an explicit `MuninnRuntime` API; consumers should instantiate `MuninnRuntime` and call `runtime.parse(...)`. ([#1](https://github.com/ChartinoLabs/Muninn/pull/1))

### Internal

- Added Towncrier-based changelog management with typed change fragments and release build instructions. ([#64](https://github.com/ChartinoLabs/Muninn/pull/64))
- Improved parser typing compatibility with newer `ty` releases. ([#71](https://github.com/ChartinoLabs/Muninn/pull/71))
- Extracted common regex patterns (IPv4 address, MAC address, table separators) into shared ``muninn.patterns`` module and refactored 44 parsers to use them. ([#536](https://github.com/ChartinoLabs/Muninn/pull/536))
- Aligned pre-commit xenon thresholds with CI (``--max-absolute B --max-average A``) and scoped to ``src/``. ([#541](https://github.com/ChartinoLabs/Muninn/pull/541))
- Add tag-based PyPI publishing workflow with dynamic versioning (hatch-vcs) and rename PyPI package to ``muninn-parsers``. ([#543](https://github.com/ChartinoLabs/Muninn/pull/543))
- Documented parser registration rules for literal commands, named-group regex routing, template generation, and regex testing guidance.
