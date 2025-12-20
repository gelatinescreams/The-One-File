<!--THEONEFILE_CONFIG
{
  "nodeData": {
    "core-router-1": {
      "shape": "router",
      "name": "Core Router 1",
      "ip": "10.0.0.1",
      "role": "Core Routing",
      "tags": [
        "core",
        "tier-1",
        "redundant"
      ],
      "notes": [
        "Primary core router",
        "BGP peering enabled"
      ],
      "mac": "00:1A:2B:3C:4D:01",
      "rackUnit": "",
      "uHeight": "2",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "core-router-2": {
      "shape": "router",
      "name": "Core Router 2",
      "ip": "10.0.0.2",
      "role": "Core Routing",
      "tags": [
        "core",
        "tier-1",
        "redundant"
      ],
      "notes": [
        "Secondary core router",
        "HSRP standby"
      ],
      "mac": "00:1A:2B:3C:4D:02",
      "rackUnit": "",
      "uHeight": "2",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "fw-external-1": {
      "shape": "firewall",
      "name": "External FW 1",
      "ip": "10.0.1.1",
      "role": "Perimeter Security",
      "tags": [
        "security",
        "perimeter",
        "ha-pair"
      ],
      "notes": [
        "Palo Alto PA-5250",
        "Active node"
      ],
      "mac": "00:1A:2B:3C:4D:10",
      "rackUnit": "",
      "uHeight": "2",
      "layer": "security",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "fw-external-2": {
      "shape": "firewall",
      "name": "External FW 2",
      "ip": "10.0.1.2",
      "role": "Perimeter Security",
      "tags": [
        "security",
        "perimeter",
        "ha-pair"
      ],
      "notes": [
        "Palo Alto PA-5250",
        "Passive node"
      ],
      "mac": "00:1A:2B:3C:4D:11",
      "rackUnit": "",
      "uHeight": "2",
      "layer": "security",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "fw-internal": {
      "shape": "firewall",
      "name": "Internal FW",
      "ip": "10.0.2.1",
      "role": "Internal Segmentation",
      "tags": [
        "security",
        "internal"
      ],
      "notes": [
        "East-West traffic inspection"
      ],
      "mac": "00:1A:2B:3C:4D:12",
      "rackUnit": "",
      "uHeight": "2",
      "layer": "security",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "core-switch-1": {
      "shape": "switch",
      "name": "Core Switch 1",
      "ip": "10.0.10.1",
      "role": "Core Switching",
      "tags": [
        "core",
        "layer3",
        "redundant"
      ],
      "notes": [
        "Cisco Nexus 9000",
        "VPC Domain 1"
      ],
      "mac": "00:1A:2B:3C:4D:20",
      "rackUnit": "",
      "uHeight": "2",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "core-switch-2": {
      "shape": "switch",
      "name": "Core Switch 2",
      "ip": "10.0.10.2",
      "role": "Core Switching",
      "tags": [
        "core",
        "layer3",
        "redundant"
      ],
      "notes": [
        "Cisco Nexus 9000",
        "VPC Domain 1"
      ],
      "mac": "00:1A:2B:3C:4D:21",
      "rackUnit": "",
      "uHeight": "2",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "dc-rack-a1": {
      "shape": "server",
      "name": "DC Rack A1",
      "ip": "10.10.0.0/24",
      "role": "Data Center Rack",
      "tags": [
        "datacenter",
        "row-a",
        "production"
      ],
      "notes": [
        "Row A, Position 1",
        "Primary compute"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": true,
      "locked": false,
      "groupId": null
    },
    "dc-rack-a2": {
      "shape": "server",
      "name": "DC Rack A2",
      "ip": "10.10.1.0/24",
      "role": "Data Center Rack",
      "tags": [
        "datacenter",
        "row-a",
        "production"
      ],
      "notes": [
        "Row A, Position 2",
        "Primary compute"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": true,
      "locked": false,
      "groupId": null
    },
    "dc-rack-b1": {
      "shape": "server",
      "name": "DC Rack B1",
      "ip": "10.10.2.0/24",
      "role": "Data Center Rack",
      "tags": [
        "datacenter",
        "row-b",
        "storage"
      ],
      "notes": [
        "Row B, Position 1",
        "Storage systems"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": true,
      "locked": false,
      "groupId": null
    },
    "dc-rack-b2": {
      "shape": "server",
      "name": "DC Rack B2",
      "ip": "10.10.3.0/24",
      "role": "Data Center Rack",
      "tags": [
        "datacenter",
        "row-b",
        "storage"
      ],
      "notes": [
        "Row B, Position 2",
        "Storage systems"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": true,
      "locked": false,
      "groupId": null
    },
    "dmz-rack": {
      "shape": "server",
      "name": "DMZ Rack",
      "ip": "172.16.0.0/24",
      "role": "DMZ Infrastructure",
      "tags": [
        "dmz",
        "security",
        "public-facing"
      ],
      "notes": [
        "Isolated DMZ zone",
        "Public-facing services"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "security",
      "assignedRack": "",
      "rackCapacity": "24",
      "isRack": true,
      "locked": false,
      "groupId": null
    },
    "mgmt-rack": {
      "shape": "server",
      "name": "Management Rack",
      "ip": "192.168.100.0/24",
      "role": "Management Infrastructure",
      "tags": [
        "management",
        "oob",
        "noc"
      ],
      "notes": [
        "Out-of-band management",
        "NOC equipment"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "logical",
      "assignedRack": "",
      "rackCapacity": "24",
      "isRack": true,
      "locked": false,
      "groupId": null
    },
    "esxi-host-01": {
      "shape": "server",
      "name": "ESXi Host 01",
      "ip": "10.10.0.11",
      "role": "Hypervisor",
      "tags": [
        "vmware",
        "compute",
        "cluster-a"
      ],
      "notes": [
        "Dell PowerEdge R750",
        "512GB RAM",
        "vSphere 8.0"
      ],
      "mac": "00:50:56:AA:01:01",
      "rackUnit": 38,
      "uHeight": "2",
      "layer": "physical",
      "assignedRack": "dc-rack-a1",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "esxi-host-02": {
      "shape": "server",
      "name": "ESXi Host 02",
      "ip": "10.10.0.12",
      "role": "Hypervisor",
      "tags": [
        "vmware",
        "compute",
        "cluster-a"
      ],
      "notes": [
        "Dell PowerEdge R750",
        "512GB RAM",
        "vSphere 8.0"
      ],
      "mac": "00:50:56:AA:01:02",
      "rackUnit": 35,
      "uHeight": "2",
      "layer": "physical",
      "assignedRack": "dc-rack-a1",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "esxi-host-03": {
      "shape": "server",
      "name": "ESXi Host 03",
      "ip": "10.10.0.13",
      "role": "Hypervisor",
      "tags": [
        "vmware",
        "compute",
        "cluster-a"
      ],
      "notes": [
        "Dell PowerEdge R750",
        "512GB RAM",
        "vSphere 8.0"
      ],
      "mac": "00:50:56:AA:01:03",
      "rackUnit": 32,
      "uHeight": "2",
      "layer": "physical",
      "assignedRack": "dc-rack-a1",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "esxi-host-04": {
      "shape": "server",
      "name": "ESXi Host 04",
      "ip": "10.10.0.14",
      "role": "Hypervisor",
      "tags": [
        "vmware",
        "compute",
        "cluster-a"
      ],
      "notes": [
        "Dell PowerEdge R750",
        "512GB RAM",
        "vSphere 8.0"
      ],
      "mac": "00:50:56:AA:01:04",
      "rackUnit": 29,
      "uHeight": "2",
      "layer": "physical",
      "assignedRack": "dc-rack-a1",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "tor-switch-a1": {
      "shape": "switch",
      "name": "ToR Switch A1",
      "ip": "10.10.0.1",
      "role": "Top of Rack",
      "tags": [
        "tor",
        "access",
        "rack-a1"
      ],
      "notes": [
        "Cisco Nexus 93180YC-FX",
        "48x25G ports"
      ],
      "mac": "00:1A:2B:3C:5D:01",
      "rackUnit": 42,
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "dc-rack-a1",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "esxi-host-05": {
      "shape": "server",
      "name": "ESXi Host 05",
      "ip": "10.10.1.11",
      "role": "Hypervisor",
      "tags": [
        "vmware",
        "compute",
        "cluster-b"
      ],
      "notes": [
        "Dell PowerEdge R750",
        "768GB RAM",
        "vSphere 8.0"
      ],
      "mac": "00:50:56:AA:02:01",
      "rackUnit": 38,
      "uHeight": "2",
      "layer": "physical",
      "assignedRack": "dc-rack-a2",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "esxi-host-06": {
      "shape": "server",
      "name": "ESXi Host 06",
      "ip": "10.10.1.12",
      "role": "Hypervisor",
      "tags": [
        "vmware",
        "compute",
        "cluster-b"
      ],
      "notes": [
        "Dell PowerEdge R750",
        "768GB RAM",
        "vSphere 8.0"
      ],
      "mac": "00:50:56:AA:02:02",
      "rackUnit": 35,
      "uHeight": "2",
      "layer": "physical",
      "assignedRack": "dc-rack-a2",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "esxi-host-07": {
      "shape": "server",
      "name": "ESXi Host 07",
      "ip": "10.10.1.13",
      "role": "Hypervisor",
      "tags": [
        "vmware",
        "compute",
        "cluster-b"
      ],
      "notes": [
        "Dell PowerEdge R750",
        "768GB RAM",
        "vSphere 8.0"
      ],
      "mac": "00:50:56:AA:02:03",
      "rackUnit": 32,
      "uHeight": "2",
      "layer": "physical",
      "assignedRack": "dc-rack-a2",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "esxi-host-08": {
      "shape": "server",
      "name": "ESXi Host 08",
      "ip": "10.10.1.14",
      "role": "Hypervisor",
      "tags": [
        "vmware",
        "compute",
        "cluster-b"
      ],
      "notes": [
        "Dell PowerEdge R750",
        "768GB RAM",
        "vSphere 8.0"
      ],
      "mac": "00:50:56:AA:02:04",
      "rackUnit": 29,
      "uHeight": "2",
      "layer": "physical",
      "assignedRack": "dc-rack-a2",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "tor-switch-a2": {
      "shape": "switch",
      "name": "ToR Switch A2",
      "ip": "10.10.1.1",
      "role": "Top of Rack",
      "tags": [
        "tor",
        "access",
        "rack-a2"
      ],
      "notes": [
        "Cisco Nexus 93180YC-FX",
        "48x25G ports"
      ],
      "mac": "00:1A:2B:3C:5D:02",
      "rackUnit": 42,
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "dc-rack-a2",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "san-primary": {
      "shape": "database",
      "name": "SAN Primary",
      "ip": "10.10.2.10",
      "role": "Primary Storage",
      "tags": [
        "storage",
        "san",
        "netapp"
      ],
      "notes": [
        "NetApp AFF A400",
        "500TB Raw",
        "FC 32Gb"
      ],
      "mac": "00:A0:98:AA:01:01",
      "rackUnit": 36,
      "uHeight": "6",
      "layer": "physical",
      "assignedRack": "dc-rack-b1",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "san-secondary": {
      "shape": "database",
      "name": "SAN Secondary",
      "ip": "10.10.2.11",
      "role": "Secondary Storage",
      "tags": [
        "storage",
        "san",
        "netapp"
      ],
      "notes": [
        "NetApp AFF A400",
        "500TB Raw",
        "FC 32Gb"
      ],
      "mac": "00:A0:98:AA:01:02",
      "rackUnit": 28,
      "uHeight": "6",
      "layer": "physical",
      "assignedRack": "dc-rack-b1",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "fc-switch-1": {
      "shape": "switch",
      "name": "FC Switch 1",
      "ip": "10.10.2.1",
      "role": "Fibre Channel",
      "tags": [
        "storage",
        "fc",
        "fabric-a"
      ],
      "notes": [
        "Brocade G620",
        "Fabric A"
      ],
      "mac": "00:1A:2B:FC:01:01",
      "rackUnit": 42,
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "dc-rack-b1",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "fc-switch-2": {
      "shape": "switch",
      "name": "FC Switch 2",
      "ip": "10.10.2.2",
      "role": "Fibre Channel",
      "tags": [
        "storage",
        "fc",
        "fabric-b"
      ],
      "notes": [
        "Brocade G620",
        "Fabric B"
      ],
      "mac": "00:1A:2B:FC:01:02",
      "rackUnit": 41,
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "dc-rack-b1",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "backup-server-1": {
      "shape": "server",
      "name": "Backup Server 1",
      "ip": "10.10.3.10",
      "role": "Backup Infrastructure",
      "tags": [
        "backup",
        "veeam",
        "protection"
      ],
      "notes": [
        "Veeam Backup Server",
        "Dell R740xd",
        "200TB"
      ],
      "mac": "00:50:56:BB:01:01",
      "rackUnit": 36,
      "uHeight": "2",
      "layer": "physical",
      "assignedRack": "dc-rack-b2",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "backup-server-2": {
      "shape": "server",
      "name": "Backup Server 2",
      "ip": "10.10.3.11",
      "role": "Backup Infrastructure",
      "tags": [
        "backup",
        "veeam",
        "protection"
      ],
      "notes": [
        "Veeam Backup Server",
        "Dell R740xd",
        "200TB"
      ],
      "mac": "00:50:56:BB:01:02",
      "rackUnit": 33,
      "uHeight": "2",
      "layer": "physical",
      "assignedRack": "dc-rack-b2",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "tape-library": {
      "shape": "database",
      "name": "Tape Library",
      "ip": "10.10.3.20",
      "role": "Archival Storage",
      "tags": [
        "backup",
        "tape",
        "lto9"
      ],
      "notes": [
        "IBM TS4500",
        "LTO-9",
        "Long-term archive"
      ],
      "mac": "00:50:56:BB:02:01",
      "rackUnit": 20,
      "uHeight": "10",
      "layer": "physical",
      "assignedRack": "dc-rack-b2",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "tor-switch-b1": {
      "shape": "switch",
      "name": "ToR Switch B1",
      "ip": "10.10.2.3",
      "role": "Top of Rack",
      "tags": [
        "tor",
        "access",
        "rack-b1"
      ],
      "notes": [
        "Cisco Nexus 93180YC-FX"
      ],
      "mac": "00:1A:2B:3C:5D:03",
      "rackUnit": 40,
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "dc-rack-b1",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "tor-switch-b2": {
      "shape": "switch",
      "name": "ToR Switch B2",
      "ip": "10.10.3.1",
      "role": "Top of Rack",
      "tags": [
        "tor",
        "access",
        "rack-b2"
      ],
      "notes": [
        "Cisco Nexus 93180YC-FX"
      ],
      "mac": "00:1A:2B:3C:5D:04",
      "rackUnit": 42,
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "dc-rack-b2",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "web-server-1": {
      "shape": "server",
      "name": "Web Server 1",
      "ip": "172.16.0.11",
      "role": "Web Frontend",
      "tags": [
        "dmz",
        "web",
        "nginx"
      ],
      "notes": [
        "NGINX reverse proxy",
        "Public facing"
      ],
      "mac": "00:50:56:CC:01:01",
      "rackUnit": 20,
      "uHeight": "1",
      "layer": "security",
      "assignedRack": "dmz-rack",
      "rackCapacity": "24",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "web-server-2": {
      "shape": "server",
      "name": "Web Server 2",
      "ip": "172.16.0.12",
      "role": "Web Frontend",
      "tags": [
        "dmz",
        "web",
        "nginx"
      ],
      "notes": [
        "NGINX reverse proxy",
        "Public facing"
      ],
      "mac": "00:50:56:CC:01:02",
      "rackUnit": 18,
      "uHeight": "1",
      "layer": "security",
      "assignedRack": "dmz-rack",
      "rackCapacity": "24",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "waf-1": {
      "shape": "firewall",
      "name": "WAF Appliance",
      "ip": "172.16.0.5",
      "role": "Web Application Firewall",
      "tags": [
        "dmz",
        "security",
        "waf"
      ],
      "notes": [
        "F5 BIG-IP ASM",
        "OWASP protection"
      ],
      "mac": "00:50:56:CC:02:01",
      "rackUnit": 22,
      "uHeight": "2",
      "layer": "security",
      "assignedRack": "dmz-rack",
      "rackCapacity": "24",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "load-balancer-dmz": {
      "shape": "switch",
      "name": "DMZ Load Balancer",
      "ip": "172.16.0.3",
      "role": "Load Balancing",
      "tags": [
        "dmz",
        "lb",
        "f5"
      ],
      "notes": [
        "F5 BIG-IP LTM",
        "VIP: 172.16.0.100"
      ],
      "mac": "00:50:56:CC:03:01",
      "rackUnit": 16,
      "uHeight": "2",
      "layer": "security",
      "assignedRack": "dmz-rack",
      "rackCapacity": "24",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "mail-gateway": {
      "shape": "server",
      "name": "Mail Gateway",
      "ip": "172.16.0.25",
      "role": "Email Security",
      "tags": [
        "dmz",
        "email",
        "security"
      ],
      "notes": [
        "Proofpoint Email Gateway",
        "Spam/malware filtering"
      ],
      "mac": "00:50:56:CC:04:01",
      "rackUnit": 14,
      "uHeight": "1",
      "layer": "security",
      "assignedRack": "dmz-rack",
      "rackCapacity": "24",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "dns-external-1": {
      "shape": "circle",
      "name": "External DNS 1",
      "ip": "172.16.0.53",
      "role": "External DNS",
      "tags": [
        "dmz",
        "dns",
        "public"
      ],
      "notes": [
        "BIND DNS",
        "Authoritative for corp.com"
      ],
      "mac": "00:50:56:CC:05:01",
      "rackUnit": 12,
      "uHeight": "1",
      "layer": "security",
      "assignedRack": "dmz-rack",
      "rackCapacity": "24",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "dns-external-2": {
      "shape": "circle",
      "name": "External DNS 2",
      "ip": "172.16.0.54",
      "role": "External DNS",
      "tags": [
        "dmz",
        "dns",
        "public"
      ],
      "notes": [
        "BIND DNS",
        "Secondary for corp.com"
      ],
      "mac": "00:50:56:CC:05:02",
      "rackUnit": 10,
      "uHeight": "1",
      "layer": "security",
      "assignedRack": "dmz-rack",
      "rackCapacity": "24",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "vcenter": {
      "shape": "server",
      "name": "vCenter Server",
      "ip": "192.168.100.10",
      "role": "Virtualization Management",
      "tags": [
        "management",
        "vmware",
        "vcsa"
      ],
      "notes": [
        "vCenter Server Appliance 8.0",
        "Single SSO domain"
      ],
      "mac": "00:50:56:DD:01:01",
      "rackUnit": 20,
      "uHeight": "2",
      "layer": "logical",
      "assignedRack": "mgmt-rack",
      "rackCapacity": "24",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "nsx-manager": {
      "shape": "server",
      "name": "NSX Manager",
      "ip": "192.168.100.15",
      "role": "Network Virtualization",
      "tags": [
        "management",
        "vmware",
        "nsx"
      ],
      "notes": [
        "NSX-T 4.1 Manager Cluster"
      ],
      "mac": "00:50:56:DD:02:01",
      "rackUnit": 17,
      "uHeight": "2",
      "layer": "logical",
      "assignedRack": "mgmt-rack",
      "rackCapacity": "24",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "siem-server": {
      "shape": "server",
      "name": "SIEM Server",
      "ip": "192.168.100.50",
      "role": "Security Monitoring",
      "tags": [
        "management",
        "security",
        "splunk"
      ],
      "notes": [
        "Splunk Enterprise",
        "Security monitoring"
      ],
      "mac": "00:50:56:DD:03:01",
      "rackUnit": 14,
      "uHeight": "2",
      "layer": "logical",
      "assignedRack": "mgmt-rack",
      "rackCapacity": "24",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "nms-server": {
      "shape": "server",
      "name": "Network Monitoring",
      "ip": "192.168.100.60",
      "role": "Network Management",
      "tags": [
        "management",
        "monitoring",
        "prtg"
      ],
      "notes": [
        "PRTG Network Monitor",
        "5000 sensors"
      ],
      "mac": "00:50:56:DD:04:01",
      "rackUnit": 11,
      "uHeight": "1",
      "layer": "logical",
      "assignedRack": "mgmt-rack",
      "rackCapacity": "24",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "jump-server": {
      "shape": "server",
      "name": "Jump Server",
      "ip": "192.168.100.100",
      "role": "Bastion Host",
      "tags": [
        "management",
        "security",
        "bastion"
      ],
      "notes": [
        "Windows Server 2022",
        "MFA enabled"
      ],
      "mac": "00:50:56:DD:05:01",
      "rackUnit": 9,
      "uHeight": "1",
      "layer": "logical",
      "assignedRack": "mgmt-rack",
      "rackCapacity": "24",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "ipam-server": {
      "shape": "server",
      "name": "IPAM/DDI",
      "ip": "192.168.100.70",
      "role": "IP Management",
      "tags": [
        "management",
        "dns",
        "dhcp"
      ],
      "notes": [
        "Infoblox DDI",
        "DNS/DHCP/IPAM"
      ],
      "mac": "00:50:56:DD:06:01",
      "rackUnit": 7,
      "uHeight": "2",
      "layer": "logical",
      "assignedRack": "mgmt-rack",
      "rackCapacity": "24",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "wlc-primary": {
      "shape": "wifi",
      "name": "WLC Primary",
      "ip": "10.20.0.1",
      "role": "Wireless Controller",
      "tags": [
        "wireless",
        "cisco",
        "9800"
      ],
      "notes": [
        "Cisco C9800-40",
        "Primary controller"
      ],
      "mac": "00:1A:2B:WL:01:01",
      "rackUnit": "",
      "uHeight": "2",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "wlc-secondary": {
      "shape": "wifi",
      "name": "WLC Secondary",
      "ip": "10.20.0.2",
      "role": "Wireless Controller",
      "tags": [
        "wireless",
        "cisco",
        "9800"
      ],
      "notes": [
        "Cisco C9800-40",
        "HA Secondary"
      ],
      "mac": "00:1A:2B:WL:01:02",
      "rackUnit": "",
      "uHeight": "2",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "mobile-zone-hq": {
      "shape": "phone",
      "name": "HQ Mobile Zone",
      "ip": "10.20.10.0/24",
      "role": "Mobile Device Zone",
      "tags": [
        "wireless",
        "byod",
        "mobile"
      ],
      "notes": [
        "Corporate BYOD",
        "MDM enrolled devices"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "mobile-zone-guest": {
      "shape": "phone",
      "name": "Guest WiFi Zone",
      "ip": "10.30.0.0/24",
      "role": "Guest Network",
      "tags": [
        "wireless",
        "guest",
        "isolated"
      ],
      "notes": [
        "Captive portal",
        "Internet only"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "mobile-zone-iot": {
      "shape": "phone",
      "name": "IoT Device Zone",
      "ip": "10.40.0.0/24",
      "role": "IoT Network",
      "tags": [
        "wireless",
        "iot",
        "building"
      ],
      "notes": [
        "Building automation",
        "Smart devices"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "branch-router-ny": {
      "shape": "router",
      "name": "NYC Branch Router",
      "ip": "10.100.0.1",
      "role": "Branch Gateway",
      "tags": [
        "branch",
        "nyc",
        "sd-wan"
      ],
      "notes": [
        "Cisco Viptela vEdge",
        "SD-WAN enabled"
      ],
      "mac": "00:1A:2B:BR:01:01",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "branch-router-la": {
      "shape": "router",
      "name": "LA Branch Router",
      "ip": "10.101.0.1",
      "role": "Branch Gateway",
      "tags": [
        "branch",
        "la",
        "sd-wan"
      ],
      "notes": [
        "Cisco Viptela vEdge",
        "SD-WAN enabled"
      ],
      "mac": "00:1A:2B:BR:02:01",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "branch-router-chi": {
      "shape": "router",
      "name": "Chicago Branch Router",
      "ip": "10.102.0.1",
      "role": "Branch Gateway",
      "tags": [
        "branch",
        "chicago",
        "sd-wan"
      ],
      "notes": [
        "Cisco Viptela vEdge",
        "SD-WAN enabled"
      ],
      "mac": "00:1A:2B:BR:03:01",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "branch-router-lon": {
      "shape": "router",
      "name": "London Branch Router",
      "ip": "10.200.0.1",
      "role": "Branch Gateway",
      "tags": [
        "branch",
        "london",
        "sd-wan"
      ],
      "notes": [
        "Cisco Viptela vEdge",
        "EMEA region"
      ],
      "mac": "00:1A:2B:BR:04:01",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "branch-router-tokyo": {
      "shape": "router",
      "name": "Tokyo Branch Router",
      "ip": "10.201.0.1",
      "role": "Branch Gateway",
      "tags": [
        "branch",
        "tokyo",
        "sd-wan"
      ],
      "notes": [
        "Cisco Viptela vEdge",
        "APAC region"
      ],
      "mac": "00:1A:2B:BR:05:01",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "cloud-aws": {
      "shape": "cloud",
      "name": "AWS Cloud",
      "ip": "vpc-0a1b2c3d",
      "role": "Public Cloud",
      "tags": [
        "cloud",
        "aws",
        "hybrid"
      ],
      "notes": [
        "AWS US-East-1",
        "VPC peering to HQ"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "logical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "cloud-azure": {
      "shape": "cloud",
      "name": "Azure Cloud",
      "ip": "vnet-corp-prod",
      "role": "Public Cloud",
      "tags": [
        "cloud",
        "azure",
        "hybrid"
      ],
      "notes": [
        "Azure East US 2",
        "ExpressRoute"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "logical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "cloud-gcp": {
      "shape": "cloud",
      "name": "GCP Cloud",
      "ip": "vpc-gcp-corp",
      "role": "Public Cloud",
      "tags": [
        "cloud",
        "gcp",
        "dev"
      ],
      "notes": [
        "GCP us-central1",
        "Dev/Test workloads"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "logical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "isp-primary": {
      "shape": "globe",
      "name": "ISP Primary",
      "ip": "203.0.113.1",
      "role": "Internet Uplink",
      "tags": [
        "wan",
        "internet",
        "primary"
      ],
      "notes": [
        "AT&T MPLS",
        "1 Gbps dedicated"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "isp-secondary": {
      "shape": "globe",
      "name": "ISP Secondary",
      "ip": "198.51.100.1",
      "role": "Internet Uplink",
      "tags": [
        "wan",
        "internet",
        "backup"
      ],
      "notes": [
        "Verizon Business",
        "500 Mbps backup"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "dc-internal-1": {
      "shape": "circle",
      "name": "DC1 Int DNS",
      "ip": "10.10.0.53",
      "role": "Internal DNS/AD",
      "tags": [
        "dns",
        "ad",
        "dc1"
      ],
      "notes": [
        "Windows Server 2022",
        "Primary DC"
      ],
      "mac": "00:50:56:AD:01:01",
      "rackUnit": 26,
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "dc-rack-a1",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "dc-internal-2": {
      "shape": "circle",
      "name": "DC2 Int DNS",
      "ip": "10.10.1.53",
      "role": "Internal DNS/AD",
      "tags": [
        "dns",
        "ad",
        "dc2"
      ],
      "notes": [
        "Windows Server 2022",
        "Secondary DC"
      ],
      "mac": "00:50:56:AD:01:02",
      "rackUnit": 26,
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "dc-rack-a2",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "app-server-1": {
      "shape": "server",
      "name": "App Server 01",
      "ip": "10.10.0.101",
      "role": "Application",
      "tags": [
        "app",
        "iis",
        "web"
      ],
      "notes": [
        "Windows Server 2022",
        "IIS Application"
      ],
      "mac": "00:50:56:AP:01:01",
      "rackUnit": 24,
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "dc-rack-a1",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "app-server-2": {
      "shape": "server",
      "name": "App Server 02",
      "ip": "10.10.0.102",
      "role": "Application",
      "tags": [
        "app",
        "iis",
        "web"
      ],
      "notes": [
        "Windows Server 2022",
        "IIS Application"
      ],
      "mac": "00:50:56:AP:01:02",
      "rackUnit": 22,
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "dc-rack-a1",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "db-server-1": {
      "shape": "database",
      "name": "SQL Server 01",
      "ip": "10.10.0.201",
      "role": "Database",
      "tags": [
        "db",
        "sql",
        "primary"
      ],
      "notes": [
        "SQL Server 2022 Enterprise",
        "AlwaysOn Primary"
      ],
      "mac": "00:50:56:DB:01:01",
      "rackUnit": 20,
      "uHeight": "2",
      "layer": "physical",
      "assignedRack": "dc-rack-a1",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "db-server-2": {
      "shape": "database",
      "name": "SQL Server 02",
      "ip": "10.10.1.201",
      "role": "Database",
      "tags": [
        "db",
        "sql",
        "secondary"
      ],
      "notes": [
        "SQL Server 2022 Enterprise",
        "AlwaysOn Secondary"
      ],
      "mac": "00:50:56:DB:01:02",
      "rackUnit": 24,
      "uHeight": "2",
      "layer": "physical",
      "assignedRack": "dc-rack-a2",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "k8s-master-1": {
      "shape": "hexagon",
      "name": "K8s Master 1",
      "ip": "10.10.1.50",
      "role": "Container Orchestration",
      "tags": [
        "kubernetes",
        "master",
        "container"
      ],
      "notes": [
        "K8s Control Plane",
        "etcd member"
      ],
      "mac": "00:50:56:K8:01:01",
      "rackUnit": 21,
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "dc-rack-a2",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "k8s-master-2": {
      "shape": "hexagon",
      "name": "K8s Master 2",
      "ip": "10.10.1.51",
      "role": "Container Orchestration",
      "tags": [
        "kubernetes",
        "master",
        "container"
      ],
      "notes": [
        "K8s Control Plane",
        "etcd member"
      ],
      "mac": "00:50:56:K8:01:02",
      "rackUnit": 19,
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "dc-rack-a2",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "k8s-master-3": {
      "shape": "hexagon",
      "name": "K8s Master 3",
      "ip": "10.10.1.52",
      "role": "Container Orchestration",
      "tags": [
        "kubernetes",
        "master",
        "container"
      ],
      "notes": [
        "K8s Control Plane",
        "etcd member"
      ],
      "mac": "00:50:56:K8:01:03",
      "rackUnit": 17,
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "dc-rack-a2",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "k8s-worker-1": {
      "shape": "server",
      "name": "K8s Worker 1",
      "ip": "10.10.1.60",
      "role": "Container Workload",
      "tags": [
        "kubernetes",
        "worker",
        "container"
      ],
      "notes": [
        "K8s Worker Node",
        "64GB RAM"
      ],
      "mac": "00:50:56:K8:02:01",
      "rackUnit": 15,
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "dc-rack-a2",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "k8s-worker-2": {
      "shape": "server",
      "name": "K8s Worker 2",
      "ip": "10.10.1.61",
      "role": "Container Workload",
      "tags": [
        "kubernetes",
        "worker",
        "container"
      ],
      "notes": [
        "K8s Worker Node",
        "64GB RAM"
      ],
      "mac": "00:50:56:K8:02:02",
      "rackUnit": 13,
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "dc-rack-a2",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "k8s-worker-3": {
      "shape": "server",
      "name": "K8s Worker 3",
      "ip": "10.10.1.62",
      "role": "Container Workload",
      "tags": [
        "kubernetes",
        "worker",
        "container"
      ],
      "notes": [
        "K8s Worker Node",
        "64GB RAM"
      ],
      "mac": "00:50:56:K8:02:03",
      "rackUnit": 11,
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "dc-rack-a2",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "k8s-worker-4": {
      "shape": "server",
      "name": "K8s Worker 4",
      "ip": "10.10.1.63",
      "role": "Container Workload",
      "tags": [
        "kubernetes",
        "worker",
        "container"
      ],
      "notes": [
        "K8s Worker Node",
        "64GB RAM"
      ],
      "mac": "00:50:56:K8:02:04",
      "rackUnit": 9,
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "dc-rack-a2",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "proxy-server-1": {
      "shape": "server",
      "name": "Proxy Server 1",
      "ip": "10.5.0.10",
      "role": "Web Proxy",
      "tags": [
        "proxy",
        "squid",
        "filtering"
      ],
      "notes": [
        "Squid Proxy",
        "Content filtering"
      ],
      "mac": "00:50:56:PX:01:01",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "security",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "proxy-server-2": {
      "shape": "server",
      "name": "Proxy Server 2",
      "ip": "10.5.0.11",
      "role": "Web Proxy",
      "tags": [
        "proxy",
        "squid",
        "filtering"
      ],
      "notes": [
        "Squid Proxy",
        "HA pair"
      ],
      "mac": "00:50:56:PX:01:02",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "security",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "vpn-concentrator": {
      "shape": "firewall",
      "name": "VPN Concentrator",
      "ip": "10.0.5.1",
      "role": "Remote Access VPN",
      "tags": [
        "vpn",
        "remote",
        "security"
      ],
      "notes": [
        "Cisco ASA 5555-X",
        "AnyConnect SSL VPN"
      ],
      "mac": "00:1A:2B:VP:01:01",
      "rackUnit": "",
      "uHeight": "2",
      "layer": "security",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "nac-server": {
      "shape": "server",
      "name": "NAC Server",
      "ip": "10.5.5.10",
      "role": "Network Access Control",
      "tags": [
        "nac",
        "ise",
        "802.1x"
      ],
      "notes": [
        "Cisco ISE 3.1",
        "RADIUS/TACACS+"
      ],
      "mac": "00:50:56:NA:01:01",
      "rackUnit": "",
      "uHeight": "2",
      "layer": "security",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "print-server": {
      "shape": "server",
      "name": "Print Server",
      "ip": "10.10.0.150",
      "role": "Print Services",
      "tags": [
        "print",
        "windows",
        "services"
      ],
      "notes": [
        "Windows Print Server",
        "50+ printers"
      ],
      "mac": "00:50:56:PR:01:01",
      "rackUnit": 18,
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "dc-rack-a1",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "file-server": {
      "shape": "database",
      "name": "File Server",
      "ip": "10.10.0.160",
      "role": "File Services",
      "tags": [
        "file",
        "smb",
        "dfs"
      ],
      "notes": [
        "Windows File Server",
        "DFS namespace"
      ],
      "mac": "00:50:56:FS:01:01",
      "rackUnit": 16,
      "uHeight": "2",
      "layer": "physical",
      "assignedRack": "dc-rack-a1",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "ca-server": {
      "shape": "server",
      "name": "Certificate Authority",
      "ip": "192.168.100.80",
      "role": "PKI Infrastructure",
      "tags": [
        "pki",
        "ca",
        "security"
      ],
      "notes": [
        "Windows CA",
        "Enterprise Root CA"
      ],
      "mac": "00:50:56:CA:01:01",
      "rackUnit": 5,
      "uHeight": "1",
      "layer": "logical",
      "assignedRack": "mgmt-rack",
      "rackCapacity": "24",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "sccm-server": {
      "shape": "server",
      "name": "SCCM Server",
      "ip": "192.168.100.90",
      "role": "Endpoint Management",
      "tags": [
        "sccm",
        "patching",
        "software"
      ],
      "notes": [
        "MECM Primary Site",
        "Software deployment"
      ],
      "mac": "00:50:56:SC:01:01",
      "rackUnit": 3,
      "uHeight": "2",
      "layer": "logical",
      "assignedRack": "mgmt-rack",
      "rackCapacity": "24",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "voip-cluster": {
      "shape": "phone",
      "name": "VoIP Cluster",
      "ip": "10.50.0.0/24",
      "role": "Voice Services",
      "tags": [
        "voip",
        "cisco",
        "ucm"
      ],
      "notes": [
        "Cisco UCM Cluster",
        "3000 endpoints"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "application",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "video-conf": {
      "shape": "laptop",
      "name": "Video Conference",
      "ip": "10.51.0.0/24",
      "role": "Video Services",
      "tags": [
        "video",
        "webex",
        "teams"
      ],
      "notes": [
        "Webex/Teams integration",
        "Meeting rooms"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "application",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "security-cameras": {
      "shape": "camera",
      "name": "Security Cameras",
      "ip": "10.60.0.0/24",
      "role": "Physical Security",
      "tags": [
        "cctv",
        "surveillance",
        "security"
      ],
      "notes": [
        "150+ IP cameras",
        "30-day retention"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "nvr-cluster": {
      "shape": "server",
      "name": "NVR Cluster",
      "ip": "10.60.0.10",
      "role": "Video Recording",
      "tags": [
        "nvr",
        "surveillance",
        "storage"
      ],
      "notes": [
        "Milestone XProtect",
        "500TB storage"
      ],
      "mac": "00:50:56:NV:01:01",
      "rackUnit": 15,
      "uHeight": "4",
      "layer": "physical",
      "assignedRack": "dc-rack-b2",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "dev-server-1": {
      "shape": "server",
      "name": "Dev Server 1",
      "ip": "10.80.0.10",
      "role": "Development",
      "tags": [
        "dev",
        "gitlab",
        "ci-cd"
      ],
      "notes": [
        "GitLab Server",
        "CI/CD pipelines"
      ],
      "mac": "00:50:56:DV:01:01",
      "rackUnit": "",
      "uHeight": "2",
      "layer": "application",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "dev-server-2": {
      "shape": "server",
      "name": "Dev Server 2",
      "ip": "10.80.0.11",
      "role": "Development",
      "tags": [
        "dev",
        "jenkins",
        "ci-cd"
      ],
      "notes": [
        "Jenkins Server",
        "Build automation"
      ],
      "mac": "00:50:56:DV:01:02",
      "rackUnit": "",
      "uHeight": "2",
      "layer": "application",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "test-environment": {
      "shape": "hexagon",
      "name": "Test Environment",
      "ip": "10.81.0.0/24",
      "role": "QA/Testing",
      "tags": [
        "test",
        "qa",
        "staging"
      ],
      "notes": [
        "Staging environment",
        "Pre-prod validation"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "application",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "erp-system": {
      "shape": "database",
      "name": "ERP System",
      "ip": "10.90.0.10",
      "role": "Business Application",
      "tags": [
        "erp",
        "sap",
        "business"
      ],
      "notes": [
        "SAP S/4HANA",
        "Financial/HR systems"
      ],
      "mac": "00:50:56:ER:01:01",
      "rackUnit": "",
      "uHeight": "4",
      "layer": "application",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "crm-system": {
      "shape": "database",
      "name": "CRM System",
      "ip": "10.91.0.10",
      "role": "Business Application",
      "tags": [
        "crm",
        "salesforce",
        "business"
      ],
      "notes": [
        "Salesforce integration",
        "Sales/Marketing"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "application",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "endpoint-1000": {
      "shape": "laptop",
      "name": "Corporate Endpoints",
      "ip": "10.70.0.0/22",
      "role": "User Workstations",
      "tags": [
        "endpoints",
        "workstations",
        "users"
      ],
      "notes": [
        "~1000 corporate laptops",
        "Windows 11"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "dist-switch-floor1": {
      "shape": "switch",
      "name": "Floor 1 Switch",
      "ip": "10.1.1.1",
      "role": "Distribution",
      "tags": [
        "distribution",
        "floor-1",
        "access"
      ],
      "notes": [
        "Cisco C9300-48P",
        "PoE+ enabled"
      ],
      "mac": "00:1A:2B:FL:01:01",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "dist-switch-floor2": {
      "shape": "switch",
      "name": "Floor 2 Switch",
      "ip": "10.1.2.1",
      "role": "Distribution",
      "tags": [
        "distribution",
        "floor-2",
        "access"
      ],
      "notes": [
        "Cisco C9300-48P",
        "PoE+ enabled"
      ],
      "mac": "00:1A:2B:FL:02:01",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "dist-switch-floor3": {
      "shape": "switch",
      "name": "Floor 3 Switch",
      "ip": "10.1.3.1",
      "role": "Distribution",
      "tags": [
        "distribution",
        "floor-3",
        "access"
      ],
      "notes": [
        "Cisco C9300-48P",
        "PoE+ enabled"
      ],
      "mac": "00:1A:2B:FL:03:01",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "dist-switch-floor4": {
      "shape": "switch",
      "name": "Floor 4 Switch",
      "ip": "10.1.4.1",
      "role": "Distribution",
      "tags": [
        "distribution",
        "floor-4",
        "access"
      ],
      "notes": [
        "Cisco C9300-48P",
        "PoE+ enabled"
      ],
      "mac": "00:1A:2B:FL:04:01",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "ap-floor1-zone1": {
      "shape": "wifi",
      "name": "AP Floor 1 Zone 1",
      "ip": "10.20.1.10",
      "role": "Wireless Access",
      "tags": [
        "wifi",
        "ap",
        "floor-1"
      ],
      "notes": [
        "Cisco 9120AX",
        "Wi-Fi 6"
      ],
      "mac": "00:1A:2B:AP:01:01",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "ap-floor2-zone1": {
      "shape": "wifi",
      "name": "AP Floor 2 Zone 1",
      "ip": "10.20.2.10",
      "role": "Wireless Access",
      "tags": [
        "wifi",
        "ap",
        "floor-2"
      ],
      "notes": [
        "Cisco 9120AX",
        "Wi-Fi 6"
      ],
      "mac": "00:1A:2B:AP:02:01",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "ap-floor3-zone1": {
      "shape": "wifi",
      "name": "AP Floor 3 Zone 1",
      "ip": "10.20.3.10",
      "role": "Wireless Access",
      "tags": [
        "wifi",
        "ap",
        "floor-3"
      ],
      "notes": [
        "Cisco 9120AX",
        "Wi-Fi 6"
      ],
      "mac": "00:1A:2B:AP:03:01",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "ap-floor4-zone1": {
      "shape": "wifi",
      "name": "AP Floor 4 Zone 1",
      "ip": "10.20.4.10",
      "role": "Wireless Access",
      "tags": [
        "wifi",
        "ap",
        "floor-4"
      ],
      "notes": [
        "Cisco 9120AX",
        "Wi-Fi 6"
      ],
      "mac": "00:1A:2B:AP:04:01",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "ups-dc-1": {
      "shape": "rectangle",
      "name": "UPS DC-1",
      "ip": "192.168.200.10",
      "role": "Power Management",
      "tags": [
        "power",
        "ups",
        "datacenter"
      ],
      "notes": [
        "APC Symmetra",
        "80kVA",
        "30 min runtime"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "ups-dc-2": {
      "shape": "rectangle",
      "name": "UPS DC-2",
      "ip": "192.168.200.11",
      "role": "Power Management",
      "tags": [
        "power",
        "ups",
        "datacenter"
      ],
      "notes": [
        "APC Symmetra",
        "80kVA",
        "Redundant"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "pdu-rack-a1": {
      "shape": "rectangle",
      "name": "PDU Rack A1",
      "ip": "192.168.200.21",
      "role": "Power Distribution",
      "tags": [
        "power",
        "pdu",
        "rack-a1"
      ],
      "notes": [
        "APC Switched PDU",
        "Per-outlet metering"
      ],
      "mac": "",
      "rackUnit": 1,
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "dc-rack-a1",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "pdu-rack-a2": {
      "shape": "rectangle",
      "name": "PDU Rack A2",
      "ip": "192.168.200.22",
      "role": "Power Distribution",
      "tags": [
        "power",
        "pdu",
        "rack-a2"
      ],
      "notes": [
        "APC Switched PDU",
        "Per-outlet metering"
      ],
      "mac": "",
      "rackUnit": 1,
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "dc-rack-a2",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "cooling-1": {
      "shape": "rectangle",
      "name": "CRAC Unit 1",
      "ip": "192.168.200.30",
      "role": "Cooling",
      "tags": [
        "cooling",
        "hvac",
        "datacenter"
      ],
      "notes": [
        "Liebert CRV",
        "Row-based cooling"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    },
    "cooling-2": {
      "shape": "rectangle",
      "name": "CRAC Unit 2",
      "ip": "192.168.200.31",
      "role": "Cooling",
      "tags": [
        "cooling",
        "hvac",
        "datacenter"
      ],
      "notes": [
        "Liebert CRV",
        "N+1 redundancy"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "physical",
      "assignedRack": "",
      "rackCapacity": "42",
      "isRack": false,
      "locked": false,
      "groupId": null
    }
  },
  "edgeData": {
    "list": [
      {
        "id": "isp1-router1",
        "from": "isp-primary",
        "to": "core-router-1",
        "width": 6,
        "color": "#10b981",
        "direction": "both",
        "type": "main",
        "notes": [
          "Primary WAN link"
        ],
        "fromPort": "Gi0/0",
        "toPort": "Gi1/0/1",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "isp2-router2",
        "from": "isp-secondary",
        "to": "core-router-2",
        "width": 6,
        "color": "#10b981",
        "direction": "both",
        "type": "main",
        "notes": [
          "Backup WAN link"
        ],
        "fromPort": "Gi0/0",
        "toPort": "Gi1/0/1",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "router1-router2",
        "from": "core-router-1",
        "to": "core-router-2",
        "width": 4,
        "color": "#f59e0b",
        "direction": "both",
        "type": "main",
        "notes": [
          "HSRP Peering"
        ],
        "fromPort": "Gi1/0/24",
        "toPort": "Gi1/0/24",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "router1-fw1",
        "from": "core-router-1",
        "to": "fw-external-1",
        "width": 4,
        "color": "#ef4444",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "router2-fw2",
        "from": "core-router-2",
        "to": "fw-external-2",
        "width": 4,
        "color": "#ef4444",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "fw1-fw2",
        "from": "fw-external-1",
        "to": "fw-external-2",
        "width": 3,
        "color": "#f59e0b",
        "direction": "both",
        "type": "main",
        "notes": [
          "HA heartbeat"
        ],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dashed",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "fw1-coresw1",
        "from": "fw-external-1",
        "to": "core-switch-1",
        "width": 4,
        "color": "#475569",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "fw2-coresw2",
        "from": "fw-external-2",
        "to": "core-switch-2",
        "width": 4,
        "color": "#475569",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw1-coresw2",
        "from": "core-switch-1",
        "to": "core-switch-2",
        "width": 5,
        "color": "#3b82f6",
        "direction": "both",
        "type": "main",
        "notes": [
          "VPC peer-link"
        ],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw1-fwint",
        "from": "core-switch-1",
        "to": "fw-internal",
        "width": 3,
        "color": "#ef4444",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw2-fwint",
        "from": "core-switch-2",
        "to": "fw-internal",
        "width": 3,
        "color": "#ef4444",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw1-racka1",
        "from": "core-switch-1",
        "to": "dc-rack-a1",
        "width": 4,
        "color": "#475569",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw2-racka1",
        "from": "core-switch-2",
        "to": "dc-rack-a1",
        "width": 4,
        "color": "#475569",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw1-racka2",
        "from": "core-switch-1",
        "to": "dc-rack-a2",
        "width": 4,
        "color": "#475569",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw2-racka2",
        "from": "core-switch-2",
        "to": "dc-rack-a2",
        "width": 4,
        "color": "#475569",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw1-rackb1",
        "from": "core-switch-1",
        "to": "dc-rack-b1",
        "width": 4,
        "color": "#475569",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw2-rackb1",
        "from": "core-switch-2",
        "to": "dc-rack-b1",
        "width": 4,
        "color": "#475569",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw1-rackb2",
        "from": "core-switch-1",
        "to": "dc-rack-b2",
        "width": 4,
        "color": "#475569",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw2-rackb2",
        "from": "core-switch-2",
        "to": "dc-rack-b2",
        "width": 4,
        "color": "#475569",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "fw1-dmz",
        "from": "fw-external-1",
        "to": "dmz-rack",
        "width": 3,
        "color": "#f59e0b",
        "direction": "both",
        "type": "main",
        "notes": [
          "DMZ segment"
        ],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "fw2-dmz",
        "from": "fw-external-2",
        "to": "dmz-rack",
        "width": 3,
        "color": "#f59e0b",
        "direction": "both",
        "type": "main",
        "notes": [
          "DMZ segment"
        ],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw1-mgmt",
        "from": "core-switch-1",
        "to": "mgmt-rack",
        "width": 3,
        "color": "#8b5cf6",
        "direction": "both",
        "type": "main",
        "notes": [
          "OOB management"
        ],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw1-wlc1",
        "from": "core-switch-1",
        "to": "wlc-primary",
        "width": 3,
        "color": "#06b6d4",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw2-wlc2",
        "from": "core-switch-2",
        "to": "wlc-secondary",
        "width": 3,
        "color": "#06b6d4",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "wlc1-wlc2",
        "from": "wlc-primary",
        "to": "wlc-secondary",
        "width": 2,
        "color": "#f59e0b",
        "direction": "both",
        "type": "main",
        "notes": [
          "HA pair"
        ],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dashed",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "wlc1-mobile-hq",
        "from": "wlc-primary",
        "to": "mobile-zone-hq",
        "width": 2,
        "color": "#06b6d4",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "wlc1-mobile-guest",
        "from": "wlc-primary",
        "to": "mobile-zone-guest",
        "width": 2,
        "color": "#06b6d4",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "wlc1-mobile-iot",
        "from": "wlc-primary",
        "to": "mobile-zone-iot",
        "width": 2,
        "color": "#06b6d4",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "router1-branch-ny",
        "from": "core-router-1",
        "to": "branch-router-ny",
        "width": 3,
        "color": "#a855f7",
        "direction": "both",
        "type": "main",
        "notes": [
          "SD-WAN tunnel"
        ],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dashed",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "router1-branch-la",
        "from": "core-router-1",
        "to": "branch-router-la",
        "width": 3,
        "color": "#a855f7",
        "direction": "both",
        "type": "main",
        "notes": [
          "SD-WAN tunnel"
        ],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dashed",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "router1-branch-chi",
        "from": "core-router-1",
        "to": "branch-router-chi",
        "width": 3,
        "color": "#a855f7",
        "direction": "both",
        "type": "main",
        "notes": [
          "SD-WAN tunnel"
        ],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dashed",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "router1-branch-lon",
        "from": "core-router-1",
        "to": "branch-router-lon",
        "width": 3,
        "color": "#a855f7",
        "direction": "both",
        "type": "main",
        "notes": [
          "SD-WAN tunnel"
        ],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dashed",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "router1-branch-tokyo",
        "from": "core-router-1",
        "to": "branch-router-tokyo",
        "width": 3,
        "color": "#a855f7",
        "direction": "both",
        "type": "main",
        "notes": [
          "SD-WAN tunnel"
        ],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dashed",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "router1-aws",
        "from": "core-router-1",
        "to": "cloud-aws",
        "width": 3,
        "color": "#f97316",
        "direction": "both",
        "type": "main",
        "notes": [
          "Direct Connect"
        ],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dashed",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "router2-azure",
        "from": "core-router-2",
        "to": "cloud-azure",
        "width": 3,
        "color": "#0ea5e9",
        "direction": "both",
        "type": "main",
        "notes": [
          "ExpressRoute"
        ],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dashed",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "fwint-gcp",
        "from": "fw-internal",
        "to": "cloud-gcp",
        "width": 2,
        "color": "#22c55e",
        "direction": "both",
        "type": "main",
        "notes": [
          "VPN tunnel"
        ],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dashed",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw1-floor1",
        "from": "core-switch-1",
        "to": "dist-switch-floor1",
        "width": 3,
        "color": "#475569",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw1-floor2",
        "from": "core-switch-1",
        "to": "dist-switch-floor2",
        "width": 3,
        "color": "#475569",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw2-floor3",
        "from": "core-switch-2",
        "to": "dist-switch-floor3",
        "width": 3,
        "color": "#475569",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw2-floor4",
        "from": "core-switch-2",
        "to": "dist-switch-floor4",
        "width": 3,
        "color": "#475569",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "floor1-endpoints",
        "from": "dist-switch-floor1",
        "to": "endpoint-1000",
        "width": 2,
        "color": "#94a3b8",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "floor1-ap1",
        "from": "dist-switch-floor1",
        "to": "ap-floor1-zone1",
        "width": 2,
        "color": "#06b6d4",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "floor2-ap2",
        "from": "dist-switch-floor2",
        "to": "ap-floor2-zone1",
        "width": 2,
        "color": "#06b6d4",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "floor3-ap3",
        "from": "dist-switch-floor3",
        "to": "ap-floor3-zone1",
        "width": 2,
        "color": "#06b6d4",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "floor4-ap4",
        "from": "dist-switch-floor4",
        "to": "ap-floor4-zone1",
        "width": 2,
        "color": "#06b6d4",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "fwint-proxy1",
        "from": "fw-internal",
        "to": "proxy-server-1",
        "width": 2,
        "color": "#ef4444",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "fwint-proxy2",
        "from": "fw-internal",
        "to": "proxy-server-2",
        "width": 2,
        "color": "#ef4444",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "fwext1-vpn",
        "from": "fw-external-1",
        "to": "vpn-concentrator",
        "width": 3,
        "color": "#8b5cf6",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw1-nac",
        "from": "core-switch-1",
        "to": "nac-server",
        "width": 2,
        "color": "#f59e0b",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw1-voip",
        "from": "core-switch-1",
        "to": "voip-cluster",
        "width": 3,
        "color": "#22c55e",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw2-video",
        "from": "core-switch-2",
        "to": "video-conf",
        "width": 3,
        "color": "#22c55e",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw1-cameras",
        "from": "core-switch-1",
        "to": "security-cameras",
        "width": 2,
        "color": "#94a3b8",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "fwint-dev1",
        "from": "fw-internal",
        "to": "dev-server-1",
        "width": 2,
        "color": "#a855f7",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "fwint-dev2",
        "from": "fw-internal",
        "to": "dev-server-2",
        "width": 2,
        "color": "#a855f7",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "fwint-test",
        "from": "fw-internal",
        "to": "test-environment",
        "width": 2,
        "color": "#a855f7",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "coresw1-erp",
        "from": "core-switch-1",
        "to": "erp-system",
        "width": 3,
        "color": "#f59e0b",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "fwext1-crm",
        "from": "fw-external-1",
        "to": "crm-system",
        "width": 2,
        "color": "#f59e0b",
        "direction": "both",
        "type": "main",
        "notes": [
          "Salesforce cloud"
        ],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dashed",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "ups1-racka1",
        "from": "ups-dc-1",
        "to": "dc-rack-a1",
        "width": 2,
        "color": "#fbbf24",
        "direction": "forward",
        "type": "main",
        "notes": [
          "Power feed A"
        ],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "ups2-racka2",
        "from": "ups-dc-2",
        "to": "dc-rack-a2",
        "width": 2,
        "color": "#fbbf24",
        "direction": "forward",
        "type": "main",
        "notes": [
          "Power feed B"
        ],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "ups1-rackb1",
        "from": "ups-dc-1",
        "to": "dc-rack-b1",
        "width": 2,
        "color": "#fbbf24",
        "direction": "forward",
        "type": "main",
        "notes": [
          "Power feed A"
        ],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "ups2-rackb2",
        "from": "ups-dc-2",
        "to": "dc-rack-b2",
        "width": 2,
        "color": "#fbbf24",
        "direction": "forward",
        "type": "main",
        "notes": [
          "Power feed B"
        ],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "cooling1-racka1",
        "from": "cooling-1",
        "to": "dc-rack-a1",
        "width": 2,
        "color": "#38bdf8",
        "direction": "forward",
        "type": "main",
        "notes": [
          "Cooling zone"
        ],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dotted",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "cooling2-rackb1",
        "from": "cooling-2",
        "to": "dc-rack-b1",
        "width": 2,
        "color": "#38bdf8",
        "direction": "forward",
        "type": "main",
        "notes": [
          "Cooling zone"
        ],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dotted",
        "_pairIndex": 0,
        "_pairTotal": 1,
        "routing": "orthogonal"
      },
      {
        "id": "custom-1765237881452",
        "type": "custom",
        "color": "#c800ff",
        "width": 4,
        "lineStyle": "solid",
        "direction": "forward",
        "points": [
          {
            "x": 3492.3994140625,
            "y": 1526.9556884765625
          },
          {
            "x": 3500.609619140625,
            "y": 1830.7386474609375
          },
          {
            "x": 3303.561279296875,
            "y": 1732.2144775390625
          }
        ],
        "notes": [],
        "routing": "orthogonal"
      }
    ]
  },
  "rectData": {
    "list": [
      {
        "id": "rect-1765237540610",
        "x": 2879.214599609375,
        "y": 159.71981811523438,
        "width": 992.196044921875,
        "height": 538.8650817871094,
        "color": "#f97316",
        "style": "filled",
        "lineStyle": "solid",
        "notes": []
      },
      {
        "id": "rect-1765237681216",
        "x": 448.3926696777344,
        "y": 1671.651123046875,
        "width": 916.3436584472656,
        "height": 924.27734375,
        "color": "#c800ff",
        "style": "outlined",
        "lineStyle": "solid",
        "notes": []
      }
    ]
  },
  "textData": {
    "list": [
      {
        "id": "text-1765237828167",
        "x": 3411.458740234375,
        "y": 1390.00439453125,
        "content": "Double click on desktop\nor long press on mobile\nto enter rack canvas view",
        "fontSize": 46,
        "color": "#e2e8f0",
        "fontWeight": "bold",
        "fontStyle": "italic",
        "textAlign": "middle",
        "textDecoration": "none",
        "bgColor": "#000000",
        "bgEnabled": false,
        "opacity": 1
      }
    ]
  },
  "edgeLegend": {
    "#10b981": "Trusted Lan",
    "#f59e0b": "Secure Lan",
    "#ef4444": "DMZ",
    "#475569": "Main ISP",
    "#3b82f6": "Alternate ISP",
    "#8b5cf6": "you can edit me too",
    "#06b6d4": "you can edit me too",
    "#a855f7": "you can edit me too",
    "#f97316": "you can edit me too",
    "#0ea5e9": "you can edit me too",
    "#22c55e": "you can edit me too",
    "#94a3b8": "you can edit me too",
    "#fbbf24": "you can edit me too",
    "#38bdf8": "you can edit me too",
    "#c800ff": "you can edit me too"
  },
  "nodePositions": {
    "core-router-1": {
      "x": 3720.166015625,
      "y": 245.9932403564453
    },
    "core-router-2": {
      "x": 2369.521102950803,
      "y": 215.57717236541498
    },
    "fw-external-1": {
      "x": 3221.7385182723783,
      "y": 1016.1364499992887
    },
    "fw-external-2": {
      "x": 1915.5213706410505,
      "y": 224.43528858865443
    },
    "fw-internal": {
      "x": 1746.9168185079352,
      "y": 477.5300527221864
    },
    "core-switch-1": {
      "x": 766.6909650929942,
      "y": 886.9286044043477
    },
    "core-switch-2": {
      "x": 1117.6501957527485,
      "y": 192.60411230209093
    },
    "dc-rack-a1": {
      "x": 527.2319059976107,
      "y": 1064.1709551070026
    },
    "dc-rack-a2": {
      "x": 284.2645846419273,
      "y": 199.327180682807
    },
    "dc-rack-b1": {
      "x": 3210.0403422634854,
      "y": 1676.0346361105321
    },
    "dc-rack-b2": {
      "x": 268.9195483475687,
      "y": 951.7132426303456
    },
    "dmz-rack": {
      "x": 2222.5242984873507,
      "y": 603.145536695888
    },
    "mgmt-rack": {
      "x": 1601.2987201807314,
      "y": 1281.4753424975324
    },
    "esxi-host-01": {
      "x": 2162.2166789540615,
      "y": 2608.110619289529
    },
    "esxi-host-02": {
      "x": 2205.94717202368,
      "y": 2689.67539624076
    },
    "esxi-host-03": {
      "x": 2154.6015436939074,
      "y": 2771.203009774913
    },
    "esxi-host-04": {
      "x": 2195.986926025096,
      "y": 2845
    },
    "tor-switch-a1": {
      "x": 2146.8943639962963,
      "y": 2845
    },
    "esxi-host-05": {
      "x": 2185.9099961569727,
      "y": 2845
    },
    "esxi-host-06": {
      "x": 2139.099728450725,
      "y": 2845
    },
    "esxi-host-07": {
      "x": 2175.7223818764883,
      "y": 2845
    },
    "esxi-host-08": {
      "x": 2131.2222777148922,
      "y": 2845
    },
    "tor-switch-a2": {
      "x": 2165.4301485385085,
      "y": 2845
    },
    "san-primary": {
      "x": 2123.2667017518106,
      "y": 2845
    },
    "san-secondary": {
      "x": 2155.0394237844876,
      "y": 2845
    },
    "fc-switch-1": {
      "x": 2115.2377370375634,
      "y": 2845
    },
    "fc-switch-2": {
      "x": 2144.5563938942755,
      "y": 2845
    },
    "backup-server-1": {
      "x": 2107.1401637413705,
      "y": 2845
    },
    "backup-server-2": {
      "x": 2133.987300103025,
      "y": 2845
    },
    "tape-library": {
      "x": 2098.9788028796397,
      "y": 2845
    },
    "tor-switch-b1": {
      "x": 2123.338434885373,
      "y": 2845
    },
    "tor-switch-b2": {
      "x": 2090.7585134456995,
      "y": 2845
    },
    "web-server-1": {
      "x": 2112.6161382091163,
      "y": 2845
    },
    "web-server-2": {
      "x": 2082.484189516922,
      "y": 2845
    },
    "waf-1": {
      "x": 2101.826793760617,
      "y": 2845
    },
    "load-balancer-dmz": {
      "x": 2074.1607573409574,
      "y": 2845
    },
    "mail-gateway": {
      "x": 2090.97682514417,
      "y": 2845
    },
    "dns-external-1": {
      "x": 2065.7931724028163,
      "y": 2845
    },
    "dns-external-2": {
      "x": 2080.0726920576153,
      "y": 2845
    },
    "vcenter": {
      "x": 2057.3864164745437,
      "y": 2845
    },
    "nsx-manager": {
      "x": 2069.1208864464534,
      "y": 2845
    },
    "siem-server": {
      "x": 2048.945494649244,
      "y": 2845
    },
    "nms-server": {
      "x": 2058.1279286387635,
      "y": 2845
    },
    "jump-server": {
      "x": 2040.4754323612206,
      "y": 2845
    },
    "ipam-server": {
      "x": 2047.1003634632284,
      "y": 2845
    },
    "wlc-primary": {
      "x": 1575.9723612611924,
      "y": 2306.135986328125
    },
    "wlc-secondary": {
      "x": 1468.1361870166274,
      "y": 1563.733642578125
    },
    "mobile-zone-hq": {
      "x": 2354.901177346808,
      "y": 2806.0078125
    },
    "mobile-zone-guest": {
      "x": 2307.6605605284435,
      "y": 2611.047119140625
    },
    "mobile-zone-iot": {
      "x": 2229.397686389302,
      "y": 2299.110107421875
    },
    "branch-router-ny": {
      "x": 3146.779566207714,
      "y": 633.6580810546875
    },
    "branch-router-la": {
      "x": 3083.8876194705945,
      "y": 506.90625
    },
    "branch-router-chi": {
      "x": 3355.02409980103,
      "y": 393.1805725097656
    },
    "branch-router-lon": {
      "x": 3113.609823320121,
      "y": 260.4093322753906
    },
    "branch-router-tokyo": {
      "x": 3699.3234994733834,
      "y": 471.4241027832031
    },
    "cloud-aws": {
      "x": 3439.090134242263,
      "y": 548.5233154296875
    },
    "cloud-azure": {
      "x": 2592.566210818907,
      "y": 2724.068115234375
    },
    "cloud-gcp": {
      "x": 2827.3183770424234,
      "y": 2731.397216796875
    },
    "isp-primary": {
      "x": 3712.192068081962,
      "y": 618.2117919921875
    },
    "isp-secondary": {
      "x": 2574.2854713754305,
      "y": 403.8440856933594
    },
    "dc-internal-1": {
      "x": 1958.4243458877936,
      "y": 2845
    },
    "dc-internal-2": {
      "x": 1963.768951182132,
      "y": 2845
    },
    "app-server-1": {
      "x": 1947.3819379304134,
      "y": 2845
    },
    "app-server-2": {
      "x": 1955.2862087394126,
      "y": 2845
    },
    "db-server-1": {
      "x": 1936.3708569559828,
      "y": 2845
    },
    "db-server-2": {
      "x": 1946.8300873488822,
      "y": 2845
    },
    "k8s-master-1": {
      "x": 1925.397658583093,
      "y": 2845
    },
    "k8s-master-2": {
      "x": 1938.405621494142,
      "y": 2845
    },
    "k8s-master-3": {
      "x": 1914.4688758763386,
      "y": 2845
    },
    "k8s-worker-1": {
      "x": 1930.017826812177,
      "y": 2845
    },
    "k8s-worker-2": {
      "x": 1903.5910154567553,
      "y": 2845
    },
    "k8s-worker-3": {
      "x": 1921.6716971072178,
      "y": 2845
    },
    "k8s-worker-4": {
      "x": 1892.7705536280016,
      "y": 2845
    },
    "proxy-server-1": {
      "x": 1806.1152433697903,
      "y": 653.7529296875
    },
    "proxy-server-2": {
      "x": 2937.4207928721535,
      "y": 2628.7880859375
    },
    "vpn-concentrator": {
      "x": 3642.252088474593,
      "y": 946.7255249023438
    },
    "nac-server": {
      "x": 1153.2626148502184,
      "y": 1172.1895751953125
    },
    "print-server": {
      "x": 1896.9328460745962,
      "y": 2845
    },
    "file-server": {
      "x": 1860.7177871362182,
      "y": 2845
    },
    "ca-server": {
      "x": 1888.8027739274805,
      "y": 2845
    },
    "sccm-server": {
      "x": 1850.1909418511675,
      "y": 2845
    },
    "voip-cluster": {
      "x": 1777.038465328039,
      "y": 1616.8961181640625
    },
    "video-conf": {
      "x": 1993.8373941679588,
      "y": 2244.936309814453
    },
    "security-cameras": {
      "x": 1674.413336949044,
      "y": 2046.0380859375
    },
    "nvr-cluster": {
      "x": 1829.4110389706402,
      "y": 2845
    },
    "dev-server-1": {
      "x": 2359.9473452212114,
      "y": 1480.4859619140625
    },
    "dev-server-2": {
      "x": 1934.8346596546826,
      "y": 1236.2509002685547
    },
    "test-environment": {
      "x": 2205.6861583047325,
      "y": 867.3496704101562
    },
    "erp-system": {
      "x": 864.9509620587212,
      "y": 1501.5821533203125
    },
    "crm-system": {
      "x": 3514.6003232048542,
      "y": 1137.7720947265625
    },
    "endpoint-1000": {
      "x": 991.6812012057328,
      "y": 2284.42236328125
    },
    "dist-switch-floor1": {
      "x": 654.2091033261356,
      "y": 2020.0086669921875
    },
    "dist-switch-floor2": {
      "x": 853.8845527112826,
      "y": 1843.2872314453125
    },
    "dist-switch-floor3": {
      "x": 1899.4353951584517,
      "y": 1456.5068359375
    },
    "dist-switch-floor4": {
      "x": 655.2108161412484,
      "y": 348.4529113769531
    },
    "ap-floor1-zone1": {
      "x": 1140.16846970184,
      "y": 2070.2916259765625
    },
    "ap-floor2-zone1": {
      "x": 688.1952143592268,
      "y": 2384.4775390625
    },
    "ap-floor3-zone1": {
      "x": 2145.3803027919676,
      "y": 1890.2816162109375
    },
    "ap-floor4-zone1": {
      "x": 433.53909074558646,
      "y": 692.0150146484375
    },
    "ups-dc-1": {
      "x": 588.0889513590637,
      "y": 1348.8856201171875
    },
    "ups-dc-2": {
      "x": 199.70106178535775,
      "y": 528.8150024414062
    },
    "pdu-rack-a1": {
      "x": 1804.774444371901,
      "y": 2845
    },
    "pdu-rack-a2": {
      "x": 1741.6184034693686,
      "y": 2845
    },
    "cooling-1": {
      "x": 326.61422338047237,
      "y": 1304.6719970703125
    },
    "cooling-2": {
      "x": 1603.293611085831,
      "y": 981.0621185302734
    }
  },
  "nodeSizes": {},
  "nodeStyles": {
    "dc-rack-b2": {
      "all": {
        "circleColor": "#ff0000"
      }
    },
    "dc-rack-a1": {
      "all": {
        "circleColor": "#ff0000"
      }
    },
    "dc-rack-b1": {
      "all": {
        "circleColor": "#ff0000",
        "titleSize": 59
      }
    }
  },
  "page": {
    "title": "The One File Corporate",
    "background": "",
    "topbarBg": "rgba(9, 12, 20, 0.9)",
    "topbarBorder": "#1f2533",
    "panel": "#0b0e13",
    "panelAlt": "#10141b",
    "accent": "#4fd1c5",
    "sidebarBg": "#10141b",
    "btnBg": "#0b0e13",
    "btnText": "#e2e8f0",
    "tagFill": "#1e293b",
    "tagText": "#e2e8f0",
    "tagBorder": "#475569",
    "inputBg": "#0b0e13",
    "inputText": "#e2e8f0",
    "inputBorder": "#1f2937",
    "inputFont": "Inter, system-ui, sans-serif",
    "inputFontSize": 14,
    "toolbarBg": "#0f172a",
    "toolbarBorder": "#1f2937",
    "toolbarText": "#94a3b8",
    "toolbarBtnBg": "#0b0e13",
    "toolbarBtnText": "#e2e8f0",
    "minimapDots": "#94a3b8",
    "canvasHintEnabled": true,
    "canvasHintText": "",
    "canvasHintBg": "#0f172a",
    "canvasHintColor": "#94a3b8",
    "danger": "#f56565",
    "textMain": "#e2e8f0",
    "textSoft": "#94a3b8",
    "topbarHeight": 113,
    "sidebarWidth": 350,
    "mobileFooterHeight": 40,
    "sidebarCollapsed": false,
    "nodeFill": "#1e293b",
    "nodeStroke": "#475569",
    "nodeTitle": "#e2e8f0",
    "nodeSub": "#94a3b8",
    "nodeTitleSize": 41,
    "nodeSubSize": 27,
    "nodeFont": "monospace",
    "defaultEdge": "#475569",
    "selectionHandle": "#f59e0b",
    "selectionHandleSize": 8,
    "groupIndicator": "#4fd1c5",
    "canvasGradientTop": "#1e2532",
    "canvasGradientBottom": "#050608",
    "canvasBorder": "#475569",
    "canvasGrid": "#475569",
    "canvasGridSize": 50,
    "rackFrameFill": "#0f172a",
    "rackFrameStroke": "#4fd1c5",
    "rackLineColor": "#475569",
    "rackTextColor": "#4fd1c5",
    "viewOnly": false,
    "defaultEdgeRouting": "orthogonal"
  },
  "canvas": {
    "zoom": 0.9828345045578523,
    "panX": 162.25942846156744,
    "panY": -131.59941950312611
  },
  "savedTopologyView": {
    "zoom": 0.9325110211947125,
    "panX": -563.7108933103631,
    "panY": -561.6887674556383
  },
  "documentTabs": [
    {
      "id": "main",
      "name": "Corporate Site B",
      "nodes": {
        "core-router-1": {
          "shape": "router",
          "name": "Core Router 1",
          "ip": "10.0.0.1",
          "role": "Core Routing",
          "tags": [
            "core",
            "tier-1",
            "redundant"
          ],
          "notes": [
            "Primary core router",
            "BGP peering enabled"
          ],
          "mac": "00:1A:2B:3C:4D:01",
          "rackUnit": "",
          "uHeight": "2",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "core-router-2": {
          "shape": "router",
          "name": "Core Router 2",
          "ip": "10.0.0.2",
          "role": "Core Routing",
          "tags": [
            "core",
            "tier-1",
            "redundant"
          ],
          "notes": [
            "Secondary core router",
            "HSRP standby"
          ],
          "mac": "00:1A:2B:3C:4D:02",
          "rackUnit": "",
          "uHeight": "2",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "fw-external-1": {
          "shape": "firewall",
          "name": "External FW 1",
          "ip": "10.0.1.1",
          "role": "Perimeter Security",
          "tags": [
            "security",
            "perimeter",
            "ha-pair"
          ],
          "notes": [
            "Palo Alto PA-5250",
            "Active node"
          ],
          "mac": "00:1A:2B:3C:4D:10",
          "rackUnit": "",
          "uHeight": "2",
          "layer": "security",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "fw-external-2": {
          "shape": "firewall",
          "name": "External FW 2",
          "ip": "10.0.1.2",
          "role": "Perimeter Security",
          "tags": [
            "security",
            "perimeter",
            "ha-pair"
          ],
          "notes": [
            "Palo Alto PA-5250",
            "Passive node"
          ],
          "mac": "00:1A:2B:3C:4D:11",
          "rackUnit": "",
          "uHeight": "2",
          "layer": "security",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "fw-internal": {
          "shape": "firewall",
          "name": "Internal FW",
          "ip": "10.0.2.1",
          "role": "Internal Segmentation",
          "tags": [
            "security",
            "internal"
          ],
          "notes": [
            "East-West traffic inspection"
          ],
          "mac": "00:1A:2B:3C:4D:12",
          "rackUnit": "",
          "uHeight": "2",
          "layer": "security",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "core-switch-1": {
          "shape": "switch",
          "name": "Core Switch 1",
          "ip": "10.0.10.1",
          "role": "Core Switching",
          "tags": [
            "core",
            "layer3",
            "redundant"
          ],
          "notes": [
            "Cisco Nexus 9000",
            "VPC Domain 1"
          ],
          "mac": "00:1A:2B:3C:4D:20",
          "rackUnit": "",
          "uHeight": "2",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "core-switch-2": {
          "shape": "switch",
          "name": "Core Switch 2",
          "ip": "10.0.10.2",
          "role": "Core Switching",
          "tags": [
            "core",
            "layer3",
            "redundant"
          ],
          "notes": [
            "Cisco Nexus 9000",
            "VPC Domain 1"
          ],
          "mac": "00:1A:2B:3C:4D:21",
          "rackUnit": "",
          "uHeight": "2",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "dc-rack-a1": {
          "shape": "server",
          "name": "DC Rack A1",
          "ip": "10.10.0.0/24",
          "role": "Data Center Rack",
          "tags": [
            "datacenter",
            "row-a",
            "production"
          ],
          "notes": [
            "Row A, Position 1",
            "Primary compute"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": true,
          "locked": false,
          "groupId": null
        },
        "dc-rack-a2": {
          "shape": "server",
          "name": "DC Rack A2",
          "ip": "10.10.1.0/24",
          "role": "Data Center Rack",
          "tags": [
            "datacenter",
            "row-a",
            "production"
          ],
          "notes": [
            "Row A, Position 2",
            "Primary compute"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": true,
          "locked": false,
          "groupId": null
        },
        "dc-rack-b1": {
          "shape": "server",
          "name": "DC Rack B1",
          "ip": "10.10.2.0/24",
          "role": "Data Center Rack",
          "tags": [
            "datacenter",
            "row-b",
            "storage"
          ],
          "notes": [
            "Row B, Position 1",
            "Storage systems"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": true,
          "locked": false,
          "groupId": null
        },
        "dc-rack-b2": {
          "shape": "server",
          "name": "DC Rack B2",
          "ip": "10.10.3.0/24",
          "role": "Data Center Rack",
          "tags": [
            "datacenter",
            "row-b",
            "storage"
          ],
          "notes": [
            "Row B, Position 2",
            "Storage systems"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": true,
          "locked": false,
          "groupId": null
        },
        "dmz-rack": {
          "shape": "server",
          "name": "DMZ Rack",
          "ip": "172.16.0.0/24",
          "role": "DMZ Infrastructure",
          "tags": [
            "dmz",
            "security",
            "public-facing"
          ],
          "notes": [
            "Isolated DMZ zone",
            "Public-facing services"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "security",
          "assignedRack": "",
          "rackCapacity": "24",
          "isRack": true,
          "locked": false,
          "groupId": null
        },
        "mgmt-rack": {
          "shape": "server",
          "name": "Management Rack",
          "ip": "192.168.100.0/24",
          "role": "Management Infrastructure",
          "tags": [
            "management",
            "oob",
            "noc"
          ],
          "notes": [
            "Out-of-band management",
            "NOC equipment"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "logical",
          "assignedRack": "",
          "rackCapacity": "24",
          "isRack": true,
          "locked": false,
          "groupId": null
        },
        "esxi-host-01": {
          "shape": "server",
          "name": "ESXi Host 01",
          "ip": "10.10.0.11",
          "role": "Hypervisor",
          "tags": [
            "vmware",
            "compute",
            "cluster-a"
          ],
          "notes": [
            "Dell PowerEdge R750",
            "512GB RAM",
            "vSphere 8.0"
          ],
          "mac": "00:50:56:AA:01:01",
          "rackUnit": 38,
          "uHeight": "2",
          "layer": "physical",
          "assignedRack": "dc-rack-a1",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "esxi-host-02": {
          "shape": "server",
          "name": "ESXi Host 02",
          "ip": "10.10.0.12",
          "role": "Hypervisor",
          "tags": [
            "vmware",
            "compute",
            "cluster-a"
          ],
          "notes": [
            "Dell PowerEdge R750",
            "512GB RAM",
            "vSphere 8.0"
          ],
          "mac": "00:50:56:AA:01:02",
          "rackUnit": 35,
          "uHeight": "2",
          "layer": "physical",
          "assignedRack": "dc-rack-a1",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "esxi-host-03": {
          "shape": "server",
          "name": "ESXi Host 03",
          "ip": "10.10.0.13",
          "role": "Hypervisor",
          "tags": [
            "vmware",
            "compute",
            "cluster-a"
          ],
          "notes": [
            "Dell PowerEdge R750",
            "512GB RAM",
            "vSphere 8.0"
          ],
          "mac": "00:50:56:AA:01:03",
          "rackUnit": 32,
          "uHeight": "2",
          "layer": "physical",
          "assignedRack": "dc-rack-a1",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "esxi-host-04": {
          "shape": "server",
          "name": "ESXi Host 04",
          "ip": "10.10.0.14",
          "role": "Hypervisor",
          "tags": [
            "vmware",
            "compute",
            "cluster-a"
          ],
          "notes": [
            "Dell PowerEdge R750",
            "512GB RAM",
            "vSphere 8.0"
          ],
          "mac": "00:50:56:AA:01:04",
          "rackUnit": 29,
          "uHeight": "2",
          "layer": "physical",
          "assignedRack": "dc-rack-a1",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "tor-switch-a1": {
          "shape": "switch",
          "name": "ToR Switch A1",
          "ip": "10.10.0.1",
          "role": "Top of Rack",
          "tags": [
            "tor",
            "access",
            "rack-a1"
          ],
          "notes": [
            "Cisco Nexus 93180YC-FX",
            "48x25G ports"
          ],
          "mac": "00:1A:2B:3C:5D:01",
          "rackUnit": 42,
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "dc-rack-a1",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "esxi-host-05": {
          "shape": "server",
          "name": "ESXi Host 05",
          "ip": "10.10.1.11",
          "role": "Hypervisor",
          "tags": [
            "vmware",
            "compute",
            "cluster-b"
          ],
          "notes": [
            "Dell PowerEdge R750",
            "768GB RAM",
            "vSphere 8.0"
          ],
          "mac": "00:50:56:AA:02:01",
          "rackUnit": 38,
          "uHeight": "2",
          "layer": "physical",
          "assignedRack": "dc-rack-a2",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "esxi-host-06": {
          "shape": "server",
          "name": "ESXi Host 06",
          "ip": "10.10.1.12",
          "role": "Hypervisor",
          "tags": [
            "vmware",
            "compute",
            "cluster-b"
          ],
          "notes": [
            "Dell PowerEdge R750",
            "768GB RAM",
            "vSphere 8.0"
          ],
          "mac": "00:50:56:AA:02:02",
          "rackUnit": 35,
          "uHeight": "2",
          "layer": "physical",
          "assignedRack": "dc-rack-a2",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "esxi-host-07": {
          "shape": "server",
          "name": "ESXi Host 07",
          "ip": "10.10.1.13",
          "role": "Hypervisor",
          "tags": [
            "vmware",
            "compute",
            "cluster-b"
          ],
          "notes": [
            "Dell PowerEdge R750",
            "768GB RAM",
            "vSphere 8.0"
          ],
          "mac": "00:50:56:AA:02:03",
          "rackUnit": 32,
          "uHeight": "2",
          "layer": "physical",
          "assignedRack": "dc-rack-a2",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "esxi-host-08": {
          "shape": "server",
          "name": "ESXi Host 08",
          "ip": "10.10.1.14",
          "role": "Hypervisor",
          "tags": [
            "vmware",
            "compute",
            "cluster-b"
          ],
          "notes": [
            "Dell PowerEdge R750",
            "768GB RAM",
            "vSphere 8.0"
          ],
          "mac": "00:50:56:AA:02:04",
          "rackUnit": 29,
          "uHeight": "2",
          "layer": "physical",
          "assignedRack": "dc-rack-a2",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "tor-switch-a2": {
          "shape": "switch",
          "name": "ToR Switch A2",
          "ip": "10.10.1.1",
          "role": "Top of Rack",
          "tags": [
            "tor",
            "access",
            "rack-a2"
          ],
          "notes": [
            "Cisco Nexus 93180YC-FX",
            "48x25G ports"
          ],
          "mac": "00:1A:2B:3C:5D:02",
          "rackUnit": 42,
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "dc-rack-a2",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "san-primary": {
          "shape": "database",
          "name": "SAN Primary",
          "ip": "10.10.2.10",
          "role": "Primary Storage",
          "tags": [
            "storage",
            "san",
            "netapp"
          ],
          "notes": [
            "NetApp AFF A400",
            "500TB Raw",
            "FC 32Gb"
          ],
          "mac": "00:A0:98:AA:01:01",
          "rackUnit": 36,
          "uHeight": "6",
          "layer": "physical",
          "assignedRack": "dc-rack-b1",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "san-secondary": {
          "shape": "database",
          "name": "SAN Secondary",
          "ip": "10.10.2.11",
          "role": "Secondary Storage",
          "tags": [
            "storage",
            "san",
            "netapp"
          ],
          "notes": [
            "NetApp AFF A400",
            "500TB Raw",
            "FC 32Gb"
          ],
          "mac": "00:A0:98:AA:01:02",
          "rackUnit": 28,
          "uHeight": "6",
          "layer": "physical",
          "assignedRack": "dc-rack-b1",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "fc-switch-1": {
          "shape": "switch",
          "name": "FC Switch 1",
          "ip": "10.10.2.1",
          "role": "Fibre Channel",
          "tags": [
            "storage",
            "fc",
            "fabric-a"
          ],
          "notes": [
            "Brocade G620",
            "Fabric A"
          ],
          "mac": "00:1A:2B:FC:01:01",
          "rackUnit": 42,
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "dc-rack-b1",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "fc-switch-2": {
          "shape": "switch",
          "name": "FC Switch 2",
          "ip": "10.10.2.2",
          "role": "Fibre Channel",
          "tags": [
            "storage",
            "fc",
            "fabric-b"
          ],
          "notes": [
            "Brocade G620",
            "Fabric B"
          ],
          "mac": "00:1A:2B:FC:01:02",
          "rackUnit": 41,
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "dc-rack-b1",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "backup-server-1": {
          "shape": "server",
          "name": "Backup Server 1",
          "ip": "10.10.3.10",
          "role": "Backup Infrastructure",
          "tags": [
            "backup",
            "veeam",
            "protection"
          ],
          "notes": [
            "Veeam Backup Server",
            "Dell R740xd",
            "200TB"
          ],
          "mac": "00:50:56:BB:01:01",
          "rackUnit": 36,
          "uHeight": "2",
          "layer": "physical",
          "assignedRack": "dc-rack-b2",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "backup-server-2": {
          "shape": "server",
          "name": "Backup Server 2",
          "ip": "10.10.3.11",
          "role": "Backup Infrastructure",
          "tags": [
            "backup",
            "veeam",
            "protection"
          ],
          "notes": [
            "Veeam Backup Server",
            "Dell R740xd",
            "200TB"
          ],
          "mac": "00:50:56:BB:01:02",
          "rackUnit": 33,
          "uHeight": "2",
          "layer": "physical",
          "assignedRack": "dc-rack-b2",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "tape-library": {
          "shape": "database",
          "name": "Tape Library",
          "ip": "10.10.3.20",
          "role": "Archival Storage",
          "tags": [
            "backup",
            "tape",
            "lto9"
          ],
          "notes": [
            "IBM TS4500",
            "LTO-9",
            "Long-term archive"
          ],
          "mac": "00:50:56:BB:02:01",
          "rackUnit": 20,
          "uHeight": "10",
          "layer": "physical",
          "assignedRack": "dc-rack-b2",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "tor-switch-b1": {
          "shape": "switch",
          "name": "ToR Switch B1",
          "ip": "10.10.2.3",
          "role": "Top of Rack",
          "tags": [
            "tor",
            "access",
            "rack-b1"
          ],
          "notes": [
            "Cisco Nexus 93180YC-FX"
          ],
          "mac": "00:1A:2B:3C:5D:03",
          "rackUnit": 40,
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "dc-rack-b1",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "tor-switch-b2": {
          "shape": "switch",
          "name": "ToR Switch B2",
          "ip": "10.10.3.1",
          "role": "Top of Rack",
          "tags": [
            "tor",
            "access",
            "rack-b2"
          ],
          "notes": [
            "Cisco Nexus 93180YC-FX"
          ],
          "mac": "00:1A:2B:3C:5D:04",
          "rackUnit": 42,
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "dc-rack-b2",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "web-server-1": {
          "shape": "server",
          "name": "Web Server 1",
          "ip": "172.16.0.11",
          "role": "Web Frontend",
          "tags": [
            "dmz",
            "web",
            "nginx"
          ],
          "notes": [
            "NGINX reverse proxy",
            "Public facing"
          ],
          "mac": "00:50:56:CC:01:01",
          "rackUnit": 20,
          "uHeight": "1",
          "layer": "security",
          "assignedRack": "dmz-rack",
          "rackCapacity": "24",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "web-server-2": {
          "shape": "server",
          "name": "Web Server 2",
          "ip": "172.16.0.12",
          "role": "Web Frontend",
          "tags": [
            "dmz",
            "web",
            "nginx"
          ],
          "notes": [
            "NGINX reverse proxy",
            "Public facing"
          ],
          "mac": "00:50:56:CC:01:02",
          "rackUnit": 18,
          "uHeight": "1",
          "layer": "security",
          "assignedRack": "dmz-rack",
          "rackCapacity": "24",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "waf-1": {
          "shape": "firewall",
          "name": "WAF Appliance",
          "ip": "172.16.0.5",
          "role": "Web Application Firewall",
          "tags": [
            "dmz",
            "security",
            "waf"
          ],
          "notes": [
            "F5 BIG-IP ASM",
            "OWASP protection"
          ],
          "mac": "00:50:56:CC:02:01",
          "rackUnit": 22,
          "uHeight": "2",
          "layer": "security",
          "assignedRack": "dmz-rack",
          "rackCapacity": "24",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "load-balancer-dmz": {
          "shape": "switch",
          "name": "DMZ Load Balancer",
          "ip": "172.16.0.3",
          "role": "Load Balancing",
          "tags": [
            "dmz",
            "lb",
            "f5"
          ],
          "notes": [
            "F5 BIG-IP LTM",
            "VIP: 172.16.0.100"
          ],
          "mac": "00:50:56:CC:03:01",
          "rackUnit": 16,
          "uHeight": "2",
          "layer": "security",
          "assignedRack": "dmz-rack",
          "rackCapacity": "24",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "mail-gateway": {
          "shape": "server",
          "name": "Mail Gateway",
          "ip": "172.16.0.25",
          "role": "Email Security",
          "tags": [
            "dmz",
            "email",
            "security"
          ],
          "notes": [
            "Proofpoint Email Gateway",
            "Spam/malware filtering"
          ],
          "mac": "00:50:56:CC:04:01",
          "rackUnit": 14,
          "uHeight": "1",
          "layer": "security",
          "assignedRack": "dmz-rack",
          "rackCapacity": "24",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "dns-external-1": {
          "shape": "circle",
          "name": "External DNS 1",
          "ip": "172.16.0.53",
          "role": "External DNS",
          "tags": [
            "dmz",
            "dns",
            "public"
          ],
          "notes": [
            "BIND DNS",
            "Authoritative for corp.com"
          ],
          "mac": "00:50:56:CC:05:01",
          "rackUnit": 12,
          "uHeight": "1",
          "layer": "security",
          "assignedRack": "dmz-rack",
          "rackCapacity": "24",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "dns-external-2": {
          "shape": "circle",
          "name": "External DNS 2",
          "ip": "172.16.0.54",
          "role": "External DNS",
          "tags": [
            "dmz",
            "dns",
            "public"
          ],
          "notes": [
            "BIND DNS",
            "Secondary for corp.com"
          ],
          "mac": "00:50:56:CC:05:02",
          "rackUnit": 10,
          "uHeight": "1",
          "layer": "security",
          "assignedRack": "dmz-rack",
          "rackCapacity": "24",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "vcenter": {
          "shape": "server",
          "name": "vCenter Server",
          "ip": "192.168.100.10",
          "role": "Virtualization Management",
          "tags": [
            "management",
            "vmware",
            "vcsa"
          ],
          "notes": [
            "vCenter Server Appliance 8.0",
            "Single SSO domain"
          ],
          "mac": "00:50:56:DD:01:01",
          "rackUnit": 20,
          "uHeight": "2",
          "layer": "logical",
          "assignedRack": "mgmt-rack",
          "rackCapacity": "24",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "nsx-manager": {
          "shape": "server",
          "name": "NSX Manager",
          "ip": "192.168.100.15",
          "role": "Network Virtualization",
          "tags": [
            "management",
            "vmware",
            "nsx"
          ],
          "notes": [
            "NSX-T 4.1 Manager Cluster"
          ],
          "mac": "00:50:56:DD:02:01",
          "rackUnit": 17,
          "uHeight": "2",
          "layer": "logical",
          "assignedRack": "mgmt-rack",
          "rackCapacity": "24",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "siem-server": {
          "shape": "server",
          "name": "SIEM Server",
          "ip": "192.168.100.50",
          "role": "Security Monitoring",
          "tags": [
            "management",
            "security",
            "splunk"
          ],
          "notes": [
            "Splunk Enterprise",
            "Security monitoring"
          ],
          "mac": "00:50:56:DD:03:01",
          "rackUnit": 14,
          "uHeight": "2",
          "layer": "logical",
          "assignedRack": "mgmt-rack",
          "rackCapacity": "24",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "nms-server": {
          "shape": "server",
          "name": "Network Monitoring",
          "ip": "192.168.100.60",
          "role": "Network Management",
          "tags": [
            "management",
            "monitoring",
            "prtg"
          ],
          "notes": [
            "PRTG Network Monitor",
            "5000 sensors"
          ],
          "mac": "00:50:56:DD:04:01",
          "rackUnit": 11,
          "uHeight": "1",
          "layer": "logical",
          "assignedRack": "mgmt-rack",
          "rackCapacity": "24",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "jump-server": {
          "shape": "server",
          "name": "Jump Server",
          "ip": "192.168.100.100",
          "role": "Bastion Host",
          "tags": [
            "management",
            "security",
            "bastion"
          ],
          "notes": [
            "Windows Server 2022",
            "MFA enabled"
          ],
          "mac": "00:50:56:DD:05:01",
          "rackUnit": 9,
          "uHeight": "1",
          "layer": "logical",
          "assignedRack": "mgmt-rack",
          "rackCapacity": "24",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "ipam-server": {
          "shape": "server",
          "name": "IPAM/DDI",
          "ip": "192.168.100.70",
          "role": "IP Management",
          "tags": [
            "management",
            "dns",
            "dhcp"
          ],
          "notes": [
            "Infoblox DDI",
            "DNS/DHCP/IPAM"
          ],
          "mac": "00:50:56:DD:06:01",
          "rackUnit": 7,
          "uHeight": "2",
          "layer": "logical",
          "assignedRack": "mgmt-rack",
          "rackCapacity": "24",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "wlc-primary": {
          "shape": "wifi",
          "name": "WLC Primary",
          "ip": "10.20.0.1",
          "role": "Wireless Controller",
          "tags": [
            "wireless",
            "cisco",
            "9800"
          ],
          "notes": [
            "Cisco C9800-40",
            "Primary controller"
          ],
          "mac": "00:1A:2B:WL:01:01",
          "rackUnit": "",
          "uHeight": "2",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "wlc-secondary": {
          "shape": "wifi",
          "name": "WLC Secondary",
          "ip": "10.20.0.2",
          "role": "Wireless Controller",
          "tags": [
            "wireless",
            "cisco",
            "9800"
          ],
          "notes": [
            "Cisco C9800-40",
            "HA Secondary"
          ],
          "mac": "00:1A:2B:WL:01:02",
          "rackUnit": "",
          "uHeight": "2",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "mobile-zone-hq": {
          "shape": "phone",
          "name": "HQ Mobile Zone",
          "ip": "10.20.10.0/24",
          "role": "Mobile Device Zone",
          "tags": [
            "wireless",
            "byod",
            "mobile"
          ],
          "notes": [
            "Corporate BYOD",
            "MDM enrolled devices"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "mobile-zone-guest": {
          "shape": "phone",
          "name": "Guest WiFi Zone",
          "ip": "10.30.0.0/24",
          "role": "Guest Network",
          "tags": [
            "wireless",
            "guest",
            "isolated"
          ],
          "notes": [
            "Captive portal",
            "Internet only"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "mobile-zone-iot": {
          "shape": "phone",
          "name": "IoT Device Zone",
          "ip": "10.40.0.0/24",
          "role": "IoT Network",
          "tags": [
            "wireless",
            "iot",
            "building"
          ],
          "notes": [
            "Building automation",
            "Smart devices"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "branch-router-ny": {
          "shape": "router",
          "name": "NYC Branch Router",
          "ip": "10.100.0.1",
          "role": "Branch Gateway",
          "tags": [
            "branch",
            "nyc",
            "sd-wan"
          ],
          "notes": [
            "Cisco Viptela vEdge",
            "SD-WAN enabled"
          ],
          "mac": "00:1A:2B:BR:01:01",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "branch-router-la": {
          "shape": "router",
          "name": "LA Branch Router",
          "ip": "10.101.0.1",
          "role": "Branch Gateway",
          "tags": [
            "branch",
            "la",
            "sd-wan"
          ],
          "notes": [
            "Cisco Viptela vEdge",
            "SD-WAN enabled"
          ],
          "mac": "00:1A:2B:BR:02:01",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "branch-router-chi": {
          "shape": "router",
          "name": "Chicago Branch Router",
          "ip": "10.102.0.1",
          "role": "Branch Gateway",
          "tags": [
            "branch",
            "chicago",
            "sd-wan"
          ],
          "notes": [
            "Cisco Viptela vEdge",
            "SD-WAN enabled"
          ],
          "mac": "00:1A:2B:BR:03:01",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "branch-router-lon": {
          "shape": "router",
          "name": "London Branch Router",
          "ip": "10.200.0.1",
          "role": "Branch Gateway",
          "tags": [
            "branch",
            "london",
            "sd-wan"
          ],
          "notes": [
            "Cisco Viptela vEdge",
            "EMEA region"
          ],
          "mac": "00:1A:2B:BR:04:01",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "branch-router-tokyo": {
          "shape": "router",
          "name": "Tokyo Branch Router",
          "ip": "10.201.0.1",
          "role": "Branch Gateway",
          "tags": [
            "branch",
            "tokyo",
            "sd-wan"
          ],
          "notes": [
            "Cisco Viptela vEdge",
            "APAC region"
          ],
          "mac": "00:1A:2B:BR:05:01",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "cloud-aws": {
          "shape": "cloud",
          "name": "AWS Cloud",
          "ip": "vpc-0a1b2c3d",
          "role": "Public Cloud",
          "tags": [
            "cloud",
            "aws",
            "hybrid"
          ],
          "notes": [
            "AWS US-East-1",
            "VPC peering to HQ"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "logical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "cloud-azure": {
          "shape": "cloud",
          "name": "Azure Cloud",
          "ip": "vnet-corp-prod",
          "role": "Public Cloud",
          "tags": [
            "cloud",
            "azure",
            "hybrid"
          ],
          "notes": [
            "Azure East US 2",
            "ExpressRoute"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "logical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "cloud-gcp": {
          "shape": "cloud",
          "name": "GCP Cloud",
          "ip": "vpc-gcp-corp",
          "role": "Public Cloud",
          "tags": [
            "cloud",
            "gcp",
            "dev"
          ],
          "notes": [
            "GCP us-central1",
            "Dev/Test workloads"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "logical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "isp-primary": {
          "shape": "globe",
          "name": "ISP Primary",
          "ip": "203.0.113.1",
          "role": "Internet Uplink",
          "tags": [
            "wan",
            "internet",
            "primary"
          ],
          "notes": [
            "AT&T MPLS",
            "1 Gbps dedicated"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "isp-secondary": {
          "shape": "globe",
          "name": "ISP Secondary",
          "ip": "198.51.100.1",
          "role": "Internet Uplink",
          "tags": [
            "wan",
            "internet",
            "backup"
          ],
          "notes": [
            "Verizon Business",
            "500 Mbps backup"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "dc-internal-1": {
          "shape": "circle",
          "name": "DC1 Int DNS",
          "ip": "10.10.0.53",
          "role": "Internal DNS/AD",
          "tags": [
            "dns",
            "ad",
            "dc1"
          ],
          "notes": [
            "Windows Server 2022",
            "Primary DC"
          ],
          "mac": "00:50:56:AD:01:01",
          "rackUnit": 26,
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "dc-rack-a1",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "dc-internal-2": {
          "shape": "circle",
          "name": "DC2 Int DNS",
          "ip": "10.10.1.53",
          "role": "Internal DNS/AD",
          "tags": [
            "dns",
            "ad",
            "dc2"
          ],
          "notes": [
            "Windows Server 2022",
            "Secondary DC"
          ],
          "mac": "00:50:56:AD:01:02",
          "rackUnit": 26,
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "dc-rack-a2",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "app-server-1": {
          "shape": "server",
          "name": "App Server 01",
          "ip": "10.10.0.101",
          "role": "Application",
          "tags": [
            "app",
            "iis",
            "web"
          ],
          "notes": [
            "Windows Server 2022",
            "IIS Application"
          ],
          "mac": "00:50:56:AP:01:01",
          "rackUnit": 24,
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "dc-rack-a1",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "app-server-2": {
          "shape": "server",
          "name": "App Server 02",
          "ip": "10.10.0.102",
          "role": "Application",
          "tags": [
            "app",
            "iis",
            "web"
          ],
          "notes": [
            "Windows Server 2022",
            "IIS Application"
          ],
          "mac": "00:50:56:AP:01:02",
          "rackUnit": 22,
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "dc-rack-a1",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "db-server-1": {
          "shape": "database",
          "name": "SQL Server 01",
          "ip": "10.10.0.201",
          "role": "Database",
          "tags": [
            "db",
            "sql",
            "primary"
          ],
          "notes": [
            "SQL Server 2022 Enterprise",
            "AlwaysOn Primary"
          ],
          "mac": "00:50:56:DB:01:01",
          "rackUnit": 20,
          "uHeight": "2",
          "layer": "physical",
          "assignedRack": "dc-rack-a1",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "db-server-2": {
          "shape": "database",
          "name": "SQL Server 02",
          "ip": "10.10.1.201",
          "role": "Database",
          "tags": [
            "db",
            "sql",
            "secondary"
          ],
          "notes": [
            "SQL Server 2022 Enterprise",
            "AlwaysOn Secondary"
          ],
          "mac": "00:50:56:DB:01:02",
          "rackUnit": 24,
          "uHeight": "2",
          "layer": "physical",
          "assignedRack": "dc-rack-a2",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "k8s-master-1": {
          "shape": "hexagon",
          "name": "K8s Master 1",
          "ip": "10.10.1.50",
          "role": "Container Orchestration",
          "tags": [
            "kubernetes",
            "master",
            "container"
          ],
          "notes": [
            "K8s Control Plane",
            "etcd member"
          ],
          "mac": "00:50:56:K8:01:01",
          "rackUnit": 21,
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "dc-rack-a2",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "k8s-master-2": {
          "shape": "hexagon",
          "name": "K8s Master 2",
          "ip": "10.10.1.51",
          "role": "Container Orchestration",
          "tags": [
            "kubernetes",
            "master",
            "container"
          ],
          "notes": [
            "K8s Control Plane",
            "etcd member"
          ],
          "mac": "00:50:56:K8:01:02",
          "rackUnit": 19,
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "dc-rack-a2",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "k8s-master-3": {
          "shape": "hexagon",
          "name": "K8s Master 3",
          "ip": "10.10.1.52",
          "role": "Container Orchestration",
          "tags": [
            "kubernetes",
            "master",
            "container"
          ],
          "notes": [
            "K8s Control Plane",
            "etcd member"
          ],
          "mac": "00:50:56:K8:01:03",
          "rackUnit": 17,
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "dc-rack-a2",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "k8s-worker-1": {
          "shape": "server",
          "name": "K8s Worker 1",
          "ip": "10.10.1.60",
          "role": "Container Workload",
          "tags": [
            "kubernetes",
            "worker",
            "container"
          ],
          "notes": [
            "K8s Worker Node",
            "64GB RAM"
          ],
          "mac": "00:50:56:K8:02:01",
          "rackUnit": 15,
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "dc-rack-a2",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "k8s-worker-2": {
          "shape": "server",
          "name": "K8s Worker 2",
          "ip": "10.10.1.61",
          "role": "Container Workload",
          "tags": [
            "kubernetes",
            "worker",
            "container"
          ],
          "notes": [
            "K8s Worker Node",
            "64GB RAM"
          ],
          "mac": "00:50:56:K8:02:02",
          "rackUnit": 13,
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "dc-rack-a2",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "k8s-worker-3": {
          "shape": "server",
          "name": "K8s Worker 3",
          "ip": "10.10.1.62",
          "role": "Container Workload",
          "tags": [
            "kubernetes",
            "worker",
            "container"
          ],
          "notes": [
            "K8s Worker Node",
            "64GB RAM"
          ],
          "mac": "00:50:56:K8:02:03",
          "rackUnit": 11,
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "dc-rack-a2",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "k8s-worker-4": {
          "shape": "server",
          "name": "K8s Worker 4",
          "ip": "10.10.1.63",
          "role": "Container Workload",
          "tags": [
            "kubernetes",
            "worker",
            "container"
          ],
          "notes": [
            "K8s Worker Node",
            "64GB RAM"
          ],
          "mac": "00:50:56:K8:02:04",
          "rackUnit": 9,
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "dc-rack-a2",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "proxy-server-1": {
          "shape": "server",
          "name": "Proxy Server 1",
          "ip": "10.5.0.10",
          "role": "Web Proxy",
          "tags": [
            "proxy",
            "squid",
            "filtering"
          ],
          "notes": [
            "Squid Proxy",
            "Content filtering"
          ],
          "mac": "00:50:56:PX:01:01",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "security",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "proxy-server-2": {
          "shape": "server",
          "name": "Proxy Server 2",
          "ip": "10.5.0.11",
          "role": "Web Proxy",
          "tags": [
            "proxy",
            "squid",
            "filtering"
          ],
          "notes": [
            "Squid Proxy",
            "HA pair"
          ],
          "mac": "00:50:56:PX:01:02",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "security",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "vpn-concentrator": {
          "shape": "firewall",
          "name": "VPN Concentrator",
          "ip": "10.0.5.1",
          "role": "Remote Access VPN",
          "tags": [
            "vpn",
            "remote",
            "security"
          ],
          "notes": [
            "Cisco ASA 5555-X",
            "AnyConnect SSL VPN"
          ],
          "mac": "00:1A:2B:VP:01:01",
          "rackUnit": "",
          "uHeight": "2",
          "layer": "security",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "nac-server": {
          "shape": "server",
          "name": "NAC Server",
          "ip": "10.5.5.10",
          "role": "Network Access Control",
          "tags": [
            "nac",
            "ise",
            "802.1x"
          ],
          "notes": [
            "Cisco ISE 3.1",
            "RADIUS/TACACS+"
          ],
          "mac": "00:50:56:NA:01:01",
          "rackUnit": "",
          "uHeight": "2",
          "layer": "security",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "print-server": {
          "shape": "server",
          "name": "Print Server",
          "ip": "10.10.0.150",
          "role": "Print Services",
          "tags": [
            "print",
            "windows",
            "services"
          ],
          "notes": [
            "Windows Print Server",
            "50+ printers"
          ],
          "mac": "00:50:56:PR:01:01",
          "rackUnit": 18,
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "dc-rack-a1",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "file-server": {
          "shape": "database",
          "name": "File Server",
          "ip": "10.10.0.160",
          "role": "File Services",
          "tags": [
            "file",
            "smb",
            "dfs"
          ],
          "notes": [
            "Windows File Server",
            "DFS namespace"
          ],
          "mac": "00:50:56:FS:01:01",
          "rackUnit": 16,
          "uHeight": "2",
          "layer": "physical",
          "assignedRack": "dc-rack-a1",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "ca-server": {
          "shape": "server",
          "name": "Certificate Authority",
          "ip": "192.168.100.80",
          "role": "PKI Infrastructure",
          "tags": [
            "pki",
            "ca",
            "security"
          ],
          "notes": [
            "Windows CA",
            "Enterprise Root CA"
          ],
          "mac": "00:50:56:CA:01:01",
          "rackUnit": 5,
          "uHeight": "1",
          "layer": "logical",
          "assignedRack": "mgmt-rack",
          "rackCapacity": "24",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "sccm-server": {
          "shape": "server",
          "name": "SCCM Server",
          "ip": "192.168.100.90",
          "role": "Endpoint Management",
          "tags": [
            "sccm",
            "patching",
            "software"
          ],
          "notes": [
            "MECM Primary Site",
            "Software deployment"
          ],
          "mac": "00:50:56:SC:01:01",
          "rackUnit": 3,
          "uHeight": "2",
          "layer": "logical",
          "assignedRack": "mgmt-rack",
          "rackCapacity": "24",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "voip-cluster": {
          "shape": "phone",
          "name": "VoIP Cluster",
          "ip": "10.50.0.0/24",
          "role": "Voice Services",
          "tags": [
            "voip",
            "cisco",
            "ucm"
          ],
          "notes": [
            "Cisco UCM Cluster",
            "3000 endpoints"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "application",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "video-conf": {
          "shape": "laptop",
          "name": "Video Conference",
          "ip": "10.51.0.0/24",
          "role": "Video Services",
          "tags": [
            "video",
            "webex",
            "teams"
          ],
          "notes": [
            "Webex/Teams integration",
            "Meeting rooms"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "application",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "security-cameras": {
          "shape": "camera",
          "name": "Security Cameras",
          "ip": "10.60.0.0/24",
          "role": "Physical Security",
          "tags": [
            "cctv",
            "surveillance",
            "security"
          ],
          "notes": [
            "150+ IP cameras",
            "30-day retention"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "nvr-cluster": {
          "shape": "server",
          "name": "NVR Cluster",
          "ip": "10.60.0.10",
          "role": "Video Recording",
          "tags": [
            "nvr",
            "surveillance",
            "storage"
          ],
          "notes": [
            "Milestone XProtect",
            "500TB storage"
          ],
          "mac": "00:50:56:NV:01:01",
          "rackUnit": 15,
          "uHeight": "4",
          "layer": "physical",
          "assignedRack": "dc-rack-b2",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "dev-server-1": {
          "shape": "server",
          "name": "Dev Server 1",
          "ip": "10.80.0.10",
          "role": "Development",
          "tags": [
            "dev",
            "gitlab",
            "ci-cd"
          ],
          "notes": [
            "GitLab Server",
            "CI/CD pipelines"
          ],
          "mac": "00:50:56:DV:01:01",
          "rackUnit": "",
          "uHeight": "2",
          "layer": "application",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "dev-server-2": {
          "shape": "server",
          "name": "Dev Server 2",
          "ip": "10.80.0.11",
          "role": "Development",
          "tags": [
            "dev",
            "jenkins",
            "ci-cd"
          ],
          "notes": [
            "Jenkins Server",
            "Build automation"
          ],
          "mac": "00:50:56:DV:01:02",
          "rackUnit": "",
          "uHeight": "2",
          "layer": "application",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "test-environment": {
          "shape": "hexagon",
          "name": "Test Environment",
          "ip": "10.81.0.0/24",
          "role": "QA/Testing",
          "tags": [
            "test",
            "qa",
            "staging"
          ],
          "notes": [
            "Staging environment",
            "Pre-prod validation"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "application",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "erp-system": {
          "shape": "database",
          "name": "ERP System",
          "ip": "10.90.0.10",
          "role": "Business Application",
          "tags": [
            "erp",
            "sap",
            "business"
          ],
          "notes": [
            "SAP S/4HANA",
            "Financial/HR systems"
          ],
          "mac": "00:50:56:ER:01:01",
          "rackUnit": "",
          "uHeight": "4",
          "layer": "application",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "crm-system": {
          "shape": "database",
          "name": "CRM System",
          "ip": "10.91.0.10",
          "role": "Business Application",
          "tags": [
            "crm",
            "salesforce",
            "business"
          ],
          "notes": [
            "Salesforce integration",
            "Sales/Marketing"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "application",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "endpoint-1000": {
          "shape": "laptop",
          "name": "Corporate Endpoints",
          "ip": "10.70.0.0/22",
          "role": "User Workstations",
          "tags": [
            "endpoints",
            "workstations",
            "users"
          ],
          "notes": [
            "~1000 corporate laptops",
            "Windows 11"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "dist-switch-floor1": {
          "shape": "switch",
          "name": "Floor 1 Switch",
          "ip": "10.1.1.1",
          "role": "Distribution",
          "tags": [
            "distribution",
            "floor-1",
            "access"
          ],
          "notes": [
            "Cisco C9300-48P",
            "PoE+ enabled"
          ],
          "mac": "00:1A:2B:FL:01:01",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "dist-switch-floor2": {
          "shape": "switch",
          "name": "Floor 2 Switch",
          "ip": "10.1.2.1",
          "role": "Distribution",
          "tags": [
            "distribution",
            "floor-2",
            "access"
          ],
          "notes": [
            "Cisco C9300-48P",
            "PoE+ enabled"
          ],
          "mac": "00:1A:2B:FL:02:01",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "dist-switch-floor3": {
          "shape": "switch",
          "name": "Floor 3 Switch",
          "ip": "10.1.3.1",
          "role": "Distribution",
          "tags": [
            "distribution",
            "floor-3",
            "access"
          ],
          "notes": [
            "Cisco C9300-48P",
            "PoE+ enabled"
          ],
          "mac": "00:1A:2B:FL:03:01",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "dist-switch-floor4": {
          "shape": "switch",
          "name": "Floor 4 Switch",
          "ip": "10.1.4.1",
          "role": "Distribution",
          "tags": [
            "distribution",
            "floor-4",
            "access"
          ],
          "notes": [
            "Cisco C9300-48P",
            "PoE+ enabled"
          ],
          "mac": "00:1A:2B:FL:04:01",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "ap-floor1-zone1": {
          "shape": "wifi",
          "name": "AP Floor 1 Zone 1",
          "ip": "10.20.1.10",
          "role": "Wireless Access",
          "tags": [
            "wifi",
            "ap",
            "floor-1"
          ],
          "notes": [
            "Cisco 9120AX",
            "Wi-Fi 6"
          ],
          "mac": "00:1A:2B:AP:01:01",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "ap-floor2-zone1": {
          "shape": "wifi",
          "name": "AP Floor 2 Zone 1",
          "ip": "10.20.2.10",
          "role": "Wireless Access",
          "tags": [
            "wifi",
            "ap",
            "floor-2"
          ],
          "notes": [
            "Cisco 9120AX",
            "Wi-Fi 6"
          ],
          "mac": "00:1A:2B:AP:02:01",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "ap-floor3-zone1": {
          "shape": "wifi",
          "name": "AP Floor 3 Zone 1",
          "ip": "10.20.3.10",
          "role": "Wireless Access",
          "tags": [
            "wifi",
            "ap",
            "floor-3"
          ],
          "notes": [
            "Cisco 9120AX",
            "Wi-Fi 6"
          ],
          "mac": "00:1A:2B:AP:03:01",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "ap-floor4-zone1": {
          "shape": "wifi",
          "name": "AP Floor 4 Zone 1",
          "ip": "10.20.4.10",
          "role": "Wireless Access",
          "tags": [
            "wifi",
            "ap",
            "floor-4"
          ],
          "notes": [
            "Cisco 9120AX",
            "Wi-Fi 6"
          ],
          "mac": "00:1A:2B:AP:04:01",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "ups-dc-1": {
          "shape": "rectangle",
          "name": "UPS DC-1",
          "ip": "192.168.200.10",
          "role": "Power Management",
          "tags": [
            "power",
            "ups",
            "datacenter"
          ],
          "notes": [
            "APC Symmetra",
            "80kVA",
            "30 min runtime"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "ups-dc-2": {
          "shape": "rectangle",
          "name": "UPS DC-2",
          "ip": "192.168.200.11",
          "role": "Power Management",
          "tags": [
            "power",
            "ups",
            "datacenter"
          ],
          "notes": [
            "APC Symmetra",
            "80kVA",
            "Redundant"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "pdu-rack-a1": {
          "shape": "rectangle",
          "name": "PDU Rack A1",
          "ip": "192.168.200.21",
          "role": "Power Distribution",
          "tags": [
            "power",
            "pdu",
            "rack-a1"
          ],
          "notes": [
            "APC Switched PDU",
            "Per-outlet metering"
          ],
          "mac": "",
          "rackUnit": 1,
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "dc-rack-a1",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "pdu-rack-a2": {
          "shape": "rectangle",
          "name": "PDU Rack A2",
          "ip": "192.168.200.22",
          "role": "Power Distribution",
          "tags": [
            "power",
            "pdu",
            "rack-a2"
          ],
          "notes": [
            "APC Switched PDU",
            "Per-outlet metering"
          ],
          "mac": "",
          "rackUnit": 1,
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "dc-rack-a2",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "cooling-1": {
          "shape": "rectangle",
          "name": "CRAC Unit 1",
          "ip": "192.168.200.30",
          "role": "Cooling",
          "tags": [
            "cooling",
            "hvac",
            "datacenter"
          ],
          "notes": [
            "Liebert CRV",
            "Row-based cooling"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "cooling-2": {
          "shape": "rectangle",
          "name": "CRAC Unit 2",
          "ip": "192.168.200.31",
          "role": "Cooling",
          "tags": [
            "cooling",
            "hvac",
            "datacenter"
          ],
          "notes": [
            "Liebert CRV",
            "N+1 redundancy"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        }
      },
      "edges": {
        "list": [
          {
            "id": "isp1-router1",
            "from": "isp-primary",
            "to": "core-router-1",
            "width": 6,
            "color": "#10b981",
            "direction": "both",
            "type": "main",
            "notes": [
              "Primary WAN link"
            ],
            "fromPort": "Gi0/0",
            "toPort": "Gi1/0/1",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "isp2-router2",
            "from": "isp-secondary",
            "to": "core-router-2",
            "width": 6,
            "color": "#10b981",
            "direction": "both",
            "type": "main",
            "notes": [
              "Backup WAN link"
            ],
            "fromPort": "Gi0/0",
            "toPort": "Gi1/0/1",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "router1-router2",
            "from": "core-router-1",
            "to": "core-router-2",
            "width": 4,
            "color": "#f59e0b",
            "direction": "both",
            "type": "main",
            "notes": [
              "HSRP Peering"
            ],
            "fromPort": "Gi1/0/24",
            "toPort": "Gi1/0/24",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "router1-fw1",
            "from": "core-router-1",
            "to": "fw-external-1",
            "width": 4,
            "color": "#ef4444",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "router2-fw2",
            "from": "core-router-2",
            "to": "fw-external-2",
            "width": 4,
            "color": "#ef4444",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "fw1-fw2",
            "from": "fw-external-1",
            "to": "fw-external-2",
            "width": 3,
            "color": "#f59e0b",
            "direction": "both",
            "type": "main",
            "notes": [
              "HA heartbeat"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "fw1-coresw1",
            "from": "fw-external-1",
            "to": "core-switch-1",
            "width": 4,
            "color": "#475569",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "fw2-coresw2",
            "from": "fw-external-2",
            "to": "core-switch-2",
            "width": 4,
            "color": "#475569",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw1-coresw2",
            "from": "core-switch-1",
            "to": "core-switch-2",
            "width": 5,
            "color": "#3b82f6",
            "direction": "both",
            "type": "main",
            "notes": [
              "VPC peer-link"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw1-fwint",
            "from": "core-switch-1",
            "to": "fw-internal",
            "width": 3,
            "color": "#ef4444",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw2-fwint",
            "from": "core-switch-2",
            "to": "fw-internal",
            "width": 3,
            "color": "#ef4444",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw1-racka1",
            "from": "core-switch-1",
            "to": "dc-rack-a1",
            "width": 4,
            "color": "#475569",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw2-racka1",
            "from": "core-switch-2",
            "to": "dc-rack-a1",
            "width": 4,
            "color": "#475569",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw1-racka2",
            "from": "core-switch-1",
            "to": "dc-rack-a2",
            "width": 4,
            "color": "#475569",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw2-racka2",
            "from": "core-switch-2",
            "to": "dc-rack-a2",
            "width": 4,
            "color": "#475569",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw1-rackb1",
            "from": "core-switch-1",
            "to": "dc-rack-b1",
            "width": 4,
            "color": "#475569",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw2-rackb1",
            "from": "core-switch-2",
            "to": "dc-rack-b1",
            "width": 4,
            "color": "#475569",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw1-rackb2",
            "from": "core-switch-1",
            "to": "dc-rack-b2",
            "width": 4,
            "color": "#475569",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw2-rackb2",
            "from": "core-switch-2",
            "to": "dc-rack-b2",
            "width": 4,
            "color": "#475569",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "fw1-dmz",
            "from": "fw-external-1",
            "to": "dmz-rack",
            "width": 3,
            "color": "#f59e0b",
            "direction": "both",
            "type": "main",
            "notes": [
              "DMZ segment"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "fw2-dmz",
            "from": "fw-external-2",
            "to": "dmz-rack",
            "width": 3,
            "color": "#f59e0b",
            "direction": "both",
            "type": "main",
            "notes": [
              "DMZ segment"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw1-mgmt",
            "from": "core-switch-1",
            "to": "mgmt-rack",
            "width": 3,
            "color": "#8b5cf6",
            "direction": "both",
            "type": "main",
            "notes": [
              "OOB management"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw1-wlc1",
            "from": "core-switch-1",
            "to": "wlc-primary",
            "width": 3,
            "color": "#06b6d4",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw2-wlc2",
            "from": "core-switch-2",
            "to": "wlc-secondary",
            "width": 3,
            "color": "#06b6d4",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "wlc1-wlc2",
            "from": "wlc-primary",
            "to": "wlc-secondary",
            "width": 2,
            "color": "#f59e0b",
            "direction": "both",
            "type": "main",
            "notes": [
              "HA pair"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "wlc1-mobile-hq",
            "from": "wlc-primary",
            "to": "mobile-zone-hq",
            "width": 2,
            "color": "#06b6d4",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "wlc1-mobile-guest",
            "from": "wlc-primary",
            "to": "mobile-zone-guest",
            "width": 2,
            "color": "#06b6d4",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "wlc1-mobile-iot",
            "from": "wlc-primary",
            "to": "mobile-zone-iot",
            "width": 2,
            "color": "#06b6d4",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "router1-branch-ny",
            "from": "core-router-1",
            "to": "branch-router-ny",
            "width": 3,
            "color": "#a855f7",
            "direction": "both",
            "type": "main",
            "notes": [
              "SD-WAN tunnel"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "router1-branch-la",
            "from": "core-router-1",
            "to": "branch-router-la",
            "width": 3,
            "color": "#a855f7",
            "direction": "both",
            "type": "main",
            "notes": [
              "SD-WAN tunnel"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "router1-branch-chi",
            "from": "core-router-1",
            "to": "branch-router-chi",
            "width": 3,
            "color": "#a855f7",
            "direction": "both",
            "type": "main",
            "notes": [
              "SD-WAN tunnel"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "router1-branch-lon",
            "from": "core-router-1",
            "to": "branch-router-lon",
            "width": 3,
            "color": "#a855f7",
            "direction": "both",
            "type": "main",
            "notes": [
              "SD-WAN tunnel"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "router1-branch-tokyo",
            "from": "core-router-1",
            "to": "branch-router-tokyo",
            "width": 3,
            "color": "#a855f7",
            "direction": "both",
            "type": "main",
            "notes": [
              "SD-WAN tunnel"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "router1-aws",
            "from": "core-router-1",
            "to": "cloud-aws",
            "width": 3,
            "color": "#f97316",
            "direction": "both",
            "type": "main",
            "notes": [
              "Direct Connect"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "router2-azure",
            "from": "core-router-2",
            "to": "cloud-azure",
            "width": 3,
            "color": "#0ea5e9",
            "direction": "both",
            "type": "main",
            "notes": [
              "ExpressRoute"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "fwint-gcp",
            "from": "fw-internal",
            "to": "cloud-gcp",
            "width": 2,
            "color": "#22c55e",
            "direction": "both",
            "type": "main",
            "notes": [
              "VPN tunnel"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw1-floor1",
            "from": "core-switch-1",
            "to": "dist-switch-floor1",
            "width": 3,
            "color": "#475569",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw1-floor2",
            "from": "core-switch-1",
            "to": "dist-switch-floor2",
            "width": 3,
            "color": "#475569",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw2-floor3",
            "from": "core-switch-2",
            "to": "dist-switch-floor3",
            "width": 3,
            "color": "#475569",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw2-floor4",
            "from": "core-switch-2",
            "to": "dist-switch-floor4",
            "width": 3,
            "color": "#475569",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "floor1-endpoints",
            "from": "dist-switch-floor1",
            "to": "endpoint-1000",
            "width": 2,
            "color": "#94a3b8",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "floor1-ap1",
            "from": "dist-switch-floor1",
            "to": "ap-floor1-zone1",
            "width": 2,
            "color": "#06b6d4",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "floor2-ap2",
            "from": "dist-switch-floor2",
            "to": "ap-floor2-zone1",
            "width": 2,
            "color": "#06b6d4",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "floor3-ap3",
            "from": "dist-switch-floor3",
            "to": "ap-floor3-zone1",
            "width": 2,
            "color": "#06b6d4",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "floor4-ap4",
            "from": "dist-switch-floor4",
            "to": "ap-floor4-zone1",
            "width": 2,
            "color": "#06b6d4",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "fwint-proxy1",
            "from": "fw-internal",
            "to": "proxy-server-1",
            "width": 2,
            "color": "#ef4444",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "fwint-proxy2",
            "from": "fw-internal",
            "to": "proxy-server-2",
            "width": 2,
            "color": "#ef4444",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "fwext1-vpn",
            "from": "fw-external-1",
            "to": "vpn-concentrator",
            "width": 3,
            "color": "#8b5cf6",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw1-nac",
            "from": "core-switch-1",
            "to": "nac-server",
            "width": 2,
            "color": "#f59e0b",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw1-voip",
            "from": "core-switch-1",
            "to": "voip-cluster",
            "width": 3,
            "color": "#22c55e",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw2-video",
            "from": "core-switch-2",
            "to": "video-conf",
            "width": 3,
            "color": "#22c55e",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw1-cameras",
            "from": "core-switch-1",
            "to": "security-cameras",
            "width": 2,
            "color": "#94a3b8",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "fwint-dev1",
            "from": "fw-internal",
            "to": "dev-server-1",
            "width": 2,
            "color": "#a855f7",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "fwint-dev2",
            "from": "fw-internal",
            "to": "dev-server-2",
            "width": 2,
            "color": "#a855f7",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "fwint-test",
            "from": "fw-internal",
            "to": "test-environment",
            "width": 2,
            "color": "#a855f7",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "coresw1-erp",
            "from": "core-switch-1",
            "to": "erp-system",
            "width": 3,
            "color": "#f59e0b",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "fwext1-crm",
            "from": "fw-external-1",
            "to": "crm-system",
            "width": 2,
            "color": "#f59e0b",
            "direction": "both",
            "type": "main",
            "notes": [
              "Salesforce cloud"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "ups1-racka1",
            "from": "ups-dc-1",
            "to": "dc-rack-a1",
            "width": 2,
            "color": "#fbbf24",
            "direction": "forward",
            "type": "main",
            "notes": [
              "Power feed A"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "ups2-racka2",
            "from": "ups-dc-2",
            "to": "dc-rack-a2",
            "width": 2,
            "color": "#fbbf24",
            "direction": "forward",
            "type": "main",
            "notes": [
              "Power feed B"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "ups1-rackb1",
            "from": "ups-dc-1",
            "to": "dc-rack-b1",
            "width": 2,
            "color": "#fbbf24",
            "direction": "forward",
            "type": "main",
            "notes": [
              "Power feed A"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "ups2-rackb2",
            "from": "ups-dc-2",
            "to": "dc-rack-b2",
            "width": 2,
            "color": "#fbbf24",
            "direction": "forward",
            "type": "main",
            "notes": [
              "Power feed B"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "cooling1-racka1",
            "from": "cooling-1",
            "to": "dc-rack-a1",
            "width": 2,
            "color": "#38bdf8",
            "direction": "forward",
            "type": "main",
            "notes": [
              "Cooling zone"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dotted",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "cooling2-rackb1",
            "from": "cooling-2",
            "to": "dc-rack-b1",
            "width": 2,
            "color": "#38bdf8",
            "direction": "forward",
            "type": "main",
            "notes": [
              "Cooling zone"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dotted",
            "_pairIndex": 0,
            "_pairTotal": 1,
            "routing": "orthogonal"
          },
          {
            "id": "custom-1765237881452",
            "type": "custom",
            "color": "#c800ff",
            "width": 4,
            "lineStyle": "solid",
            "direction": "forward",
            "points": [
              {
                "x": 3492.3994140625,
                "y": 1526.9556884765625
              },
              {
                "x": 3500.609619140625,
                "y": 1830.7386474609375
              },
              {
                "x": 3303.561279296875,
                "y": 1732.2144775390625
              }
            ],
            "notes": [],
            "routing": "orthogonal"
          }
        ]
      },
      "positions": {
        "core-router-1": {
          "x": 3720.166015625,
          "y": 245.9932403564453
        },
        "core-router-2": {
          "x": 2369.521102950803,
          "y": 215.57717236541498
        },
        "fw-external-1": {
          "x": 3221.7385182723783,
          "y": 1016.1364499992887
        },
        "fw-external-2": {
          "x": 1915.5213706410505,
          "y": 224.43528858865443
        },
        "fw-internal": {
          "x": 1746.9168185079352,
          "y": 477.5300527221864
        },
        "core-switch-1": {
          "x": 766.6909650929942,
          "y": 886.9286044043477
        },
        "core-switch-2": {
          "x": 1117.6501957527485,
          "y": 192.60411230209093
        },
        "dc-rack-a1": {
          "x": 527.2319059976107,
          "y": 1064.1709551070026
        },
        "dc-rack-a2": {
          "x": 284.2645846419273,
          "y": 199.327180682807
        },
        "dc-rack-b1": {
          "x": 3210.0403422634854,
          "y": 1676.0346361105321
        },
        "dc-rack-b2": {
          "x": 268.9195483475687,
          "y": 951.7132426303456
        },
        "dmz-rack": {
          "x": 2222.5242984873507,
          "y": 603.145536695888
        },
        "mgmt-rack": {
          "x": 1601.2987201807314,
          "y": 1281.4753424975324
        },
        "esxi-host-01": {
          "x": 2162.2166789540615,
          "y": 2608.110619289529
        },
        "esxi-host-02": {
          "x": 2205.94717202368,
          "y": 2689.67539624076
        },
        "esxi-host-03": {
          "x": 2154.6015436939074,
          "y": 2771.203009774913
        },
        "esxi-host-04": {
          "x": 2195.986926025096,
          "y": 2845
        },
        "tor-switch-a1": {
          "x": 2146.8943639962963,
          "y": 2845
        },
        "esxi-host-05": {
          "x": 2185.9099961569727,
          "y": 2845
        },
        "esxi-host-06": {
          "x": 2139.099728450725,
          "y": 2845
        },
        "esxi-host-07": {
          "x": 2175.7223818764883,
          "y": 2845
        },
        "esxi-host-08": {
          "x": 2131.2222777148922,
          "y": 2845
        },
        "tor-switch-a2": {
          "x": 2165.4301485385085,
          "y": 2845
        },
        "san-primary": {
          "x": 2123.2667017518106,
          "y": 2845
        },
        "san-secondary": {
          "x": 2155.0394237844876,
          "y": 2845
        },
        "fc-switch-1": {
          "x": 2115.2377370375634,
          "y": 2845
        },
        "fc-switch-2": {
          "x": 2144.5563938942755,
          "y": 2845
        },
        "backup-server-1": {
          "x": 2107.1401637413705,
          "y": 2845
        },
        "backup-server-2": {
          "x": 2133.987300103025,
          "y": 2845
        },
        "tape-library": {
          "x": 2098.9788028796397,
          "y": 2845
        },
        "tor-switch-b1": {
          "x": 2123.338434885373,
          "y": 2845
        },
        "tor-switch-b2": {
          "x": 2090.7585134456995,
          "y": 2845
        },
        "web-server-1": {
          "x": 2112.6161382091163,
          "y": 2845
        },
        "web-server-2": {
          "x": 2082.484189516922,
          "y": 2845
        },
        "waf-1": {
          "x": 2101.826793760617,
          "y": 2845
        },
        "load-balancer-dmz": {
          "x": 2074.1607573409574,
          "y": 2845
        },
        "mail-gateway": {
          "x": 2090.97682514417,
          "y": 2845
        },
        "dns-external-1": {
          "x": 2065.7931724028163,
          "y": 2845
        },
        "dns-external-2": {
          "x": 2080.0726920576153,
          "y": 2845
        },
        "vcenter": {
          "x": 2057.3864164745437,
          "y": 2845
        },
        "nsx-manager": {
          "x": 2069.1208864464534,
          "y": 2845
        },
        "siem-server": {
          "x": 2048.945494649244,
          "y": 2845
        },
        "nms-server": {
          "x": 2058.1279286387635,
          "y": 2845
        },
        "jump-server": {
          "x": 2040.4754323612206,
          "y": 2845
        },
        "ipam-server": {
          "x": 2047.1003634632284,
          "y": 2845
        },
        "wlc-primary": {
          "x": 1575.9723612611924,
          "y": 2306.135986328125
        },
        "wlc-secondary": {
          "x": 1468.1361870166274,
          "y": 1563.733642578125
        },
        "mobile-zone-hq": {
          "x": 2354.901177346808,
          "y": 2806.0078125
        },
        "mobile-zone-guest": {
          "x": 2307.6605605284435,
          "y": 2611.047119140625
        },
        "mobile-zone-iot": {
          "x": 2229.397686389302,
          "y": 2299.110107421875
        },
        "branch-router-ny": {
          "x": 3146.779566207714,
          "y": 633.6580810546875
        },
        "branch-router-la": {
          "x": 3083.8876194705945,
          "y": 506.90625
        },
        "branch-router-chi": {
          "x": 3355.02409980103,
          "y": 393.1805725097656
        },
        "branch-router-lon": {
          "x": 3113.609823320121,
          "y": 260.4093322753906
        },
        "branch-router-tokyo": {
          "x": 3699.3234994733834,
          "y": 471.4241027832031
        },
        "cloud-aws": {
          "x": 3439.090134242263,
          "y": 548.5233154296875
        },
        "cloud-azure": {
          "x": 2592.566210818907,
          "y": 2724.068115234375
        },
        "cloud-gcp": {
          "x": 2827.3183770424234,
          "y": 2731.397216796875
        },
        "isp-primary": {
          "x": 3712.192068081962,
          "y": 618.2117919921875
        },
        "isp-secondary": {
          "x": 2574.2854713754305,
          "y": 403.8440856933594
        },
        "dc-internal-1": {
          "x": 1958.4243458877936,
          "y": 2845
        },
        "dc-internal-2": {
          "x": 1963.768951182132,
          "y": 2845
        },
        "app-server-1": {
          "x": 1947.3819379304134,
          "y": 2845
        },
        "app-server-2": {
          "x": 1955.2862087394126,
          "y": 2845
        },
        "db-server-1": {
          "x": 1936.3708569559828,
          "y": 2845
        },
        "db-server-2": {
          "x": 1946.8300873488822,
          "y": 2845
        },
        "k8s-master-1": {
          "x": 1925.397658583093,
          "y": 2845
        },
        "k8s-master-2": {
          "x": 1938.405621494142,
          "y": 2845
        },
        "k8s-master-3": {
          "x": 1914.4688758763386,
          "y": 2845
        },
        "k8s-worker-1": {
          "x": 1930.017826812177,
          "y": 2845
        },
        "k8s-worker-2": {
          "x": 1903.5910154567553,
          "y": 2845
        },
        "k8s-worker-3": {
          "x": 1921.6716971072178,
          "y": 2845
        },
        "k8s-worker-4": {
          "x": 1892.7705536280016,
          "y": 2845
        },
        "proxy-server-1": {
          "x": 1806.1152433697903,
          "y": 653.7529296875
        },
        "proxy-server-2": {
          "x": 2937.4207928721535,
          "y": 2628.7880859375
        },
        "vpn-concentrator": {
          "x": 3642.252088474593,
          "y": 946.7255249023438
        },
        "nac-server": {
          "x": 1153.2626148502184,
          "y": 1172.1895751953125
        },
        "print-server": {
          "x": 1896.9328460745962,
          "y": 2845
        },
        "file-server": {
          "x": 1860.7177871362182,
          "y": 2845
        },
        "ca-server": {
          "x": 1888.8027739274805,
          "y": 2845
        },
        "sccm-server": {
          "x": 1850.1909418511675,
          "y": 2845
        },
        "voip-cluster": {
          "x": 1777.038465328039,
          "y": 1616.8961181640625
        },
        "video-conf": {
          "x": 1993.8373941679588,
          "y": 2244.936309814453
        },
        "security-cameras": {
          "x": 1674.413336949044,
          "y": 2046.0380859375
        },
        "nvr-cluster": {
          "x": 1829.4110389706402,
          "y": 2845
        },
        "dev-server-1": {
          "x": 2359.9473452212114,
          "y": 1480.4859619140625
        },
        "dev-server-2": {
          "x": 1934.8346596546826,
          "y": 1236.2509002685547
        },
        "test-environment": {
          "x": 2205.6861583047325,
          "y": 867.3496704101562
        },
        "erp-system": {
          "x": 864.9509620587212,
          "y": 1501.5821533203125
        },
        "crm-system": {
          "x": 3514.6003232048542,
          "y": 1137.7720947265625
        },
        "endpoint-1000": {
          "x": 991.6812012057328,
          "y": 2284.42236328125
        },
        "dist-switch-floor1": {
          "x": 654.2091033261356,
          "y": 2020.0086669921875
        },
        "dist-switch-floor2": {
          "x": 853.8845527112826,
          "y": 1843.2872314453125
        },
        "dist-switch-floor3": {
          "x": 1899.4353951584517,
          "y": 1456.5068359375
        },
        "dist-switch-floor4": {
          "x": 655.2108161412484,
          "y": 348.4529113769531
        },
        "ap-floor1-zone1": {
          "x": 1140.16846970184,
          "y": 2070.2916259765625
        },
        "ap-floor2-zone1": {
          "x": 688.1952143592268,
          "y": 2384.4775390625
        },
        "ap-floor3-zone1": {
          "x": 2145.3803027919676,
          "y": 1890.2816162109375
        },
        "ap-floor4-zone1": {
          "x": 433.53909074558646,
          "y": 692.0150146484375
        },
        "ups-dc-1": {
          "x": 588.0889513590637,
          "y": 1348.8856201171875
        },
        "ups-dc-2": {
          "x": 199.70106178535775,
          "y": 528.8150024414062
        },
        "pdu-rack-a1": {
          "x": 1804.774444371901,
          "y": 2845
        },
        "pdu-rack-a2": {
          "x": 1741.6184034693686,
          "y": 2845
        },
        "cooling-1": {
          "x": 326.61422338047237,
          "y": 1304.6719970703125
        },
        "cooling-2": {
          "x": 1603.293611085831,
          "y": 981.0621185302734
        }
      },
      "sizes": {},
      "styles": {
        "dc-rack-b2": {
          "all": {
            "circleColor": "#ff0000"
          }
        },
        "dc-rack-a1": {
          "all": {
            "circleColor": "#ff0000"
          }
        },
        "dc-rack-b1": {
          "all": {
            "circleColor": "#ff0000",
            "titleSize": 59
          }
        }
      },
      "legend": {
        "#10b981": "Trusted Lan",
        "#f59e0b": "Secure Lan",
        "#ef4444": "DMZ",
        "#475569": "Main ISP",
        "#3b82f6": "Alternate ISP",
        "#8b5cf6": "you can edit me too",
        "#06b6d4": "you can edit me too",
        "#a855f7": "you can edit me too",
        "#f97316": "you can edit me too",
        "#0ea5e9": "you can edit me too",
        "#22c55e": "you can edit me too",
        "#94a3b8": "you can edit me too",
        "#fbbf24": "you can edit me too",
        "#38bdf8": "you can edit me too",
        "#c800ff": "you can edit me too"
      },
      "rects": {
        "list": [
          {
            "id": "rect-1765237540610",
            "x": 2879.214599609375,
            "y": 159.71981811523438,
            "width": 992.196044921875,
            "height": 538.8650817871094,
            "color": "#f97316",
            "style": "filled",
            "lineStyle": "solid",
            "notes": []
          },
          {
            "id": "rect-1765237681216",
            "x": 448.3926696777344,
            "y": 1671.651123046875,
            "width": 916.3436584472656,
            "height": 924.27734375,
            "color": "#c800ff",
            "style": "outlined",
            "lineStyle": "solid",
            "notes": []
          }
        ]
      },
      "texts": {
        "list": [
          {
            "id": "text-1765237828167",
            "x": 3411.458740234375,
            "y": 1390.00439453125,
            "content": "Double click on desktop\nor long press on mobile\nto enter rack canvas view",
            "fontSize": 46,
            "color": "#e2e8f0",
            "fontWeight": "bold",
            "fontStyle": "italic",
            "textAlign": "middle",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          }
        ]
      },
      "pageState": {
        "title": "The One File Corporate",
        "background": "",
        "topbarBg": "rgba(9, 12, 20, 0.9)",
        "topbarBorder": "#1f2533",
        "panel": "#0b0e13",
        "panelAlt": "#10141b",
        "accent": "#4fd1c5",
        "sidebarBg": "#10141b",
        "btnBg": "#0b0e13",
        "btnText": "#e2e8f0",
        "tagFill": "#1e293b",
        "tagText": "#e2e8f0",
        "tagBorder": "#475569",
        "inputBg": "#0b0e13",
        "inputText": "#e2e8f0",
        "inputBorder": "#1f2937",
        "inputFont": "Inter, system-ui, sans-serif",
        "inputFontSize": 14,
        "toolbarBg": "#0f172a",
        "toolbarBorder": "#1f2937",
        "toolbarText": "#94a3b8",
        "toolbarBtnBg": "#0b0e13",
        "toolbarBtnText": "#e2e8f0",
        "minimapDots": "#94a3b8",
        "canvasHintEnabled": true,
        "canvasHintText": "",
        "canvasHintBg": "#0f172a",
        "canvasHintColor": "#94a3b8",
        "danger": "#f56565",
        "textMain": "#e2e8f0",
        "textSoft": "#94a3b8",
        "topbarHeight": 113,
        "sidebarWidth": 350,
        "mobileFooterHeight": 40,
        "sidebarCollapsed": false,
        "nodeFill": "#1e293b",
        "nodeStroke": "#475569",
        "nodeTitle": "#e2e8f0",
        "nodeSub": "#94a3b8",
        "nodeTitleSize": 41,
        "nodeSubSize": 27,
        "nodeFont": "monospace",
        "defaultEdge": "#475569",
        "selectionHandle": "#f59e0b",
        "selectionHandleSize": 8,
        "groupIndicator": "#4fd1c5",
        "canvasGradientTop": "#1e2532",
        "canvasGradientBottom": "#050608",
        "canvasBorder": "#475569",
        "canvasGrid": "#475569",
        "canvasGridSize": 50,
        "rackFrameFill": "#0f172a",
        "rackFrameStroke": "#4fd1c5",
        "rackLineColor": "#475569",
        "rackTextColor": "#4fd1c5",
        "viewOnly": false,
        "defaultEdgeRouting": "orthogonal"
      }
    },
    {
      "id": "tab-1765235136918",
      "name": "Homelab 2",
      "nodes": {
        "internet": {
          "shape": "square",
          "name": "Internet",
          "ip": "0.0.0.0",
          "role": "",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "internet-copy": {
          "shape": "firewall",
          "name": "OPNSENSE",
          "ip": "0.0.0.0",
          "role": "",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "opnsense-copy": {
          "shape": "firewall",
          "name": "Docker",
          "ip": "0.0.0.0",
          "role": "",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "docker-copy": {
          "shape": "firewall",
          "name": "Docker2",
          "ip": "0.0.0.0",
          "role": "",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "docker-copy-1": {
          "shape": "firewall",
          "name": "Docker3",
          "ip": "0.0.0.0",
          "role": "",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "docker-copy-2": {
          "shape": "firewall",
          "name": "Docker 4",
          "ip": "0.0.0.0",
          "role": "",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "opnsense-copy-1": {
          "shape": "firewall",
          "name": "OPNSENSE GUEST",
          "ip": "0.0.0.0",
          "role": "",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "phone": {
          "shape": "phone",
          "name": "Phone",
          "ip": "0.0.0.0",
          "role": "",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "desktop": {
          "shape": "pc",
          "name": "Desktop",
          "ip": "0.0.0.0",
          "role": "",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "dns": {
          "shape": "cloud",
          "name": "DNS",
          "ip": "0.0.0.0",
          "role": "",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": false,
          "locked": false,
          "groupId": null
        },
        "racked": {
          "shape": "server",
          "name": "Racked",
          "ip": "",
          "role": "Rack",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "physical",
          "assignedRack": "",
          "rackCapacity": "42",
          "isRack": true,
          "locked": false,
          "groupId": null
        }
      },
      "edges": {
        "list": [
          {
            "id": "internet-internet-copy-1765238145151",
            "from": "internet",
            "to": "internet-copy",
            "width": 4,
            "color": "#55e208",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "internet-copy-opnsense-copy-1765238187451",
            "from": "internet-copy",
            "to": "opnsense-copy",
            "width": 4,
            "color": "#4c00ff",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "internet-copy-docker-copy-1765238242477",
            "from": "internet-copy",
            "to": "docker-copy",
            "width": 4,
            "color": "#4c00ff",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "internet-copy-docker-copy-1-1765238244637",
            "from": "internet-copy",
            "to": "docker-copy-1",
            "width": 4,
            "color": "#4c00ff",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "internet-copy-docker-copy-2-1765238246233",
            "from": "internet-copy",
            "to": "docker-copy-2",
            "width": 4,
            "color": "#4c00ff",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "internet-opnsense-copy-1-1765238266117",
            "from": "internet",
            "to": "opnsense-copy-1",
            "width": 4,
            "color": "#80ff00",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "opnsense-copy-1-dns-1765238347996",
            "from": "opnsense-copy-1",
            "to": "dns",
            "width": 4,
            "color": "#fb00ff",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "dns-desktop-1765238386101",
            "from": "dns",
            "to": "desktop",
            "width": 4,
            "color": "#ff00d0",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "phone-dns-1765238391156",
            "from": "phone",
            "to": "dns",
            "width": 4,
            "color": "#ff00d0",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "custom-1765238841477",
            "type": "custom",
            "color": "#f97316",
            "width": 4,
            "lineStyle": "solid",
            "direction": "both",
            "points": [
              {
                "x": 2905.255615234375,
                "y": 805.3433837890625
              },
              {
                "x": 3189.95556640625,
                "y": 1005.8710327148438
              },
              {
                "x": 2788.900390625,
                "y": 1008.3466796875
              }
            ],
            "notes": []
          }
        ]
      },
      "positions": {
        "internet": {
          "x": 2071.640165880771,
          "y": 218.24354238566275
        },
        "internet-copy": {
          "x": 2066.9677515897347,
          "y": 473.4119134177565
        },
        "opnsense-copy": {
          "x": 1775.6360865506722,
          "y": 668.3718438376784
        },
        "docker-copy": {
          "x": 1934.7898139534577,
          "y": 782.2775961320921
        },
        "docker-copy-1": {
          "x": 2158.1262397347077,
          "y": 767.7122274797483
        },
        "docker-copy-2": {
          "x": 2345.8584174690827,
          "y": 631.7681967180296
        },
        "opnsense-copy-1": {
          "x": 2757.879480087803,
          "y": 307.6117116091891
        },
        "phone": {
          "x": 3312.857751572178,
          "y": 502.58220111114224
        },
        "desktop": {
          "x": 2987.696130478428,
          "y": 487.5842152712985
        },
        "dns": {
          "x": 3200.4643189549906,
          "y": 320.469591247861
        },
        "racked": {
          "x": 2600.8697010779656,
          "y": 975.5665527522032
        }
      },
      "sizes": {
        "core-router-1": 36,
        "internet": 85,
        "phone": 121,
        "desktop": 147,
        "racked": 137
      },
      "styles": {},
      "legend": {
        "#475569": "you can edit me too",
        "#65758b": "you can edit me too",
        "#63748c": "you can edit me too",
        "#5e6f87": "you can edit me too",
        "#586a84": "you can edit me too",
        "#4f627d": "you can edit me too",
        "#455873": "you can edit me too",
        "#3d506c": "you can edit me too",
        "#354964": "you can edit me too",
        "#2e415c": "you can edit me too",
        "#293c56": "you can edit me too",
        "#273a53": "you can edit me too",
        "#253750": "you can edit me too",
        "#23354d": "you can edit me too",
        "#203046": "you can edit me too",
        "#1e2d43": "you can edit me too",
        "#1a283d": "you can edit me too",
        "#172435": "you can edit me too",
        "#141f2e": "you can edit me too",
        "#111a27": "you can edit me too",
        "#0f1824": "you can edit me too",
        "#0d1521": "you can edit me too",
        "#0c131d": "you can edit me too",
        "#0c1d1c": "you can edit me too",
        "#0c1c1d": "you can edit me too",
        "#0c191d": "you can edit me too",
        "#0c141d": "you can edit me too",
        "#0c0d1d": "you can edit me too",
        "#130c1d": "you can edit me too",
        "#1b0c1d": "you can edit me too",
        "#1d0c17": "you can edit me too",
        "#1d0c10": "you can edit me too",
        "#1d0c0c": "you can edit me too",
        "#3b1b1b": "you can edit me too",
        "#3c1a1a": "you can edit me too",
        "#3f1c1c": "you can edit me too",
        "#401c1c": "you can edit me too",
        "#451c1c": "you can edit me too",
        "#461b1b": "you can edit me too",
        "#4c1a1a": "you can edit me too",
        "#521919": "you can edit me too",
        "#571919": "you can edit me too",
        "#5d1818": "you can edit me too",
        "#631717": "you can edit me too",
        "#651515": "you can edit me too",
        "#6a1616": "you can edit me too",
        "#6f1515": "you can edit me too",
        "#711414": "you can edit me too",
        "#761414": "you can edit me too",
        "#771313": "you can edit me too",
        "#7c1313": "you can edit me too",
        "#811313": "you can edit me too",
        "#821212": "you can edit me too",
        "#871212": "you can edit me too",
        "#881111": "you can edit me too",
        "#8d1111": "you can edit me too",
        "#8e1010": "you can edit me too",
        "#8f0f0f": "you can edit me too",
        "#900e0e": "you can edit me too",
        "#8e0b0b": "you can edit me too",
        "#8c0d0d": "you can edit me too",
        "#880c0c": "you can edit me too",
        "#830c0c": "you can edit me too",
        "#7e0c0c": "you can edit me too",
        "#790c0c": "you can edit me too",
        "#730c0c": "you can edit me too",
        "#6f0b0b": "you can edit me too",
        "#0b6f64": "you can edit me too",
        "#0b6f5f": "you can edit me too",
        "#0b6f56": "you can edit me too",
        "#0b6f49": "you can edit me too",
        "#0b6f31": "you can edit me too",
        "#0b6f1f": "you can edit me too",
        "#0b6f0d": "you can edit me too",
        "#176f0b": "you can edit me too",
        "#266f0b": "you can edit me too",
        "#296f0b": "you can edit me too",
        "#2e6f0b": "you can edit me too",
        "#1a2d10": "you can edit me too",
        "#1c3111": "you can edit me too",
        "#213814": "you can edit me too",
        "#233c15": "you can edit me too",
        "#254017": "you can edit me too",
        "#294918": "you can edit me too",
        "#2b4d1a": "you can edit me too",
        "#2d511a": "you can edit me too",
        "#315a1b": "you can edit me too",
        "#35631c": "you can edit me too",
        "#37681d": "you can edit me too",
        "#3b721d": "you can edit me too",
        "#3f7b1e": "you can edit me too",
        "#42851e": "you can edit me too",
        "#46901d": "you can edit me too",
        "#499a1d": "you can edit me too",
        "#4b9f1d": "you can edit me too",
        "#4ca61c": "you can edit me too",
        "#50b01c": "you can edit me too",
        "#51b71a": "you can edit me too",
        "#50b918": "you can edit me too",
        "#51c115": "you can edit me too",
        "#53c615": "you can edit me too",
        "#53c814": "you can edit me too",
        "#52c913": "you can edit me too",
        "#54d011": "you can edit me too",
        "#53d110": "you can edit me too",
        "#55d510": "you can edit me too",
        "#55d70f": "you can edit me too",
        "#54d80e": "you can edit me too",
        "#54da0b": "you can edit me too",
        "#56df0c": "you can edit me too",
        "#53db0a": "you can edit me too",
        "#55e00b": "you can edit me too",
        "#55e109": "you can edit me too",
        "#55e208": "ISP LINE",
        "#4c00ff": "MY Guest NETWORK",
        "#80ff00": "you can edit me too",
        "#3b4234": "you can edit me too",
        "#3a3442": "you can edit me too",
        "#3b3442": "you can edit me too",
        "#3c3442": "you can edit me too",
        "#3d3442": "you can edit me too",
        "#3e3442": "you can edit me too",
        "#3f3442": "you can edit me too",
        "#403442": "you can edit me too",
        "#413442": "you can edit me too",
        "#653d66": "you can edit me too",
        "#683f69": "you can edit me too",
        "#6c416c": "you can edit me too",
        "#6f4370": "you can edit me too",
        "#704270": "you can edit me too",
        "#734474": "you can edit me too",
        "#784479": "you can edit me too",
        "#7d447e": "you can edit me too",
        "#7e437f": "you can edit me too",
        "#834384": "you can edit me too",
        "#844285": "you can edit me too",
        "#89418b": "you can edit me too",
        "#8e428f": "you can edit me too",
        "#904091": "you can edit me too",
        "#923e93": "you can edit me too",
        "#973e98": "you can edit me too",
        "#943c96": "you can edit me too",
        "#993c9a": "you can edit me too",
        "#963a98": "you can edit me too",
        "#973899": "you can edit me too",
        "#99369b": "you can edit me too",
        "#9a359c": "you can edit me too",
        "#9b349d": "you can edit me too",
        "#9d329f": "you can edit me too",
        "#9e31a0": "you can edit me too",
        "#a02fa2": "you can edit me too",
        "#9d2d9f": "you can edit me too",
        "#9f2ba1": "you can edit me too",
        "#a129a3": "you can edit me too",
        "#a327a5": "you can edit me too",
        "#a525a7": "you can edit me too",
        "#a723a9": "you can edit me too",
        "#a921ab": "you can edit me too",
        "#ab1fad": "you can edit me too",
        "#ad1daf": "you can edit me too",
        "#ae1cb0": "you can edit me too",
        "#b019b3": "you can edit me too",
        "#b118b4": "you can edit me too",
        "#b316b6": "you can edit me too",
        "#b816bb": "you can edit me too",
        "#b514b8": "you can edit me too",
        "#ba14bd": "you can edit me too",
        "#b712ba": "you can edit me too",
        "#bb13be": "you can edit me too",
        "#b811bb": "you can edit me too",
        "#be10c1": "you can edit me too",
        "#bb0ebe": "you can edit me too",
        "#bd0cc0": "you can edit me too",
        "#be0bc1": "you can edit me too",
        "#c108c4": "you can edit me too",
        "#be06c1": "you can edit me too",
        "#c103c4": "you can edit me too",
        "#c301c6": "you can edit me too",
        "#c400c7": "you can edit me too",
        "#c900cc": "you can edit me too",
        "#ce00d1": "you can edit me too",
        "#d300d6": "you can edit me too",
        "#d800db": "you can edit me too",
        "#dd00e0": "you can edit me too",
        "#e200e6": "you can edit me too",
        "#ec00f0": "you can edit me too",
        "#f100f5": "you can edit me too",
        "#f600fa": "you can edit me too",
        "#fb00ff": "you can edit me too",
        "#ff00d0": "iPhone (always guest iPhone)",
        "#f97316": "you can edit me too"
      },
      "rects": {
        "list": [
          {
            "id": "rect-1765238219615",
            "x": 2680.053955078125,
            "y": 251.44879150390625,
            "width": 814.10400390625,
            "height": 389.26678466796875,
            "color": "#ec0999",
            "style": "filled",
            "lineStyle": "solid",
            "notes": []
          }
        ]
      },
      "texts": {
        "list": [
          {
            "id": "text-1765238422602",
            "x": 2402.130859375,
            "y": 736.7828979492188,
            "content": "Double click on desktop\nor long press on mobile\nto enter rack canvas view",
            "fontSize": 48,
            "color": "#e2e8f0",
            "fontWeight": "normal",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          }
        ]
      },
      "pageState": {
        "title": "The One File",
        "background": "",
        "topbarBg": "rgba(9, 12, 20, 0.9)",
        "topbarBorder": "#1f2533",
        "panel": "#2f0e0e",
        "panelAlt": "#10141b",
        "accent": "#a75252",
        "sidebarBg": "#10141b",
        "btnBg": "#0b0e13",
        "btnText": "#e2e8f0",
        "tagFill": "#1e293b",
        "tagText": "#e2e8f0",
        "tagBorder": "#475569",
        "inputBg": "#0b0e13",
        "inputText": "#e2e8f0",
        "inputBorder": "#1f2937",
        "inputFont": "Inter, system-ui, sans-serif",
        "inputFontSize": 14,
        "toolbarBg": "#441215",
        "toolbarBorder": "#1f2937",
        "toolbarText": "#94a3b8",
        "toolbarBtnBg": "#0b0e13",
        "toolbarBtnText": "#e2e8f0",
        "minimapDots": "#94a3b8",
        "canvasHintEnabled": true,
        "canvasHintText": "",
        "canvasHintBg": "#0f172a",
        "canvasHintColor": "#94a3b8",
        "danger": "#f56565",
        "textMain": "#e2e8f0",
        "textSoft": "#94a3b8",
        "topbarHeight": 112,
        "sidebarWidth": 350,
        "mobileFooterHeight": 40,
        "sidebarCollapsed": false,
        "nodeFill": "#1e293b",
        "nodeStroke": "#475569",
        "nodeTitle": "#e2e8f0",
        "nodeSub": "#94a3b8",
        "nodeTitleSize": 18,
        "nodeSubSize": 13,
        "nodeFont": "Inter, system-ui, sans-serif",
        "defaultEdge": "#475569",
        "selectionHandle": "#f59e0b",
        "selectionHandleSize": 8,
        "groupIndicator": "#4fd1c5",
        "canvasGradientTop": "#1e2532",
        "canvasGradientBottom": "#050608",
        "canvasBorder": "#475569",
        "canvasGrid": "#475569",
        "canvasGridSize": 50,
        "rackFrameFill": "#0f172a",
        "rackFrameStroke": "#4fd1c5",
        "rackLineColor": "#475569",
        "rackTextColor": "#4fd1c5",
        "viewOnly": false,
        "defaultEdgeRouting": "curved"
      }
    }
  ],
  "currentTabIndex": 0,
  "encryptedSections": {},
  "auditLog": [
    {
      "timestamp": 1766190386262,
      "type": "save",
      "description": "File saved: the-one-file-corporate.html",
      "details": {},
      "tab": "Corporate Site B"
    },
    {
      "timestamp": 1766190382903,
      "type": "tab",
      "description": "Switched to tab: Corporate Site B",
      "details": {},
      "tab": "Corporate Site B"
    },
    {
      "timestamp": 1766190372732,
      "type": "save",
      "description": "File saved: the-one-file.html",
      "details": {},
      "tab": "Homelab 2"
    },
    {
      "timestamp": 1766190356740,
      "type": "export",
      "description": "Exported JSON: the-one-file.json",
      "details": {},
      "tab": "Homelab 2"
    },
    {
      "timestamp": 1766190353695,
      "type": "tab",
      "description": "Switched to tab: Homelab 2",
      "details": {},
      "tab": "Homelab 2"
    },
    {
      "timestamp": 1766190348545,
      "type": "export",
      "description": "Exported JSON: the-one-file-corporate.json",
      "details": {},
      "tab": "Corporate Site B"
    },
    {
      "timestamp": 1766190340714,
      "type": "save",
      "description": "File saved: the-one-file-corporate.html",
      "details": {},
      "tab": "Corporate Site B"
    },
    {
      "timestamp": 1766190337770,
      "type": "node",
      "description": "apply routing to all",
      "details": {},
      "tab": "Corporate Site B"
    },
    {
      "timestamp": 1766190327814,
      "type": "tab",
      "description": "Switched to tab: Corporate Site B",
      "details": {},
      "tab": "Corporate Site B"
    },
    {
      "timestamp": 1766190321554,
      "type": "save",
      "description": "File saved: the-one-file.html",
      "details": {},
      "tab": "Homelab 2"
    },
    {
      "timestamp": 1766190320188,
      "type": "tab",
      "description": "Switched to tab: Homelab 2",
      "details": {},
      "tab": "Homelab 2"
    },
    {
      "timestamp": 1766190293090,
      "type": "save",
      "description": "File saved: the-one-file-corporate.html",
      "details": {},
      "tab": "Corporate Site B"
    },
    {
      "timestamp": 1766190290259,
      "type": "import",
      "description": "Imported JSON: the-one-file-corporate-demo.json (105 nodes, 64 connections)",
      "details": {},
      "tab": "Corporate Site B"
    },
    {
      "timestamp": 1766022128543,
      "type": "tab",
      "description": "Switched to tab: Corporate Site B",
      "details": {},
      "tab": "Corporate Site B"
    },
    {
      "timestamp": 1766022121954,
      "type": "export",
      "description": "Exported JSON: the-one-file-data-2025-12-18.json",
      "details": {},
      "tab": "Homelab 2"
    },
    {
      "timestamp": 1766022111697,
      "type": "save",
      "description": "File saved: the-one-file.html",
      "details": {},
      "tab": "Homelab 2"
    },
    {
      "timestamp": 1766022108613,
      "type": "save",
      "description": "File saved: the-one-file.html",
      "details": {},
      "tab": "Homelab 2"
    },
    {
      "timestamp": 1766022105579,
      "type": "tab",
      "description": "Switched to tab: Homelab 2",
      "details": {},
      "tab": "Homelab 2"
    },
    {
      "timestamp": 1766022100565,
      "type": "save",
      "description": "File saved: the-one-file-corporate.html",
      "details": {},
      "tab": "Corporate Site B"
    },
    {
      "timestamp": 1766022093656,
      "type": "save",
      "description": "File saved: the-one-file-corporate.html",
      "details": {},
      "tab": "Corporate Site B"
    },
    {
      "timestamp": 1766022075148,
      "type": "save",
      "description": "File saved: the-one-file-corporate.html",
      "details": {},
      "tab": "Corporate Site B"
    },
    {
      "timestamp": 1766022066503,
      "type": "import",
      "description": "Imported JSON: the-one-file-corporate-demo.json (105 nodes, 64 connections)",
      "details": {},
      "tab": "Corporate Site B"
    },
    {
      "timestamp": 1765402929770,
      "type": "tab",
      "description": "Switched to tab: Corporate Site B",
      "details": {},
      "tab": "Corporate Site B"
    },
    {
      "timestamp": 1765402922300,
      "type": "export",
      "description": "Exported JSON: the-one-file-data-2025-12-10.json",
      "details": {},
      "tab": "Homelab 2"
    },
    {
      "timestamp": 1765402914493,
      "type": "save",
      "description": "File saved: the-one-file.html",
      "details": {},
      "tab": "Homelab 2"
    },
    {
      "timestamp": 1765402910921,
      "type": "tab",
      "description": "Switched to tab: Homelab 2",
      "details": {},
      "tab": "Homelab 2"
    },
    {
      "timestamp": 1765402904206,
      "type": "save",
      "description": "File saved: the-one-file-corporate.html",
      "details": {},
      "tab": "Corporate Site B"
    },
    {
      "timestamp": 1765402899387,
      "type": "import",
      "description": "Imported JSON: the-one-file-corporate-demo.json (105 nodes, 64 connections)",
      "details": {},
      "tab": "Corporate Site B"
    },
    {
      "timestamp": 1765402888416,
      "type": "save",
      "description": "File saved: the-one-file-corporate.html",
      "details": {},
      "tab": "Corporate Site B"
    },
    {
      "timestamp": 1765402884873,
      "type": "tab",
      "description": "Switched to tab: Corporate Site B",
      "details": {},
      "tab": "Corporate Site B"
    },
    {
      "timestamp": 1765402878108,
      "type": "save",
      "description": "File saved: the-one-file.html",
      "details": {},
      "tab": "Homelab 2"
    },
    {
      "timestamp": 1765402866440,
      "type": "save",
      "description": "File saved: the-one-file.html",
      "details": {},
      "tab": "Homelab 2"
    },
    {
      "timestamp": 1765402865008,
      "type": "tab",
      "description": "Switched to tab: Homelab 2",
      "details": {},
      "tab": "Homelab 2"
    },
    {
      "timestamp": 1765402860428,
      "type": "save",
      "description": "File saved: the-one-file-corporate.html",
      "details": {},
      "tab": "Corporate Site B"
    },
    {
      "timestamp": 1765402858103,
      "type": "import",
      "description": "Imported JSON: theonefile-networkening-corporate-demo.json (105 nodes, 65 connections)",
      "details": {},
      "tab": "Corporate Site B"
    }
  ]
}
THEONEFILE_CONFIG-->

# The One File Corporate

> Exported from The One File on 2025-12-20T00:27:39.487Z

## Legend

- #10b981: Trusted Lan
- #f59e0b: Secure Lan
- #ef4444: DMZ
- #475569: Main ISP
- #3b82f6: Alternate ISP
- #8b5cf6: you can edit me too
- #06b6d4: you can edit me too
- #a855f7: you can edit me too
- #f97316: you can edit me too
- #0ea5e9: you can edit me too
- #22c55e: you can edit me too
- #94a3b8: you can edit me too
- #fbbf24: you can edit me too
- #38bdf8: you can edit me too
- #c800ff: you can edit me too

## Nodes

### core-router-1
- **Name:** Core Router 1
- **IP:** 10.0.0.1
- **Role:** Core Routing
- **Shape:** router
- **Tags:** core; tier-1; redundant
- **Layer:** physical
- **MAC:** 00:1A:2B:3C:4D:01
- **Rack Unit:** 
- **U Height:** 2
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 3720, 246
- **Size:** 50
- **Notes:**
  - Primary core router
  - BGP peering enabled

### core-router-2
- **Name:** Core Router 2
- **IP:** 10.0.0.2
- **Role:** Core Routing
- **Shape:** router
- **Tags:** core; tier-1; redundant
- **Layer:** physical
- **MAC:** 00:1A:2B:3C:4D:02
- **Rack Unit:** 
- **U Height:** 2
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2370, 216
- **Size:** 50
- **Notes:**
  - Secondary core router
  - HSRP standby

### fw-external-1
- **Name:** External FW 1
- **IP:** 10.0.1.1
- **Role:** Perimeter Security
- **Shape:** firewall
- **Tags:** security; perimeter; ha-pair
- **Layer:** security
- **MAC:** 00:1A:2B:3C:4D:10
- **Rack Unit:** 
- **U Height:** 2
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 3222, 1016
- **Size:** 50
- **Notes:**
  - Palo Alto PA-5250
  - Active node

### fw-external-2
- **Name:** External FW 2
- **IP:** 10.0.1.2
- **Role:** Perimeter Security
- **Shape:** firewall
- **Tags:** security; perimeter; ha-pair
- **Layer:** security
- **MAC:** 00:1A:2B:3C:4D:11
- **Rack Unit:** 
- **U Height:** 2
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1916, 224
- **Size:** 50
- **Notes:**
  - Palo Alto PA-5250
  - Passive node

### fw-internal
- **Name:** Internal FW
- **IP:** 10.0.2.1
- **Role:** Internal Segmentation
- **Shape:** firewall
- **Tags:** security; internal
- **Layer:** security
- **MAC:** 00:1A:2B:3C:4D:12
- **Rack Unit:** 
- **U Height:** 2
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1747, 478
- **Size:** 50
- **Notes:**
  - East-West traffic inspection

### core-switch-1
- **Name:** Core Switch 1
- **IP:** 10.0.10.1
- **Role:** Core Switching
- **Shape:** switch
- **Tags:** core; layer3; redundant
- **Layer:** physical
- **MAC:** 00:1A:2B:3C:4D:20
- **Rack Unit:** 
- **U Height:** 2
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 767, 887
- **Size:** 50
- **Notes:**
  - Cisco Nexus 9000
  - VPC Domain 1

### core-switch-2
- **Name:** Core Switch 2
- **IP:** 10.0.10.2
- **Role:** Core Switching
- **Shape:** switch
- **Tags:** core; layer3; redundant
- **Layer:** physical
- **MAC:** 00:1A:2B:3C:4D:21
- **Rack Unit:** 
- **U Height:** 2
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1118, 193
- **Size:** 50
- **Notes:**
  - Cisco Nexus 9000
  - VPC Domain 1

### dc-rack-a1
- **Name:** DC Rack A1
- **IP:** 10.10.0.0/24
- **Role:** Data Center Rack
- **Shape:** server
- **Tags:** datacenter; row-a; production
- **Layer:** physical
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** true
- **Locked:** false
- **Group ID:** 
- **Position:** 527, 1064
- **Size:** 50
- **Notes:**
  - Row A, Position 1
  - Primary compute
- **Styles:** `{"all":{"circleColor":"#ff0000"}}`

### dc-rack-a2
- **Name:** DC Rack A2
- **IP:** 10.10.1.0/24
- **Role:** Data Center Rack
- **Shape:** server
- **Tags:** datacenter; row-a; production
- **Layer:** physical
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** true
- **Locked:** false
- **Group ID:** 
- **Position:** 284, 199
- **Size:** 50
- **Notes:**
  - Row A, Position 2
  - Primary compute

### dc-rack-b1
- **Name:** DC Rack B1
- **IP:** 10.10.2.0/24
- **Role:** Data Center Rack
- **Shape:** server
- **Tags:** datacenter; row-b; storage
- **Layer:** physical
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** true
- **Locked:** false
- **Group ID:** 
- **Position:** 3210, 1676
- **Size:** 50
- **Notes:**
  - Row B, Position 1
  - Storage systems
- **Styles:** `{"all":{"circleColor":"#ff0000","titleSize":59}}`

### dc-rack-b2
- **Name:** DC Rack B2
- **IP:** 10.10.3.0/24
- **Role:** Data Center Rack
- **Shape:** server
- **Tags:** datacenter; row-b; storage
- **Layer:** physical
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** true
- **Locked:** false
- **Group ID:** 
- **Position:** 269, 952
- **Size:** 50
- **Notes:**
  - Row B, Position 2
  - Storage systems
- **Styles:** `{"all":{"circleColor":"#ff0000"}}`

### dmz-rack
- **Name:** DMZ Rack
- **IP:** 172.16.0.0/24
- **Role:** DMZ Infrastructure
- **Shape:** server
- **Tags:** dmz; security; public-facing
- **Layer:** security
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 24
- **Is Rack:** true
- **Locked:** false
- **Group ID:** 
- **Position:** 2223, 603
- **Size:** 50
- **Notes:**
  - Isolated DMZ zone
  - Public-facing services

### mgmt-rack
- **Name:** Management Rack
- **IP:** 192.168.100.0/24
- **Role:** Management Infrastructure
- **Shape:** server
- **Tags:** management; oob; noc
- **Layer:** logical
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 24
- **Is Rack:** true
- **Locked:** false
- **Group ID:** 
- **Position:** 1601, 1281
- **Size:** 50
- **Notes:**
  - Out-of-band management
  - NOC equipment

### esxi-host-01
- **Name:** ESXi Host 01
- **IP:** 10.10.0.11
- **Role:** Hypervisor
- **Shape:** server
- **Tags:** vmware; compute; cluster-a
- **Layer:** physical
- **MAC:** 00:50:56:AA:01:01
- **Rack Unit:** 38
- **U Height:** 2
- **Assigned Rack:** dc-rack-a1
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2162, 2608
- **Size:** 50
- **Notes:**
  - Dell PowerEdge R750
  - 512GB RAM
  - vSphere 8.0

### esxi-host-02
- **Name:** ESXi Host 02
- **IP:** 10.10.0.12
- **Role:** Hypervisor
- **Shape:** server
- **Tags:** vmware; compute; cluster-a
- **Layer:** physical
- **MAC:** 00:50:56:AA:01:02
- **Rack Unit:** 35
- **U Height:** 2
- **Assigned Rack:** dc-rack-a1
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2206, 2690
- **Size:** 50
- **Notes:**
  - Dell PowerEdge R750
  - 512GB RAM
  - vSphere 8.0

### esxi-host-03
- **Name:** ESXi Host 03
- **IP:** 10.10.0.13
- **Role:** Hypervisor
- **Shape:** server
- **Tags:** vmware; compute; cluster-a
- **Layer:** physical
- **MAC:** 00:50:56:AA:01:03
- **Rack Unit:** 32
- **U Height:** 2
- **Assigned Rack:** dc-rack-a1
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2155, 2771
- **Size:** 50
- **Notes:**
  - Dell PowerEdge R750
  - 512GB RAM
  - vSphere 8.0

### esxi-host-04
- **Name:** ESXi Host 04
- **IP:** 10.10.0.14
- **Role:** Hypervisor
- **Shape:** server
- **Tags:** vmware; compute; cluster-a
- **Layer:** physical
- **MAC:** 00:50:56:AA:01:04
- **Rack Unit:** 29
- **U Height:** 2
- **Assigned Rack:** dc-rack-a1
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2196, 2845
- **Size:** 50
- **Notes:**
  - Dell PowerEdge R750
  - 512GB RAM
  - vSphere 8.0

### tor-switch-a1
- **Name:** ToR Switch A1
- **IP:** 10.10.0.1
- **Role:** Top of Rack
- **Shape:** switch
- **Tags:** tor; access; rack-a1
- **Layer:** physical
- **MAC:** 00:1A:2B:3C:5D:01
- **Rack Unit:** 42
- **U Height:** 1
- **Assigned Rack:** dc-rack-a1
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2147, 2845
- **Size:** 50
- **Notes:**
  - Cisco Nexus 93180YC-FX
  - 48x25G ports

### esxi-host-05
- **Name:** ESXi Host 05
- **IP:** 10.10.1.11
- **Role:** Hypervisor
- **Shape:** server
- **Tags:** vmware; compute; cluster-b
- **Layer:** physical
- **MAC:** 00:50:56:AA:02:01
- **Rack Unit:** 38
- **U Height:** 2
- **Assigned Rack:** dc-rack-a2
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2186, 2845
- **Size:** 50
- **Notes:**
  - Dell PowerEdge R750
  - 768GB RAM
  - vSphere 8.0

### esxi-host-06
- **Name:** ESXi Host 06
- **IP:** 10.10.1.12
- **Role:** Hypervisor
- **Shape:** server
- **Tags:** vmware; compute; cluster-b
- **Layer:** physical
- **MAC:** 00:50:56:AA:02:02
- **Rack Unit:** 35
- **U Height:** 2
- **Assigned Rack:** dc-rack-a2
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2139, 2845
- **Size:** 50
- **Notes:**
  - Dell PowerEdge R750
  - 768GB RAM
  - vSphere 8.0

### esxi-host-07
- **Name:** ESXi Host 07
- **IP:** 10.10.1.13
- **Role:** Hypervisor
- **Shape:** server
- **Tags:** vmware; compute; cluster-b
- **Layer:** physical
- **MAC:** 00:50:56:AA:02:03
- **Rack Unit:** 32
- **U Height:** 2
- **Assigned Rack:** dc-rack-a2
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2176, 2845
- **Size:** 50
- **Notes:**
  - Dell PowerEdge R750
  - 768GB RAM
  - vSphere 8.0

### esxi-host-08
- **Name:** ESXi Host 08
- **IP:** 10.10.1.14
- **Role:** Hypervisor
- **Shape:** server
- **Tags:** vmware; compute; cluster-b
- **Layer:** physical
- **MAC:** 00:50:56:AA:02:04
- **Rack Unit:** 29
- **U Height:** 2
- **Assigned Rack:** dc-rack-a2
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2131, 2845
- **Size:** 50
- **Notes:**
  - Dell PowerEdge R750
  - 768GB RAM
  - vSphere 8.0

### tor-switch-a2
- **Name:** ToR Switch A2
- **IP:** 10.10.1.1
- **Role:** Top of Rack
- **Shape:** switch
- **Tags:** tor; access; rack-a2
- **Layer:** physical
- **MAC:** 00:1A:2B:3C:5D:02
- **Rack Unit:** 42
- **U Height:** 1
- **Assigned Rack:** dc-rack-a2
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2165, 2845
- **Size:** 50
- **Notes:**
  - Cisco Nexus 93180YC-FX
  - 48x25G ports

### san-primary
- **Name:** SAN Primary
- **IP:** 10.10.2.10
- **Role:** Primary Storage
- **Shape:** database
- **Tags:** storage; san; netapp
- **Layer:** physical
- **MAC:** 00:A0:98:AA:01:01
- **Rack Unit:** 36
- **U Height:** 6
- **Assigned Rack:** dc-rack-b1
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2123, 2845
- **Size:** 50
- **Notes:**
  - NetApp AFF A400
  - 500TB Raw
  - FC 32Gb

### san-secondary
- **Name:** SAN Secondary
- **IP:** 10.10.2.11
- **Role:** Secondary Storage
- **Shape:** database
- **Tags:** storage; san; netapp
- **Layer:** physical
- **MAC:** 00:A0:98:AA:01:02
- **Rack Unit:** 28
- **U Height:** 6
- **Assigned Rack:** dc-rack-b1
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2155, 2845
- **Size:** 50
- **Notes:**
  - NetApp AFF A400
  - 500TB Raw
  - FC 32Gb

### fc-switch-1
- **Name:** FC Switch 1
- **IP:** 10.10.2.1
- **Role:** Fibre Channel
- **Shape:** switch
- **Tags:** storage; fc; fabric-a
- **Layer:** physical
- **MAC:** 00:1A:2B:FC:01:01
- **Rack Unit:** 42
- **U Height:** 1
- **Assigned Rack:** dc-rack-b1
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2115, 2845
- **Size:** 50
- **Notes:**
  - Brocade G620
  - Fabric A

### fc-switch-2
- **Name:** FC Switch 2
- **IP:** 10.10.2.2
- **Role:** Fibre Channel
- **Shape:** switch
- **Tags:** storage; fc; fabric-b
- **Layer:** physical
- **MAC:** 00:1A:2B:FC:01:02
- **Rack Unit:** 41
- **U Height:** 1
- **Assigned Rack:** dc-rack-b1
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2145, 2845
- **Size:** 50
- **Notes:**
  - Brocade G620
  - Fabric B

### backup-server-1
- **Name:** Backup Server 1
- **IP:** 10.10.3.10
- **Role:** Backup Infrastructure
- **Shape:** server
- **Tags:** backup; veeam; protection
- **Layer:** physical
- **MAC:** 00:50:56:BB:01:01
- **Rack Unit:** 36
- **U Height:** 2
- **Assigned Rack:** dc-rack-b2
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2107, 2845
- **Size:** 50
- **Notes:**
  - Veeam Backup Server
  - Dell R740xd
  - 200TB

### backup-server-2
- **Name:** Backup Server 2
- **IP:** 10.10.3.11
- **Role:** Backup Infrastructure
- **Shape:** server
- **Tags:** backup; veeam; protection
- **Layer:** physical
- **MAC:** 00:50:56:BB:01:02
- **Rack Unit:** 33
- **U Height:** 2
- **Assigned Rack:** dc-rack-b2
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2134, 2845
- **Size:** 50
- **Notes:**
  - Veeam Backup Server
  - Dell R740xd
  - 200TB

### tape-library
- **Name:** Tape Library
- **IP:** 10.10.3.20
- **Role:** Archival Storage
- **Shape:** database
- **Tags:** backup; tape; lto9
- **Layer:** physical
- **MAC:** 00:50:56:BB:02:01
- **Rack Unit:** 20
- **U Height:** 10
- **Assigned Rack:** dc-rack-b2
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2099, 2845
- **Size:** 50
- **Notes:**
  - IBM TS4500
  - LTO-9
  - Long-term archive

### tor-switch-b1
- **Name:** ToR Switch B1
- **IP:** 10.10.2.3
- **Role:** Top of Rack
- **Shape:** switch
- **Tags:** tor; access; rack-b1
- **Layer:** physical
- **MAC:** 00:1A:2B:3C:5D:03
- **Rack Unit:** 40
- **U Height:** 1
- **Assigned Rack:** dc-rack-b1
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2123, 2845
- **Size:** 50
- **Notes:**
  - Cisco Nexus 93180YC-FX

### tor-switch-b2
- **Name:** ToR Switch B2
- **IP:** 10.10.3.1
- **Role:** Top of Rack
- **Shape:** switch
- **Tags:** tor; access; rack-b2
- **Layer:** physical
- **MAC:** 00:1A:2B:3C:5D:04
- **Rack Unit:** 42
- **U Height:** 1
- **Assigned Rack:** dc-rack-b2
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2091, 2845
- **Size:** 50
- **Notes:**
  - Cisco Nexus 93180YC-FX

### web-server-1
- **Name:** Web Server 1
- **IP:** 172.16.0.11
- **Role:** Web Frontend
- **Shape:** server
- **Tags:** dmz; web; nginx
- **Layer:** security
- **MAC:** 00:50:56:CC:01:01
- **Rack Unit:** 20
- **U Height:** 1
- **Assigned Rack:** dmz-rack
- **Rack Capacity:** 24
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2113, 2845
- **Size:** 50
- **Notes:**
  - NGINX reverse proxy
  - Public facing

### web-server-2
- **Name:** Web Server 2
- **IP:** 172.16.0.12
- **Role:** Web Frontend
- **Shape:** server
- **Tags:** dmz; web; nginx
- **Layer:** security
- **MAC:** 00:50:56:CC:01:02
- **Rack Unit:** 18
- **U Height:** 1
- **Assigned Rack:** dmz-rack
- **Rack Capacity:** 24
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2082, 2845
- **Size:** 50
- **Notes:**
  - NGINX reverse proxy
  - Public facing

### waf-1
- **Name:** WAF Appliance
- **IP:** 172.16.0.5
- **Role:** Web Application Firewall
- **Shape:** firewall
- **Tags:** dmz; security; waf
- **Layer:** security
- **MAC:** 00:50:56:CC:02:01
- **Rack Unit:** 22
- **U Height:** 2
- **Assigned Rack:** dmz-rack
- **Rack Capacity:** 24
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2102, 2845
- **Size:** 50
- **Notes:**
  - F5 BIG-IP ASM
  - OWASP protection

### load-balancer-dmz
- **Name:** DMZ Load Balancer
- **IP:** 172.16.0.3
- **Role:** Load Balancing
- **Shape:** switch
- **Tags:** dmz; lb; f5
- **Layer:** security
- **MAC:** 00:50:56:CC:03:01
- **Rack Unit:** 16
- **U Height:** 2
- **Assigned Rack:** dmz-rack
- **Rack Capacity:** 24
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2074, 2845
- **Size:** 50
- **Notes:**
  - F5 BIG-IP LTM
  - VIP: 172.16.0.100

### mail-gateway
- **Name:** Mail Gateway
- **IP:** 172.16.0.25
- **Role:** Email Security
- **Shape:** server
- **Tags:** dmz; email; security
- **Layer:** security
- **MAC:** 00:50:56:CC:04:01
- **Rack Unit:** 14
- **U Height:** 1
- **Assigned Rack:** dmz-rack
- **Rack Capacity:** 24
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2091, 2845
- **Size:** 50
- **Notes:**
  - Proofpoint Email Gateway
  - Spam/malware filtering

### dns-external-1
- **Name:** External DNS 1
- **IP:** 172.16.0.53
- **Role:** External DNS
- **Shape:** circle
- **Tags:** dmz; dns; public
- **Layer:** security
- **MAC:** 00:50:56:CC:05:01
- **Rack Unit:** 12
- **U Height:** 1
- **Assigned Rack:** dmz-rack
- **Rack Capacity:** 24
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2066, 2845
- **Size:** 50
- **Notes:**
  - BIND DNS
  - Authoritative for corp.com

### dns-external-2
- **Name:** External DNS 2
- **IP:** 172.16.0.54
- **Role:** External DNS
- **Shape:** circle
- **Tags:** dmz; dns; public
- **Layer:** security
- **MAC:** 00:50:56:CC:05:02
- **Rack Unit:** 10
- **U Height:** 1
- **Assigned Rack:** dmz-rack
- **Rack Capacity:** 24
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2080, 2845
- **Size:** 50
- **Notes:**
  - BIND DNS
  - Secondary for corp.com

### vcenter
- **Name:** vCenter Server
- **IP:** 192.168.100.10
- **Role:** Virtualization Management
- **Shape:** server
- **Tags:** management; vmware; vcsa
- **Layer:** logical
- **MAC:** 00:50:56:DD:01:01
- **Rack Unit:** 20
- **U Height:** 2
- **Assigned Rack:** mgmt-rack
- **Rack Capacity:** 24
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2057, 2845
- **Size:** 50
- **Notes:**
  - vCenter Server Appliance 8.0
  - Single SSO domain

### nsx-manager
- **Name:** NSX Manager
- **IP:** 192.168.100.15
- **Role:** Network Virtualization
- **Shape:** server
- **Tags:** management; vmware; nsx
- **Layer:** logical
- **MAC:** 00:50:56:DD:02:01
- **Rack Unit:** 17
- **U Height:** 2
- **Assigned Rack:** mgmt-rack
- **Rack Capacity:** 24
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2069, 2845
- **Size:** 50
- **Notes:**
  - NSX-T 4.1 Manager Cluster

### siem-server
- **Name:** SIEM Server
- **IP:** 192.168.100.50
- **Role:** Security Monitoring
- **Shape:** server
- **Tags:** management; security; splunk
- **Layer:** logical
- **MAC:** 00:50:56:DD:03:01
- **Rack Unit:** 14
- **U Height:** 2
- **Assigned Rack:** mgmt-rack
- **Rack Capacity:** 24
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2049, 2845
- **Size:** 50
- **Notes:**
  - Splunk Enterprise
  - Security monitoring

### nms-server
- **Name:** Network Monitoring
- **IP:** 192.168.100.60
- **Role:** Network Management
- **Shape:** server
- **Tags:** management; monitoring; prtg
- **Layer:** logical
- **MAC:** 00:50:56:DD:04:01
- **Rack Unit:** 11
- **U Height:** 1
- **Assigned Rack:** mgmt-rack
- **Rack Capacity:** 24
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2058, 2845
- **Size:** 50
- **Notes:**
  - PRTG Network Monitor
  - 5000 sensors

### jump-server
- **Name:** Jump Server
- **IP:** 192.168.100.100
- **Role:** Bastion Host
- **Shape:** server
- **Tags:** management; security; bastion
- **Layer:** logical
- **MAC:** 00:50:56:DD:05:01
- **Rack Unit:** 9
- **U Height:** 1
- **Assigned Rack:** mgmt-rack
- **Rack Capacity:** 24
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2040, 2845
- **Size:** 50
- **Notes:**
  - Windows Server 2022
  - MFA enabled

### ipam-server
- **Name:** IPAM/DDI
- **IP:** 192.168.100.70
- **Role:** IP Management
- **Shape:** server
- **Tags:** management; dns; dhcp
- **Layer:** logical
- **MAC:** 00:50:56:DD:06:01
- **Rack Unit:** 7
- **U Height:** 2
- **Assigned Rack:** mgmt-rack
- **Rack Capacity:** 24
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2047, 2845
- **Size:** 50
- **Notes:**
  - Infoblox DDI
  - DNS/DHCP/IPAM

### wlc-primary
- **Name:** WLC Primary
- **IP:** 10.20.0.1
- **Role:** Wireless Controller
- **Shape:** wifi
- **Tags:** wireless; cisco; 9800
- **Layer:** physical
- **MAC:** 00:1A:2B:WL:01:01
- **Rack Unit:** 
- **U Height:** 2
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1576, 2306
- **Size:** 50
- **Notes:**
  - Cisco C9800-40
  - Primary controller

### wlc-secondary
- **Name:** WLC Secondary
- **IP:** 10.20.0.2
- **Role:** Wireless Controller
- **Shape:** wifi
- **Tags:** wireless; cisco; 9800
- **Layer:** physical
- **MAC:** 00:1A:2B:WL:01:02
- **Rack Unit:** 
- **U Height:** 2
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1468, 1564
- **Size:** 50
- **Notes:**
  - Cisco C9800-40
  - HA Secondary

### mobile-zone-hq
- **Name:** HQ Mobile Zone
- **IP:** 10.20.10.0/24
- **Role:** Mobile Device Zone
- **Shape:** phone
- **Tags:** wireless; byod; mobile
- **Layer:** physical
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2355, 2806
- **Size:** 50
- **Notes:**
  - Corporate BYOD
  - MDM enrolled devices

### mobile-zone-guest
- **Name:** Guest WiFi Zone
- **IP:** 10.30.0.0/24
- **Role:** Guest Network
- **Shape:** phone
- **Tags:** wireless; guest; isolated
- **Layer:** physical
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2308, 2611
- **Size:** 50
- **Notes:**
  - Captive portal
  - Internet only

### mobile-zone-iot
- **Name:** IoT Device Zone
- **IP:** 10.40.0.0/24
- **Role:** IoT Network
- **Shape:** phone
- **Tags:** wireless; iot; building
- **Layer:** physical
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2229, 2299
- **Size:** 50
- **Notes:**
  - Building automation
  - Smart devices

### branch-router-ny
- **Name:** NYC Branch Router
- **IP:** 10.100.0.1
- **Role:** Branch Gateway
- **Shape:** router
- **Tags:** branch; nyc; sd-wan
- **Layer:** physical
- **MAC:** 00:1A:2B:BR:01:01
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 3147, 634
- **Size:** 50
- **Notes:**
  - Cisco Viptela vEdge
  - SD-WAN enabled

### branch-router-la
- **Name:** LA Branch Router
- **IP:** 10.101.0.1
- **Role:** Branch Gateway
- **Shape:** router
- **Tags:** branch; la; sd-wan
- **Layer:** physical
- **MAC:** 00:1A:2B:BR:02:01
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 3084, 507
- **Size:** 50
- **Notes:**
  - Cisco Viptela vEdge
  - SD-WAN enabled

### branch-router-chi
- **Name:** Chicago Branch Router
- **IP:** 10.102.0.1
- **Role:** Branch Gateway
- **Shape:** router
- **Tags:** branch; chicago; sd-wan
- **Layer:** physical
- **MAC:** 00:1A:2B:BR:03:01
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 3355, 393
- **Size:** 50
- **Notes:**
  - Cisco Viptela vEdge
  - SD-WAN enabled

### branch-router-lon
- **Name:** London Branch Router
- **IP:** 10.200.0.1
- **Role:** Branch Gateway
- **Shape:** router
- **Tags:** branch; london; sd-wan
- **Layer:** physical
- **MAC:** 00:1A:2B:BR:04:01
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 3114, 260
- **Size:** 50
- **Notes:**
  - Cisco Viptela vEdge
  - EMEA region

### branch-router-tokyo
- **Name:** Tokyo Branch Router
- **IP:** 10.201.0.1
- **Role:** Branch Gateway
- **Shape:** router
- **Tags:** branch; tokyo; sd-wan
- **Layer:** physical
- **MAC:** 00:1A:2B:BR:05:01
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 3699, 471
- **Size:** 50
- **Notes:**
  - Cisco Viptela vEdge
  - APAC region

### cloud-aws
- **Name:** AWS Cloud
- **IP:** vpc-0a1b2c3d
- **Role:** Public Cloud
- **Shape:** cloud
- **Tags:** cloud; aws; hybrid
- **Layer:** logical
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 3439, 549
- **Size:** 50
- **Notes:**
  - AWS US-East-1
  - VPC peering to HQ

### cloud-azure
- **Name:** Azure Cloud
- **IP:** vnet-corp-prod
- **Role:** Public Cloud
- **Shape:** cloud
- **Tags:** cloud; azure; hybrid
- **Layer:** logical
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2593, 2724
- **Size:** 50
- **Notes:**
  - Azure East US 2
  - ExpressRoute

### cloud-gcp
- **Name:** GCP Cloud
- **IP:** vpc-gcp-corp
- **Role:** Public Cloud
- **Shape:** cloud
- **Tags:** cloud; gcp; dev
- **Layer:** logical
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2827, 2731
- **Size:** 50
- **Notes:**
  - GCP us-central1
  - Dev/Test workloads

### isp-primary
- **Name:** ISP Primary
- **IP:** 203.0.113.1
- **Role:** Internet Uplink
- **Shape:** globe
- **Tags:** wan; internet; primary
- **Layer:** physical
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 3712, 618
- **Size:** 50
- **Notes:**
  - AT&T MPLS
  - 1 Gbps dedicated

### isp-secondary
- **Name:** ISP Secondary
- **IP:** 198.51.100.1
- **Role:** Internet Uplink
- **Shape:** globe
- **Tags:** wan; internet; backup
- **Layer:** physical
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2574, 404
- **Size:** 50
- **Notes:**
  - Verizon Business
  - 500 Mbps backup

### dc-internal-1
- **Name:** DC1 Int DNS
- **IP:** 10.10.0.53
- **Role:** Internal DNS/AD
- **Shape:** circle
- **Tags:** dns; ad; dc1
- **Layer:** physical
- **MAC:** 00:50:56:AD:01:01
- **Rack Unit:** 26
- **U Height:** 1
- **Assigned Rack:** dc-rack-a1
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1958, 2845
- **Size:** 50
- **Notes:**
  - Windows Server 2022
  - Primary DC

### dc-internal-2
- **Name:** DC2 Int DNS
- **IP:** 10.10.1.53
- **Role:** Internal DNS/AD
- **Shape:** circle
- **Tags:** dns; ad; dc2
- **Layer:** physical
- **MAC:** 00:50:56:AD:01:02
- **Rack Unit:** 26
- **U Height:** 1
- **Assigned Rack:** dc-rack-a2
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1964, 2845
- **Size:** 50
- **Notes:**
  - Windows Server 2022
  - Secondary DC

### app-server-1
- **Name:** App Server 01
- **IP:** 10.10.0.101
- **Role:** Application
- **Shape:** server
- **Tags:** app; iis; web
- **Layer:** physical
- **MAC:** 00:50:56:AP:01:01
- **Rack Unit:** 24
- **U Height:** 1
- **Assigned Rack:** dc-rack-a1
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1947, 2845
- **Size:** 50
- **Notes:**
  - Windows Server 2022
  - IIS Application

### app-server-2
- **Name:** App Server 02
- **IP:** 10.10.0.102
- **Role:** Application
- **Shape:** server
- **Tags:** app; iis; web
- **Layer:** physical
- **MAC:** 00:50:56:AP:01:02
- **Rack Unit:** 22
- **U Height:** 1
- **Assigned Rack:** dc-rack-a1
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1955, 2845
- **Size:** 50
- **Notes:**
  - Windows Server 2022
  - IIS Application

### db-server-1
- **Name:** SQL Server 01
- **IP:** 10.10.0.201
- **Role:** Database
- **Shape:** database
- **Tags:** db; sql; primary
- **Layer:** physical
- **MAC:** 00:50:56:DB:01:01
- **Rack Unit:** 20
- **U Height:** 2
- **Assigned Rack:** dc-rack-a1
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1936, 2845
- **Size:** 50
- **Notes:**
  - SQL Server 2022 Enterprise
  - AlwaysOn Primary

### db-server-2
- **Name:** SQL Server 02
- **IP:** 10.10.1.201
- **Role:** Database
- **Shape:** database
- **Tags:** db; sql; secondary
- **Layer:** physical
- **MAC:** 00:50:56:DB:01:02
- **Rack Unit:** 24
- **U Height:** 2
- **Assigned Rack:** dc-rack-a2
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1947, 2845
- **Size:** 50
- **Notes:**
  - SQL Server 2022 Enterprise
  - AlwaysOn Secondary

### k8s-master-1
- **Name:** K8s Master 1
- **IP:** 10.10.1.50
- **Role:** Container Orchestration
- **Shape:** hexagon
- **Tags:** kubernetes; master; container
- **Layer:** physical
- **MAC:** 00:50:56:K8:01:01
- **Rack Unit:** 21
- **U Height:** 1
- **Assigned Rack:** dc-rack-a2
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1925, 2845
- **Size:** 50
- **Notes:**
  - K8s Control Plane
  - etcd member

### k8s-master-2
- **Name:** K8s Master 2
- **IP:** 10.10.1.51
- **Role:** Container Orchestration
- **Shape:** hexagon
- **Tags:** kubernetes; master; container
- **Layer:** physical
- **MAC:** 00:50:56:K8:01:02
- **Rack Unit:** 19
- **U Height:** 1
- **Assigned Rack:** dc-rack-a2
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1938, 2845
- **Size:** 50
- **Notes:**
  - K8s Control Plane
  - etcd member

### k8s-master-3
- **Name:** K8s Master 3
- **IP:** 10.10.1.52
- **Role:** Container Orchestration
- **Shape:** hexagon
- **Tags:** kubernetes; master; container
- **Layer:** physical
- **MAC:** 00:50:56:K8:01:03
- **Rack Unit:** 17
- **U Height:** 1
- **Assigned Rack:** dc-rack-a2
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1914, 2845
- **Size:** 50
- **Notes:**
  - K8s Control Plane
  - etcd member

### k8s-worker-1
- **Name:** K8s Worker 1
- **IP:** 10.10.1.60
- **Role:** Container Workload
- **Shape:** server
- **Tags:** kubernetes; worker; container
- **Layer:** physical
- **MAC:** 00:50:56:K8:02:01
- **Rack Unit:** 15
- **U Height:** 1
- **Assigned Rack:** dc-rack-a2
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1930, 2845
- **Size:** 50
- **Notes:**
  - K8s Worker Node
  - 64GB RAM

### k8s-worker-2
- **Name:** K8s Worker 2
- **IP:** 10.10.1.61
- **Role:** Container Workload
- **Shape:** server
- **Tags:** kubernetes; worker; container
- **Layer:** physical
- **MAC:** 00:50:56:K8:02:02
- **Rack Unit:** 13
- **U Height:** 1
- **Assigned Rack:** dc-rack-a2
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1904, 2845
- **Size:** 50
- **Notes:**
  - K8s Worker Node
  - 64GB RAM

### k8s-worker-3
- **Name:** K8s Worker 3
- **IP:** 10.10.1.62
- **Role:** Container Workload
- **Shape:** server
- **Tags:** kubernetes; worker; container
- **Layer:** physical
- **MAC:** 00:50:56:K8:02:03
- **Rack Unit:** 11
- **U Height:** 1
- **Assigned Rack:** dc-rack-a2
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1922, 2845
- **Size:** 50
- **Notes:**
  - K8s Worker Node
  - 64GB RAM

### k8s-worker-4
- **Name:** K8s Worker 4
- **IP:** 10.10.1.63
- **Role:** Container Workload
- **Shape:** server
- **Tags:** kubernetes; worker; container
- **Layer:** physical
- **MAC:** 00:50:56:K8:02:04
- **Rack Unit:** 9
- **U Height:** 1
- **Assigned Rack:** dc-rack-a2
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1893, 2845
- **Size:** 50
- **Notes:**
  - K8s Worker Node
  - 64GB RAM

### proxy-server-1
- **Name:** Proxy Server 1
- **IP:** 10.5.0.10
- **Role:** Web Proxy
- **Shape:** server
- **Tags:** proxy; squid; filtering
- **Layer:** security
- **MAC:** 00:50:56:PX:01:01
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1806, 654
- **Size:** 50
- **Notes:**
  - Squid Proxy
  - Content filtering

### proxy-server-2
- **Name:** Proxy Server 2
- **IP:** 10.5.0.11
- **Role:** Web Proxy
- **Shape:** server
- **Tags:** proxy; squid; filtering
- **Layer:** security
- **MAC:** 00:50:56:PX:01:02
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2937, 2629
- **Size:** 50
- **Notes:**
  - Squid Proxy
  - HA pair

### vpn-concentrator
- **Name:** VPN Concentrator
- **IP:** 10.0.5.1
- **Role:** Remote Access VPN
- **Shape:** firewall
- **Tags:** vpn; remote; security
- **Layer:** security
- **MAC:** 00:1A:2B:VP:01:01
- **Rack Unit:** 
- **U Height:** 2
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 3642, 947
- **Size:** 50
- **Notes:**
  - Cisco ASA 5555-X
  - AnyConnect SSL VPN

### nac-server
- **Name:** NAC Server
- **IP:** 10.5.5.10
- **Role:** Network Access Control
- **Shape:** server
- **Tags:** nac; ise; 802.1x
- **Layer:** security
- **MAC:** 00:50:56:NA:01:01
- **Rack Unit:** 
- **U Height:** 2
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1153, 1172
- **Size:** 50
- **Notes:**
  - Cisco ISE 3.1
  - RADIUS/TACACS+

### print-server
- **Name:** Print Server
- **IP:** 10.10.0.150
- **Role:** Print Services
- **Shape:** server
- **Tags:** print; windows; services
- **Layer:** physical
- **MAC:** 00:50:56:PR:01:01
- **Rack Unit:** 18
- **U Height:** 1
- **Assigned Rack:** dc-rack-a1
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1897, 2845
- **Size:** 50
- **Notes:**
  - Windows Print Server
  - 50+ printers

### file-server
- **Name:** File Server
- **IP:** 10.10.0.160
- **Role:** File Services
- **Shape:** database
- **Tags:** file; smb; dfs
- **Layer:** physical
- **MAC:** 00:50:56:FS:01:01
- **Rack Unit:** 16
- **U Height:** 2
- **Assigned Rack:** dc-rack-a1
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1861, 2845
- **Size:** 50
- **Notes:**
  - Windows File Server
  - DFS namespace

### ca-server
- **Name:** Certificate Authority
- **IP:** 192.168.100.80
- **Role:** PKI Infrastructure
- **Shape:** server
- **Tags:** pki; ca; security
- **Layer:** logical
- **MAC:** 00:50:56:CA:01:01
- **Rack Unit:** 5
- **U Height:** 1
- **Assigned Rack:** mgmt-rack
- **Rack Capacity:** 24
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1889, 2845
- **Size:** 50
- **Notes:**
  - Windows CA
  - Enterprise Root CA

### sccm-server
- **Name:** SCCM Server
- **IP:** 192.168.100.90
- **Role:** Endpoint Management
- **Shape:** server
- **Tags:** sccm; patching; software
- **Layer:** logical
- **MAC:** 00:50:56:SC:01:01
- **Rack Unit:** 3
- **U Height:** 2
- **Assigned Rack:** mgmt-rack
- **Rack Capacity:** 24
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1850, 2845
- **Size:** 50
- **Notes:**
  - MECM Primary Site
  - Software deployment

### voip-cluster
- **Name:** VoIP Cluster
- **IP:** 10.50.0.0/24
- **Role:** Voice Services
- **Shape:** phone
- **Tags:** voip; cisco; ucm
- **Layer:** application
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1777, 1617
- **Size:** 50
- **Notes:**
  - Cisco UCM Cluster
  - 3000 endpoints

### video-conf
- **Name:** Video Conference
- **IP:** 10.51.0.0/24
- **Role:** Video Services
- **Shape:** laptop
- **Tags:** video; webex; teams
- **Layer:** application
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1994, 2245
- **Size:** 50
- **Notes:**
  - Webex/Teams integration
  - Meeting rooms

### security-cameras
- **Name:** Security Cameras
- **IP:** 10.60.0.0/24
- **Role:** Physical Security
- **Shape:** camera
- **Tags:** cctv; surveillance; security
- **Layer:** physical
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1674, 2046
- **Size:** 50
- **Notes:**
  - 150+ IP cameras
  - 30-day retention

### nvr-cluster
- **Name:** NVR Cluster
- **IP:** 10.60.0.10
- **Role:** Video Recording
- **Shape:** server
- **Tags:** nvr; surveillance; storage
- **Layer:** physical
- **MAC:** 00:50:56:NV:01:01
- **Rack Unit:** 15
- **U Height:** 4
- **Assigned Rack:** dc-rack-b2
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1829, 2845
- **Size:** 50
- **Notes:**
  - Milestone XProtect
  - 500TB storage

### dev-server-1
- **Name:** Dev Server 1
- **IP:** 10.80.0.10
- **Role:** Development
- **Shape:** server
- **Tags:** dev; gitlab; ci-cd
- **Layer:** application
- **MAC:** 00:50:56:DV:01:01
- **Rack Unit:** 
- **U Height:** 2
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2360, 1480
- **Size:** 50
- **Notes:**
  - GitLab Server
  - CI/CD pipelines

### dev-server-2
- **Name:** Dev Server 2
- **IP:** 10.80.0.11
- **Role:** Development
- **Shape:** server
- **Tags:** dev; jenkins; ci-cd
- **Layer:** application
- **MAC:** 00:50:56:DV:01:02
- **Rack Unit:** 
- **U Height:** 2
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1935, 1236
- **Size:** 50
- **Notes:**
  - Jenkins Server
  - Build automation

### test-environment
- **Name:** Test Environment
- **IP:** 10.81.0.0/24
- **Role:** QA/Testing
- **Shape:** hexagon
- **Tags:** test; qa; staging
- **Layer:** application
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2206, 867
- **Size:** 50
- **Notes:**
  - Staging environment
  - Pre-prod validation

### erp-system
- **Name:** ERP System
- **IP:** 10.90.0.10
- **Role:** Business Application
- **Shape:** database
- **Tags:** erp; sap; business
- **Layer:** application
- **MAC:** 00:50:56:ER:01:01
- **Rack Unit:** 
- **U Height:** 4
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 865, 1502
- **Size:** 50
- **Notes:**
  - SAP S/4HANA
  - Financial/HR systems

### crm-system
- **Name:** CRM System
- **IP:** 10.91.0.10
- **Role:** Business Application
- **Shape:** database
- **Tags:** crm; salesforce; business
- **Layer:** application
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 3515, 1138
- **Size:** 50
- **Notes:**
  - Salesforce integration
  - Sales/Marketing

### endpoint-1000
- **Name:** Corporate Endpoints
- **IP:** 10.70.0.0/22
- **Role:** User Workstations
- **Shape:** laptop
- **Tags:** endpoints; workstations; users
- **Layer:** physical
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 992, 2284
- **Size:** 50
- **Notes:**
  - ~1000 corporate laptops
  - Windows 11

### dist-switch-floor1
- **Name:** Floor 1 Switch
- **IP:** 10.1.1.1
- **Role:** Distribution
- **Shape:** switch
- **Tags:** distribution; floor-1; access
- **Layer:** physical
- **MAC:** 00:1A:2B:FL:01:01
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 654, 2020
- **Size:** 50
- **Notes:**
  - Cisco C9300-48P
  - PoE+ enabled

### dist-switch-floor2
- **Name:** Floor 2 Switch
- **IP:** 10.1.2.1
- **Role:** Distribution
- **Shape:** switch
- **Tags:** distribution; floor-2; access
- **Layer:** physical
- **MAC:** 00:1A:2B:FL:02:01
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 854, 1843
- **Size:** 50
- **Notes:**
  - Cisco C9300-48P
  - PoE+ enabled

### dist-switch-floor3
- **Name:** Floor 3 Switch
- **IP:** 10.1.3.1
- **Role:** Distribution
- **Shape:** switch
- **Tags:** distribution; floor-3; access
- **Layer:** physical
- **MAC:** 00:1A:2B:FL:03:01
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1899, 1457
- **Size:** 50
- **Notes:**
  - Cisco C9300-48P
  - PoE+ enabled

### dist-switch-floor4
- **Name:** Floor 4 Switch
- **IP:** 10.1.4.1
- **Role:** Distribution
- **Shape:** switch
- **Tags:** distribution; floor-4; access
- **Layer:** physical
- **MAC:** 00:1A:2B:FL:04:01
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 655, 348
- **Size:** 50
- **Notes:**
  - Cisco C9300-48P
  - PoE+ enabled

### ap-floor1-zone1
- **Name:** AP Floor 1 Zone 1
- **IP:** 10.20.1.10
- **Role:** Wireless Access
- **Shape:** wifi
- **Tags:** wifi; ap; floor-1
- **Layer:** physical
- **MAC:** 00:1A:2B:AP:01:01
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1140, 2070
- **Size:** 50
- **Notes:**
  - Cisco 9120AX
  - Wi-Fi 6

### ap-floor2-zone1
- **Name:** AP Floor 2 Zone 1
- **IP:** 10.20.2.10
- **Role:** Wireless Access
- **Shape:** wifi
- **Tags:** wifi; ap; floor-2
- **Layer:** physical
- **MAC:** 00:1A:2B:AP:02:01
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 688, 2384
- **Size:** 50
- **Notes:**
  - Cisco 9120AX
  - Wi-Fi 6

### ap-floor3-zone1
- **Name:** AP Floor 3 Zone 1
- **IP:** 10.20.3.10
- **Role:** Wireless Access
- **Shape:** wifi
- **Tags:** wifi; ap; floor-3
- **Layer:** physical
- **MAC:** 00:1A:2B:AP:03:01
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 2145, 1890
- **Size:** 50
- **Notes:**
  - Cisco 9120AX
  - Wi-Fi 6

### ap-floor4-zone1
- **Name:** AP Floor 4 Zone 1
- **IP:** 10.20.4.10
- **Role:** Wireless Access
- **Shape:** wifi
- **Tags:** wifi; ap; floor-4
- **Layer:** physical
- **MAC:** 00:1A:2B:AP:04:01
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 434, 692
- **Size:** 50
- **Notes:**
  - Cisco 9120AX
  - Wi-Fi 6

### ups-dc-1
- **Name:** UPS DC-1
- **IP:** 192.168.200.10
- **Role:** Power Management
- **Shape:** rectangle
- **Tags:** power; ups; datacenter
- **Layer:** physical
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 588, 1349
- **Size:** 50
- **Notes:**
  - APC Symmetra
  - 80kVA
  - 30 min runtime

### ups-dc-2
- **Name:** UPS DC-2
- **IP:** 192.168.200.11
- **Role:** Power Management
- **Shape:** rectangle
- **Tags:** power; ups; datacenter
- **Layer:** physical
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 200, 529
- **Size:** 50
- **Notes:**
  - APC Symmetra
  - 80kVA
  - Redundant

### pdu-rack-a1
- **Name:** PDU Rack A1
- **IP:** 192.168.200.21
- **Role:** Power Distribution
- **Shape:** rectangle
- **Tags:** power; pdu; rack-a1
- **Layer:** physical
- **MAC:** 
- **Rack Unit:** 1
- **U Height:** 1
- **Assigned Rack:** dc-rack-a1
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1805, 2845
- **Size:** 50
- **Notes:**
  - APC Switched PDU
  - Per-outlet metering

### pdu-rack-a2
- **Name:** PDU Rack A2
- **IP:** 192.168.200.22
- **Role:** Power Distribution
- **Shape:** rectangle
- **Tags:** power; pdu; rack-a2
- **Layer:** physical
- **MAC:** 
- **Rack Unit:** 1
- **U Height:** 1
- **Assigned Rack:** dc-rack-a2
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1742, 2845
- **Size:** 50
- **Notes:**
  - APC Switched PDU
  - Per-outlet metering

### cooling-1
- **Name:** CRAC Unit 1
- **IP:** 192.168.200.30
- **Role:** Cooling
- **Shape:** rectangle
- **Tags:** cooling; hvac; datacenter
- **Layer:** physical
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 327, 1305
- **Size:** 50
- **Notes:**
  - Liebert CRV
  - Row-based cooling

### cooling-2
- **Name:** CRAC Unit 2
- **IP:** 192.168.200.31
- **Role:** Cooling
- **Shape:** rectangle
- **Tags:** cooling; hvac; datacenter
- **Layer:** physical
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 42
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 1603, 981
- **Size:** 50
- **Notes:**
  - Liebert CRV
  - N+1 redundancy

## Connections

- isp-primary (Gi0/0) --> core-router-1 (Gi1/0/1)
  - **ID:** isp1-router1
  - **Label:** 
  - **Color:** #10b981
  - **Width:** 6
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 
  - **Notes:**
    - Primary WAN link

- isp-secondary (Gi0/0) --> core-router-2 (Gi1/0/1)
  - **ID:** isp2-router2
  - **Label:** 
  - **Color:** #10b981
  - **Width:** 6
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 
  - **Notes:**
    - Backup WAN link

- core-router-1 (Gi1/0/24) --> core-router-2 (Gi1/0/24)
  - **ID:** router1-router2
  - **Label:** 
  - **Color:** #f59e0b
  - **Width:** 4
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 
  - **Notes:**
    - HSRP Peering

- core-router-1 --> fw-external-1
  - **ID:** router1-fw1
  - **Label:** 
  - **Color:** #ef4444
  - **Width:** 4
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core-router-2 --> fw-external-2
  - **ID:** router2-fw2
  - **Label:** 
  - **Color:** #ef4444
  - **Width:** 4
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- fw-external-1 --> fw-external-2
  - **ID:** fw1-fw2
  - **Label:** 
  - **Color:** #f59e0b
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** dashed
  - **Group ID:** 
  - **Notes:**
    - HA heartbeat

- fw-external-1 --> core-switch-1
  - **ID:** fw1-coresw1
  - **Label:** 
  - **Color:** #475569
  - **Width:** 4
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- fw-external-2 --> core-switch-2
  - **ID:** fw2-coresw2
  - **Label:** 
  - **Color:** #475569
  - **Width:** 4
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core-switch-1 --> core-switch-2
  - **ID:** coresw1-coresw2
  - **Label:** 
  - **Color:** #3b82f6
  - **Width:** 5
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 
  - **Notes:**
    - VPC peer-link

- core-switch-1 --> fw-internal
  - **ID:** coresw1-fwint
  - **Label:** 
  - **Color:** #ef4444
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core-switch-2 --> fw-internal
  - **ID:** coresw2-fwint
  - **Label:** 
  - **Color:** #ef4444
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core-switch-1 --> dc-rack-a1
  - **ID:** coresw1-racka1
  - **Label:** 
  - **Color:** #475569
  - **Width:** 4
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core-switch-2 --> dc-rack-a1
  - **ID:** coresw2-racka1
  - **Label:** 
  - **Color:** #475569
  - **Width:** 4
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core-switch-1 --> dc-rack-a2
  - **ID:** coresw1-racka2
  - **Label:** 
  - **Color:** #475569
  - **Width:** 4
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core-switch-2 --> dc-rack-a2
  - **ID:** coresw2-racka2
  - **Label:** 
  - **Color:** #475569
  - **Width:** 4
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core-switch-1 --> dc-rack-b1
  - **ID:** coresw1-rackb1
  - **Label:** 
  - **Color:** #475569
  - **Width:** 4
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core-switch-2 --> dc-rack-b1
  - **ID:** coresw2-rackb1
  - **Label:** 
  - **Color:** #475569
  - **Width:** 4
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core-switch-1 --> dc-rack-b2
  - **ID:** coresw1-rackb2
  - **Label:** 
  - **Color:** #475569
  - **Width:** 4
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core-switch-2 --> dc-rack-b2
  - **ID:** coresw2-rackb2
  - **Label:** 
  - **Color:** #475569
  - **Width:** 4
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- fw-external-1 --> dmz-rack
  - **ID:** fw1-dmz
  - **Label:** 
  - **Color:** #f59e0b
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 
  - **Notes:**
    - DMZ segment

- fw-external-2 --> dmz-rack
  - **ID:** fw2-dmz
  - **Label:** 
  - **Color:** #f59e0b
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 
  - **Notes:**
    - DMZ segment

- core-switch-1 --> mgmt-rack
  - **ID:** coresw1-mgmt
  - **Label:** 
  - **Color:** #8b5cf6
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 
  - **Notes:**
    - OOB management

- core-switch-1 --> wlc-primary
  - **ID:** coresw1-wlc1
  - **Label:** 
  - **Color:** #06b6d4
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core-switch-2 --> wlc-secondary
  - **ID:** coresw2-wlc2
  - **Label:** 
  - **Color:** #06b6d4
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- wlc-primary --> wlc-secondary
  - **ID:** wlc1-wlc2
  - **Label:** 
  - **Color:** #f59e0b
  - **Width:** 2
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** dashed
  - **Group ID:** 
  - **Notes:**
    - HA pair

- wlc-primary --> mobile-zone-hq
  - **ID:** wlc1-mobile-hq
  - **Label:** 
  - **Color:** #06b6d4
  - **Width:** 2
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- wlc-primary --> mobile-zone-guest
  - **ID:** wlc1-mobile-guest
  - **Label:** 
  - **Color:** #06b6d4
  - **Width:** 2
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- wlc-primary --> mobile-zone-iot
  - **ID:** wlc1-mobile-iot
  - **Label:** 
  - **Color:** #06b6d4
  - **Width:** 2
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core-router-1 --> branch-router-ny
  - **ID:** router1-branch-ny
  - **Label:** 
  - **Color:** #a855f7
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** dashed
  - **Group ID:** 
  - **Notes:**
    - SD-WAN tunnel

- core-router-1 --> branch-router-la
  - **ID:** router1-branch-la
  - **Label:** 
  - **Color:** #a855f7
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** dashed
  - **Group ID:** 
  - **Notes:**
    - SD-WAN tunnel

- core-router-1 --> branch-router-chi
  - **ID:** router1-branch-chi
  - **Label:** 
  - **Color:** #a855f7
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** dashed
  - **Group ID:** 
  - **Notes:**
    - SD-WAN tunnel

- core-router-1 --> branch-router-lon
  - **ID:** router1-branch-lon
  - **Label:** 
  - **Color:** #a855f7
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** dashed
  - **Group ID:** 
  - **Notes:**
    - SD-WAN tunnel

- core-router-1 --> branch-router-tokyo
  - **ID:** router1-branch-tokyo
  - **Label:** 
  - **Color:** #a855f7
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** dashed
  - **Group ID:** 
  - **Notes:**
    - SD-WAN tunnel

- core-router-1 --> cloud-aws
  - **ID:** router1-aws
  - **Label:** 
  - **Color:** #f97316
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** dashed
  - **Group ID:** 
  - **Notes:**
    - Direct Connect

- core-router-2 --> cloud-azure
  - **ID:** router2-azure
  - **Label:** 
  - **Color:** #0ea5e9
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** dashed
  - **Group ID:** 
  - **Notes:**
    - ExpressRoute

- fw-internal --> cloud-gcp
  - **ID:** fwint-gcp
  - **Label:** 
  - **Color:** #22c55e
  - **Width:** 2
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** dashed
  - **Group ID:** 
  - **Notes:**
    - VPN tunnel

- core-switch-1 --> dist-switch-floor1
  - **ID:** coresw1-floor1
  - **Label:** 
  - **Color:** #475569
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core-switch-1 --> dist-switch-floor2
  - **ID:** coresw1-floor2
  - **Label:** 
  - **Color:** #475569
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core-switch-2 --> dist-switch-floor3
  - **ID:** coresw2-floor3
  - **Label:** 
  - **Color:** #475569
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core-switch-2 --> dist-switch-floor4
  - **ID:** coresw2-floor4
  - **Label:** 
  - **Color:** #475569
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- dist-switch-floor1 --> endpoint-1000
  - **ID:** floor1-endpoints
  - **Label:** 
  - **Color:** #94a3b8
  - **Width:** 2
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- dist-switch-floor1 --> ap-floor1-zone1
  - **ID:** floor1-ap1
  - **Label:** 
  - **Color:** #06b6d4
  - **Width:** 2
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- dist-switch-floor2 --> ap-floor2-zone1
  - **ID:** floor2-ap2
  - **Label:** 
  - **Color:** #06b6d4
  - **Width:** 2
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- dist-switch-floor3 --> ap-floor3-zone1
  - **ID:** floor3-ap3
  - **Label:** 
  - **Color:** #06b6d4
  - **Width:** 2
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- dist-switch-floor4 --> ap-floor4-zone1
  - **ID:** floor4-ap4
  - **Label:** 
  - **Color:** #06b6d4
  - **Width:** 2
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- fw-internal --> proxy-server-1
  - **ID:** fwint-proxy1
  - **Label:** 
  - **Color:** #ef4444
  - **Width:** 2
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- fw-internal --> proxy-server-2
  - **ID:** fwint-proxy2
  - **Label:** 
  - **Color:** #ef4444
  - **Width:** 2
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- fw-external-1 --> vpn-concentrator
  - **ID:** fwext1-vpn
  - **Label:** 
  - **Color:** #8b5cf6
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core-switch-1 --> nac-server
  - **ID:** coresw1-nac
  - **Label:** 
  - **Color:** #f59e0b
  - **Width:** 2
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core-switch-1 --> voip-cluster
  - **ID:** coresw1-voip
  - **Label:** 
  - **Color:** #22c55e
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core-switch-2 --> video-conf
  - **ID:** coresw2-video
  - **Label:** 
  - **Color:** #22c55e
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core-switch-1 --> security-cameras
  - **ID:** coresw1-cameras
  - **Label:** 
  - **Color:** #94a3b8
  - **Width:** 2
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- fw-internal --> dev-server-1
  - **ID:** fwint-dev1
  - **Label:** 
  - **Color:** #a855f7
  - **Width:** 2
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- fw-internal --> dev-server-2
  - **ID:** fwint-dev2
  - **Label:** 
  - **Color:** #a855f7
  - **Width:** 2
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- fw-internal --> test-environment
  - **ID:** fwint-test
  - **Label:** 
  - **Color:** #a855f7
  - **Width:** 2
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core-switch-1 --> erp-system
  - **ID:** coresw1-erp
  - **Label:** 
  - **Color:** #f59e0b
  - **Width:** 3
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- fw-external-1 --> crm-system
  - **ID:** fwext1-crm
  - **Label:** 
  - **Color:** #f59e0b
  - **Width:** 2
  - **Direction:** both
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** dashed
  - **Group ID:** 
  - **Notes:**
    - Salesforce cloud

- ups-dc-1 --> dc-rack-a1
  - **ID:** ups1-racka1
  - **Label:** 
  - **Color:** #fbbf24
  - **Width:** 2
  - **Direction:** forward
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 
  - **Notes:**
    - Power feed A

- ups-dc-2 --> dc-rack-a2
  - **ID:** ups2-racka2
  - **Label:** 
  - **Color:** #fbbf24
  - **Width:** 2
  - **Direction:** forward
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 
  - **Notes:**
    - Power feed B

- ups-dc-1 --> dc-rack-b1
  - **ID:** ups1-rackb1
  - **Label:** 
  - **Color:** #fbbf24
  - **Width:** 2
  - **Direction:** forward
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 
  - **Notes:**
    - Power feed A

- ups-dc-2 --> dc-rack-b2
  - **ID:** ups2-rackb2
  - **Label:** 
  - **Color:** #fbbf24
  - **Width:** 2
  - **Direction:** forward
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 
  - **Notes:**
    - Power feed B

- cooling-1 --> dc-rack-a1
  - **ID:** cooling1-racka1
  - **Label:** 
  - **Color:** #38bdf8
  - **Width:** 2
  - **Direction:** forward
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 
  - **Notes:**
    - Cooling zone

- cooling-2 --> dc-rack-b1
  - **ID:** cooling2-rackb1
  - **Label:** 
  - **Color:** #38bdf8
  - **Width:** 2
  - **Direction:** forward
  - **Routing:** orthogonal
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 
  - **Notes:**
    - Cooling zone

- undefined --> undefined
  - **ID:** custom-1765237881452
  - **Label:** 
  - **Color:** #c800ff
  - **Width:** 4
  - **Direction:** forward
  - **Routing:** orthogonal
  - **Type:** custom
  - **Line Style:** solid
  - **Group ID:** 
  - **Points:** 3492,1527 3501,1831 3304,1732

## Zones

### rect-1765237540610
- **Position:** 2879, 160
- **Size:** 992 x 539
- **Color:** #f97316
- **Style:** filled
- **Line Style:** solid
- **Border Color:** 
- **Border Width:** 2

### rect-1765237681216
- **Position:** 448, 1672
- **Size:** 916 x 924
- **Color:** #c800ff
- **Style:** outlined
- **Line Style:** solid
- **Border Color:** 
- **Border Width:** 2

## Text Labels

### text-1765237828167
- **Content:** Double click on desktop<br>or long press on mobile<br>to enter rack canvas view
- **Position:** 3411, 1390
- **Font Size:** 46
- **Color:** #e2e8f0
- **Font Weight:** bold
- **Font Style:** italic
- **Text Align:** middle
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1

