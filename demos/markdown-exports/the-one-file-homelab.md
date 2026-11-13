<!--THEONEFILE_CONFIG
{
  "nodeData": {
    "internet": {
      "shape": "cloud",
      "name": "Internet",
      "ip": "",
      "role": "",
      "tags": [
        "wan"
      ],
      "notes": [],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer1",
      "assignedRack": "",
      "hostedOn": "",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "ont": {
      "shape": "gateway",
      "name": "Fiber ONT",
      "ip": "WAN 198.51.100.24",
      "role": "",
      "tags": [
        "wan",
        "isp"
      ],
      "notes": [
        "ISP owned ONT in bridge mode. Public address 198.51.100.24 handed to OPNsense by DHCP."
      ],
      "mac": "02:00:5E:10:00:01",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer1",
      "assignedRack": "",
      "hostedOn": "",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "opnsense": {
      "shape": "firewall",
      "name": "OPNsense",
      "ip": "10.10.10.1",
      "role": "Firewall and router",
      "tags": [
        "core",
        "firewall",
        "dhcp"
      ],
      "notes": [
        "<h3>OPNsense edge firewall</h3><p>Fanless four port box. 2.5GbE WAN to the ONT, 10GbE trunk to the core switch with every VLAN tagged.</p><ul><li>DHCP and Unbound forwarding to AdGuard Home</li><li>Inter VLAN rules: IoT and Guest can only reach the internet</li><li>WireGuard on UDP 51820 for roaming devices</li><li>Nightly config backup to the NAS</li></ul><table><thead><tr><th>VLAN</th><th>Name</th><th>Subnet</th></tr></thead><tbody><tr><td>10</td><td>Mgmt</td><td>10.10.10.0/24</td></tr><tr><td>20</td><td>Servers</td><td>10.10.20.0/24</td></tr><tr><td>30</td><td>IoT</td><td>10.10.30.0/24</td></tr><tr><td>40</td><td>Guest</td><td>10.10.40.0/24</td></tr><tr><td>99</td><td>WireGuard</td><td>10.10.99.0/24</td></tr></tbody></table><pre><code>[Interface]\nAddress = 10.10.99.1/24\nListenPort = 51820\n\n[Peer]\n# roaming laptop\nAllowedIPs = 10.10.99.10/32</code></pre>"
      ],
      "mac": "02:00:5E:10:00:02",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer3",
      "assignedRack": "",
      "hostedOn": "",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "wireguard": {
      "shape": "vpn",
      "name": "WireGuard",
      "ip": "10.10.99.1",
      "role": "VPN endpoint",
      "tags": [
        "vpn",
        "remote access"
      ],
      "notes": [
        "Runs on OPNsense. Peers get 10.10.99.0/24 and DNS from AdGuard Home."
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer3",
      "assignedRack": "",
      "hostedOn": "opnsense",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "laptop": {
      "shape": "laptop",
      "name": "Roaming Laptop",
      "ip": "10.10.99.10",
      "role": "",
      "tags": [
        "client",
        "remote"
      ],
      "notes": [],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer1",
      "assignedRack": "",
      "hostedOn": "",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "offsite": {
      "shape": "bucket",
      "name": "Offsite Backup",
      "ip": "Object storage bucket",
      "role": "",
      "tags": [
        "backup",
        "offsite"
      ],
      "notes": [
        "Encrypted restic repository. 30 daily, 12 monthly snapshots."
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer2",
      "assignedRack": "",
      "hostedOn": "",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "core": {
      "shape": "switch",
      "name": "Core Switch",
      "ip": "10.10.10.2",
      "role": "8 port 10G SFP+",
      "tags": [
        "core",
        "10g"
      ],
      "notes": [
        "<h3>Port map</h3><ul><li>SFP+ 1: OPNsense trunk</li><li>SFP+ 2: PoE switch</li><li>SFP+ 3 to 5: pve1, pve2, NAS</li><li>SFP+ 8: spare</li></ul>"
      ],
      "mac": "02:00:5E:10:00:03",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer1",
      "assignedRack": "",
      "hostedOn": "",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "pve1": {
      "shape": "server",
      "name": "pve1",
      "ip": "10.10.20.11",
      "role": "Proxmox VE",
      "tags": [
        "proxmox",
        "cluster"
      ],
      "notes": [
        "<h3>Proxmox node pve1</h3><ul><li>Ryzen 7, 64 GB ECC, 2 x 1 TB NVMe ZFS mirror</li><li>Dual 10GbE: vmbr0 VLAN aware bridge</li><li>Clustered with pve2, QDevice runs on the NAS</li></ul><pre><code>pvecm status\nQuorate: Yes\nNodes: 2 plus QDevice\nTotal votes: 3</code></pre>"
      ],
      "mac": "02:00:5E:20:00:11",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer1",
      "assignedRack": "",
      "hostedOn": "",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "pve2": {
      "shape": "server",
      "name": "pve2",
      "ip": "10.10.20.12",
      "role": "Proxmox VE",
      "tags": [
        "proxmox",
        "cluster"
      ],
      "notes": [
        "Second cluster node. Mini PC, 32 GB RAM, 10GbE through a Thunderbolt adapter."
      ],
      "mac": "02:00:5E:20:00:12",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer1",
      "assignedRack": "",
      "hostedOn": "",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "nas": {
      "shape": "nas",
      "name": "NAS",
      "ip": "10.10.20.20",
      "role": "TrueNAS, 4 x 12 TB RAIDZ1",
      "tags": [
        "storage",
        "nfs",
        "smb"
      ],
      "notes": [
        "<h3>Backups</h3><ol><li>Proxmox Backup Server pulls every VM at 01:00</li><li>NAS snapshots every hour, kept for 48 hours</li><li>Offsite sync at 03:00, encrypted before upload</li></ol><p><b>Rule:</b> three copies, two media, one offsite.</p>"
      ],
      "mac": "02:00:5E:20:00:20",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer1",
      "assignedRack": "",
      "hostedOn": "",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "haos": {
      "shape": "vm",
      "name": "Home Assistant",
      "ip": "10.10.20.30",
      "role": "VM",
      "tags": [
        "automation"
      ],
      "notes": [],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer4",
      "assignedRack": "",
      "hostedOn": "pve1",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "docker": {
      "shape": "docker",
      "name": "Docker Host",
      "ip": "10.10.20.31",
      "role": "VM",
      "tags": [
        "containers"
      ],
      "notes": [
        "<h3>Containers</h3><ul><li>Jellyfin</li><li>Immich</li><li>Vaultwarden</li><li>Uptime Kuma</li></ul>"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer4",
      "assignedRack": "",
      "hostedOn": "pve1",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "adguard": {
      "shape": "container",
      "name": "AdGuard Home",
      "ip": "10.10.20.53",
      "role": "LXC, DNS",
      "tags": [
        "dns"
      ],
      "notes": [
        "Primary DNS for every VLAN. Upstream DNS over TLS. Local zone lab.home.arpa."
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer2",
      "assignedRack": "",
      "hostedOn": "pve2",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "caddy": {
      "shape": "container",
      "name": "Reverse Proxy",
      "ip": "10.10.20.80",
      "role": "LXC, Caddy",
      "tags": [
        "proxy",
        "tls"
      ],
      "notes": [
        "Wildcard certificate for *.lab.home.arpa. Only reachable from LAN and WireGuard."
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer2",
      "assignedRack": "",
      "hostedOn": "pve2",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "pbs": {
      "shape": "vm",
      "name": "Backup Server",
      "ip": "10.10.20.40",
      "role": "Proxmox Backup Server",
      "tags": [
        "backup"
      ],
      "notes": [],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer2",
      "assignedRack": "",
      "hostedOn": "pve2",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "poe": {
      "shape": "switch",
      "name": "PoE Switch",
      "ip": "10.10.10.3",
      "role": "16 port 2.5GbE PoE",
      "tags": [
        "poe",
        "access"
      ],
      "notes": [],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer1",
      "assignedRack": "",
      "hostedOn": "",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "ap1": {
      "shape": "access-point",
      "name": "AP Living Room",
      "ip": "10.10.10.21",
      "role": "Wi Fi 7 AP",
      "tags": [
        "wifi"
      ],
      "notes": [
        "SSIDs: Willow (VLAN 10 and 20 by key), Willow IoT (VLAN 30), Willow Guest (VLAN 40)."
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer1",
      "assignedRack": "",
      "hostedOn": "",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "kvm": {
      "shape": "pi",
      "name": "PiKVM",
      "ip": "10.10.10.5",
      "role": "Out of band console",
      "tags": [
        "oob"
      ],
      "notes": [],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer3",
      "assignedRack": "",
      "hostedOn": "",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "ap2": {
      "shape": "access-point",
      "name": "AP Office",
      "ip": "10.10.10.22",
      "role": "Wi Fi 7 AP",
      "tags": [
        "wifi"
      ],
      "notes": [],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer1",
      "assignedRack": "",
      "hostedOn": "",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "zigbee": {
      "shape": "hub",
      "name": "Zigbee Hub",
      "ip": "10.10.30.10",
      "role": "Ethernet coordinator",
      "tags": [
        "zigbee"
      ],
      "notes": [],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer1",
      "assignedRack": "",
      "hostedOn": "",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "doorbell": {
      "shape": "doorbell",
      "name": "Doorbell",
      "ip": "10.10.30.20",
      "role": "RTSP camera",
      "tags": [
        "camera"
      ],
      "notes": [],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer1",
      "assignedRack": "",
      "hostedOn": "",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "tv": {
      "shape": "smart-tv",
      "name": "Living Room TV",
      "ip": "10.10.30.30",
      "role": "",
      "tags": [
        "media"
      ],
      "notes": [],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer1",
      "assignedRack": "",
      "hostedOn": "",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "thermo": {
      "shape": "thermostat",
      "name": "Thermostat",
      "ip": "10.10.30.40",
      "role": "",
      "tags": [
        "climate"
      ],
      "notes": [],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer1",
      "assignedRack": "",
      "hostedOn": "",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "guest1": {
      "shape": "laptop",
      "name": "Guest Laptop",
      "ip": "10.10.40.101",
      "role": "",
      "tags": [
        "guest"
      ],
      "notes": [],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer1",
      "assignedRack": "",
      "hostedOn": "",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "guest2": {
      "shape": "phone",
      "name": "Guest Phone",
      "ip": "10.10.40.102",
      "role": "",
      "tags": [
        "guest"
      ],
      "notes": [],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer1",
      "assignedRack": "",
      "hostedOn": "",
      "isRack": false,
      "locked": false,
      "groupId": null,
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    }
  },
  "edgeData": {
    "list": [
      {
        "id": "edge-net-20",
        "from": "internet",
        "to": "ont",
        "width": 5,
        "color": "#22c55e",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "straight",
        "label": "2 Gbps fiber",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-net-21",
        "from": "ont",
        "to": "opnsense",
        "width": 5,
        "color": "#22c55e",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "straight",
        "label": "2.5GbE",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-net-22",
        "from": "opnsense",
        "to": "core",
        "width": 6,
        "color": "#3b82f6",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "straight",
        "label": "10GbE trunk",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-net-23",
        "from": "wireguard",
        "to": "laptop",
        "width": 4,
        "color": "#a855f7",
        "direction": "both",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dashed",
        "routing": "straight",
        "label": "WireGuard",
        "animate": true,
        "animationStyle": "dots",
        "animationSpeed": 1.5,
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-net-24",
        "from": "core",
        "to": "pve1",
        "width": 5,
        "color": "#3b82f6",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "SFP+ 3",
        "toPort": "enp1s0",
        "lineStyle": "solid",
        "routing": "straight",
        "label": "10GbE",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-net-25",
        "from": "core",
        "to": "pve2",
        "width": 5,
        "color": "#3b82f6",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "SFP+ 4",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "straight",
        "label": "10GbE",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-net-26",
        "from": "core",
        "to": "nas",
        "width": 5,
        "color": "#3b82f6",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "SFP+ 5",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "straight",
        "label": "10GbE",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-net-27",
        "from": "core",
        "to": "poe",
        "width": 5,
        "color": "#3b82f6",
        "direction": "none",
        "type": "main",
        "notes": [
          "10GbE trunk carrying VLAN 10, 30 and 40"
        ],
        "fromPort": "SFP+ 2",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "straight",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-net-28",
        "from": "poe",
        "to": "ap1",
        "width": 4,
        "color": "#14b8a6",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "straight",
        "label": "2.5GbE PoE",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-net-29",
        "from": "poe",
        "to": "ap2",
        "width": 4,
        "color": "#14b8a6",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "straight",
        "label": "2.5GbE PoE",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-net-30",
        "from": "poe",
        "to": "kvm",
        "width": 4,
        "color": "#14b8a6",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "straight",
        "label": "1GbE",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-net-31",
        "from": "ap1",
        "to": "zigbee",
        "width": 4,
        "color": "#14b8a6",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "straight",
        "label": "VLAN 30",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-net-32",
        "from": "ap1",
        "to": "doorbell",
        "width": 4,
        "color": "#94a3b8",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dotted",
        "routing": "straight",
        "label": "VLAN 30",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-net-33",
        "from": "ap2",
        "to": "tv",
        "width": 4,
        "color": "#94a3b8",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dotted",
        "routing": "straight",
        "label": "VLAN 30",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-net-34",
        "from": "ap2",
        "to": "thermo",
        "width": 4,
        "color": "#94a3b8",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dotted",
        "routing": "straight",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-net-35",
        "from": "pbs",
        "to": "nas",
        "width": 4,
        "color": "#f97316",
        "direction": "forward",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dashed",
        "routing": "straight",
        "label": "NFS",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-net-36",
        "from": "nas",
        "to": "offsite",
        "width": 4,
        "color": "#f97316",
        "direction": "forward",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dashed",
        "routing": "straight",
        "label": "Nightly sync",
        "animate": true,
        "animationStyle": "arrows",
        "animationSpeed": 1.5,
        "_pairIndex": 0,
        "_pairTotal": 1
      }
    ]
  },
  "rectData": {
    "list": [
      {
        "id": "rect-net-7",
        "x": 40,
        "y": 1000,
        "width": 960,
        "height": 560,
        "color": "#3b82f6",
        "style": "filled",
        "lineStyle": "dashed",
        "fillOpacity": 0.12,
        "borderWidth": 2,
        "notes": []
      },
      {
        "id": "rect-net-10",
        "x": 1040,
        "y": 1000,
        "width": 520,
        "height": 560,
        "color": "#f59e0b",
        "style": "filled",
        "lineStyle": "dashed",
        "fillOpacity": 0.12,
        "borderWidth": 2,
        "notes": []
      },
      {
        "id": "rect-net-13",
        "x": 1600,
        "y": 1000,
        "width": 520,
        "height": 560,
        "color": "#10b981",
        "style": "filled",
        "lineStyle": "dashed",
        "fillOpacity": 0.12,
        "borderWidth": 2,
        "notes": []
      },
      {
        "id": "rect-net-16",
        "x": 2160,
        "y": 1000,
        "width": 520,
        "height": 560,
        "color": "#a855f7",
        "style": "filled",
        "lineStyle": "dashed",
        "fillOpacity": 0.12,
        "borderWidth": 2,
        "notes": []
      }
    ]
  },
  "textData": {
    "list": [
      {
        "id": "text-net-1",
        "x": 60,
        "y": 110,
        "content": "Willow Creek Homelab",
        "fontSize": 46,
        "color": "#e2e8f0",
        "fontWeight": "bold",
        "fontStyle": "normal",
        "textAlign": "start",
        "textDecoration": "none",
        "bgColor": "#000000",
        "bgEnabled": false,
        "opacity": 1
      },
      {
        "id": "text-net-2",
        "x": 60,
        "y": 160,
        "content": "Network overview with VLANs, Proxmox, storage and remote access",
        "fontSize": 20,
        "color": "#94a3b8",
        "fontWeight": "normal",
        "fontStyle": "normal",
        "textAlign": "start",
        "textDecoration": "none",
        "bgColor": "#000000",
        "bgEnabled": false,
        "opacity": 1
      },
      {
        "id": "text-net-3",
        "x": 60,
        "y": 200,
        "content": "Layers: Physical, Services, Security, Apps",
        "fontSize": 16,
        "color": "#64748b",
        "fontWeight": "normal",
        "fontStyle": "normal",
        "textAlign": "start",
        "textDecoration": "none",
        "bgColor": "#000000",
        "bgEnabled": false,
        "opacity": 1
      },
      {
        "id": "text-net-4",
        "x": 1400,
        "y": 150,
        "content": "Published through the reverse proxy",
        "fontSize": 22,
        "color": "#93c5fd",
        "fontWeight": "bold",
        "fontStyle": "normal",
        "textAlign": "start",
        "textDecoration": "none",
        "bgColor": "#000000",
        "bgEnabled": false,
        "opacity": 1
      },
      {
        "id": "text-net-5",
        "x": 1400,
        "y": 190,
        "content": "Jellyfin at media.lab.home.arpa\nImmich at photos.lab.home.arpa\nVaultwarden at vault.lab.home.arpa\nUptime Kuma at status.lab.home.arpa\nHome Assistant at ha.lab.home.arpa",
        "fontSize": 17,
        "color": "#cbd5e1",
        "fontWeight": "normal",
        "fontStyle": "normal",
        "textAlign": "start",
        "textDecoration": "none",
        "bgColor": "#000000",
        "bgEnabled": false,
        "opacity": 1
      },
      {
        "id": "text-net-6",
        "x": 2000,
        "y": 190,
        "content": "LAN and WireGuard only.\nNothing is port forwarded.\nDNS: AdGuard Home rewrites\n*.lab.home.arpa to 10.10.20.80",
        "fontSize": 17,
        "color": "#94a3b8",
        "fontWeight": "normal",
        "fontStyle": "normal",
        "textAlign": "start",
        "textDecoration": "none",
        "bgColor": "#000000",
        "bgEnabled": false,
        "opacity": 1
      },
      {
        "id": "text-net-8",
        "x": 58,
        "y": 1034,
        "content": "Servers  VLAN 20",
        "fontSize": 24,
        "color": "#3b82f6",
        "fontWeight": "bold",
        "fontStyle": "normal",
        "textAlign": "start",
        "textDecoration": "none",
        "bgColor": "#000000",
        "bgEnabled": false,
        "opacity": 1
      },
      {
        "id": "text-net-9",
        "x": 58,
        "y": 1064,
        "content": "10.10.20.0/24  Proxmox cluster, storage, core services",
        "fontSize": 16,
        "color": "#94a3b8",
        "fontWeight": "normal",
        "fontStyle": "normal",
        "textAlign": "start",
        "textDecoration": "none",
        "bgColor": "#000000",
        "bgEnabled": false,
        "opacity": 1
      },
      {
        "id": "text-net-11",
        "x": 1058,
        "y": 1034,
        "content": "Mgmt  VLAN 10",
        "fontSize": 24,
        "color": "#f59e0b",
        "fontWeight": "bold",
        "fontStyle": "normal",
        "textAlign": "start",
        "textDecoration": "none",
        "bgColor": "#000000",
        "bgEnabled": false,
        "opacity": 1
      },
      {
        "id": "text-net-12",
        "x": 1058,
        "y": 1064,
        "content": "10.10.10.0/24  switches, APs, out of band",
        "fontSize": 16,
        "color": "#94a3b8",
        "fontWeight": "normal",
        "fontStyle": "normal",
        "textAlign": "start",
        "textDecoration": "none",
        "bgColor": "#000000",
        "bgEnabled": false,
        "opacity": 1
      },
      {
        "id": "text-net-14",
        "x": 1618,
        "y": 1034,
        "content": "IoT  VLAN 30",
        "fontSize": 24,
        "color": "#10b981",
        "fontWeight": "bold",
        "fontStyle": "normal",
        "textAlign": "start",
        "textDecoration": "none",
        "bgColor": "#000000",
        "bgEnabled": false,
        "opacity": 1
      },
      {
        "id": "text-net-15",
        "x": 1618,
        "y": 1064,
        "content": "10.10.30.0/24  internet only, no LAN access",
        "fontSize": 16,
        "color": "#94a3b8",
        "fontWeight": "normal",
        "fontStyle": "normal",
        "textAlign": "start",
        "textDecoration": "none",
        "bgColor": "#000000",
        "bgEnabled": false,
        "opacity": 1
      },
      {
        "id": "text-net-17",
        "x": 2178,
        "y": 1034,
        "content": "Guest  VLAN 40",
        "fontSize": 24,
        "color": "#a855f7",
        "fontWeight": "bold",
        "fontStyle": "normal",
        "textAlign": "start",
        "textDecoration": "none",
        "bgColor": "#000000",
        "bgEnabled": false,
        "opacity": 1
      },
      {
        "id": "text-net-18",
        "x": 2178,
        "y": 1064,
        "content": "10.10.40.0/24  client isolation on",
        "fontSize": 16,
        "color": "#94a3b8",
        "fontWeight": "normal",
        "fontStyle": "normal",
        "textAlign": "start",
        "textDecoration": "none",
        "bgColor": "#000000",
        "bgEnabled": false,
        "opacity": 1
      },
      {
        "id": "text-net-19",
        "x": 2200,
        "y": 1400,
        "content": "Guest SSID is broadcast by both APs.\nInternet only, 50 Mbps per client,\nportal disabled.",
        "fontSize": 17,
        "color": "#c4b5fd",
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
  "imageData": {
    "list": []
  },
  "edgeLegend": {
    "#22c55e": "WAN and internet",
    "#3b82f6": "10GbE backbone",
    "#14b8a6": "2.5GbE PoE",
    "#a855f7": "WireGuard tunnel",
    "#f97316": "Backup traffic",
    "#94a3b8": "Wireless clients"
  },
  "zoneLegend": {},
  "zonePresets": {},
  "nodePositions": {
    "internet": {
      "x": 1020,
      "y": 170
    },
    "ont": {
      "x": 1020,
      "y": 380
    },
    "opnsense": {
      "x": 1020,
      "y": 640
    },
    "wireguard": {
      "x": 1600,
      "y": 640
    },
    "laptop": {
      "x": 2200,
      "y": 640
    },
    "offsite": {
      "x": 330,
      "y": 640
    },
    "core": {
      "x": 1020,
      "y": 880
    },
    "pve1": {
      "x": 200,
      "y": 1160
    },
    "pve2": {
      "x": 520,
      "y": 1160
    },
    "nas": {
      "x": 840,
      "y": 1160
    },
    "haos": {
      "x": 140,
      "y": 1420
    },
    "docker": {
      "x": 300,
      "y": 1420
    },
    "adguard": {
      "x": 470,
      "y": 1420
    },
    "caddy": {
      "x": 640,
      "y": 1420
    },
    "pbs": {
      "x": 840,
      "y": 1420
    },
    "poe": {
      "x": 1190,
      "y": 1160
    },
    "ap1": {
      "x": 1430,
      "y": 1160
    },
    "kvm": {
      "x": 1190,
      "y": 1420
    },
    "ap2": {
      "x": 1430,
      "y": 1420
    },
    "zigbee": {
      "x": 1740,
      "y": 1160
    },
    "doorbell": {
      "x": 1980,
      "y": 1160
    },
    "tv": {
      "x": 1740,
      "y": 1420
    },
    "thermo": {
      "x": 1980,
      "y": 1420
    },
    "guest1": {
      "x": 2300,
      "y": 1160
    },
    "guest2": {
      "x": 2540,
      "y": 1160
    }
  },
  "nodeSizes": {
    "internet": 70,
    "ont": 52,
    "opnsense": 58,
    "wireguard": 48,
    "laptop": 50,
    "offsite": 52,
    "core": 56,
    "pve1": 54,
    "pve2": 54,
    "nas": 54,
    "haos": 40,
    "docker": 40,
    "adguard": 40,
    "caddy": 40,
    "pbs": 40,
    "poe": 50,
    "ap1": 46,
    "kvm": 42,
    "ap2": 46,
    "zigbee": 42,
    "doorbell": 42,
    "tv": 42,
    "thermo": 42,
    "guest1": 44,
    "guest2": 40
  },
  "nodeStyles": {},
  "page": {
    "title": "Willow Creek Homelab",
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
    "topbarHeight": 52,
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
    "canvasGridEnabled": true,
    "rackFrameFill": "#0f172a",
    "rackGridEnabled": true,
    "rackFrameStroke": "#4fd1c5",
    "rackLineColor": "#475569",
    "rackTextColor": "#4fd1c5",
    "viewOnly": false,
    "defaultEdgeRouting": "straight",
    "animateConnections": false,
    "animationStyle": "arrows",
    "animationDirection": "all",
    "animationSpeed": 1.5,
    "mappingMode": "network",
    "canvasTemplate": "grid",
    "motionTrailsEnabled": true,
    "motionTrailLength": 8,
    "motionTrailStyle": "solid",
    "motionTrailArrow": true,
    "showPortLabels": true,
    "snapToGrid": true,
    "canvasWidth": 4000,
    "canvasHeight": 3000,
    "layerNames": {
      "layer1": "Physical",
      "layer2": "Services",
      "layer3": "Security",
      "layer4": "Apps"
    },
    "markDuplicateIps": false,
    "showHostedOnLinks": true,
    "autoPingEnabled": false,
    "autoPingInterval": 60
  },
  "canvas": {
    "zoom": 1.8155410312273057,
    "panX": 258.4000000000001,
    "panY": -21.200000000000045
  },
  "savedTopologyView": {
    "zoom": 1.8155410312273057,
    "panX": 258.4000000000001,
    "panY": -21.200000000000045
  },
  "tabViews": {
    "main": {
      "zoom": 1.8155410312273057,
      "panX": 258.4000000000001,
      "panY": -21.200000000000045
    }
  },
  "documentTabs": [
    {
      "id": "main",
      "name": "Network",
      "nodes": {
        "internet": {
          "shape": "cloud",
          "name": "Internet",
          "ip": "",
          "role": "",
          "tags": [
            "wan"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "ont": {
          "shape": "gateway",
          "name": "Fiber ONT",
          "ip": "WAN 198.51.100.24",
          "role": "",
          "tags": [
            "wan",
            "isp"
          ],
          "notes": [
            "ISP owned ONT in bridge mode. Public address 198.51.100.24 handed to OPNsense by DHCP."
          ],
          "mac": "02:00:5E:10:00:01",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "opnsense": {
          "shape": "firewall",
          "name": "OPNsense",
          "ip": "10.10.10.1",
          "role": "Firewall and router",
          "tags": [
            "core",
            "firewall",
            "dhcp"
          ],
          "notes": [
            "<h3>OPNsense edge firewall</h3><p>Fanless four port box. 2.5GbE WAN to the ONT, 10GbE trunk to the core switch with every VLAN tagged.</p><ul><li>DHCP and Unbound forwarding to AdGuard Home</li><li>Inter VLAN rules: IoT and Guest can only reach the internet</li><li>WireGuard on UDP 51820 for roaming devices</li><li>Nightly config backup to the NAS</li></ul><table><thead><tr><th>VLAN</th><th>Name</th><th>Subnet</th></tr></thead><tbody><tr><td>10</td><td>Mgmt</td><td>10.10.10.0/24</td></tr><tr><td>20</td><td>Servers</td><td>10.10.20.0/24</td></tr><tr><td>30</td><td>IoT</td><td>10.10.30.0/24</td></tr><tr><td>40</td><td>Guest</td><td>10.10.40.0/24</td></tr><tr><td>99</td><td>WireGuard</td><td>10.10.99.0/24</td></tr></tbody></table><pre><code>[Interface]\nAddress = 10.10.99.1/24\nListenPort = 51820\n\n[Peer]\n# roaming laptop\nAllowedIPs = 10.10.99.10/32</code></pre>"
          ],
          "mac": "02:00:5E:10:00:02",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer3",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "wireguard": {
          "shape": "vpn",
          "name": "WireGuard",
          "ip": "10.10.99.1",
          "role": "VPN endpoint",
          "tags": [
            "vpn",
            "remote access"
          ],
          "notes": [
            "Runs on OPNsense. Peers get 10.10.99.0/24 and DNS from AdGuard Home."
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer3",
          "assignedRack": "",
          "hostedOn": "opnsense",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "laptop": {
          "shape": "laptop",
          "name": "Roaming Laptop",
          "ip": "10.10.99.10",
          "role": "",
          "tags": [
            "client",
            "remote"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "offsite": {
          "shape": "bucket",
          "name": "Offsite Backup",
          "ip": "Object storage bucket",
          "role": "",
          "tags": [
            "backup",
            "offsite"
          ],
          "notes": [
            "Encrypted restic repository. 30 daily, 12 monthly snapshots."
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer2",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "core": {
          "shape": "switch",
          "name": "Core Switch",
          "ip": "10.10.10.2",
          "role": "8 port 10G SFP+",
          "tags": [
            "core",
            "10g"
          ],
          "notes": [
            "<h3>Port map</h3><ul><li>SFP+ 1: OPNsense trunk</li><li>SFP+ 2: PoE switch</li><li>SFP+ 3 to 5: pve1, pve2, NAS</li><li>SFP+ 8: spare</li></ul>"
          ],
          "mac": "02:00:5E:10:00:03",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "pve1": {
          "shape": "server",
          "name": "pve1",
          "ip": "10.10.20.11",
          "role": "Proxmox VE",
          "tags": [
            "proxmox",
            "cluster"
          ],
          "notes": [
            "<h3>Proxmox node pve1</h3><ul><li>Ryzen 7, 64 GB ECC, 2 x 1 TB NVMe ZFS mirror</li><li>Dual 10GbE: vmbr0 VLAN aware bridge</li><li>Clustered with pve2, QDevice runs on the NAS</li></ul><pre><code>pvecm status\nQuorate: Yes\nNodes: 2 plus QDevice\nTotal votes: 3</code></pre>"
          ],
          "mac": "02:00:5E:20:00:11",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "pve2": {
          "shape": "server",
          "name": "pve2",
          "ip": "10.10.20.12",
          "role": "Proxmox VE",
          "tags": [
            "proxmox",
            "cluster"
          ],
          "notes": [
            "Second cluster node. Mini PC, 32 GB RAM, 10GbE through a Thunderbolt adapter."
          ],
          "mac": "02:00:5E:20:00:12",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "nas": {
          "shape": "nas",
          "name": "NAS",
          "ip": "10.10.20.20",
          "role": "TrueNAS, 4 x 12 TB RAIDZ1",
          "tags": [
            "storage",
            "nfs",
            "smb"
          ],
          "notes": [
            "<h3>Backups</h3><ol><li>Proxmox Backup Server pulls every VM at 01:00</li><li>NAS snapshots every hour, kept for 48 hours</li><li>Offsite sync at 03:00, encrypted before upload</li></ol><p><b>Rule:</b> three copies, two media, one offsite.</p>"
          ],
          "mac": "02:00:5E:20:00:20",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "haos": {
          "shape": "vm",
          "name": "Home Assistant",
          "ip": "10.10.20.30",
          "role": "VM",
          "tags": [
            "automation"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer4",
          "assignedRack": "",
          "hostedOn": "pve1",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "docker": {
          "shape": "docker",
          "name": "Docker Host",
          "ip": "10.10.20.31",
          "role": "VM",
          "tags": [
            "containers"
          ],
          "notes": [
            "<h3>Containers</h3><ul><li>Jellyfin</li><li>Immich</li><li>Vaultwarden</li><li>Uptime Kuma</li></ul>"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer4",
          "assignedRack": "",
          "hostedOn": "pve1",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "adguard": {
          "shape": "container",
          "name": "AdGuard Home",
          "ip": "10.10.20.53",
          "role": "LXC, DNS",
          "tags": [
            "dns"
          ],
          "notes": [
            "Primary DNS for every VLAN. Upstream DNS over TLS. Local zone lab.home.arpa."
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer2",
          "assignedRack": "",
          "hostedOn": "pve2",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "caddy": {
          "shape": "container",
          "name": "Reverse Proxy",
          "ip": "10.10.20.80",
          "role": "LXC, Caddy",
          "tags": [
            "proxy",
            "tls"
          ],
          "notes": [
            "Wildcard certificate for *.lab.home.arpa. Only reachable from LAN and WireGuard."
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer2",
          "assignedRack": "",
          "hostedOn": "pve2",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "pbs": {
          "shape": "vm",
          "name": "Backup Server",
          "ip": "10.10.20.40",
          "role": "Proxmox Backup Server",
          "tags": [
            "backup"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer2",
          "assignedRack": "",
          "hostedOn": "pve2",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "poe": {
          "shape": "switch",
          "name": "PoE Switch",
          "ip": "10.10.10.3",
          "role": "16 port 2.5GbE PoE",
          "tags": [
            "poe",
            "access"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "ap1": {
          "shape": "access-point",
          "name": "AP Living Room",
          "ip": "10.10.10.21",
          "role": "Wi Fi 7 AP",
          "tags": [
            "wifi"
          ],
          "notes": [
            "SSIDs: Willow (VLAN 10 and 20 by key), Willow IoT (VLAN 30), Willow Guest (VLAN 40)."
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "kvm": {
          "shape": "pi",
          "name": "PiKVM",
          "ip": "10.10.10.5",
          "role": "Out of band console",
          "tags": [
            "oob"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer3",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "ap2": {
          "shape": "access-point",
          "name": "AP Office",
          "ip": "10.10.10.22",
          "role": "Wi Fi 7 AP",
          "tags": [
            "wifi"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "zigbee": {
          "shape": "hub",
          "name": "Zigbee Hub",
          "ip": "10.10.30.10",
          "role": "Ethernet coordinator",
          "tags": [
            "zigbee"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "doorbell": {
          "shape": "doorbell",
          "name": "Doorbell",
          "ip": "10.10.30.20",
          "role": "RTSP camera",
          "tags": [
            "camera"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "tv": {
          "shape": "smart-tv",
          "name": "Living Room TV",
          "ip": "10.10.30.30",
          "role": "",
          "tags": [
            "media"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "thermo": {
          "shape": "thermostat",
          "name": "Thermostat",
          "ip": "10.10.30.40",
          "role": "",
          "tags": [
            "climate"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "guest1": {
          "shape": "laptop",
          "name": "Guest Laptop",
          "ip": "10.10.40.101",
          "role": "",
          "tags": [
            "guest"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "guest2": {
          "shape": "phone",
          "name": "Guest Phone",
          "ip": "10.10.40.102",
          "role": "",
          "tags": [
            "guest"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        }
      },
      "edges": {
        "list": [
          {
            "id": "edge-net-20",
            "from": "internet",
            "to": "ont",
            "width": 5,
            "color": "#22c55e",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "2 Gbps fiber",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-net-21",
            "from": "ont",
            "to": "opnsense",
            "width": 5,
            "color": "#22c55e",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "2.5GbE",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-net-22",
            "from": "opnsense",
            "to": "core",
            "width": 6,
            "color": "#3b82f6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "10GbE trunk",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-net-23",
            "from": "wireguard",
            "to": "laptop",
            "width": 4,
            "color": "#a855f7",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "routing": "straight",
            "label": "WireGuard",
            "animate": true,
            "animationStyle": "dots",
            "animationSpeed": 1.5,
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-net-24",
            "from": "core",
            "to": "pve1",
            "width": 5,
            "color": "#3b82f6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "SFP+ 3",
            "toPort": "enp1s0",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "10GbE",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-net-25",
            "from": "core",
            "to": "pve2",
            "width": 5,
            "color": "#3b82f6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "SFP+ 4",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "10GbE",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-net-26",
            "from": "core",
            "to": "nas",
            "width": 5,
            "color": "#3b82f6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "SFP+ 5",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "10GbE",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-net-27",
            "from": "core",
            "to": "poe",
            "width": 5,
            "color": "#3b82f6",
            "direction": "none",
            "type": "main",
            "notes": [
              "10GbE trunk carrying VLAN 10, 30 and 40"
            ],
            "fromPort": "SFP+ 2",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-net-28",
            "from": "poe",
            "to": "ap1",
            "width": 4,
            "color": "#14b8a6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "2.5GbE PoE",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-net-29",
            "from": "poe",
            "to": "ap2",
            "width": 4,
            "color": "#14b8a6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "2.5GbE PoE",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-net-30",
            "from": "poe",
            "to": "kvm",
            "width": 4,
            "color": "#14b8a6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "1GbE",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-net-31",
            "from": "ap1",
            "to": "zigbee",
            "width": 4,
            "color": "#14b8a6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "VLAN 30",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-net-32",
            "from": "ap1",
            "to": "doorbell",
            "width": 4,
            "color": "#94a3b8",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dotted",
            "routing": "straight",
            "label": "VLAN 30",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-net-33",
            "from": "ap2",
            "to": "tv",
            "width": 4,
            "color": "#94a3b8",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dotted",
            "routing": "straight",
            "label": "VLAN 30",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-net-34",
            "from": "ap2",
            "to": "thermo",
            "width": 4,
            "color": "#94a3b8",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dotted",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-net-35",
            "from": "pbs",
            "to": "nas",
            "width": 4,
            "color": "#f97316",
            "direction": "forward",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "routing": "straight",
            "label": "NFS",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-net-36",
            "from": "nas",
            "to": "offsite",
            "width": 4,
            "color": "#f97316",
            "direction": "forward",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "routing": "straight",
            "label": "Nightly sync",
            "animate": true,
            "animationStyle": "arrows",
            "animationSpeed": 1.5,
            "_pairIndex": 0,
            "_pairTotal": 1
          }
        ]
      },
      "positions": {
        "internet": {
          "x": 1020,
          "y": 170
        },
        "ont": {
          "x": 1020,
          "y": 380
        },
        "opnsense": {
          "x": 1020,
          "y": 640
        },
        "wireguard": {
          "x": 1600,
          "y": 640
        },
        "laptop": {
          "x": 2200,
          "y": 640
        },
        "offsite": {
          "x": 330,
          "y": 640
        },
        "core": {
          "x": 1020,
          "y": 880
        },
        "pve1": {
          "x": 200,
          "y": 1160
        },
        "pve2": {
          "x": 520,
          "y": 1160
        },
        "nas": {
          "x": 840,
          "y": 1160
        },
        "haos": {
          "x": 140,
          "y": 1420
        },
        "docker": {
          "x": 300,
          "y": 1420
        },
        "adguard": {
          "x": 470,
          "y": 1420
        },
        "caddy": {
          "x": 640,
          "y": 1420
        },
        "pbs": {
          "x": 840,
          "y": 1420
        },
        "poe": {
          "x": 1190,
          "y": 1160
        },
        "ap1": {
          "x": 1430,
          "y": 1160
        },
        "kvm": {
          "x": 1190,
          "y": 1420
        },
        "ap2": {
          "x": 1430,
          "y": 1420
        },
        "zigbee": {
          "x": 1740,
          "y": 1160
        },
        "doorbell": {
          "x": 1980,
          "y": 1160
        },
        "tv": {
          "x": 1740,
          "y": 1420
        },
        "thermo": {
          "x": 1980,
          "y": 1420
        },
        "guest1": {
          "x": 2300,
          "y": 1160
        },
        "guest2": {
          "x": 2540,
          "y": 1160
        }
      },
      "sizes": {
        "internet": 70,
        "ont": 52,
        "opnsense": 58,
        "wireguard": 48,
        "laptop": 50,
        "offsite": 52,
        "core": 56,
        "pve1": 54,
        "pve2": 54,
        "nas": 54,
        "haos": 40,
        "docker": 40,
        "adguard": 40,
        "caddy": 40,
        "pbs": 40,
        "poe": 50,
        "ap1": 46,
        "kvm": 42,
        "ap2": 46,
        "zigbee": 42,
        "doorbell": 42,
        "tv": 42,
        "thermo": 42,
        "guest1": 44,
        "guest2": 40
      },
      "styles": {},
      "legend": {
        "#22c55e": "WAN and internet",
        "#3b82f6": "10GbE backbone",
        "#14b8a6": "2.5GbE PoE",
        "#a855f7": "WireGuard tunnel",
        "#f97316": "Backup traffic",
        "#94a3b8": "Wireless clients"
      },
      "rects": {
        "list": [
          {
            "id": "rect-net-7",
            "x": 40,
            "y": 1000,
            "width": 960,
            "height": 560,
            "color": "#3b82f6",
            "style": "filled",
            "lineStyle": "dashed",
            "fillOpacity": 0.12,
            "borderWidth": 2,
            "notes": []
          },
          {
            "id": "rect-net-10",
            "x": 1040,
            "y": 1000,
            "width": 520,
            "height": 560,
            "color": "#f59e0b",
            "style": "filled",
            "lineStyle": "dashed",
            "fillOpacity": 0.12,
            "borderWidth": 2,
            "notes": []
          },
          {
            "id": "rect-net-13",
            "x": 1600,
            "y": 1000,
            "width": 520,
            "height": 560,
            "color": "#10b981",
            "style": "filled",
            "lineStyle": "dashed",
            "fillOpacity": 0.12,
            "borderWidth": 2,
            "notes": []
          },
          {
            "id": "rect-net-16",
            "x": 2160,
            "y": 1000,
            "width": 520,
            "height": 560,
            "color": "#a855f7",
            "style": "filled",
            "lineStyle": "dashed",
            "fillOpacity": 0.12,
            "borderWidth": 2,
            "notes": []
          }
        ]
      },
      "texts": {
        "list": [
          {
            "id": "text-net-1",
            "x": 60,
            "y": 110,
            "content": "Willow Creek Homelab",
            "fontSize": 46,
            "color": "#e2e8f0",
            "fontWeight": "bold",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-net-2",
            "x": 60,
            "y": 160,
            "content": "Network overview with VLANs, Proxmox, storage and remote access",
            "fontSize": 20,
            "color": "#94a3b8",
            "fontWeight": "normal",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-net-3",
            "x": 60,
            "y": 200,
            "content": "Layers: Physical, Services, Security, Apps",
            "fontSize": 16,
            "color": "#64748b",
            "fontWeight": "normal",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-net-4",
            "x": 1400,
            "y": 150,
            "content": "Published through the reverse proxy",
            "fontSize": 22,
            "color": "#93c5fd",
            "fontWeight": "bold",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-net-5",
            "x": 1400,
            "y": 190,
            "content": "Jellyfin at media.lab.home.arpa\nImmich at photos.lab.home.arpa\nVaultwarden at vault.lab.home.arpa\nUptime Kuma at status.lab.home.arpa\nHome Assistant at ha.lab.home.arpa",
            "fontSize": 17,
            "color": "#cbd5e1",
            "fontWeight": "normal",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-net-6",
            "x": 2000,
            "y": 190,
            "content": "LAN and WireGuard only.\nNothing is port forwarded.\nDNS: AdGuard Home rewrites\n*.lab.home.arpa to 10.10.20.80",
            "fontSize": 17,
            "color": "#94a3b8",
            "fontWeight": "normal",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-net-8",
            "x": 58,
            "y": 1034,
            "content": "Servers  VLAN 20",
            "fontSize": 24,
            "color": "#3b82f6",
            "fontWeight": "bold",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-net-9",
            "x": 58,
            "y": 1064,
            "content": "10.10.20.0/24  Proxmox cluster, storage, core services",
            "fontSize": 16,
            "color": "#94a3b8",
            "fontWeight": "normal",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-net-11",
            "x": 1058,
            "y": 1034,
            "content": "Mgmt  VLAN 10",
            "fontSize": 24,
            "color": "#f59e0b",
            "fontWeight": "bold",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-net-12",
            "x": 1058,
            "y": 1064,
            "content": "10.10.10.0/24  switches, APs, out of band",
            "fontSize": 16,
            "color": "#94a3b8",
            "fontWeight": "normal",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-net-14",
            "x": 1618,
            "y": 1034,
            "content": "IoT  VLAN 30",
            "fontSize": 24,
            "color": "#10b981",
            "fontWeight": "bold",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-net-15",
            "x": 1618,
            "y": 1064,
            "content": "10.10.30.0/24  internet only, no LAN access",
            "fontSize": 16,
            "color": "#94a3b8",
            "fontWeight": "normal",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-net-17",
            "x": 2178,
            "y": 1034,
            "content": "Guest  VLAN 40",
            "fontSize": 24,
            "color": "#a855f7",
            "fontWeight": "bold",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-net-18",
            "x": 2178,
            "y": 1064,
            "content": "10.10.40.0/24  client isolation on",
            "fontSize": 16,
            "color": "#94a3b8",
            "fontWeight": "normal",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-net-19",
            "x": 2200,
            "y": 1400,
            "content": "Guest SSID is broadcast by both APs.\nInternet only, 50 Mbps per client,\nportal disabled.",
            "fontSize": 17,
            "color": "#c4b5fd",
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
      "images": {
        "list": []
      },
      "pageState": {
        "title": "Willow Creek Homelab",
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
        "topbarHeight": 52,
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
        "canvasGridEnabled": true,
        "rackFrameFill": "#0f172a",
        "rackGridEnabled": true,
        "rackFrameStroke": "#4fd1c5",
        "rackLineColor": "#475569",
        "rackTextColor": "#4fd1c5",
        "viewOnly": false,
        "defaultEdgeRouting": "straight",
        "animateConnections": false,
        "animationStyle": "arrows",
        "animationDirection": "all",
        "animationSpeed": 1.5,
        "mappingMode": "network",
        "canvasTemplate": "grid",
        "motionTrailsEnabled": true,
        "motionTrailLength": 8,
        "motionTrailStyle": "solid",
        "motionTrailArrow": true,
        "showPortLabels": true,
        "snapToGrid": true,
        "canvasWidth": 4000,
        "canvasHeight": 3000,
        "layerNames": {
          "layer1": "Physical",
          "layer2": "Services",
          "layer3": "Security",
          "layer4": "Apps"
        },
        "markDuplicateIps": false,
        "showHostedOnLinks": true,
        "autoPingEnabled": false,
        "autoPingInterval": 60
      }
    },
    {
      "id": "tab-homelab-rack",
      "name": "Rack",
      "nodes": {
        "rack-main": {
          "shape": "server",
          "name": "Main Rack 20U",
          "ip": "",
          "role": "rack",
          "tags": [
            "rack"
          ],
          "notes": [
            "<h3>Main rack</h3><ul><li>20U, 600 mm deep</li><li>Front and rear devices share units where they fit</li><li>Servers and the NAS are full depth</li><li>Vertical PDU on the right rail uses no rack units</li></ul>"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": true,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          },
          "rackCapacity": 20,
          "rackFaceView": "split"
        },
        "rack-mini": {
          "shape": "server",
          "name": "Mini Rack 10 inch",
          "ip": "",
          "role": "rack",
          "tags": [
            "rack",
            "10 inch"
          ],
          "notes": [
            "8U 10 inch rack on the desk. Units are numbered from the top like the printed rails."
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": true,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          },
          "rackCapacity": 8,
          "rackNumbering": "top"
        },
        "rk-patch": {
          "shape": "patch-panel",
          "name": "Patch Panel 24",
          "ip": "Cat6A keystone",
          "role": "",
          "tags": [
            "cabling"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "20",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "rack-main",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "rk-core": {
          "shape": "switch",
          "name": "Core Switch",
          "ip": "10.10.10.2",
          "role": "8 x 10G SFP+",
          "tags": [
            "core",
            "10g"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "19",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "rack-main",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "rk-poe": {
          "shape": "switch",
          "name": "PoE Switch",
          "ip": "10.10.10.3",
          "role": "16 x 2.5GbE PoE",
          "tags": [
            "poe"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "18",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "rack-main",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "rk-ont": {
          "shape": "rack-shelf",
          "name": "Fiber ONT Shelf",
          "ip": "Bridge mode",
          "role": "",
          "tags": [
            "wan"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "18",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "rack-main",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          },
          "rackFace": "rear"
        },
        "rk-cable": {
          "shape": "cable-management",
          "name": "Cable Manager",
          "ip": "",
          "role": "",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "17",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "rack-main",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "rk-fw": {
          "shape": "firewall",
          "name": "OPNsense",
          "ip": "10.10.10.1",
          "role": "",
          "tags": [
            "firewall"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "16",
          "uHeight": "1",
          "layer": "layer3",
          "assignedRack": "rack-main",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "rk-blank": {
          "shape": "blank-panel",
          "name": "Blank Panel",
          "ip": "",
          "role": "",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "14",
          "uHeight": "2",
          "layer": "layer1",
          "assignedRack": "rack-main",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "rk-pve1": {
          "shape": "server",
          "name": "pve1",
          "ip": "10.10.20.11",
          "role": "2U, full depth",
          "tags": [
            "proxmox"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "12",
          "uHeight": "2",
          "layer": "layer1",
          "assignedRack": "rack-main",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          },
          "rackFullDepth": true
        },
        "rk-pve2": {
          "shape": "server",
          "name": "pve2",
          "ip": "10.10.20.12",
          "role": "2U, full depth",
          "tags": [
            "proxmox"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "10",
          "uHeight": "2",
          "layer": "layer1",
          "assignedRack": "rack-main",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          },
          "rackFullDepth": true
        },
        "rk-nas": {
          "shape": "nas",
          "name": "NAS",
          "ip": "10.10.20.20",
          "role": "4U, 8 bay",
          "tags": [
            "storage"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "6",
          "uHeight": "4",
          "layer": "layer1",
          "assignedRack": "rack-main",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          },
          "rackFullDepth": true
        },
        "rk-kvm": {
          "shape": "kvm",
          "name": "PiKVM Shelf",
          "ip": "10.10.10.5",
          "role": "",
          "tags": [
            "oob"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "5",
          "uHeight": "1",
          "layer": "layer3",
          "assignedRack": "rack-main",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "rk-rpdu": {
          "shape": "pdu",
          "name": "Rear PDU",
          "ip": "",
          "role": "8 outlet, switched",
          "tags": [
            "power"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "4",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "rack-main",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          },
          "rackFace": "rear"
        },
        "rk-ups": {
          "shape": "ups",
          "name": "UPS 1500VA",
          "ip": "",
          "role": "Line interactive, 2U",
          "tags": [
            "power"
          ],
          "notes": [
            "Runtime about 18 minutes at 320 W. NUT server on the NAS shuts the cluster down at 30 percent."
          ],
          "mac": "",
          "rackUnit": "1",
          "uHeight": "2",
          "layer": "layer1",
          "assignedRack": "rack-main",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          },
          "rackFullDepth": true
        },
        "rk-vpdu": {
          "shape": "pdu",
          "name": "Vertical PDU",
          "ip": "",
          "role": "0U side rail, 12 outlets",
          "tags": [
            "power",
            "0U"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "rack-main",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          },
          "rackMount": "right"
        },
        "mr-patch": {
          "shape": "patch-panel",
          "name": "Mini Patch Panel",
          "ip": "12 port",
          "role": "",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "8",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "rack-mini",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "mr-switch": {
          "shape": "switch",
          "name": "Mini Switch",
          "ip": "10.10.10.4",
          "role": "8 x 2.5GbE, 2 x 10G",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "7",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "rack-mini",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "mr-pc1": {
          "shape": "server",
          "name": "Mini PC 1",
          "ip": "10.10.20.61",
          "role": "k3s control plane",
          "tags": [
            "k3s"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "6",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "rack-mini",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "mr-pc2": {
          "shape": "server",
          "name": "Mini PC 2",
          "ip": "10.10.20.62",
          "role": "k3s worker",
          "tags": [
            "k3s"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "5",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "rack-mini",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "mr-pc3": {
          "shape": "server",
          "name": "Mini PC 3",
          "ip": "10.10.20.63",
          "role": "k3s worker",
          "tags": [
            "k3s"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "4",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "rack-mini",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "mr-pi": {
          "shape": "pi",
          "name": "Pi Shelf",
          "ip": "10.10.10.6",
          "role": "Pi 5, NUT and status page",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "3",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "rack-mini",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "mr-ups": {
          "shape": "ups",
          "name": "Mini UPS",
          "ip": "",
          "role": "DC UPS, 2U",
          "tags": [
            "power"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "1",
          "uHeight": "2",
          "layer": "layer1",
          "assignedRack": "rack-mini",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "x-internet": {
          "shape": "cloud",
          "name": "Internet",
          "ip": "",
          "role": "",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "x-ap1": {
          "shape": "access-point",
          "name": "AP Living Room",
          "ip": "10.10.10.21",
          "role": "",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "x-ap2": {
          "shape": "access-point",
          "name": "AP Office",
          "ip": "10.10.10.22",
          "role": "",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "x-desk": {
          "shape": "pc",
          "name": "Office Desk",
          "ip": "10.10.20.100",
          "role": "Wall jack 12",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "x-cam": {
          "shape": "camera",
          "name": "Garage Camera",
          "ip": "10.10.30.21",
          "role": "",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "x-laptop": {
          "shape": "laptop",
          "name": "Workbench Laptop",
          "ip": "10.10.20.101",
          "role": "",
          "tags": [],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        }
      },
      "edges": {
        "list": [
          {
            "id": "edge-rack-8",
            "from": "x-internet",
            "to": "rk-ont",
            "width": 5,
            "color": "#22c55e",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "Fiber",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-rack-9",
            "from": "rk-ont",
            "to": "rk-fw",
            "width": 4,
            "color": "#22c55e",
            "direction": "none",
            "type": "main",
            "notes": [
              "2.5GbE, LAN to igc0"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 8
          },
          {
            "id": "edge-rack-10",
            "from": "rk-fw",
            "to": "rk-core",
            "width": 4,
            "color": "#3b82f6",
            "direction": "none",
            "type": "main",
            "notes": [
              "10GbE DAC, ix0 to SFP+ 1"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "_pairIndex": 1,
            "_pairTotal": 8
          },
          {
            "id": "edge-rack-11",
            "from": "rk-core",
            "to": "rk-pve1",
            "width": 4,
            "color": "#3b82f6",
            "direction": "none",
            "type": "main",
            "notes": [
              "10GbE DAC, SFP+ 3"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "_pairIndex": 2,
            "_pairTotal": 8
          },
          {
            "id": "edge-rack-12",
            "from": "rk-core",
            "to": "rk-pve2",
            "width": 4,
            "color": "#3b82f6",
            "direction": "none",
            "type": "main",
            "notes": [
              "10GbE DAC, SFP+ 4"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "_pairIndex": 3,
            "_pairTotal": 8
          },
          {
            "id": "edge-rack-13",
            "from": "rk-core",
            "to": "rk-nas",
            "width": 4,
            "color": "#3b82f6",
            "direction": "none",
            "type": "main",
            "notes": [
              "10GbE DAC, SFP+ 5"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "_pairIndex": 4,
            "_pairTotal": 8
          },
          {
            "id": "edge-rack-14",
            "from": "rk-core",
            "to": "rk-poe",
            "width": 4,
            "color": "#3b82f6",
            "direction": "none",
            "type": "main",
            "notes": [
              "10GbE, SFP+ 2"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "_pairIndex": 5,
            "_pairTotal": 8
          },
          {
            "id": "edge-rack-15",
            "from": "rk-poe",
            "to": "rk-patch",
            "width": 4,
            "color": "#14b8a6",
            "direction": "none",
            "type": "main",
            "notes": [
              "Patch, 1 to 12"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "_pairIndex": 6,
            "_pairTotal": 8
          },
          {
            "id": "edge-rack-16",
            "from": "rk-patch",
            "to": "x-ap1",
            "width": 4,
            "color": "#14b8a6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "Port 3",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "Cat6A drop 3",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-rack-17",
            "from": "rk-patch",
            "to": "x-ap2",
            "width": 4,
            "color": "#14b8a6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "Port 7",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "Cat6A drop 7",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-rack-18",
            "from": "rk-patch",
            "to": "x-desk",
            "width": 4,
            "color": "#14b8a6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "Port 12",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "Cat6A drop 12",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-rack-19",
            "from": "rk-ups",
            "to": "rk-nas",
            "width": 4,
            "color": "#f97316",
            "direction": "none",
            "type": "main",
            "notes": [
              "USB UPS signal"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dotted",
            "routing": "straight",
            "_pairIndex": 7,
            "_pairTotal": 8
          },
          {
            "id": "edge-rack-20",
            "from": "rk-core",
            "to": "mr-switch",
            "width": 5,
            "color": "#3b82f6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "SFP+ 6",
            "toPort": "SFP+ 1",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "10G fiber",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-rack-21",
            "from": "mr-switch",
            "to": "mr-pc1",
            "width": 4,
            "color": "#14b8a6",
            "direction": "none",
            "type": "main",
            "notes": [
              "2.5GbE"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 4
          },
          {
            "id": "edge-rack-22",
            "from": "mr-switch",
            "to": "mr-pc2",
            "width": 4,
            "color": "#14b8a6",
            "direction": "none",
            "type": "main",
            "notes": [
              "2.5GbE"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "_pairIndex": 1,
            "_pairTotal": 4
          },
          {
            "id": "edge-rack-23",
            "from": "mr-switch",
            "to": "mr-pc3",
            "width": 4,
            "color": "#14b8a6",
            "direction": "none",
            "type": "main",
            "notes": [
              "2.5GbE"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "_pairIndex": 2,
            "_pairTotal": 4
          },
          {
            "id": "edge-rack-24",
            "from": "mr-switch",
            "to": "mr-pi",
            "width": 4,
            "color": "#14b8a6",
            "direction": "none",
            "type": "main",
            "notes": [
              "1GbE"
            ],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "_pairIndex": 3,
            "_pairTotal": 4
          },
          {
            "id": "edge-rack-25",
            "from": "mr-patch",
            "to": "x-cam",
            "width": 4,
            "color": "#14b8a6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "Port 2",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "PoE injector",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-rack-26",
            "from": "mr-patch",
            "to": "x-laptop",
            "width": 4,
            "color": "#14b8a6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "Port 5",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "Dock",
            "_pairIndex": 0,
            "_pairTotal": 1
          }
        ]
      },
      "positions": {
        "rack-main": {
          "x": 1000,
          "y": 760
        },
        "rack-mini": {
          "x": 1820,
          "y": 760
        },
        "rk-patch": {
          "x": 1440,
          "y": 265
        },
        "rk-core": {
          "x": 1440,
          "y": 395
        },
        "rk-poe": {
          "x": 1440,
          "y": 525
        },
        "rk-ont": {
          "x": 2560,
          "y": 525
        },
        "rk-cable": {
          "x": 1440,
          "y": 655
        },
        "rk-fw": {
          "x": 1440,
          "y": 785
        },
        "rk-blank": {
          "x": 1440,
          "y": 980
        },
        "rk-pve1": {
          "x": 1440,
          "y": 1240
        },
        "rk-pve2": {
          "x": 1440,
          "y": 1500
        },
        "rk-nas": {
          "x": 1440,
          "y": 1890
        },
        "rk-kvm": {
          "x": 1440,
          "y": 2215
        },
        "rk-rpdu": {
          "x": 2560,
          "y": 2345
        },
        "rk-ups": {
          "x": 1440,
          "y": 2670
        },
        "rk-vpdu": {
          "x": 1850,
          "y": 200
        },
        "mr-patch": {
          "x": 2000,
          "y": 362.5
        },
        "mr-switch": {
          "x": 2000,
          "y": 687.5
        },
        "mr-pc1": {
          "x": 2000,
          "y": 1012.5
        },
        "mr-pc2": {
          "x": 2000,
          "y": 1337.5
        },
        "mr-pc3": {
          "x": 2000,
          "y": 1662.5
        },
        "mr-pi": {
          "x": 2000,
          "y": 1987.5
        },
        "mr-ups": {
          "x": 2000,
          "y": 2475
        },
        "x-internet": {
          "x": 1000,
          "y": 330
        },
        "x-ap1": {
          "x": 420,
          "y": 1200
        },
        "x-ap2": {
          "x": 760,
          "y": 1200
        },
        "x-desk": {
          "x": 1100,
          "y": 1200
        },
        "x-cam": {
          "x": 1820,
          "y": 1200
        },
        "x-laptop": {
          "x": 2240,
          "y": 1200
        }
      },
      "sizes": {
        "rack-main": 100,
        "rack-mini": 90,
        "rk-patch": 26,
        "rk-core": 39,
        "rk-poe": 39,
        "rk-ont": 26,
        "rk-cable": 26,
        "rk-fw": 39,
        "rk-blank": 52,
        "rk-pve1": 78,
        "rk-pve2": 78,
        "rk-nas": 80,
        "rk-kvm": 26,
        "rk-rpdu": 39,
        "rk-ups": 78,
        "rk-vpdu": 39,
        "mr-patch": 65,
        "mr-switch": 80,
        "mr-pc1": 80,
        "mr-pc2": 80,
        "mr-pc3": 80,
        "mr-pi": 80,
        "mr-ups": 80,
        "x-internet": 66,
        "x-ap1": 46,
        "x-ap2": 46,
        "x-desk": 48,
        "x-cam": 44,
        "x-laptop": 46
      },
      "styles": {
        "rk-patch": {
          "all": {
            "titleSize": 17,
            "subSize": 13,
            "titleOffsetX": 185,
            "titleOffsetY": 24,
            "subOffsetX": 185,
            "subOffsetY": -32
          }
        },
        "rk-core": {
          "all": {
            "titleSize": 17,
            "subSize": 13,
            "titleOffsetX": 185,
            "titleOffsetY": 37,
            "subOffsetX": 185,
            "subOffsetY": -45
          }
        },
        "rk-poe": {
          "all": {
            "titleSize": 17,
            "subSize": 13,
            "titleOffsetX": 185,
            "titleOffsetY": 37,
            "subOffsetX": 185,
            "subOffsetY": -45
          }
        },
        "rk-ont": {
          "all": {
            "titleSize": 17,
            "subSize": 13,
            "titleOffsetX": 185,
            "titleOffsetY": 24,
            "subOffsetX": 185,
            "subOffsetY": -32
          }
        },
        "rk-cable": {
          "all": {
            "titleSize": 17,
            "subSize": 13,
            "titleOffsetX": 185,
            "titleOffsetY": 24,
            "subOffsetX": 185,
            "subOffsetY": -32
          }
        },
        "rk-fw": {
          "all": {
            "titleSize": 17,
            "subSize": 13,
            "titleOffsetX": 185,
            "titleOffsetY": 37,
            "subOffsetX": 185,
            "subOffsetY": -45
          }
        },
        "rk-blank": {
          "all": {
            "titleSize": 17,
            "subSize": 13,
            "titleOffsetX": 185,
            "titleOffsetY": 50,
            "subOffsetX": 185,
            "subOffsetY": -58
          }
        },
        "rk-pve1": {
          "all": {
            "titleSize": 17,
            "subSize": 13,
            "titleOffsetX": 185,
            "titleOffsetY": 76,
            "subOffsetX": 185,
            "subOffsetY": -84
          }
        },
        "rk-pve2": {
          "all": {
            "titleSize": 17,
            "subSize": 13,
            "titleOffsetX": 185,
            "titleOffsetY": 76,
            "subOffsetX": 185,
            "subOffsetY": -84
          }
        },
        "rk-nas": {
          "all": {
            "titleSize": 17,
            "subSize": 13,
            "titleOffsetX": 185,
            "titleOffsetY": 78,
            "subOffsetX": 185,
            "subOffsetY": -86
          }
        },
        "rk-kvm": {
          "all": {
            "titleSize": 17,
            "subSize": 13,
            "titleOffsetX": 185,
            "titleOffsetY": 24,
            "subOffsetX": 185,
            "subOffsetY": -32
          }
        },
        "rk-rpdu": {
          "all": {
            "titleSize": 17,
            "subSize": 13,
            "titleOffsetX": 185,
            "titleOffsetY": 37,
            "subOffsetX": 185,
            "subOffsetY": -45
          }
        },
        "rk-ups": {
          "all": {
            "titleSize": 17,
            "subSize": 13,
            "titleOffsetX": 185,
            "titleOffsetY": 76,
            "subOffsetX": 185,
            "subOffsetY": -84
          }
        },
        "mr-patch": {
          "all": {
            "titleSize": 22,
            "subSize": 16,
            "titleOffsetX": 200,
            "titleOffsetY": 61,
            "subOffsetX": 200,
            "subOffsetY": -67
          }
        },
        "mr-switch": {
          "all": {
            "titleSize": 22,
            "subSize": 16,
            "titleOffsetX": 200,
            "titleOffsetY": 76,
            "subOffsetX": 200,
            "subOffsetY": -82
          }
        },
        "mr-pc1": {
          "all": {
            "titleSize": 22,
            "subSize": 16,
            "titleOffsetX": 200,
            "titleOffsetY": 76,
            "subOffsetX": 200,
            "subOffsetY": -82
          }
        },
        "mr-pc2": {
          "all": {
            "titleSize": 22,
            "subSize": 16,
            "titleOffsetX": 200,
            "titleOffsetY": 76,
            "subOffsetX": 200,
            "subOffsetY": -82
          }
        },
        "mr-pc3": {
          "all": {
            "titleSize": 22,
            "subSize": 16,
            "titleOffsetX": 200,
            "titleOffsetY": 76,
            "subOffsetX": 200,
            "subOffsetY": -82
          }
        },
        "mr-pi": {
          "all": {
            "titleSize": 22,
            "subSize": 16,
            "titleOffsetX": 200,
            "titleOffsetY": 76,
            "subOffsetX": 200,
            "subOffsetY": -82
          }
        },
        "mr-ups": {
          "all": {
            "titleSize": 22,
            "subSize": 16,
            "titleOffsetX": 200,
            "titleOffsetY": 76,
            "subOffsetX": 200,
            "subOffsetY": -82
          }
        }
      },
      "legend": {
        "#22c55e": "WAN",
        "#3b82f6": "10GbE DAC",
        "#14b8a6": "Copper patch",
        "#f97316": "Power and UPS signal"
      },
      "rects": {
        "list": []
      },
      "texts": {
        "list": [
          {
            "id": "text-rack-1",
            "x": 60,
            "y": 110,
            "content": "Rack Room",
            "fontSize": 46,
            "color": "#e2e8f0",
            "fontWeight": "bold",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-rack-2",
            "x": 60,
            "y": 160,
            "content": "A 20U main rack and an 8U 10 inch mini rack, both custom sizes",
            "fontSize": 20,
            "color": "#94a3b8",
            "fontWeight": "normal",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-rack-3",
            "x": 60,
            "y": 200,
            "content": "Select a rack and press Enter, or double click it, to open Rack View",
            "fontSize": 16,
            "color": "#64748b",
            "fontWeight": "normal",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-rack-4",
            "x": 60,
            "y": 560,
            "content": "Main Rack 20U",
            "fontSize": 26,
            "color": "#4fd1c5",
            "fontWeight": "bold",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-rack-5",
            "x": 60,
            "y": 600,
            "content": "Side by side front and rear view\nFront: patch panel, core switch, PoE switch,\ncable manager, OPNsense, PiKVM\nFull depth: pve1, pve2, NAS, UPS\nRear: fiber ONT shelf, switched PDU\nRight rail: 0U vertical PDU",
            "fontSize": 18,
            "color": "#cbd5e1",
            "fontWeight": "normal",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-rack-6",
            "x": 2080,
            "y": 560,
            "content": "Mini Rack 10 inch",
            "fontSize": 26,
            "color": "#4fd1c5",
            "fontWeight": "bold",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-rack-7",
            "x": 2080,
            "y": 600,
            "content": "8U, numbered top down\nPatch panel and 2.5GbE switch\nThree mini PCs running k3s\nPi shelf and a DC UPS",
            "fontSize": 18,
            "color": "#cbd5e1",
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
      "images": {
        "list": []
      },
      "pageState": {
        "title": "Willow Creek Homelab",
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
        "topbarHeight": 52,
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
        "canvasGridEnabled": true,
        "rackFrameFill": "#0f172a",
        "rackGridEnabled": true,
        "rackFrameStroke": "#4fd1c5",
        "rackLineColor": "#475569",
        "rackTextColor": "#4fd1c5",
        "viewOnly": false,
        "defaultEdgeRouting": "straight",
        "animateConnections": false,
        "animationStyle": "arrows",
        "animationDirection": "all",
        "animationSpeed": 1.5,
        "mappingMode": "network",
        "canvasTemplate": "grid",
        "motionTrailsEnabled": true,
        "motionTrailLength": 8,
        "motionTrailStyle": "solid",
        "motionTrailArrow": true,
        "showPortLabels": true,
        "snapToGrid": true,
        "canvasWidth": 4000,
        "canvasHeight": 3000,
        "layerNames": {
          "layer1": "Physical",
          "layer2": "Services",
          "layer3": "Security",
          "layer4": "Apps"
        },
        "markDuplicateIps": false,
        "showHostedOnLinks": true,
        "autoPingEnabled": false,
        "autoPingInterval": 60
      }
    },
    {
      "id": "tab-homelab-iot",
      "name": "Smart Home",
      "nodes": {
        "ha": {
          "shape": "hub",
          "name": "Home Assistant",
          "ip": "10.10.20.30",
          "role": "VM on pve1",
          "tags": [
            "automation",
            "core"
          ],
          "notes": [
            "<h3>Automations</h3><ul><li><b>Good night:</b> locks the front door, turns off downstairs lights, arms cameras</li><li><b>Doorbell:</b> shows the camera on the TV and sends a phone alert</li><li><b>Leak:</b> closes the water valve and flashes the hallway light red</li><li><b>Away:</b> thermostat to eco, vacuum starts</li></ul><pre><code>trigger: state\nentity_id: binary_sensor.washer_leak\nto: \"on\"</code></pre>"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer4",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "mqtt": {
          "shape": "queue",
          "name": "MQTT Broker",
          "ip": "10.10.20.31:1883",
          "role": "Mosquitto container",
          "tags": [
            "mqtt"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer2",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "z2m": {
          "shape": "hub",
          "name": "Zigbee Hub",
          "ip": "10.10.30.10",
          "role": "Zigbee2MQTT",
          "tags": [
            "zigbee"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "z-motion": {
          "shape": "motion-sensor",
          "name": "Hall Motion",
          "ip": "Zigbee",
          "role": "",
          "tags": [
            "sensor"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "z-leak": {
          "shape": "sensor",
          "name": "Washer Leak",
          "ip": "Zigbee",
          "role": "",
          "tags": [
            "sensor",
            "safety"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer3",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "z-bulb": {
          "shape": "smart-bulb",
          "name": "Hall Lights",
          "ip": "Zigbee group",
          "role": "",
          "tags": [
            "lighting"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "z-valve": {
          "shape": "smart-plug",
          "name": "Water Valve",
          "ip": "Zigbee",
          "role": "",
          "tags": [
            "safety"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer3",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "speaker": {
          "shape": "smart-speaker",
          "name": "Kitchen Speaker",
          "ip": "10.10.30.50",
          "role": "Thread border router",
          "tags": [
            "matter"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "t-lock": {
          "shape": "smart-lock",
          "name": "Front Door Lock",
          "ip": "Thread",
          "role": "",
          "tags": [
            "security"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer3",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "t-blind": {
          "shape": "smart-plug",
          "name": "Office Blinds",
          "ip": "Thread",
          "role": "",
          "tags": [
            "climate"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "t-plug": {
          "shape": "smart-plug",
          "name": "Desk Plug",
          "ip": "Matter",
          "role": "",
          "tags": [
            "energy"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "w-thermo": {
          "shape": "thermostat",
          "name": "Thermostat",
          "ip": "10.10.30.40",
          "role": "",
          "tags": [
            "climate"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "w-door": {
          "shape": "doorbell",
          "name": "Doorbell",
          "ip": "10.10.30.20",
          "role": "",
          "tags": [
            "camera"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer3",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "w-vac": {
          "shape": "vacuum",
          "name": "Robot Vacuum",
          "ip": "10.10.30.60",
          "role": "",
          "tags": [
            "cleaning"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "w-tv": {
          "shape": "smart-tv",
          "name": "Living Room TV",
          "ip": "10.10.30.30",
          "role": "",
          "tags": [
            "media"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "iot-ap": {
          "shape": "access-point",
          "name": "AP Living Room",
          "ip": "10.10.10.21",
          "role": "SSID Willow IoT",
          "tags": [
            "wifi"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "nvr": {
          "shape": "monitor",
          "name": "Frigate NVR",
          "ip": "10.10.20.32",
          "role": "Container, Coral TPU",
          "tags": [
            "camera",
            "nvr"
          ],
          "notes": [],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer3",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": null,
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        }
      },
      "edges": {
        "list": [
          {
            "id": "edge-iot-12",
            "from": "z2m",
            "to": "z-motion",
            "width": 4,
            "color": "#84cc16",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dotted",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-iot-13",
            "from": "z2m",
            "to": "z-leak",
            "width": 4,
            "color": "#84cc16",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dotted",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-iot-14",
            "from": "z2m",
            "to": "z-bulb",
            "width": 4,
            "color": "#84cc16",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dotted",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-iot-15",
            "from": "z2m",
            "to": "z-valve",
            "width": 4,
            "color": "#84cc16",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dotted",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-iot-16",
            "from": "speaker",
            "to": "t-lock",
            "width": 4,
            "color": "#c084fc",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dotted",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-iot-17",
            "from": "speaker",
            "to": "t-blind",
            "width": 4,
            "color": "#c084fc",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dotted",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-iot-18",
            "from": "speaker",
            "to": "t-plug",
            "width": 4,
            "color": "#c084fc",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dotted",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-iot-19",
            "from": "z2m",
            "to": "mqtt",
            "width": 4,
            "color": "#84cc16",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "orthogonal",
            "label": "MQTT",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-iot-20",
            "from": "mqtt",
            "to": "ha",
            "width": 4,
            "color": "#3b82f6",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "1883",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-iot-21",
            "from": "speaker",
            "to": "ha",
            "width": 4,
            "color": "#c084fc",
            "direction": "both",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "Matter",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-iot-22",
            "from": "iot-ap",
            "to": "w-thermo",
            "width": 4,
            "color": "#38bdf8",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dotted",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-iot-23",
            "from": "iot-ap",
            "to": "w-vac",
            "width": 4,
            "color": "#38bdf8",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dotted",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-iot-24",
            "from": "iot-ap",
            "to": "w-tv",
            "width": 4,
            "color": "#38bdf8",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dotted",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-iot-25",
            "from": "iot-ap",
            "to": "w-door",
            "width": 4,
            "color": "#38bdf8",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dotted",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-iot-26",
            "from": "iot-ap",
            "to": "ha",
            "width": 4,
            "color": "#38bdf8",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "VLAN 30 to 20",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-iot-27",
            "from": "w-door",
            "to": "nvr",
            "width": 4,
            "color": "#38bdf8",
            "direction": "forward",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "RTSP",
            "animate": true,
            "animationStyle": "dots",
            "animationSpeed": 1.5,
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-iot-28",
            "from": "nvr",
            "to": "ha",
            "width": 4,
            "color": "#3b82f6",
            "direction": "forward",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "Events",
            "_pairIndex": 0,
            "_pairTotal": 1
          }
        ]
      },
      "positions": {
        "ha": {
          "x": 1260,
          "y": 1050
        },
        "mqtt": {
          "x": 440,
          "y": 1050
        },
        "z2m": {
          "x": 440,
          "y": 420
        },
        "z-motion": {
          "x": 180,
          "y": 640
        },
        "z-leak": {
          "x": 360,
          "y": 640
        },
        "z-bulb": {
          "x": 540,
          "y": 640
        },
        "z-valve": {
          "x": 720,
          "y": 640
        },
        "speaker": {
          "x": 1260,
          "y": 420
        },
        "t-lock": {
          "x": 1020,
          "y": 640
        },
        "t-blind": {
          "x": 1260,
          "y": 640
        },
        "t-plug": {
          "x": 1500,
          "y": 640
        },
        "w-thermo": {
          "x": 1840,
          "y": 640
        },
        "w-door": {
          "x": 2300,
          "y": 420
        },
        "w-vac": {
          "x": 2070,
          "y": 640
        },
        "w-tv": {
          "x": 2300,
          "y": 640
        },
        "iot-ap": {
          "x": 1900,
          "y": 420
        },
        "nvr": {
          "x": 2080,
          "y": 1050
        }
      },
      "sizes": {
        "ha": 70,
        "mqtt": 50,
        "z2m": 50,
        "z-motion": 40,
        "z-leak": 40,
        "z-bulb": 40,
        "z-valve": 40,
        "speaker": 50,
        "t-lock": 40,
        "t-blind": 40,
        "t-plug": 40,
        "w-thermo": 42,
        "w-door": 46,
        "w-vac": 42,
        "w-tv": 42,
        "iot-ap": 46,
        "nvr": 50
      },
      "styles": {},
      "legend": {
        "#84cc16": "Zigbee mesh",
        "#c084fc": "Thread and Matter",
        "#38bdf8": "Wi Fi, VLAN 30",
        "#3b82f6": "Wired"
      },
      "rects": {
        "list": [
          {
            "id": "rect-iot-3",
            "x": 60,
            "y": 260,
            "width": 760,
            "height": 520,
            "color": "#84cc16",
            "style": "filled",
            "lineStyle": "dashed",
            "fillOpacity": 0.12,
            "borderWidth": 2,
            "notes": []
          },
          {
            "id": "rect-iot-6",
            "x": 880,
            "y": 260,
            "width": 760,
            "height": 520,
            "color": "#c084fc",
            "style": "filled",
            "lineStyle": "dashed",
            "fillOpacity": 0.12,
            "borderWidth": 2,
            "notes": []
          },
          {
            "id": "rect-iot-9",
            "x": 1700,
            "y": 260,
            "width": 760,
            "height": 520,
            "color": "#38bdf8",
            "style": "filled",
            "lineStyle": "dashed",
            "fillOpacity": 0.12,
            "borderWidth": 2,
            "notes": []
          }
        ]
      },
      "texts": {
        "list": [
          {
            "id": "text-iot-1",
            "x": 60,
            "y": 110,
            "content": "IoT and Smart Home",
            "fontSize": 46,
            "color": "#e2e8f0",
            "fontWeight": "bold",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-iot-2",
            "x": 60,
            "y": 160,
            "content": "Everything on VLAN 30, controlled by Home Assistant on pve1",
            "fontSize": 20,
            "color": "#94a3b8",
            "fontWeight": "normal",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-iot-4",
            "x": 78,
            "y": 294,
            "content": "Zigbee",
            "fontSize": 24,
            "color": "#84cc16",
            "fontWeight": "bold",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-iot-5",
            "x": 78,
            "y": 324,
            "content": "Channel 25, 32 devices",
            "fontSize": 16,
            "color": "#94a3b8",
            "fontWeight": "normal",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-iot-7",
            "x": 898,
            "y": 294,
            "content": "Thread and Matter",
            "fontSize": 24,
            "color": "#c084fc",
            "fontWeight": "bold",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-iot-8",
            "x": 898,
            "y": 324,
            "content": "Border router in the kitchen speaker",
            "fontSize": 16,
            "color": "#94a3b8",
            "fontWeight": "normal",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-iot-10",
            "x": 1718,
            "y": 294,
            "content": "Wi Fi IoT",
            "fontSize": 24,
            "color": "#38bdf8",
            "fontWeight": "bold",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-iot-11",
            "x": 1718,
            "y": 324,
            "content": "SSID Willow IoT, 2.4 GHz only",
            "fontSize": 16,
            "color": "#94a3b8",
            "fontWeight": "normal",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-iot-29",
            "x": 80,
            "y": 1250,
            "content": "Automations",
            "fontSize": 24,
            "color": "#e2e8f0",
            "fontWeight": "bold",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-iot-30",
            "x": 80,
            "y": 1290,
            "content": "Good night: lock the front door, lights off, arm cameras\nDoorbell: camera on the TV and a phone alert\nLeak: close the water valve, hall light flashes red\nAway: thermostat to eco and start the vacuum",
            "fontSize": 18,
            "color": "#cbd5e1",
            "fontWeight": "normal",
            "fontStyle": "normal",
            "textAlign": "start",
            "textDecoration": "none",
            "bgColor": "#000000",
            "bgEnabled": false,
            "opacity": 1
          },
          {
            "id": "text-iot-31",
            "x": 1000,
            "y": 1290,
            "content": "Select Home Assistant to read the full automation notes.",
            "fontSize": 16,
            "color": "#94a3b8",
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
      "images": {
        "list": []
      },
      "pageState": {
        "title": "Willow Creek Homelab",
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
        "topbarHeight": 52,
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
        "canvasGridEnabled": true,
        "rackFrameFill": "#0f172a",
        "rackGridEnabled": true,
        "rackFrameStroke": "#4fd1c5",
        "rackLineColor": "#475569",
        "rackTextColor": "#4fd1c5",
        "viewOnly": false,
        "defaultEdgeRouting": "straight",
        "animateConnections": false,
        "animationStyle": "arrows",
        "animationDirection": "all",
        "animationSpeed": 1.5,
        "mappingMode": "smarthome",
        "canvasTemplate": "grid",
        "motionTrailsEnabled": true,
        "motionTrailLength": 8,
        "motionTrailStyle": "solid",
        "motionTrailArrow": true,
        "showPortLabels": true,
        "snapToGrid": true,
        "canvasWidth": 4000,
        "canvasHeight": 3000,
        "layerNames": {},
        "markDuplicateIps": false,
        "showHostedOnLinks": true,
        "autoPingEnabled": false,
        "autoPingInterval": 60
      }
    }
  ],
  "currentTabIndex": 0,
  "encryptedSections": {},
  "auditLog": [
    {
      "timestamp": 1794457262766,
      "type": "export",
      "description": "Exported CSV: willow-creek-homelab.csv",
      "details": {},
      "tab": "Network"
    },
    {
      "timestamp": 1794457261296,
      "type": "import",
      "description": "Imported JSON: the-one-file-homelab-demo.json (25 nodes, 17 connections)",
      "details": {},
      "tab": "Network"
    }
  ],
  "savedStyleSets": [],
  "recordings": [],
  "customLanguage": null
}
THEONEFILE_CONFIG-->

# Willow Creek Homelab

> Exported from The One File on 2026-11-12T04:21:02.773Z

## Legend

- #22c55e: WAN and internet
- #3b82f6: 10GbE backbone
- #14b8a6: 2.5GbE PoE
- #a855f7: WireGuard tunnel
- #f97316: Backup traffic
- #94a3b8: Wireless clients

## Layers

- layer1: Physical
- layer2: Services
- layer3: Security
- layer4: Apps

## Nodes

### internet
- **Name:** Internet
- **IP:** 
- **Role:** 
- **Shape:** cloud
- **Tags:** wan
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1020, 170
- **Size:** 70

### ont
- **Name:** Fiber ONT
- **IP:** WAN 198.51.100.24
- **Role:** 
- **Shape:** gateway
- **Tags:** wan; isp
- **Layer:** layer1
- **MAC:** 02:00:5E:10:00:01
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1020, 380
- **Size:** 52
- **Notes:**
  - ISP owned ONT in bridge mode. Public address 198.51.100.24 handed to OPNsense by DHCP.

### opnsense
- **Name:** OPNsense
- **IP:** 10.10.10.1
- **Role:** Firewall and router
- **Shape:** firewall
- **Tags:** core; firewall; dhcp
- **Layer:** layer3
- **MAC:** 02:00:5E:10:00:02
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1020, 640
- **Size:** 58
- **Notes:**
  - <h3>OPNsense edge firewall</h3><p>Fanless four port box. 2.5GbE WAN to the ONT, 10GbE trunk to the core switch with every VLAN tagged.</p><ul><li>DHCP and Unbound forwarding to AdGuard Home</li><li>Inter VLAN rules: IoT and Guest can only reach the internet</li><li>WireGuard on UDP 51820 for roaming devices</li><li>Nightly config backup to the NAS</li></ul><table><thead><tr><th>VLAN</th><th>Name</th><th>Subnet</th></tr></thead><tbody><tr><td>10</td><td>Mgmt</td><td>10.10.10.0/24</td></tr><tr><td>20</td><td>Servers</td><td>10.10.20.0/24</td></tr><tr><td>30</td><td>IoT</td><td>10.10.30.0/24</td></tr><tr><td>40</td><td>Guest</td><td>10.10.40.0/24</td></tr><tr><td>99</td><td>WireGuard</td><td>10.10.99.0/24</td></tr></tbody></table><pre><code>[Interface]<br>Address = 10.10.99.1/24<br>ListenPort = 51820<br><br>[Peer]<br># roaming laptop<br>AllowedIPs = 10.10.99.10/32</code></pre>

### wireguard
- **Name:** WireGuard
- **IP:** 10.10.99.1
- **Role:** VPN endpoint
- **Shape:** vpn
- **Tags:** vpn; remote access
- **Layer:** layer3
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Hosted On:** opnsense
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1600, 640
- **Size:** 48
- **Notes:**
  - Runs on OPNsense. Peers get 10.10.99.0/24 and DNS from AdGuard Home.

### laptop
- **Name:** Roaming Laptop
- **IP:** 10.10.99.10
- **Role:** 
- **Shape:** laptop
- **Tags:** client; remote
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 2200, 640
- **Size:** 50

### offsite
- **Name:** Offsite Backup
- **IP:** Object storage bucket
- **Role:** 
- **Shape:** bucket
- **Tags:** backup; offsite
- **Layer:** layer2
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 330, 640
- **Size:** 52
- **Notes:**
  - Encrypted restic repository. 30 daily, 12 monthly snapshots.

### core
- **Name:** Core Switch
- **IP:** 10.10.10.2
- **Role:** 8 port 10G SFP+
- **Shape:** switch
- **Tags:** core; 10g
- **Layer:** layer1
- **MAC:** 02:00:5E:10:00:03
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1020, 880
- **Size:** 56
- **Notes:**
  - <h3>Port map</h3><ul><li>SFP+ 1: OPNsense trunk</li><li>SFP+ 2: PoE switch</li><li>SFP+ 3 to 5: pve1, pve2, NAS</li><li>SFP+ 8: spare</li></ul>

### pve1
- **Name:** pve1
- **IP:** 10.10.20.11
- **Role:** Proxmox VE
- **Shape:** server
- **Tags:** proxmox; cluster
- **Layer:** layer1
- **MAC:** 02:00:5E:20:00:11
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 200, 1160
- **Size:** 54
- **Notes:**
  - <h3>Proxmox node pve1</h3><ul><li>Ryzen 7, 64 GB ECC, 2 x 1 TB NVMe ZFS mirror</li><li>Dual 10GbE: vmbr0 VLAN aware bridge</li><li>Clustered with pve2, QDevice runs on the NAS</li></ul><pre><code>pvecm status<br>Quorate: Yes<br>Nodes: 2 plus QDevice<br>Total votes: 3</code></pre>

### pve2
- **Name:** pve2
- **IP:** 10.10.20.12
- **Role:** Proxmox VE
- **Shape:** server
- **Tags:** proxmox; cluster
- **Layer:** layer1
- **MAC:** 02:00:5E:20:00:12
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 520, 1160
- **Size:** 54
- **Notes:**
  - Second cluster node. Mini PC, 32 GB RAM, 10GbE through a Thunderbolt adapter.

### nas
- **Name:** NAS
- **IP:** 10.10.20.20
- **Role:** TrueNAS, 4 x 12 TB RAIDZ1
- **Shape:** nas
- **Tags:** storage; nfs; smb
- **Layer:** layer1
- **MAC:** 02:00:5E:20:00:20
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 840, 1160
- **Size:** 54
- **Notes:**
  - <h3>Backups</h3><ol><li>Proxmox Backup Server pulls every VM at 01:00</li><li>NAS snapshots every hour, kept for 48 hours</li><li>Offsite sync at 03:00, encrypted before upload</li></ol><p><b>Rule:</b> three copies, two media, one offsite.</p>

### haos
- **Name:** Home Assistant
- **IP:** 10.10.20.30
- **Role:** VM
- **Shape:** vm
- **Tags:** automation
- **Layer:** layer4
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Hosted On:** pve1
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 140, 1420
- **Size:** 40

### docker
- **Name:** Docker Host
- **IP:** 10.10.20.31
- **Role:** VM
- **Shape:** docker
- **Tags:** containers
- **Layer:** layer4
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Hosted On:** pve1
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 300, 1420
- **Size:** 40
- **Notes:**
  - <h3>Containers</h3><ul><li>Jellyfin</li><li>Immich</li><li>Vaultwarden</li><li>Uptime Kuma</li></ul>

### adguard
- **Name:** AdGuard Home
- **IP:** 10.10.20.53
- **Role:** LXC, DNS
- **Shape:** container
- **Tags:** dns
- **Layer:** layer2
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Hosted On:** pve2
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 470, 1420
- **Size:** 40
- **Notes:**
  - Primary DNS for every VLAN. Upstream DNS over TLS. Local zone lab.home.arpa.

### caddy
- **Name:** Reverse Proxy
- **IP:** 10.10.20.80
- **Role:** LXC, Caddy
- **Shape:** container
- **Tags:** proxy; tls
- **Layer:** layer2
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Hosted On:** pve2
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 640, 1420
- **Size:** 40
- **Notes:**
  - Wildcard certificate for *.lab.home.arpa. Only reachable from LAN and WireGuard.

### pbs
- **Name:** Backup Server
- **IP:** 10.10.20.40
- **Role:** Proxmox Backup Server
- **Shape:** vm
- **Tags:** backup
- **Layer:** layer2
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Hosted On:** pve2
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 840, 1420
- **Size:** 40

### poe
- **Name:** PoE Switch
- **IP:** 10.10.10.3
- **Role:** 16 port 2.5GbE PoE
- **Shape:** switch
- **Tags:** poe; access
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1190, 1160
- **Size:** 50

### ap1
- **Name:** AP Living Room
- **IP:** 10.10.10.21
- **Role:** Wi Fi 7 AP
- **Shape:** access-point
- **Tags:** wifi
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1430, 1160
- **Size:** 46
- **Notes:**
  - SSIDs: Willow (VLAN 10 and 20 by key), Willow IoT (VLAN 30), Willow Guest (VLAN 40).

### kvm
- **Name:** PiKVM
- **IP:** 10.10.10.5
- **Role:** Out of band console
- **Shape:** pi
- **Tags:** oob
- **Layer:** layer3
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1190, 1420
- **Size:** 42

### ap2
- **Name:** AP Office
- **IP:** 10.10.10.22
- **Role:** Wi Fi 7 AP
- **Shape:** access-point
- **Tags:** wifi
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1430, 1420
- **Size:** 46

### zigbee
- **Name:** Zigbee Hub
- **IP:** 10.10.30.10
- **Role:** Ethernet coordinator
- **Shape:** hub
- **Tags:** zigbee
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1740, 1160
- **Size:** 42

### doorbell
- **Name:** Doorbell
- **IP:** 10.10.30.20
- **Role:** RTSP camera
- **Shape:** doorbell
- **Tags:** camera
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1980, 1160
- **Size:** 42

### tv
- **Name:** Living Room TV
- **IP:** 10.10.30.30
- **Role:** 
- **Shape:** smart-tv
- **Tags:** media
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1740, 1420
- **Size:** 42

### thermo
- **Name:** Thermostat
- **IP:** 10.10.30.40
- **Role:** 
- **Shape:** thermostat
- **Tags:** climate
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1980, 1420
- **Size:** 42

### guest1
- **Name:** Guest Laptop
- **IP:** 10.10.40.101
- **Role:** 
- **Shape:** laptop
- **Tags:** guest
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 2300, 1160
- **Size:** 44

### guest2
- **Name:** Guest Phone
- **IP:** 10.10.40.102
- **Role:** 
- **Shape:** phone
- **Tags:** guest
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 2540, 1160
- **Size:** 40

## Connections

- internet --> ont
  - **ID:** edge-net-20
  - **Label:** 2 Gbps fiber
  - **Color:** #22c55e
  - **Width:** 5
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- ont --> opnsense
  - **ID:** edge-net-21
  - **Label:** 2.5GbE
  - **Color:** #22c55e
  - **Width:** 5
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- opnsense --> core
  - **ID:** edge-net-22
  - **Label:** 10GbE trunk
  - **Color:** #3b82f6
  - **Width:** 6
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- wireguard --> laptop
  - **ID:** edge-net-23
  - **Label:** WireGuard
  - **Color:** #a855f7
  - **Width:** 4
  - **Direction:** both
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dashed
  - **Group ID:** 
  - **Animate:** true
  - **Animation Style:** dots
  - **Animation Speed:** 1.5

- core (SFP+ 3) --> pve1 (enp1s0)
  - **ID:** edge-net-24
  - **Label:** 10GbE
  - **Color:** #3b82f6
  - **Width:** 5
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core (SFP+ 4) --> pve2
  - **ID:** edge-net-25
  - **Label:** 10GbE
  - **Color:** #3b82f6
  - **Width:** 5
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core (SFP+ 5) --> nas
  - **ID:** edge-net-26
  - **Label:** 10GbE
  - **Color:** #3b82f6
  - **Width:** 5
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- core (SFP+ 2) --> poe
  - **ID:** edge-net-27
  - **Label:** 
  - **Color:** #3b82f6
  - **Width:** 5
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 
  - **Notes:**
    - 10GbE trunk carrying VLAN 10, 30 and 40

- poe --> ap1
  - **ID:** edge-net-28
  - **Label:** 2.5GbE PoE
  - **Color:** #14b8a6
  - **Width:** 4
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- poe --> ap2
  - **ID:** edge-net-29
  - **Label:** 2.5GbE PoE
  - **Color:** #14b8a6
  - **Width:** 4
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- poe --> kvm
  - **ID:** edge-net-30
  - **Label:** 1GbE
  - **Color:** #14b8a6
  - **Width:** 4
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- ap1 --> zigbee
  - **ID:** edge-net-31
  - **Label:** VLAN 30
  - **Color:** #14b8a6
  - **Width:** 4
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- ap1 --> doorbell
  - **ID:** edge-net-32
  - **Label:** VLAN 30
  - **Color:** #94a3b8
  - **Width:** 4
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- ap2 --> tv
  - **ID:** edge-net-33
  - **Label:** VLAN 30
  - **Color:** #94a3b8
  - **Width:** 4
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- ap2 --> thermo
  - **ID:** edge-net-34
  - **Label:** 
  - **Color:** #94a3b8
  - **Width:** 4
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- pbs --> nas
  - **ID:** edge-net-35
  - **Label:** NFS
  - **Color:** #f97316
  - **Width:** 4
  - **Direction:** forward
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dashed
  - **Group ID:** 

- nas --> offsite
  - **ID:** edge-net-36
  - **Label:** Nightly sync
  - **Color:** #f97316
  - **Width:** 4
  - **Direction:** forward
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dashed
  - **Group ID:** 
  - **Animate:** true
  - **Animation Style:** arrows
  - **Animation Speed:** 1.5

## Zones

### rect-net-7
- **Position:** 40, 1000
- **Size:** 960 x 560
- **Color:** #3b82f6
- **Style:** filled
- **Line Style:** dashed
- **Border Color:** 
- **Border Width:** 2
- **Group ID:** 
- **Fill Opacity:** 0.12

### rect-net-10
- **Position:** 1040, 1000
- **Size:** 520 x 560
- **Color:** #f59e0b
- **Style:** filled
- **Line Style:** dashed
- **Border Color:** 
- **Border Width:** 2
- **Group ID:** 
- **Fill Opacity:** 0.12

### rect-net-13
- **Position:** 1600, 1000
- **Size:** 520 x 560
- **Color:** #10b981
- **Style:** filled
- **Line Style:** dashed
- **Border Color:** 
- **Border Width:** 2
- **Group ID:** 
- **Fill Opacity:** 0.12

### rect-net-16
- **Position:** 2160, 1000
- **Size:** 520 x 560
- **Color:** #a855f7
- **Style:** filled
- **Line Style:** dashed
- **Border Color:** 
- **Border Width:** 2
- **Group ID:** 
- **Fill Opacity:** 0.12

## Text Labels

### text-net-1
- **Position:** 60, 110
- **Content:** Willow Creek Homelab
- **Font Size:** 46
- **Color:** #e2e8f0
- **Font Weight:** bold
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-net-2
- **Position:** 60, 160
- **Content:** Network overview with VLANs, Proxmox, storage and remote access
- **Font Size:** 20
- **Color:** #94a3b8
- **Font Weight:** normal
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-net-3
- **Position:** 60, 200
- **Content:** Layers: Physical, Services, Security, Apps
- **Font Size:** 16
- **Color:** #64748b
- **Font Weight:** normal
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-net-4
- **Position:** 1400, 150
- **Content:** Published through the reverse proxy
- **Font Size:** 22
- **Color:** #93c5fd
- **Font Weight:** bold
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-net-5
- **Position:** 1400, 190
- **Content:** Jellyfin at media.lab.home.arpa<br>Immich at photos.lab.home.arpa<br>Vaultwarden at vault.lab.home.arpa<br>Uptime Kuma at status.lab.home.arpa<br>Home Assistant at ha.lab.home.arpa
- **Font Size:** 17
- **Color:** #cbd5e1
- **Font Weight:** normal
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-net-6
- **Position:** 2000, 190
- **Content:** LAN and WireGuard only.<br>Nothing is port forwarded.<br>DNS: AdGuard Home rewrites<br>*.lab.home.arpa to 10.10.20.80
- **Font Size:** 17
- **Color:** #94a3b8
- **Font Weight:** normal
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-net-8
- **Position:** 58, 1034
- **Content:** Servers  VLAN 20
- **Font Size:** 24
- **Color:** #3b82f6
- **Font Weight:** bold
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-net-9
- **Position:** 58, 1064
- **Content:** 10.10.20.0/24  Proxmox cluster, storage, core services
- **Font Size:** 16
- **Color:** #94a3b8
- **Font Weight:** normal
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-net-11
- **Position:** 1058, 1034
- **Content:** Mgmt  VLAN 10
- **Font Size:** 24
- **Color:** #f59e0b
- **Font Weight:** bold
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-net-12
- **Position:** 1058, 1064
- **Content:** 10.10.10.0/24  switches, APs, out of band
- **Font Size:** 16
- **Color:** #94a3b8
- **Font Weight:** normal
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-net-14
- **Position:** 1618, 1034
- **Content:** IoT  VLAN 30
- **Font Size:** 24
- **Color:** #10b981
- **Font Weight:** bold
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-net-15
- **Position:** 1618, 1064
- **Content:** 10.10.30.0/24  internet only, no LAN access
- **Font Size:** 16
- **Color:** #94a3b8
- **Font Weight:** normal
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-net-17
- **Position:** 2178, 1034
- **Content:** Guest  VLAN 40
- **Font Size:** 24
- **Color:** #a855f7
- **Font Weight:** bold
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-net-18
- **Position:** 2178, 1064
- **Content:** 10.10.40.0/24  client isolation on
- **Font Size:** 16
- **Color:** #94a3b8
- **Font Weight:** normal
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-net-19
- **Position:** 2200, 1400
- **Content:** Guest SSID is broadcast by both APs.<br>Internet only, 50 Mbps per client,<br>portal disabled.
- **Font Size:** 17
- **Color:** #c4b5fd
- **Font Weight:** normal
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

