<!--THEONEFILE_CONFIG
{
  "nodeData": {
    "root": {
      "shape": "circle",
      "name": "Homelab 2027",
      "ip": "Quieter, safer, cheaper to run",
      "role": "",
      "tags": [],
      "notes": [
        "<h3>Goals</h3><ol><li>Under 150 W idle for the whole rack</li><li>Every service behind SSO</li><li>Tested restores every quarter</li></ol><p><b>Budget:</b> 1,800 for the year.</p>"
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
    "net": {
      "shape": "rounded-square",
      "name": "Network",
      "ip": "Q1",
      "role": "",
      "tags": [
        "q1"
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
      "groupId": "grp-net",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "net-0": {
      "shape": "pill",
      "name": "10G to the office",
      "ip": "Q1, fiber run",
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
      "groupId": "grp-net",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "net-1": {
      "shape": "pill",
      "name": "Split IoT VLAN",
      "ip": "Cameras on their own",
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
      "groupId": "grp-net",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "net-2": {
      "shape": "pill",
      "name": "IPv6 everywhere",
      "ip": "Prefix delegation",
      "role": "",
      "tags": [],
      "notes": [
        "<ul><li>Ask ISP for a /56</li><li>One /64 per VLAN</li><li>Firewall rules first</li></ul>"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer1",
      "assignedRack": "",
      "hostedOn": "",
      "isRack": false,
      "locked": false,
      "groupId": "grp-net",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "net-3": {
      "shape": "pill",
      "name": "Second WAN",
      "ip": "LTE failover",
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
      "groupId": "grp-net",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "storage": {
      "shape": "rounded-square",
      "name": "Storage",
      "ip": "Q2",
      "role": "",
      "tags": [
        "q2"
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
      "groupId": "grp-storage",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "storage-0": {
      "shape": "pill",
      "name": "Replace 4 TB disks",
      "ip": "Move to 3 x 16 TB",
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
      "groupId": "grp-storage",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "storage-1": {
      "shape": "pill",
      "name": "Offsite copy",
      "ip": "Friend's house, encrypted",
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
      "groupId": "grp-storage",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "storage-2": {
      "shape": "pill",
      "name": "Restore drills",
      "ip": "Every quarter",
      "role": "",
      "tags": [],
      "notes": [
        "<h3>Restore drill</h3><ol><li>Pick a random VM</li><li>Restore to a scratch host</li><li>Time it and write it down</li></ol>"
      ],
      "mac": "",
      "rackUnit": "",
      "uHeight": "1",
      "layer": "layer1",
      "assignedRack": "",
      "hostedOn": "",
      "isRack": false,
      "locked": false,
      "groupId": "grp-storage",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "compute": {
      "shape": "rounded-square",
      "name": "Compute",
      "ip": "Q2 to Q3",
      "role": "",
      "tags": [
        "q3"
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
      "groupId": "grp-compute",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "compute-0": {
      "shape": "pill",
      "name": "Retire old tower",
      "ip": "Saves about 60 W",
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
      "groupId": "grp-compute",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "compute-1": {
      "shape": "pill",
      "name": "Three node mini PC cluster",
      "ip": "Proxmox with Ceph",
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
      "groupId": "grp-compute",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "compute-2": {
      "shape": "pill",
      "name": "GPU box",
      "ip": "Only if prices drop",
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
      "groupId": "grp-compute",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "security": {
      "shape": "rounded-square",
      "name": "Security",
      "ip": "All year",
      "role": "",
      "tags": [
        "ongoing"
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
      "groupId": "grp-security",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "security-0": {
      "shape": "pill",
      "name": "Single sign on",
      "ip": "Authentik in front of everything",
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
      "groupId": "grp-security",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "security-1": {
      "shape": "pill",
      "name": "Hardware keys",
      "ip": "Two per person",
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
      "groupId": "grp-security",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "security-2": {
      "shape": "pill",
      "name": "Vulnerability scans",
      "ip": "Monthly, report to Notes",
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
      "groupId": "grp-security",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "security-3": {
      "shape": "pill",
      "name": "Secrets manager",
      "ip": "Move API keys out of compose files",
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
      "groupId": "grp-security",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "auto": {
      "shape": "rounded-square",
      "name": "Automation",
      "ip": "Q3",
      "role": "",
      "tags": [
        "q3"
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
      "groupId": "grp-auto",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "auto-0": {
      "shape": "pill",
      "name": "Infrastructure as code",
      "ip": "Terraform and Ansible",
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
      "groupId": "grp-auto",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "auto-1": {
      "shape": "pill",
      "name": "Auto updates",
      "ip": "Staged, canary first",
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
      "groupId": "grp-auto",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "auto-2": {
      "shape": "pill",
      "name": "Status page",
      "ip": "Public, read only",
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
      "groupId": "grp-auto",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "learn": {
      "shape": "rounded-square",
      "name": "Learning",
      "ip": "Q4",
      "role": "",
      "tags": [
        "q4"
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
      "groupId": "grp-learn",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "learn-0": {
      "shape": "pill",
      "name": "Kubernetes cert",
      "ip": "Study 4 hours a week",
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
      "groupId": "grp-learn",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "learn-1": {
      "shape": "pill",
      "name": "Blog the build",
      "ip": "One post a month",
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
      "groupId": "grp-learn",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "learn-2": {
      "shape": "pill",
      "name": "Teach a workshop",
      "ip": "Local maker space",
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
      "groupId": "grp-learn",
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
        "id": "edge-roadmap-3",
        "from": "root",
        "to": "net",
        "width": 6,
        "color": "#3b82f6",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-4",
        "from": "net",
        "to": "net-0",
        "width": 3,
        "color": "#3b82f6",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-5",
        "from": "net",
        "to": "net-1",
        "width": 3,
        "color": "#3b82f6",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-6",
        "from": "net",
        "to": "net-2",
        "width": 3,
        "color": "#3b82f6",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-7",
        "from": "net",
        "to": "net-3",
        "width": 3,
        "color": "#3b82f6",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-8",
        "from": "root",
        "to": "storage",
        "width": 6,
        "color": "#f97316",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-9",
        "from": "storage",
        "to": "storage-0",
        "width": 3,
        "color": "#f97316",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-10",
        "from": "storage",
        "to": "storage-1",
        "width": 3,
        "color": "#f97316",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-11",
        "from": "storage",
        "to": "storage-2",
        "width": 3,
        "color": "#f97316",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-12",
        "from": "root",
        "to": "compute",
        "width": 6,
        "color": "#22c55e",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-13",
        "from": "compute",
        "to": "compute-0",
        "width": 3,
        "color": "#22c55e",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-14",
        "from": "compute",
        "to": "compute-1",
        "width": 3,
        "color": "#22c55e",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-15",
        "from": "compute",
        "to": "compute-2",
        "width": 3,
        "color": "#22c55e",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-16",
        "from": "root",
        "to": "security",
        "width": 6,
        "color": "#ef4444",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-17",
        "from": "security",
        "to": "security-0",
        "width": 3,
        "color": "#ef4444",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-18",
        "from": "security",
        "to": "security-1",
        "width": 3,
        "color": "#ef4444",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-19",
        "from": "security",
        "to": "security-2",
        "width": 3,
        "color": "#ef4444",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-20",
        "from": "security",
        "to": "security-3",
        "width": 3,
        "color": "#ef4444",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-21",
        "from": "root",
        "to": "auto",
        "width": 6,
        "color": "#a855f7",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-22",
        "from": "auto",
        "to": "auto-0",
        "width": 3,
        "color": "#a855f7",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-23",
        "from": "auto",
        "to": "auto-1",
        "width": 3,
        "color": "#a855f7",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-24",
        "from": "auto",
        "to": "auto-2",
        "width": 3,
        "color": "#a855f7",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-25",
        "from": "root",
        "to": "learn",
        "width": 6,
        "color": "#eab308",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-26",
        "from": "learn",
        "to": "learn-0",
        "width": 3,
        "color": "#eab308",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-27",
        "from": "learn",
        "to": "learn-1",
        "width": 3,
        "color": "#eab308",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-roadmap-28",
        "from": "learn",
        "to": "learn-2",
        "width": 3,
        "color": "#eab308",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "curved",
        "_pairIndex": 0,
        "_pairTotal": 1
      }
    ]
  },
  "rectData": {
    "list": []
  },
  "textData": {
    "list": [
      {
        "id": "text-roadmap-1",
        "x": 60,
        "y": 100,
        "content": "Homelab Roadmap 2027",
        "fontSize": 44,
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
        "id": "text-roadmap-2",
        "x": 60,
        "y": 148,
        "content": "Brainstorm for next year. Each branch is a group, so it moves as one.",
        "fontSize": 19,
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
        "id": "text-roadmap-29",
        "x": 60,
        "y": 1480,
        "content": "Colours follow the branch. Select any idea to read its notes.",
        "fontSize": 17,
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
  "imageData": {
    "list": []
  },
  "edgeLegend": {
    "#3b82f6": "Network",
    "#f97316": "Storage",
    "#22c55e": "Compute",
    "#ef4444": "Security",
    "#a855f7": "Automation",
    "#eab308": "Learning"
  },
  "zoneLegend": {},
  "zonePresets": {},
  "nodePositions": {
    "root": {
      "x": 1380,
      "y": 900
    },
    "net": {
      "x": 840,
      "y": 900
    },
    "net-0": {
      "x": 580,
      "y": 1160
    },
    "net-1": {
      "x": 450,
      "y": 1000
    },
    "net-2": {
      "x": 450,
      "y": 800
    },
    "net-3": {
      "x": 580,
      "y": 640
    },
    "storage": {
      "x": 1110,
      "y": 550
    },
    "storage-0": {
      "x": 740,
      "y": 410
    },
    "storage-1": {
      "x": 900,
      "y": 270
    },
    "storage-2": {
      "x": 1140,
      "y": 220
    },
    "compute": {
      "x": 1650,
      "y": 550
    },
    "compute-0": {
      "x": 1620,
      "y": 220
    },
    "compute-1": {
      "x": 1860,
      "y": 270
    },
    "compute-2": {
      "x": 2020,
      "y": 410
    },
    "security": {
      "x": 1920,
      "y": 900
    },
    "security-0": {
      "x": 2180,
      "y": 640
    },
    "security-1": {
      "x": 2310,
      "y": 800
    },
    "security-2": {
      "x": 2310,
      "y": 1000
    },
    "security-3": {
      "x": 2180,
      "y": 1160
    },
    "auto": {
      "x": 1650,
      "y": 1250
    },
    "auto-0": {
      "x": 2020,
      "y": 1390
    },
    "auto-1": {
      "x": 1860,
      "y": 1530
    },
    "auto-2": {
      "x": 1620,
      "y": 1580
    },
    "learn": {
      "x": 1110,
      "y": 1250
    },
    "learn-0": {
      "x": 1140,
      "y": 1580
    },
    "learn-1": {
      "x": 900,
      "y": 1530
    },
    "learn-2": {
      "x": 740,
      "y": 1390
    }
  },
  "nodeSizes": {
    "root": 100,
    "net": 52,
    "net-0": 36,
    "net-1": 36,
    "net-2": 36,
    "net-3": 36,
    "storage": 52,
    "storage-0": 36,
    "storage-1": 36,
    "storage-2": 36,
    "compute": 52,
    "compute-0": 36,
    "compute-1": 36,
    "compute-2": 36,
    "security": 52,
    "security-0": 36,
    "security-1": 36,
    "security-2": 36,
    "security-3": 36,
    "auto": 52,
    "auto-0": 36,
    "auto-1": 36,
    "auto-2": 36,
    "learn": 52,
    "learn-0": 36,
    "learn-1": 36,
    "learn-2": 36
  },
  "nodeStyles": {
    "root": {
      "all": {
        "circleColor": "#0f172a",
        "circleBorder": "#e2e8f0",
        "titleSize": 30
      }
    },
    "net": {
      "all": {
        "circleColor": "#1b3563",
        "circleBorder": "#3b82f6",
        "titleColor": "#3b82f6",
        "titleSize": 24
      }
    },
    "net-0": {
      "all": {
        "circleColor": "#111827",
        "circleBorder": "#3b82f6",
        "titleSize": 18,
        "subColor": "#94a3b8"
      }
    },
    "net-1": {
      "all": {
        "circleColor": "#111827",
        "circleBorder": "#3b82f6",
        "titleSize": 18,
        "subColor": "#94a3b8"
      }
    },
    "net-2": {
      "all": {
        "circleColor": "#111827",
        "circleBorder": "#3b82f6",
        "titleSize": 18,
        "subColor": "#94a3b8"
      }
    },
    "net-3": {
      "all": {
        "circleColor": "#111827",
        "circleBorder": "#3b82f6",
        "titleSize": 18,
        "subColor": "#94a3b8"
      }
    },
    "storage": {
      "all": {
        "circleColor": "#513124",
        "circleBorder": "#f97316",
        "titleColor": "#f97316",
        "titleSize": 24
      }
    },
    "storage-0": {
      "all": {
        "circleColor": "#111827",
        "circleBorder": "#f97316",
        "titleSize": 18,
        "subColor": "#94a3b8"
      }
    },
    "storage-1": {
      "all": {
        "circleColor": "#111827",
        "circleBorder": "#f97316",
        "titleSize": 18,
        "subColor": "#94a3b8"
      }
    },
    "storage-2": {
      "all": {
        "circleColor": "#111827",
        "circleBorder": "#f97316",
        "titleSize": 18,
        "subColor": "#94a3b8"
      }
    },
    "compute": {
      "all": {
        "circleColor": "#144839",
        "circleBorder": "#22c55e",
        "titleColor": "#22c55e",
        "titleSize": 24
      }
    },
    "compute-0": {
      "all": {
        "circleColor": "#111827",
        "circleBorder": "#22c55e",
        "titleSize": 18,
        "subColor": "#94a3b8"
      }
    },
    "compute-1": {
      "all": {
        "circleColor": "#111827",
        "circleBorder": "#22c55e",
        "titleSize": 18,
        "subColor": "#94a3b8"
      }
    },
    "compute-2": {
      "all": {
        "circleColor": "#111827",
        "circleBorder": "#22c55e",
        "titleSize": 18,
        "subColor": "#94a3b8"
      }
    },
    "security": {
      "all": {
        "circleColor": "#4e2431",
        "circleBorder": "#ef4444",
        "titleColor": "#ef4444",
        "titleSize": 24
      }
    },
    "security-0": {
      "all": {
        "circleColor": "#111827",
        "circleBorder": "#ef4444",
        "titleSize": 18,
        "subColor": "#94a3b8"
      }
    },
    "security-1": {
      "all": {
        "circleColor": "#111827",
        "circleBorder": "#ef4444",
        "titleSize": 18,
        "subColor": "#94a3b8"
      }
    },
    "security-2": {
      "all": {
        "circleColor": "#111827",
        "circleBorder": "#ef4444",
        "titleSize": 18,
        "subColor": "#94a3b8"
      }
    },
    "security-3": {
      "all": {
        "circleColor": "#111827",
        "circleBorder": "#ef4444",
        "titleSize": 18,
        "subColor": "#94a3b8"
      }
    },
    "auto": {
      "all": {
        "circleColor": "#3a2863",
        "circleBorder": "#a855f7",
        "titleColor": "#a855f7",
        "titleSize": 24
      }
    },
    "auto-0": {
      "all": {
        "circleColor": "#111827",
        "circleBorder": "#a855f7",
        "titleSize": 18,
        "subColor": "#94a3b8"
      }
    },
    "auto-1": {
      "all": {
        "circleColor": "#111827",
        "circleBorder": "#a855f7",
        "titleSize": 18,
        "subColor": "#94a3b8"
      }
    },
    "auto-2": {
      "all": {
        "circleColor": "#111827",
        "circleBorder": "#a855f7",
        "titleSize": 18,
        "subColor": "#94a3b8"
      }
    },
    "learn": {
      "all": {
        "circleColor": "#4c4320",
        "circleBorder": "#eab308",
        "titleColor": "#eab308",
        "titleSize": 24
      }
    },
    "learn-0": {
      "all": {
        "circleColor": "#111827",
        "circleBorder": "#eab308",
        "titleSize": 18,
        "subColor": "#94a3b8"
      }
    },
    "learn-1": {
      "all": {
        "circleColor": "#111827",
        "circleBorder": "#eab308",
        "titleSize": 18,
        "subColor": "#94a3b8"
      }
    },
    "learn-2": {
      "all": {
        "circleColor": "#111827",
        "circleBorder": "#eab308",
        "titleSize": 18,
        "subColor": "#94a3b8"
      }
    }
  },
  "iconCache": {},
  "page": {
    "title": "Homelab Roadmap 2027",
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
    "canvasGridEnabled": false,
    "rackFrameFill": "#0f172a",
    "rackFrameStroke": "#4fd1c5",
    "rackLineColor": "#475569",
    "rackTextColor": "#4fd1c5",
    "rackGridEnabled": true,
    "viewOnly": false,
    "defaultEdgeRouting": "straight",
    "animateConnections": false,
    "animationStyle": "arrows",
    "animationDirection": "all",
    "animationSpeed": 1.5,
    "motionTrailsEnabled": true,
    "motionTrailLength": 8,
    "motionTrailStyle": "solid",
    "motionTrailArrow": true,
    "showPortLabels": true,
    "snapToGrid": true,
    "canvasWidth": 4000,
    "canvasHeight": 3000,
    "layerNames": {
      "layer1": "Ideas",
      "layer2": "Planned",
      "layer3": "Doing",
      "layer4": "Done"
    },
    "markDuplicateIps": false,
    "showHostedOnLinks": true,
    "mappingMode": "mindmap",
    "autoPingEnabled": false,
    "autoPingInterval": 30,
    "canvasTemplate": "none"
  },
  "autoPingEnabled": false,
  "autoPingInterval": 30,
  "canvas": {
    "zoom": 1.7361111111111112,
    "panX": 228,
    "panY": -24
  },
  "savedTopologyView": {
    "zoom": 1.7361111111111112,
    "panX": 228,
    "panY": -24
  },
  "tabViews": {
    "main": {
      "zoom": 1.7361111111111112,
      "panX": 228,
      "panY": -24
    }
  },
  "documentTabs": [
    {
      "id": "main",
      "name": "Roadmap",
      "nodes": {
        "root": {
          "shape": "circle",
          "name": "Homelab 2027",
          "ip": "Quieter, safer, cheaper to run",
          "role": "",
          "tags": [],
          "notes": [
            "<h3>Goals</h3><ol><li>Under 150 W idle for the whole rack</li><li>Every service behind SSO</li><li>Tested restores every quarter</li></ol><p><b>Budget:</b> 1,800 for the year.</p>"
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
        "net": {
          "shape": "rounded-square",
          "name": "Network",
          "ip": "Q1",
          "role": "",
          "tags": [
            "q1"
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
          "groupId": "grp-net",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "net-0": {
          "shape": "pill",
          "name": "10G to the office",
          "ip": "Q1, fiber run",
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
          "groupId": "grp-net",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "net-1": {
          "shape": "pill",
          "name": "Split IoT VLAN",
          "ip": "Cameras on their own",
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
          "groupId": "grp-net",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "net-2": {
          "shape": "pill",
          "name": "IPv6 everywhere",
          "ip": "Prefix delegation",
          "role": "",
          "tags": [],
          "notes": [
            "<ul><li>Ask ISP for a /56</li><li>One /64 per VLAN</li><li>Firewall rules first</li></ul>"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": "grp-net",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "net-3": {
          "shape": "pill",
          "name": "Second WAN",
          "ip": "LTE failover",
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
          "groupId": "grp-net",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "storage": {
          "shape": "rounded-square",
          "name": "Storage",
          "ip": "Q2",
          "role": "",
          "tags": [
            "q2"
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
          "groupId": "grp-storage",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "storage-0": {
          "shape": "pill",
          "name": "Replace 4 TB disks",
          "ip": "Move to 3 x 16 TB",
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
          "groupId": "grp-storage",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "storage-1": {
          "shape": "pill",
          "name": "Offsite copy",
          "ip": "Friend's house, encrypted",
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
          "groupId": "grp-storage",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "storage-2": {
          "shape": "pill",
          "name": "Restore drills",
          "ip": "Every quarter",
          "role": "",
          "tags": [],
          "notes": [
            "<h3>Restore drill</h3><ol><li>Pick a random VM</li><li>Restore to a scratch host</li><li>Time it and write it down</li></ol>"
          ],
          "mac": "",
          "rackUnit": "",
          "uHeight": "1",
          "layer": "layer1",
          "assignedRack": "",
          "hostedOn": "",
          "isRack": false,
          "locked": false,
          "groupId": "grp-storage",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "compute": {
          "shape": "rounded-square",
          "name": "Compute",
          "ip": "Q2 to Q3",
          "role": "",
          "tags": [
            "q3"
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
          "groupId": "grp-compute",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "compute-0": {
          "shape": "pill",
          "name": "Retire old tower",
          "ip": "Saves about 60 W",
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
          "groupId": "grp-compute",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "compute-1": {
          "shape": "pill",
          "name": "Three node mini PC cluster",
          "ip": "Proxmox with Ceph",
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
          "groupId": "grp-compute",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "compute-2": {
          "shape": "pill",
          "name": "GPU box",
          "ip": "Only if prices drop",
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
          "groupId": "grp-compute",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "security": {
          "shape": "rounded-square",
          "name": "Security",
          "ip": "All year",
          "role": "",
          "tags": [
            "ongoing"
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
          "groupId": "grp-security",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "security-0": {
          "shape": "pill",
          "name": "Single sign on",
          "ip": "Authentik in front of everything",
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
          "groupId": "grp-security",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "security-1": {
          "shape": "pill",
          "name": "Hardware keys",
          "ip": "Two per person",
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
          "groupId": "grp-security",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "security-2": {
          "shape": "pill",
          "name": "Vulnerability scans",
          "ip": "Monthly, report to Notes",
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
          "groupId": "grp-security",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "security-3": {
          "shape": "pill",
          "name": "Secrets manager",
          "ip": "Move API keys out of compose files",
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
          "groupId": "grp-security",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "auto": {
          "shape": "rounded-square",
          "name": "Automation",
          "ip": "Q3",
          "role": "",
          "tags": [
            "q3"
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
          "groupId": "grp-auto",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "auto-0": {
          "shape": "pill",
          "name": "Infrastructure as code",
          "ip": "Terraform and Ansible",
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
          "groupId": "grp-auto",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "auto-1": {
          "shape": "pill",
          "name": "Auto updates",
          "ip": "Staged, canary first",
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
          "groupId": "grp-auto",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "auto-2": {
          "shape": "pill",
          "name": "Status page",
          "ip": "Public, read only",
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
          "groupId": "grp-auto",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "learn": {
          "shape": "rounded-square",
          "name": "Learning",
          "ip": "Q4",
          "role": "",
          "tags": [
            "q4"
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
          "groupId": "grp-learn",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "learn-0": {
          "shape": "pill",
          "name": "Kubernetes cert",
          "ip": "Study 4 hours a week",
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
          "groupId": "grp-learn",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "learn-1": {
          "shape": "pill",
          "name": "Blog the build",
          "ip": "One post a month",
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
          "groupId": "grp-learn",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "learn-2": {
          "shape": "pill",
          "name": "Teach a workshop",
          "ip": "Local maker space",
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
          "groupId": "grp-learn",
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
            "id": "edge-roadmap-3",
            "from": "root",
            "to": "net",
            "width": 6,
            "color": "#3b82f6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-4",
            "from": "net",
            "to": "net-0",
            "width": 3,
            "color": "#3b82f6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-5",
            "from": "net",
            "to": "net-1",
            "width": 3,
            "color": "#3b82f6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-6",
            "from": "net",
            "to": "net-2",
            "width": 3,
            "color": "#3b82f6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-7",
            "from": "net",
            "to": "net-3",
            "width": 3,
            "color": "#3b82f6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-8",
            "from": "root",
            "to": "storage",
            "width": 6,
            "color": "#f97316",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-9",
            "from": "storage",
            "to": "storage-0",
            "width": 3,
            "color": "#f97316",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-10",
            "from": "storage",
            "to": "storage-1",
            "width": 3,
            "color": "#f97316",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-11",
            "from": "storage",
            "to": "storage-2",
            "width": 3,
            "color": "#f97316",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-12",
            "from": "root",
            "to": "compute",
            "width": 6,
            "color": "#22c55e",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-13",
            "from": "compute",
            "to": "compute-0",
            "width": 3,
            "color": "#22c55e",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-14",
            "from": "compute",
            "to": "compute-1",
            "width": 3,
            "color": "#22c55e",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-15",
            "from": "compute",
            "to": "compute-2",
            "width": 3,
            "color": "#22c55e",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-16",
            "from": "root",
            "to": "security",
            "width": 6,
            "color": "#ef4444",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-17",
            "from": "security",
            "to": "security-0",
            "width": 3,
            "color": "#ef4444",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-18",
            "from": "security",
            "to": "security-1",
            "width": 3,
            "color": "#ef4444",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-19",
            "from": "security",
            "to": "security-2",
            "width": 3,
            "color": "#ef4444",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-20",
            "from": "security",
            "to": "security-3",
            "width": 3,
            "color": "#ef4444",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-21",
            "from": "root",
            "to": "auto",
            "width": 6,
            "color": "#a855f7",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-22",
            "from": "auto",
            "to": "auto-0",
            "width": 3,
            "color": "#a855f7",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-23",
            "from": "auto",
            "to": "auto-1",
            "width": 3,
            "color": "#a855f7",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-24",
            "from": "auto",
            "to": "auto-2",
            "width": 3,
            "color": "#a855f7",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-25",
            "from": "root",
            "to": "learn",
            "width": 6,
            "color": "#eab308",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-26",
            "from": "learn",
            "to": "learn-0",
            "width": 3,
            "color": "#eab308",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-27",
            "from": "learn",
            "to": "learn-1",
            "width": 3,
            "color": "#eab308",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-roadmap-28",
            "from": "learn",
            "to": "learn-2",
            "width": 3,
            "color": "#eab308",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          }
        ]
      },
      "positions": {
        "root": {
          "x": 1380,
          "y": 900
        },
        "net": {
          "x": 840,
          "y": 900
        },
        "net-0": {
          "x": 580,
          "y": 1160
        },
        "net-1": {
          "x": 450,
          "y": 1000
        },
        "net-2": {
          "x": 450,
          "y": 800
        },
        "net-3": {
          "x": 580,
          "y": 640
        },
        "storage": {
          "x": 1110,
          "y": 550
        },
        "storage-0": {
          "x": 740,
          "y": 410
        },
        "storage-1": {
          "x": 900,
          "y": 270
        },
        "storage-2": {
          "x": 1140,
          "y": 220
        },
        "compute": {
          "x": 1650,
          "y": 550
        },
        "compute-0": {
          "x": 1620,
          "y": 220
        },
        "compute-1": {
          "x": 1860,
          "y": 270
        },
        "compute-2": {
          "x": 2020,
          "y": 410
        },
        "security": {
          "x": 1920,
          "y": 900
        },
        "security-0": {
          "x": 2180,
          "y": 640
        },
        "security-1": {
          "x": 2310,
          "y": 800
        },
        "security-2": {
          "x": 2310,
          "y": 1000
        },
        "security-3": {
          "x": 2180,
          "y": 1160
        },
        "auto": {
          "x": 1650,
          "y": 1250
        },
        "auto-0": {
          "x": 2020,
          "y": 1390
        },
        "auto-1": {
          "x": 1860,
          "y": 1530
        },
        "auto-2": {
          "x": 1620,
          "y": 1580
        },
        "learn": {
          "x": 1110,
          "y": 1250
        },
        "learn-0": {
          "x": 1140,
          "y": 1580
        },
        "learn-1": {
          "x": 900,
          "y": 1530
        },
        "learn-2": {
          "x": 740,
          "y": 1390
        }
      },
      "sizes": {
        "root": 100,
        "net": 52,
        "net-0": 36,
        "net-1": 36,
        "net-2": 36,
        "net-3": 36,
        "storage": 52,
        "storage-0": 36,
        "storage-1": 36,
        "storage-2": 36,
        "compute": 52,
        "compute-0": 36,
        "compute-1": 36,
        "compute-2": 36,
        "security": 52,
        "security-0": 36,
        "security-1": 36,
        "security-2": 36,
        "security-3": 36,
        "auto": 52,
        "auto-0": 36,
        "auto-1": 36,
        "auto-2": 36,
        "learn": 52,
        "learn-0": 36,
        "learn-1": 36,
        "learn-2": 36
      },
      "styles": {
        "root": {
          "all": {
            "circleColor": "#0f172a",
            "circleBorder": "#e2e8f0",
            "titleSize": 30
          }
        },
        "net": {
          "all": {
            "circleColor": "#1b3563",
            "circleBorder": "#3b82f6",
            "titleColor": "#3b82f6",
            "titleSize": 24
          }
        },
        "net-0": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#3b82f6",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "net-1": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#3b82f6",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "net-2": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#3b82f6",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "net-3": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#3b82f6",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "storage": {
          "all": {
            "circleColor": "#513124",
            "circleBorder": "#f97316",
            "titleColor": "#f97316",
            "titleSize": 24
          }
        },
        "storage-0": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#f97316",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "storage-1": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#f97316",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "storage-2": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#f97316",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "compute": {
          "all": {
            "circleColor": "#144839",
            "circleBorder": "#22c55e",
            "titleColor": "#22c55e",
            "titleSize": 24
          }
        },
        "compute-0": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#22c55e",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "compute-1": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#22c55e",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "compute-2": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#22c55e",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "security": {
          "all": {
            "circleColor": "#4e2431",
            "circleBorder": "#ef4444",
            "titleColor": "#ef4444",
            "titleSize": 24
          }
        },
        "security-0": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#ef4444",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "security-1": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#ef4444",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "security-2": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#ef4444",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "security-3": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#ef4444",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "auto": {
          "all": {
            "circleColor": "#3a2863",
            "circleBorder": "#a855f7",
            "titleColor": "#a855f7",
            "titleSize": 24
          }
        },
        "auto-0": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#a855f7",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "auto-1": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#a855f7",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "auto-2": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#a855f7",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "learn": {
          "all": {
            "circleColor": "#4c4320",
            "circleBorder": "#eab308",
            "titleColor": "#eab308",
            "titleSize": 24
          }
        },
        "learn-0": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#eab308",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "learn-1": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#eab308",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "learn-2": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#eab308",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        }
      },
      "legend": {
        "#3b82f6": "Network",
        "#f97316": "Storage",
        "#22c55e": "Compute",
        "#ef4444": "Security",
        "#a855f7": "Automation",
        "#eab308": "Learning"
      },
      "rects": {
        "list": []
      },
      "texts": {
        "list": [
          {
            "id": "text-roadmap-1",
            "x": 60,
            "y": 100,
            "content": "Homelab Roadmap 2027",
            "fontSize": 44,
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
            "id": "text-roadmap-2",
            "x": 60,
            "y": 148,
            "content": "Brainstorm for next year. Each branch is a group, so it moves as one.",
            "fontSize": 19,
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
            "id": "text-roadmap-29",
            "x": 60,
            "y": 1480,
            "content": "Colours follow the branch. Select any idea to read its notes.",
            "fontSize": 17,
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
        "title": "Homelab Roadmap 2027",
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
        "canvasGridEnabled": false,
        "rackFrameFill": "#0f172a",
        "rackFrameStroke": "#4fd1c5",
        "rackLineColor": "#475569",
        "rackTextColor": "#4fd1c5",
        "rackGridEnabled": true,
        "viewOnly": false,
        "defaultEdgeRouting": "straight",
        "animateConnections": false,
        "animationStyle": "arrows",
        "animationDirection": "all",
        "animationSpeed": 1.5,
        "motionTrailsEnabled": true,
        "motionTrailLength": 8,
        "motionTrailStyle": "solid",
        "motionTrailArrow": true,
        "showPortLabels": true,
        "snapToGrid": true,
        "canvasWidth": 4000,
        "canvasHeight": 3000,
        "layerNames": {
          "layer1": "Ideas",
          "layer2": "Planned",
          "layer3": "Doing",
          "layer4": "Done"
        },
        "markDuplicateIps": false,
        "showHostedOnLinks": true,
        "mappingMode": "mindmap",
        "autoPingEnabled": false,
        "autoPingInterval": 30,
        "canvasTemplate": "none"
      }
    },
    {
      "id": "tab-mindmap-sprint",
      "name": "Q1 Sprint",
      "nodes": {
        "q1": {
          "shape": "circle",
          "name": "Q1 Network",
          "ip": "Jan to Mar",
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
        "q1-fiber": {
          "shape": "rounded-square",
          "name": "10G Office Run",
          "ip": "Week 1 to 3",
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
          "groupId": "grp-q1-fiber",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "q1-fiber-0": {
          "shape": "pill",
          "name": "Buy OM4 fiber",
          "ip": "Done",
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
          "groupId": "grp-q1-fiber",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "q1-fiber-1": {
          "shape": "pill",
          "name": "Pull through conduit",
          "ip": "Week 2",
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
          "groupId": "grp-q1-fiber",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "q1-fiber-2": {
          "shape": "pill",
          "name": "Terminate and test",
          "ip": "Week 3",
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
          "groupId": "grp-q1-fiber",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "q1-vlan": {
          "shape": "rounded-square",
          "name": "Camera VLAN",
          "ip": "Week 4",
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
          "groupId": "grp-q1-vlan",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "q1-vlan-0": {
          "shape": "pill",
          "name": "New VLAN 35",
          "ip": "Firewall rules",
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
          "groupId": "grp-q1-vlan",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "q1-vlan-1": {
          "shape": "pill",
          "name": "Move 6 cameras",
          "ip": "One evening",
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
          "groupId": "grp-q1-vlan",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "q1-vlan-2": {
          "shape": "pill",
          "name": "Block internet",
          "ip": "NVR only",
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
          "groupId": "grp-q1-vlan",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "q1-v6": {
          "shape": "rounded-square",
          "name": "IPv6",
          "ip": "Week 5 to 8",
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
          "groupId": "grp-q1-v6",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "q1-v6-0": {
          "shape": "pill",
          "name": "Prefix delegation",
          "ip": "Test on guest first",
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
          "groupId": "grp-q1-v6",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "q1-v6-1": {
          "shape": "pill",
          "name": "DNS AAAA records",
          "ip": "Internal zone",
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
          "groupId": "grp-q1-v6",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "q1-v6-2": {
          "shape": "pill",
          "name": "Rule audit",
          "ip": "Default deny inbound",
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
          "groupId": "grp-q1-v6",
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
            "id": "edge-sprint-3",
            "from": "q1",
            "to": "q1-fiber",
            "width": 6,
            "color": "#3b82f6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-sprint-4",
            "from": "q1-fiber",
            "to": "q1-fiber-0",
            "width": 3,
            "color": "#3b82f6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-sprint-5",
            "from": "q1-fiber",
            "to": "q1-fiber-1",
            "width": 3,
            "color": "#3b82f6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-sprint-6",
            "from": "q1-fiber",
            "to": "q1-fiber-2",
            "width": 3,
            "color": "#3b82f6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-sprint-7",
            "from": "q1",
            "to": "q1-vlan",
            "width": 6,
            "color": "#14b8a6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-sprint-8",
            "from": "q1-vlan",
            "to": "q1-vlan-0",
            "width": 3,
            "color": "#14b8a6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-sprint-9",
            "from": "q1-vlan",
            "to": "q1-vlan-1",
            "width": 3,
            "color": "#14b8a6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-sprint-10",
            "from": "q1-vlan",
            "to": "q1-vlan-2",
            "width": 3,
            "color": "#14b8a6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-sprint-11",
            "from": "q1",
            "to": "q1-v6",
            "width": 6,
            "color": "#8b5cf6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-sprint-12",
            "from": "q1-v6",
            "to": "q1-v6-0",
            "width": 3,
            "color": "#8b5cf6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-sprint-13",
            "from": "q1-v6",
            "to": "q1-v6-1",
            "width": 3,
            "color": "#8b5cf6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-sprint-14",
            "from": "q1-v6",
            "to": "q1-v6-2",
            "width": 3,
            "color": "#8b5cf6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "curved",
            "_pairIndex": 0,
            "_pairTotal": 1
          }
        ]
      },
      "positions": {
        "q1": {
          "x": 1380,
          "y": 900
        },
        "q1-fiber": {
          "x": 890,
          "y": 690
        },
        "q1-fiber-0": {
          "x": 510,
          "y": 710
        },
        "q1-fiber-1": {
          "x": 560,
          "y": 540
        },
        "q1-fiber-2": {
          "x": 720,
          "y": 420
        },
        "q1-vlan": {
          "x": 1870,
          "y": 690
        },
        "q1-vlan-0": {
          "x": 2040,
          "y": 420
        },
        "q1-vlan-1": {
          "x": 2200,
          "y": 540
        },
        "q1-vlan-2": {
          "x": 2250,
          "y": 710
        },
        "q1-v6": {
          "x": 1380,
          "y": 1320
        },
        "q1-v6-0": {
          "x": 1590,
          "y": 1570
        },
        "q1-v6-1": {
          "x": 1380,
          "y": 1620
        },
        "q1-v6-2": {
          "x": 1170,
          "y": 1570
        }
      },
      "sizes": {
        "q1": 80,
        "q1-fiber": 52,
        "q1-fiber-0": 36,
        "q1-fiber-1": 36,
        "q1-fiber-2": 36,
        "q1-vlan": 52,
        "q1-vlan-0": 36,
        "q1-vlan-1": 36,
        "q1-vlan-2": 36,
        "q1-v6": 52,
        "q1-v6-0": 36,
        "q1-v6-1": 36,
        "q1-v6-2": 36
      },
      "styles": {
        "q1": {
          "all": {
            "circleColor": "#0f172a",
            "circleBorder": "#e2e8f0",
            "titleSize": 30
          }
        },
        "q1-fiber": {
          "all": {
            "circleColor": "#1b3563",
            "circleBorder": "#3b82f6",
            "titleColor": "#3b82f6",
            "titleSize": 24
          }
        },
        "q1-fiber-0": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#3b82f6",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "q1-fiber-1": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#3b82f6",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "q1-fiber-2": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#3b82f6",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "q1-vlan": {
          "all": {
            "circleColor": "#10444d",
            "circleBorder": "#14b8a6",
            "titleColor": "#14b8a6",
            "titleSize": 24
          }
        },
        "q1-vlan-0": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#14b8a6",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "q1-vlan-1": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#14b8a6",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "q1-vlan-2": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#14b8a6",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "q1-v6": {
          "all": {
            "circleColor": "#322a63",
            "circleBorder": "#8b5cf6",
            "titleColor": "#8b5cf6",
            "titleSize": 24
          }
        },
        "q1-v6-0": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#8b5cf6",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "q1-v6-1": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#8b5cf6",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        },
        "q1-v6-2": {
          "all": {
            "circleColor": "#111827",
            "circleBorder": "#8b5cf6",
            "titleSize": 18,
            "subColor": "#94a3b8"
          }
        }
      },
      "legend": {
        "#3b82f6": "10G Office Run",
        "#14b8a6": "Camera VLAN",
        "#8b5cf6": "IPv6"
      },
      "rects": {
        "list": []
      },
      "texts": {
        "list": [
          {
            "id": "text-sprint-1",
            "x": 60,
            "y": 100,
            "content": "Q1 Sprint: Network",
            "fontSize": 44,
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
            "id": "text-sprint-2",
            "x": 60,
            "y": 148,
            "content": "The Network branch broken into tasks",
            "fontSize": 19,
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
        "title": "Homelab Roadmap 2027",
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
        "canvasGridEnabled": false,
        "rackFrameFill": "#0f172a",
        "rackFrameStroke": "#4fd1c5",
        "rackLineColor": "#475569",
        "rackTextColor": "#4fd1c5",
        "rackGridEnabled": true,
        "viewOnly": false,
        "defaultEdgeRouting": "straight",
        "animateConnections": false,
        "animationStyle": "arrows",
        "animationDirection": "all",
        "animationSpeed": 1.5,
        "motionTrailsEnabled": true,
        "motionTrailLength": 8,
        "motionTrailStyle": "solid",
        "motionTrailArrow": true,
        "showPortLabels": true,
        "snapToGrid": true,
        "canvasWidth": 4000,
        "canvasHeight": 3000,
        "layerNames": {
          "layer1": "Ideas",
          "layer2": "Planned",
          "layer3": "Doing",
          "layer4": "Done"
        },
        "markDuplicateIps": false,
        "showHostedOnLinks": true,
        "mappingMode": "mindmap",
        "autoPingEnabled": false,
        "autoPingInterval": 60,
        "canvasTemplate": "none"
      }
    }
  ],
  "currentTabIndex": 0,
  "encryptedSections": {},
  "auditLog": [
    {
      "timestamp": 1794457295077,
      "type": "export",
      "description": "Exported CSV: homelab-roadmap-2027.csv",
      "details": {},
      "tab": "Roadmap"
    },
    {
      "timestamp": 1794457293604,
      "type": "import",
      "description": "Imported JSON: theonefile-networkening-mindmap-demo.json (27 nodes, 26 connections)",
      "details": {},
      "tab": "Roadmap"
    }
  ],
  "savedStyleSets": [],
  "recordings": [],
  "customLanguage": null
}
THEONEFILE_CONFIG-->

# Homelab Roadmap 2027

> Exported from The One File on 2026-11-12T04:21:35.083Z

## Legend

- #3b82f6: Network
- #f97316: Storage
- #22c55e: Compute
- #ef4444: Security
- #a855f7: Automation
- #eab308: Learning

## Layers

- layer1: Ideas
- layer2: Planned
- layer3: Doing
- layer4: Done

## Nodes

### root
- **Name:** Homelab 2027
- **IP:** Quieter, safer, cheaper to run
- **Role:** 
- **Shape:** circle
- **Tags:** _none_
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
- **Position:** 1380, 900
- **Size:** 100
- **Notes:**
  - <h3>Goals</h3><ol><li>Under 150 W idle for the whole rack</li><li>Every service behind SSO</li><li>Tested restores every quarter</li></ol><p><b>Budget:</b> 1,800 for the year.</p>
- **Styles:** `{"all":{"circleColor":"#0f172a","circleBorder":"#e2e8f0","titleSize":30}}`

### net
- **Name:** Network
- **IP:** Q1
- **Role:** 
- **Shape:** rounded-square
- **Tags:** q1
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-net
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 840, 900
- **Size:** 52
- **Styles:** `{"all":{"circleColor":"#1b3563","circleBorder":"#3b82f6","titleColor":"#3b82f6","titleSize":24}}`

### net-0
- **Name:** 10G to the office
- **IP:** Q1, fiber run
- **Role:** 
- **Shape:** pill
- **Tags:** _none_
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-net
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 580, 1160
- **Size:** 36
- **Styles:** `{"all":{"circleColor":"#111827","circleBorder":"#3b82f6","titleSize":18,"subColor":"#94a3b8"}}`

### net-1
- **Name:** Split IoT VLAN
- **IP:** Cameras on their own
- **Role:** 
- **Shape:** pill
- **Tags:** _none_
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-net
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 450, 1000
- **Size:** 36
- **Styles:** `{"all":{"circleColor":"#111827","circleBorder":"#3b82f6","titleSize":18,"subColor":"#94a3b8"}}`

### net-2
- **Name:** IPv6 everywhere
- **IP:** Prefix delegation
- **Role:** 
- **Shape:** pill
- **Tags:** _none_
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-net
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 450, 800
- **Size:** 36
- **Notes:**
  - <ul><li>Ask ISP for a /56</li><li>One /64 per VLAN</li><li>Firewall rules first</li></ul>
- **Styles:** `{"all":{"circleColor":"#111827","circleBorder":"#3b82f6","titleSize":18,"subColor":"#94a3b8"}}`

### net-3
- **Name:** Second WAN
- **IP:** LTE failover
- **Role:** 
- **Shape:** pill
- **Tags:** _none_
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-net
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 580, 640
- **Size:** 36
- **Styles:** `{"all":{"circleColor":"#111827","circleBorder":"#3b82f6","titleSize":18,"subColor":"#94a3b8"}}`

### storage
- **Name:** Storage
- **IP:** Q2
- **Role:** 
- **Shape:** rounded-square
- **Tags:** q2
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-storage
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1110, 550
- **Size:** 52
- **Styles:** `{"all":{"circleColor":"#513124","circleBorder":"#f97316","titleColor":"#f97316","titleSize":24}}`

### storage-0
- **Name:** Replace 4 TB disks
- **IP:** Move to 3 x 16 TB
- **Role:** 
- **Shape:** pill
- **Tags:** _none_
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-storage
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 740, 410
- **Size:** 36
- **Styles:** `{"all":{"circleColor":"#111827","circleBorder":"#f97316","titleSize":18,"subColor":"#94a3b8"}}`

### storage-1
- **Name:** Offsite copy
- **IP:** Friend's house, encrypted
- **Role:** 
- **Shape:** pill
- **Tags:** _none_
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-storage
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 900, 270
- **Size:** 36
- **Styles:** `{"all":{"circleColor":"#111827","circleBorder":"#f97316","titleSize":18,"subColor":"#94a3b8"}}`

### storage-2
- **Name:** Restore drills
- **IP:** Every quarter
- **Role:** 
- **Shape:** pill
- **Tags:** _none_
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-storage
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1140, 220
- **Size:** 36
- **Notes:**
  - <h3>Restore drill</h3><ol><li>Pick a random VM</li><li>Restore to a scratch host</li><li>Time it and write it down</li></ol>
- **Styles:** `{"all":{"circleColor":"#111827","circleBorder":"#f97316","titleSize":18,"subColor":"#94a3b8"}}`

### compute
- **Name:** Compute
- **IP:** Q2 to Q3
- **Role:** 
- **Shape:** rounded-square
- **Tags:** q3
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-compute
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1650, 550
- **Size:** 52
- **Styles:** `{"all":{"circleColor":"#144839","circleBorder":"#22c55e","titleColor":"#22c55e","titleSize":24}}`

### compute-0
- **Name:** Retire old tower
- **IP:** Saves about 60 W
- **Role:** 
- **Shape:** pill
- **Tags:** _none_
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-compute
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1620, 220
- **Size:** 36
- **Styles:** `{"all":{"circleColor":"#111827","circleBorder":"#22c55e","titleSize":18,"subColor":"#94a3b8"}}`

### compute-1
- **Name:** Three node mini PC cluster
- **IP:** Proxmox with Ceph
- **Role:** 
- **Shape:** pill
- **Tags:** _none_
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-compute
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1860, 270
- **Size:** 36
- **Styles:** `{"all":{"circleColor":"#111827","circleBorder":"#22c55e","titleSize":18,"subColor":"#94a3b8"}}`

### compute-2
- **Name:** GPU box
- **IP:** Only if prices drop
- **Role:** 
- **Shape:** pill
- **Tags:** _none_
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-compute
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 2020, 410
- **Size:** 36
- **Styles:** `{"all":{"circleColor":"#111827","circleBorder":"#22c55e","titleSize":18,"subColor":"#94a3b8"}}`

### security
- **Name:** Security
- **IP:** All year
- **Role:** 
- **Shape:** rounded-square
- **Tags:** ongoing
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-security
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1920, 900
- **Size:** 52
- **Styles:** `{"all":{"circleColor":"#4e2431","circleBorder":"#ef4444","titleColor":"#ef4444","titleSize":24}}`

### security-0
- **Name:** Single sign on
- **IP:** Authentik in front of everything
- **Role:** 
- **Shape:** pill
- **Tags:** _none_
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-security
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 2180, 640
- **Size:** 36
- **Styles:** `{"all":{"circleColor":"#111827","circleBorder":"#ef4444","titleSize":18,"subColor":"#94a3b8"}}`

### security-1
- **Name:** Hardware keys
- **IP:** Two per person
- **Role:** 
- **Shape:** pill
- **Tags:** _none_
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-security
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 2310, 800
- **Size:** 36
- **Styles:** `{"all":{"circleColor":"#111827","circleBorder":"#ef4444","titleSize":18,"subColor":"#94a3b8"}}`

### security-2
- **Name:** Vulnerability scans
- **IP:** Monthly, report to Notes
- **Role:** 
- **Shape:** pill
- **Tags:** _none_
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-security
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 2310, 1000
- **Size:** 36
- **Styles:** `{"all":{"circleColor":"#111827","circleBorder":"#ef4444","titleSize":18,"subColor":"#94a3b8"}}`

### security-3
- **Name:** Secrets manager
- **IP:** Move API keys out of compose files
- **Role:** 
- **Shape:** pill
- **Tags:** _none_
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-security
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 2180, 1160
- **Size:** 36
- **Styles:** `{"all":{"circleColor":"#111827","circleBorder":"#ef4444","titleSize":18,"subColor":"#94a3b8"}}`

### auto
- **Name:** Automation
- **IP:** Q3
- **Role:** 
- **Shape:** rounded-square
- **Tags:** q3
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-auto
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1650, 1250
- **Size:** 52
- **Styles:** `{"all":{"circleColor":"#3a2863","circleBorder":"#a855f7","titleColor":"#a855f7","titleSize":24}}`

### auto-0
- **Name:** Infrastructure as code
- **IP:** Terraform and Ansible
- **Role:** 
- **Shape:** pill
- **Tags:** _none_
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-auto
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 2020, 1390
- **Size:** 36
- **Styles:** `{"all":{"circleColor":"#111827","circleBorder":"#a855f7","titleSize":18,"subColor":"#94a3b8"}}`

### auto-1
- **Name:** Auto updates
- **IP:** Staged, canary first
- **Role:** 
- **Shape:** pill
- **Tags:** _none_
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-auto
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1860, 1530
- **Size:** 36
- **Styles:** `{"all":{"circleColor":"#111827","circleBorder":"#a855f7","titleSize":18,"subColor":"#94a3b8"}}`

### auto-2
- **Name:** Status page
- **IP:** Public, read only
- **Role:** 
- **Shape:** pill
- **Tags:** _none_
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-auto
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1620, 1580
- **Size:** 36
- **Styles:** `{"all":{"circleColor":"#111827","circleBorder":"#a855f7","titleSize":18,"subColor":"#94a3b8"}}`

### learn
- **Name:** Learning
- **IP:** Q4
- **Role:** 
- **Shape:** rounded-square
- **Tags:** q4
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-learn
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1110, 1250
- **Size:** 52
- **Styles:** `{"all":{"circleColor":"#4c4320","circleBorder":"#eab308","titleColor":"#eab308","titleSize":24}}`

### learn-0
- **Name:** Kubernetes cert
- **IP:** Study 4 hours a week
- **Role:** 
- **Shape:** pill
- **Tags:** _none_
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-learn
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1140, 1580
- **Size:** 36
- **Styles:** `{"all":{"circleColor":"#111827","circleBorder":"#eab308","titleSize":18,"subColor":"#94a3b8"}}`

### learn-1
- **Name:** Blog the build
- **IP:** One post a month
- **Role:** 
- **Shape:** pill
- **Tags:** _none_
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-learn
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 900, 1530
- **Size:** 36
- **Styles:** `{"all":{"circleColor":"#111827","circleBorder":"#eab308","titleSize":18,"subColor":"#94a3b8"}}`

### learn-2
- **Name:** Teach a workshop
- **IP:** Local maker space
- **Role:** 
- **Shape:** pill
- **Tags:** _none_
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-learn
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 740, 1390
- **Size:** 36
- **Styles:** `{"all":{"circleColor":"#111827","circleBorder":"#eab308","titleSize":18,"subColor":"#94a3b8"}}`

## Connections

- root --> net
  - **ID:** edge-roadmap-3
  - **Label:** 
  - **Color:** #3b82f6
  - **Width:** 6
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- net --> net-0
  - **ID:** edge-roadmap-4
  - **Label:** 
  - **Color:** #3b82f6
  - **Width:** 3
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- net --> net-1
  - **ID:** edge-roadmap-5
  - **Label:** 
  - **Color:** #3b82f6
  - **Width:** 3
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- net --> net-2
  - **ID:** edge-roadmap-6
  - **Label:** 
  - **Color:** #3b82f6
  - **Width:** 3
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- net --> net-3
  - **ID:** edge-roadmap-7
  - **Label:** 
  - **Color:** #3b82f6
  - **Width:** 3
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- root --> storage
  - **ID:** edge-roadmap-8
  - **Label:** 
  - **Color:** #f97316
  - **Width:** 6
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- storage --> storage-0
  - **ID:** edge-roadmap-9
  - **Label:** 
  - **Color:** #f97316
  - **Width:** 3
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- storage --> storage-1
  - **ID:** edge-roadmap-10
  - **Label:** 
  - **Color:** #f97316
  - **Width:** 3
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- storage --> storage-2
  - **ID:** edge-roadmap-11
  - **Label:** 
  - **Color:** #f97316
  - **Width:** 3
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- root --> compute
  - **ID:** edge-roadmap-12
  - **Label:** 
  - **Color:** #22c55e
  - **Width:** 6
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- compute --> compute-0
  - **ID:** edge-roadmap-13
  - **Label:** 
  - **Color:** #22c55e
  - **Width:** 3
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- compute --> compute-1
  - **ID:** edge-roadmap-14
  - **Label:** 
  - **Color:** #22c55e
  - **Width:** 3
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- compute --> compute-2
  - **ID:** edge-roadmap-15
  - **Label:** 
  - **Color:** #22c55e
  - **Width:** 3
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- root --> security
  - **ID:** edge-roadmap-16
  - **Label:** 
  - **Color:** #ef4444
  - **Width:** 6
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- security --> security-0
  - **ID:** edge-roadmap-17
  - **Label:** 
  - **Color:** #ef4444
  - **Width:** 3
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- security --> security-1
  - **ID:** edge-roadmap-18
  - **Label:** 
  - **Color:** #ef4444
  - **Width:** 3
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- security --> security-2
  - **ID:** edge-roadmap-19
  - **Label:** 
  - **Color:** #ef4444
  - **Width:** 3
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- security --> security-3
  - **ID:** edge-roadmap-20
  - **Label:** 
  - **Color:** #ef4444
  - **Width:** 3
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- root --> auto
  - **ID:** edge-roadmap-21
  - **Label:** 
  - **Color:** #a855f7
  - **Width:** 6
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- auto --> auto-0
  - **ID:** edge-roadmap-22
  - **Label:** 
  - **Color:** #a855f7
  - **Width:** 3
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- auto --> auto-1
  - **ID:** edge-roadmap-23
  - **Label:** 
  - **Color:** #a855f7
  - **Width:** 3
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- auto --> auto-2
  - **ID:** edge-roadmap-24
  - **Label:** 
  - **Color:** #a855f7
  - **Width:** 3
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- root --> learn
  - **ID:** edge-roadmap-25
  - **Label:** 
  - **Color:** #eab308
  - **Width:** 6
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- learn --> learn-0
  - **ID:** edge-roadmap-26
  - **Label:** 
  - **Color:** #eab308
  - **Width:** 3
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- learn --> learn-1
  - **ID:** edge-roadmap-27
  - **Label:** 
  - **Color:** #eab308
  - **Width:** 3
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

- learn --> learn-2
  - **ID:** edge-roadmap-28
  - **Label:** 
  - **Color:** #eab308
  - **Width:** 3
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

## Zones

_No zones_

## Text Labels

### text-roadmap-1
- **Position:** 60, 100
- **Content:** Homelab Roadmap 2027
- **Font Size:** 44
- **Color:** #e2e8f0
- **Font Weight:** bold
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-roadmap-2
- **Position:** 60, 148
- **Content:** Brainstorm for next year. Each branch is a group, so it moves as one.
- **Font Size:** 19
- **Color:** #94a3b8
- **Font Weight:** normal
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-roadmap-29
- **Position:** 60, 1480
- **Content:** Colours follow the branch. Select any idea to read its notes.
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

