<!--THEONEFILE_CONFIG
{
  "nodeData": {
    "hub": {
      "shape": "hub",
      "name": "Home Hub",
      "ip": "Zigbee, Thread, Wi Fi",
      "role": "Home Assistant",
      "tags": [
        "core"
      ],
      "notes": [
        "<h3>Home Hub</h3><p>Runs Home Assistant with a built in Zigbee and Thread radio.</p><ul><li>94 devices</li><li>31 automations</li><li>Nightly backup to the NAS</li></ul>"
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
    "lr-l1": {
      "shape": "smart-bulb",
      "name": "Ceiling 1",
      "ip": "Zigbee bulb",
      "role": "",
      "tags": [
        "lights"
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
      "groupId": "grp-living-lights",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "lr-l2": {
      "shape": "smart-bulb",
      "name": "Ceiling 2",
      "ip": "Zigbee bulb",
      "role": "",
      "tags": [
        "lights"
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
      "groupId": "grp-living-lights",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "lr-l3": {
      "shape": "smart-bulb",
      "name": "Ceiling 3",
      "ip": "Zigbee bulb",
      "role": "",
      "tags": [
        "lights"
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
      "groupId": "grp-living-lights",
      "ping": {
        "enabled": false,
        "protocol": "http",
        "customUrl": "",
        "timeout": 3000,
        "status": "unknown",
        "lastCheck": null
      }
    },
    "lr-tv": {
      "shape": "smart-tv",
      "name": "TV",
      "ip": "Wi Fi",
      "role": "",
      "tags": [
        "media"
      ],
      "notes": [],
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
    "lr-spk": {
      "shape": "smart-speaker",
      "name": "Soundbar",
      "ip": "Wi Fi",
      "role": "",
      "tags": [
        "media"
      ],
      "notes": [],
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
    "lr-motion": {
      "shape": "motion-sensor",
      "name": "Living Motion",
      "ip": "Zigbee",
      "role": "",
      "tags": [],
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
      },
      "fovEnabled": true,
      "fovAngle": 110,
      "fovDistance": 200,
      "fovRotation": 45,
      "fovColor": "#10b981",
      "fovOpacity": 15,
      "fovAnimationType": "pulse",
      "fovAnimate": true,
      "fovSpeed": 3,
      "fovBorderColor": "#10b981",
      "fovBorderOpacity": 50
    },
    "k-plug": {
      "shape": "smart-plug",
      "name": "Coffee Plug",
      "ip": "Zigbee router",
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
    "k-lights": {
      "shape": "smart-bulb",
      "name": "Kitchen Lights",
      "ip": "Zigbee",
      "role": "",
      "tags": [
        "lights"
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
    "k-smoke": {
      "shape": "smoke-detector",
      "name": "Smoke Alarm",
      "ip": "Zigbee",
      "role": "",
      "tags": [
        "safety"
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
      },
      "fovEnabled": true,
      "fovAngle": 360,
      "fovDistance": 110,
      "fovColor": "#ef4444",
      "fovOpacity": 12,
      "fovAnimationType": "pulse",
      "fovAnimate": false,
      "fovBorderColor": "#ef4444",
      "fovBorderOpacity": 40
    },
    "k-leak": {
      "shape": "sensor",
      "name": "Sink Leak",
      "ip": "Zigbee",
      "role": "",
      "tags": [
        "safety"
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
    "k-speaker": {
      "shape": "smart-speaker",
      "name": "Kitchen Speaker",
      "ip": "Thread border router",
      "role": "",
      "tags": [],
      "notes": [],
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
    "k-temp": {
      "shape": "sensor",
      "name": "Fridge Temp",
      "ip": "Thread",
      "role": "",
      "tags": [],
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
    "e-bell": {
      "shape": "doorbell",
      "name": "Doorbell",
      "ip": "Wi Fi, 2K",
      "role": "",
      "tags": [
        "camera"
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
      },
      "fovEnabled": true,
      "fovAngle": 85,
      "fovDistance": 150,
      "fovRotation": 0,
      "fovColor": "#f59e0b",
      "fovOpacity": 18,
      "fovAnimationType": "sweep",
      "fovAnimate": false,
      "fovBorderColor": "#f59e0b",
      "fovBorderOpacity": 60
    },
    "e-lock": {
      "shape": "smart-lock",
      "name": "Front Lock",
      "ip": "Thread",
      "role": "",
      "tags": [
        "security"
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
    "e-motion": {
      "shape": "motion-sensor",
      "name": "Hall Motion",
      "ip": "Zigbee",
      "role": "",
      "tags": [],
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
      },
      "fovEnabled": true,
      "fovAngle": 110,
      "fovDistance": 200,
      "fovRotation": 0,
      "fovColor": "#10b981",
      "fovOpacity": 15,
      "fovAnimationType": "pulse",
      "fovAnimate": true,
      "fovSpeed": 3,
      "fovBorderColor": "#10b981",
      "fovBorderOpacity": 50
    },
    "g-door": {
      "shape": "garage",
      "name": "Garage Door",
      "ip": "Wi Fi relay",
      "role": "",
      "tags": [
        "security"
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
    "g-ev": {
      "shape": "smart-plug",
      "name": "EV Charger",
      "ip": "Wi Fi, 11 kW",
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
    "g-cam": {
      "shape": "camera",
      "name": "Garage Cam",
      "ip": "PoE",
      "role": "",
      "tags": [],
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
      },
      "fovEnabled": true,
      "fovAngle": 85,
      "fovDistance": 230,
      "fovRotation": 315,
      "fovColor": "#f59e0b",
      "fovOpacity": 18,
      "fovAnimationType": "sweep",
      "fovAnimate": false,
      "fovBorderColor": "#f59e0b",
      "fovBorderOpacity": 60
    },
    "u-valve": {
      "shape": "smart-plug",
      "name": "Water Main Valve",
      "ip": "Zigbee",
      "role": "",
      "tags": [
        "safety"
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
    "u-washer": {
      "shape": "smart-plug",
      "name": "Washer Plug",
      "ip": "Zigbee router, power meter",
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
    "u-leak": {
      "shape": "sensor",
      "name": "Washer Leak",
      "ip": "Zigbee",
      "role": "",
      "tags": [
        "safety"
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
    "u-vac": {
      "shape": "vacuum",
      "name": "Robot Vacuum",
      "ip": "Wi Fi",
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
    "o-lamp": {
      "shape": "smart-bulb",
      "name": "Desk Lamp",
      "ip": "Zigbee",
      "role": "",
      "tags": [
        "lights"
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
    "o-blinds": {
      "shape": "smart-plug",
      "name": "Office Blinds",
      "ip": "Thread",
      "role": "",
      "tags": [],
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
    "o-air": {
      "shape": "sensor",
      "name": "Air Quality",
      "ip": "Thread, CO2 and VOC",
      "role": "",
      "tags": [],
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
    "b-hum": {
      "shape": "sensor",
      "name": "Humidity",
      "ip": "Zigbee",
      "role": "",
      "tags": [],
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
    "b-fan": {
      "shape": "smart-plug",
      "name": "Bath Fan",
      "ip": "Zigbee switch",
      "role": "",
      "tags": [],
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
    "p-cam": {
      "shape": "camera",
      "name": "Patio Cam",
      "ip": "PoE",
      "role": "",
      "tags": [],
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
      },
      "fovEnabled": true,
      "fovAngle": 85,
      "fovDistance": 300,
      "fovRotation": 135,
      "fovColor": "#f59e0b",
      "fovOpacity": 18,
      "fovAnimationType": "sweep",
      "fovAnimate": false,
      "fovBorderColor": "#f59e0b",
      "fovBorderOpacity": 60
    },
    "p-lights": {
      "shape": "smart-plug",
      "name": "String Lights",
      "ip": "Outdoor plug",
      "role": "",
      "tags": [
        "lights"
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
    "p-sprinkler": {
      "shape": "sprinkler",
      "name": "Sprinkler Zone 1",
      "ip": "Wi Fi controller",
      "role": "",
      "tags": [],
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
      },
      "fovEnabled": true,
      "fovAngle": 180,
      "fovDistance": 200,
      "fovRotation": 270,
      "fovColor": "#06b6d4",
      "fovOpacity": 20,
      "fovAnimationType": "spin",
      "fovAnimate": true,
      "fovSpeed": 6
    }
  },
  "edgeData": {
    "list": [
      {
        "id": "edge-ground-26",
        "from": "hub",
        "to": "lr-l1",
        "width": 3,
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
        "id": "edge-ground-27",
        "from": "hub",
        "to": "lr-l2",
        "width": 3,
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
        "id": "edge-ground-28",
        "from": "hub",
        "to": "lr-l3",
        "width": 3,
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
        "id": "edge-ground-29",
        "from": "hub",
        "to": "lr-motion",
        "width": 3,
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
        "id": "edge-ground-30",
        "from": "hub",
        "to": "lr-tv",
        "width": 3,
        "color": "#38bdf8",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dashed",
        "routing": "straight",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-ground-31",
        "from": "hub",
        "to": "lr-spk",
        "width": 3,
        "color": "#38bdf8",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dashed",
        "routing": "straight",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-ground-32",
        "from": "hub",
        "to": "k-plug",
        "width": 3,
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
        "id": "edge-ground-33",
        "from": "k-plug",
        "to": "k-lights",
        "width": 3,
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
        "id": "edge-ground-34",
        "from": "k-plug",
        "to": "k-leak",
        "width": 3,
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
        "id": "edge-ground-35",
        "from": "k-lights",
        "to": "k-smoke",
        "width": 3,
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
        "id": "edge-ground-36",
        "from": "hub",
        "to": "k-speaker",
        "width": 3,
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
        "id": "edge-ground-37",
        "from": "k-speaker",
        "to": "k-temp",
        "width": 3,
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
        "id": "edge-ground-38",
        "from": "k-speaker",
        "to": "o-blinds",
        "width": 3,
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
        "id": "edge-ground-39",
        "from": "k-speaker",
        "to": "o-air",
        "width": 3,
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
        "id": "edge-ground-40",
        "from": "k-lights",
        "to": "e-motion",
        "width": 3,
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
        "id": "edge-ground-41",
        "from": "k-speaker",
        "to": "e-lock",
        "width": 3,
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
        "id": "edge-ground-42",
        "from": "e-lock",
        "to": "e-bell",
        "width": 3,
        "color": "#38bdf8",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dashed",
        "routing": "straight",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-ground-43",
        "from": "g-door",
        "to": "g-ev",
        "width": 3,
        "color": "#38bdf8",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dashed",
        "routing": "straight",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-ground-44",
        "from": "hub",
        "to": "u-washer",
        "width": 3,
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
        "id": "edge-ground-45",
        "from": "u-washer",
        "to": "u-valve",
        "width": 3,
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
        "id": "edge-ground-46",
        "from": "u-washer",
        "to": "u-leak",
        "width": 3,
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
        "id": "edge-ground-47",
        "from": "u-washer",
        "to": "o-lamp",
        "width": 3,
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
        "id": "edge-ground-48",
        "from": "o-lamp",
        "to": "b-hum",
        "width": 3,
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
        "id": "edge-ground-49",
        "from": "b-hum",
        "to": "b-fan",
        "width": 3,
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
        "id": "edge-ground-50",
        "from": "u-leak",
        "to": "u-valve",
        "width": 4,
        "color": "#f59e0b",
        "direction": "forward",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "straight",
        "label": "Leak closes valve",
        "animate": true,
        "animationStyle": "arrows",
        "animationSpeed": 1.5,
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-ground-51",
        "from": "e-bell",
        "to": "lr-tv",
        "width": 4,
        "color": "#f59e0b",
        "direction": "forward",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dashed",
        "routing": "straight",
        "label": "Doorbell on TV",
        "waypoints": [
          {
            "x": 2160,
            "y": 300
          },
          {
            "x": 860,
            "y": 300
          }
        ],
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-ground-52",
        "from": "p-cam",
        "to": "p-lights",
        "width": 3,
        "color": "#38bdf8",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dashed",
        "routing": "straight",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-ground-53",
        "from": "p-lights",
        "to": "p-sprinkler",
        "width": 3,
        "color": "#38bdf8",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "dashed",
        "routing": "straight",
        "_pairIndex": 0,
        "_pairTotal": 1
      },
      {
        "id": "edge-ground-54",
        "from": "p-cam",
        "to": "g-cam",
        "width": 4,
        "color": "#3b82f6",
        "direction": "none",
        "type": "main",
        "notes": [],
        "fromPort": "",
        "toPort": "",
        "lineStyle": "solid",
        "routing": "straight",
        "label": "PoE to garage switch",
        "_pairIndex": 0,
        "_pairTotal": 1
      }
    ]
  },
  "rectData": {
    "list": [
      {
        "id": "rect-ground-3",
        "x": 100,
        "y": 220,
        "width": 900,
        "height": 640,
        "color": "#3b82f6",
        "style": "filled",
        "lineStyle": "solid",
        "fillOpacity": 0.1,
        "borderWidth": 2,
        "notes": []
      },
      {
        "id": "rect-ground-6",
        "x": 1000,
        "y": 220,
        "width": 800,
        "height": 640,
        "color": "#f59e0b",
        "style": "filled",
        "lineStyle": "solid",
        "fillOpacity": 0.1,
        "borderWidth": 2,
        "notes": []
      },
      {
        "id": "rect-ground-9",
        "x": 1800,
        "y": 220,
        "width": 450,
        "height": 640,
        "color": "#a855f7",
        "style": "filled",
        "lineStyle": "solid",
        "fillOpacity": 0.1,
        "borderWidth": 2,
        "notes": []
      },
      {
        "id": "rect-ground-12",
        "x": 2250,
        "y": 220,
        "width": 450,
        "height": 640,
        "color": "#64748b",
        "style": "filled",
        "lineStyle": "solid",
        "fillOpacity": 0.1,
        "borderWidth": 2,
        "notes": []
      },
      {
        "id": "rect-ground-15",
        "x": 100,
        "y": 860,
        "width": 600,
        "height": 600,
        "color": "#14b8a6",
        "style": "filled",
        "lineStyle": "solid",
        "fillOpacity": 0.1,
        "borderWidth": 2,
        "notes": []
      },
      {
        "id": "rect-ground-18",
        "x": 700,
        "y": 860,
        "width": 700,
        "height": 600,
        "color": "#06b6d4",
        "style": "filled",
        "lineStyle": "solid",
        "fillOpacity": 0.1,
        "borderWidth": 2,
        "notes": []
      },
      {
        "id": "rect-ground-21",
        "x": 1400,
        "y": 860,
        "width": 400,
        "height": 600,
        "color": "#ec4899",
        "style": "filled",
        "lineStyle": "solid",
        "fillOpacity": 0.1,
        "borderWidth": 2,
        "notes": []
      },
      {
        "id": "rect-ground-23",
        "x": 1800,
        "y": 860,
        "width": 900,
        "height": 600,
        "color": "#22c55e",
        "style": "filled",
        "lineStyle": "solid",
        "fillOpacity": 0.1,
        "borderWidth": 2,
        "notes": []
      }
    ]
  },
  "textData": {
    "list": [
      {
        "id": "text-ground-1",
        "x": 60,
        "y": 100,
        "content": "Maple House: Ground Floor",
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
        "id": "text-ground-2",
        "x": 60,
        "y": 148,
        "content": "Rooms are zones, devices sit where they are mounted, lines show the radio mesh",
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
        "id": "text-ground-4",
        "x": 118,
        "y": 254,
        "content": "Living Room",
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
        "id": "text-ground-5",
        "x": 118,
        "y": 284,
        "content": "Movie scene, ceiling lights grouped",
        "fontSize": 15,
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
        "id": "text-ground-7",
        "x": 1018,
        "y": 254,
        "content": "Kitchen",
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
        "id": "text-ground-8",
        "x": 1018,
        "y": 284,
        "content": "Leak and smoke protection",
        "fontSize": 15,
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
        "id": "text-ground-10",
        "x": 1818,
        "y": 254,
        "content": "Entry",
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
        "id": "text-ground-11",
        "x": 1818,
        "y": 284,
        "content": "Front door",
        "fontSize": 15,
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
        "id": "text-ground-13",
        "x": 2268,
        "y": 254,
        "content": "Garage",
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
        "id": "text-ground-14",
        "x": 2268,
        "y": 284,
        "content": "EV charging",
        "fontSize": 15,
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
        "id": "text-ground-16",
        "x": 118,
        "y": 894,
        "content": "Utility",
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
        "id": "text-ground-17",
        "x": 118,
        "y": 924,
        "content": "Washer and water main",
        "fontSize": 15,
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
        "id": "text-ground-19",
        "x": 718,
        "y": 894,
        "content": "Office",
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
        "id": "text-ground-20",
        "x": 718,
        "y": 924,
        "content": "Focus mode",
        "fontSize": 15,
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
        "id": "text-ground-22",
        "x": 1418,
        "y": 894,
        "content": "Bath",
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
        "id": "text-ground-24",
        "x": 1818,
        "y": 894,
        "content": "Back Patio",
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
        "id": "text-ground-25",
        "x": 1818,
        "y": 924,
        "content": "Outdoor, irrigation zone 1",
        "fontSize": 15,
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
    "#84cc16": "Zigbee mesh",
    "#c084fc": "Thread",
    "#38bdf8": "Wi Fi",
    "#3b82f6": "Ethernet",
    "#f59e0b": "Automation link"
  },
  "zoneLegend": {
    "#10b981": "Motion sensor",
    "#ef4444": "Smoke alarm",
    "#f59e0b": "Camera view",
    "#06b6d4": "Sprinkler"
  },
  "zonePresets": {},
  "nodePositions": {
    "hub": {
      "x": 560,
      "y": 470
    },
    "lr-l1": {
      "x": 260,
      "y": 720
    },
    "lr-l2": {
      "x": 480,
      "y": 720
    },
    "lr-l3": {
      "x": 700,
      "y": 720
    },
    "lr-tv": {
      "x": 860,
      "y": 400
    },
    "lr-spk": {
      "x": 860,
      "y": 580
    },
    "lr-motion": {
      "x": 160,
      "y": 800
    },
    "k-plug": {
      "x": 1150,
      "y": 420
    },
    "k-lights": {
      "x": 1400,
      "y": 420
    },
    "k-smoke": {
      "x": 1650,
      "y": 420
    },
    "k-leak": {
      "x": 1150,
      "y": 720
    },
    "k-speaker": {
      "x": 1400,
      "y": 720
    },
    "k-temp": {
      "x": 1650,
      "y": 720
    },
    "e-bell": {
      "x": 2160,
      "y": 330
    },
    "e-lock": {
      "x": 2020,
      "y": 560
    },
    "e-motion": {
      "x": 2020,
      "y": 780
    },
    "g-door": {
      "x": 2480,
      "y": 400
    },
    "g-ev": {
      "x": 2480,
      "y": 600
    },
    "g-cam": {
      "x": 2620,
      "y": 790
    },
    "u-valve": {
      "x": 260,
      "y": 1080
    },
    "u-washer": {
      "x": 520,
      "y": 1080
    },
    "u-leak": {
      "x": 520,
      "y": 1300
    },
    "u-vac": {
      "x": 260,
      "y": 1300
    },
    "o-lamp": {
      "x": 860,
      "y": 1080
    },
    "o-blinds": {
      "x": 1160,
      "y": 1080
    },
    "o-air": {
      "x": 1010,
      "y": 1300
    },
    "b-hum": {
      "x": 1600,
      "y": 1080
    },
    "b-fan": {
      "x": 1600,
      "y": 1300
    },
    "p-cam": {
      "x": 1880,
      "y": 1020
    },
    "p-lights": {
      "x": 2160,
      "y": 1300
    },
    "p-sprinkler": {
      "x": 2480,
      "y": 1150
    }
  },
  "nodeSizes": {
    "hub": 56,
    "lr-l1": 32,
    "lr-l2": 32,
    "lr-l3": 32,
    "lr-tv": 40,
    "lr-spk": 34,
    "lr-motion": 28,
    "k-plug": 32,
    "k-lights": 34,
    "k-smoke": 30,
    "k-leak": 28,
    "k-speaker": 34,
    "k-temp": 28,
    "e-bell": 32,
    "e-lock": 32,
    "e-motion": 28,
    "g-door": 38,
    "g-ev": 34,
    "g-cam": 28,
    "u-valve": 32,
    "u-washer": 32,
    "u-leak": 28,
    "u-vac": 34,
    "o-lamp": 30,
    "o-blinds": 30,
    "o-air": 28,
    "b-hum": 28,
    "b-fan": 30,
    "p-cam": 28,
    "p-lights": 30,
    "p-sprinkler": 32
  },
  "nodeStyles": {},
  "page": {
    "title": "Maple House Smart Home",
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
    "canvasTemplate": "blueprint",
    "motionTrailsEnabled": true,
    "motionTrailLength": 8,
    "motionTrailStyle": "solid",
    "motionTrailArrow": true,
    "showPortLabels": true,
    "snapToGrid": true,
    "canvasWidth": 4000,
    "canvasHeight": 3000,
    "layerNames": {
      "layer1": "Lighting",
      "layer2": "Security",
      "layer3": "Climate",
      "layer4": "Media"
    },
    "markDuplicateIps": false,
    "showHostedOnLinks": true,
    "autoPingEnabled": false,
    "autoPingInterval": 60
  },
  "canvas": {
    "zoom": 1.8457752255947495,
    "panX": 296.44444444444434,
    "panY": -42.666666666666856
  },
  "savedTopologyView": {
    "zoom": 1.8457752255947495,
    "panX": 296.44444444444434,
    "panY": -42.666666666666856
  },
  "tabViews": {
    "main": {
      "zoom": 1.8457752255947495,
      "panX": 296.44444444444434,
      "panY": -42.666666666666856
    }
  },
  "documentTabs": [
    {
      "id": "main",
      "name": "Ground Floor",
      "nodes": {
        "hub": {
          "shape": "hub",
          "name": "Home Hub",
          "ip": "Zigbee, Thread, Wi Fi",
          "role": "Home Assistant",
          "tags": [
            "core"
          ],
          "notes": [
            "<h3>Home Hub</h3><p>Runs Home Assistant with a built in Zigbee and Thread radio.</p><ul><li>94 devices</li><li>31 automations</li><li>Nightly backup to the NAS</li></ul>"
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
        "lr-l1": {
          "shape": "smart-bulb",
          "name": "Ceiling 1",
          "ip": "Zigbee bulb",
          "role": "",
          "tags": [
            "lights"
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
          "groupId": "grp-living-lights",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "lr-l2": {
          "shape": "smart-bulb",
          "name": "Ceiling 2",
          "ip": "Zigbee bulb",
          "role": "",
          "tags": [
            "lights"
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
          "groupId": "grp-living-lights",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "lr-l3": {
          "shape": "smart-bulb",
          "name": "Ceiling 3",
          "ip": "Zigbee bulb",
          "role": "",
          "tags": [
            "lights"
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
          "groupId": "grp-living-lights",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "lr-tv": {
          "shape": "smart-tv",
          "name": "TV",
          "ip": "Wi Fi",
          "role": "",
          "tags": [
            "media"
          ],
          "notes": [],
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
        "lr-spk": {
          "shape": "smart-speaker",
          "name": "Soundbar",
          "ip": "Wi Fi",
          "role": "",
          "tags": [
            "media"
          ],
          "notes": [],
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
        "lr-motion": {
          "shape": "motion-sensor",
          "name": "Living Motion",
          "ip": "Zigbee",
          "role": "",
          "tags": [],
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
          },
          "fovEnabled": true,
          "fovAngle": 110,
          "fovDistance": 200,
          "fovRotation": 45,
          "fovColor": "#10b981",
          "fovOpacity": 15,
          "fovAnimationType": "pulse",
          "fovAnimate": true,
          "fovSpeed": 3,
          "fovBorderColor": "#10b981",
          "fovBorderOpacity": 50
        },
        "k-plug": {
          "shape": "smart-plug",
          "name": "Coffee Plug",
          "ip": "Zigbee router",
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
        "k-lights": {
          "shape": "smart-bulb",
          "name": "Kitchen Lights",
          "ip": "Zigbee",
          "role": "",
          "tags": [
            "lights"
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
        "k-smoke": {
          "shape": "smoke-detector",
          "name": "Smoke Alarm",
          "ip": "Zigbee",
          "role": "",
          "tags": [
            "safety"
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
          },
          "fovEnabled": true,
          "fovAngle": 360,
          "fovDistance": 110,
          "fovColor": "#ef4444",
          "fovOpacity": 12,
          "fovAnimationType": "pulse",
          "fovAnimate": false,
          "fovBorderColor": "#ef4444",
          "fovBorderOpacity": 40
        },
        "k-leak": {
          "shape": "sensor",
          "name": "Sink Leak",
          "ip": "Zigbee",
          "role": "",
          "tags": [
            "safety"
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
        "k-speaker": {
          "shape": "smart-speaker",
          "name": "Kitchen Speaker",
          "ip": "Thread border router",
          "role": "",
          "tags": [],
          "notes": [],
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
        "k-temp": {
          "shape": "sensor",
          "name": "Fridge Temp",
          "ip": "Thread",
          "role": "",
          "tags": [],
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
        "e-bell": {
          "shape": "doorbell",
          "name": "Doorbell",
          "ip": "Wi Fi, 2K",
          "role": "",
          "tags": [
            "camera"
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
          },
          "fovEnabled": true,
          "fovAngle": 85,
          "fovDistance": 150,
          "fovRotation": 0,
          "fovColor": "#f59e0b",
          "fovOpacity": 18,
          "fovAnimationType": "sweep",
          "fovAnimate": false,
          "fovBorderColor": "#f59e0b",
          "fovBorderOpacity": 60
        },
        "e-lock": {
          "shape": "smart-lock",
          "name": "Front Lock",
          "ip": "Thread",
          "role": "",
          "tags": [
            "security"
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
        "e-motion": {
          "shape": "motion-sensor",
          "name": "Hall Motion",
          "ip": "Zigbee",
          "role": "",
          "tags": [],
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
          },
          "fovEnabled": true,
          "fovAngle": 110,
          "fovDistance": 200,
          "fovRotation": 0,
          "fovColor": "#10b981",
          "fovOpacity": 15,
          "fovAnimationType": "pulse",
          "fovAnimate": true,
          "fovSpeed": 3,
          "fovBorderColor": "#10b981",
          "fovBorderOpacity": 50
        },
        "g-door": {
          "shape": "garage",
          "name": "Garage Door",
          "ip": "Wi Fi relay",
          "role": "",
          "tags": [
            "security"
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
        "g-ev": {
          "shape": "smart-plug",
          "name": "EV Charger",
          "ip": "Wi Fi, 11 kW",
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
        "g-cam": {
          "shape": "camera",
          "name": "Garage Cam",
          "ip": "PoE",
          "role": "",
          "tags": [],
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
          },
          "fovEnabled": true,
          "fovAngle": 85,
          "fovDistance": 230,
          "fovRotation": 315,
          "fovColor": "#f59e0b",
          "fovOpacity": 18,
          "fovAnimationType": "sweep",
          "fovAnimate": false,
          "fovBorderColor": "#f59e0b",
          "fovBorderOpacity": 60
        },
        "u-valve": {
          "shape": "smart-plug",
          "name": "Water Main Valve",
          "ip": "Zigbee",
          "role": "",
          "tags": [
            "safety"
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
        "u-washer": {
          "shape": "smart-plug",
          "name": "Washer Plug",
          "ip": "Zigbee router, power meter",
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
        "u-leak": {
          "shape": "sensor",
          "name": "Washer Leak",
          "ip": "Zigbee",
          "role": "",
          "tags": [
            "safety"
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
        "u-vac": {
          "shape": "vacuum",
          "name": "Robot Vacuum",
          "ip": "Wi Fi",
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
        "o-lamp": {
          "shape": "smart-bulb",
          "name": "Desk Lamp",
          "ip": "Zigbee",
          "role": "",
          "tags": [
            "lights"
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
        "o-blinds": {
          "shape": "smart-plug",
          "name": "Office Blinds",
          "ip": "Thread",
          "role": "",
          "tags": [],
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
        "o-air": {
          "shape": "sensor",
          "name": "Air Quality",
          "ip": "Thread, CO2 and VOC",
          "role": "",
          "tags": [],
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
        "b-hum": {
          "shape": "sensor",
          "name": "Humidity",
          "ip": "Zigbee",
          "role": "",
          "tags": [],
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
        "b-fan": {
          "shape": "smart-plug",
          "name": "Bath Fan",
          "ip": "Zigbee switch",
          "role": "",
          "tags": [],
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
        "p-cam": {
          "shape": "camera",
          "name": "Patio Cam",
          "ip": "PoE",
          "role": "",
          "tags": [],
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
          },
          "fovEnabled": true,
          "fovAngle": 85,
          "fovDistance": 300,
          "fovRotation": 135,
          "fovColor": "#f59e0b",
          "fovOpacity": 18,
          "fovAnimationType": "sweep",
          "fovAnimate": false,
          "fovBorderColor": "#f59e0b",
          "fovBorderOpacity": 60
        },
        "p-lights": {
          "shape": "smart-plug",
          "name": "String Lights",
          "ip": "Outdoor plug",
          "role": "",
          "tags": [
            "lights"
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
        "p-sprinkler": {
          "shape": "sprinkler",
          "name": "Sprinkler Zone 1",
          "ip": "Wi Fi controller",
          "role": "",
          "tags": [],
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
          },
          "fovEnabled": true,
          "fovAngle": 180,
          "fovDistance": 200,
          "fovRotation": 270,
          "fovColor": "#06b6d4",
          "fovOpacity": 20,
          "fovAnimationType": "spin",
          "fovAnimate": true,
          "fovSpeed": 6
        }
      },
      "edges": {
        "list": [
          {
            "id": "edge-ground-26",
            "from": "hub",
            "to": "lr-l1",
            "width": 3,
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
            "id": "edge-ground-27",
            "from": "hub",
            "to": "lr-l2",
            "width": 3,
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
            "id": "edge-ground-28",
            "from": "hub",
            "to": "lr-l3",
            "width": 3,
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
            "id": "edge-ground-29",
            "from": "hub",
            "to": "lr-motion",
            "width": 3,
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
            "id": "edge-ground-30",
            "from": "hub",
            "to": "lr-tv",
            "width": 3,
            "color": "#38bdf8",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-ground-31",
            "from": "hub",
            "to": "lr-spk",
            "width": 3,
            "color": "#38bdf8",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-ground-32",
            "from": "hub",
            "to": "k-plug",
            "width": 3,
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
            "id": "edge-ground-33",
            "from": "k-plug",
            "to": "k-lights",
            "width": 3,
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
            "id": "edge-ground-34",
            "from": "k-plug",
            "to": "k-leak",
            "width": 3,
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
            "id": "edge-ground-35",
            "from": "k-lights",
            "to": "k-smoke",
            "width": 3,
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
            "id": "edge-ground-36",
            "from": "hub",
            "to": "k-speaker",
            "width": 3,
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
            "id": "edge-ground-37",
            "from": "k-speaker",
            "to": "k-temp",
            "width": 3,
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
            "id": "edge-ground-38",
            "from": "k-speaker",
            "to": "o-blinds",
            "width": 3,
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
            "id": "edge-ground-39",
            "from": "k-speaker",
            "to": "o-air",
            "width": 3,
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
            "id": "edge-ground-40",
            "from": "k-lights",
            "to": "e-motion",
            "width": 3,
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
            "id": "edge-ground-41",
            "from": "k-speaker",
            "to": "e-lock",
            "width": 3,
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
            "id": "edge-ground-42",
            "from": "e-lock",
            "to": "e-bell",
            "width": 3,
            "color": "#38bdf8",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-ground-43",
            "from": "g-door",
            "to": "g-ev",
            "width": 3,
            "color": "#38bdf8",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-ground-44",
            "from": "hub",
            "to": "u-washer",
            "width": 3,
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
            "id": "edge-ground-45",
            "from": "u-washer",
            "to": "u-valve",
            "width": 3,
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
            "id": "edge-ground-46",
            "from": "u-washer",
            "to": "u-leak",
            "width": 3,
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
            "id": "edge-ground-47",
            "from": "u-washer",
            "to": "o-lamp",
            "width": 3,
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
            "id": "edge-ground-48",
            "from": "o-lamp",
            "to": "b-hum",
            "width": 3,
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
            "id": "edge-ground-49",
            "from": "b-hum",
            "to": "b-fan",
            "width": 3,
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
            "id": "edge-ground-50",
            "from": "u-leak",
            "to": "u-valve",
            "width": 4,
            "color": "#f59e0b",
            "direction": "forward",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "Leak closes valve",
            "animate": true,
            "animationStyle": "arrows",
            "animationSpeed": 1.5,
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-ground-51",
            "from": "e-bell",
            "to": "lr-tv",
            "width": 4,
            "color": "#f59e0b",
            "direction": "forward",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "routing": "straight",
            "label": "Doorbell on TV",
            "waypoints": [
              {
                "x": 2160,
                "y": 300
              },
              {
                "x": 860,
                "y": 300
              }
            ],
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-ground-52",
            "from": "p-cam",
            "to": "p-lights",
            "width": 3,
            "color": "#38bdf8",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-ground-53",
            "from": "p-lights",
            "to": "p-sprinkler",
            "width": 3,
            "color": "#38bdf8",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-ground-54",
            "from": "p-cam",
            "to": "g-cam",
            "width": 4,
            "color": "#3b82f6",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "PoE to garage switch",
            "_pairIndex": 0,
            "_pairTotal": 1
          }
        ]
      },
      "positions": {
        "hub": {
          "x": 560,
          "y": 470
        },
        "lr-l1": {
          "x": 260,
          "y": 720
        },
        "lr-l2": {
          "x": 480,
          "y": 720
        },
        "lr-l3": {
          "x": 700,
          "y": 720
        },
        "lr-tv": {
          "x": 860,
          "y": 400
        },
        "lr-spk": {
          "x": 860,
          "y": 580
        },
        "lr-motion": {
          "x": 160,
          "y": 800
        },
        "k-plug": {
          "x": 1150,
          "y": 420
        },
        "k-lights": {
          "x": 1400,
          "y": 420
        },
        "k-smoke": {
          "x": 1650,
          "y": 420
        },
        "k-leak": {
          "x": 1150,
          "y": 720
        },
        "k-speaker": {
          "x": 1400,
          "y": 720
        },
        "k-temp": {
          "x": 1650,
          "y": 720
        },
        "e-bell": {
          "x": 2160,
          "y": 330
        },
        "e-lock": {
          "x": 2020,
          "y": 560
        },
        "e-motion": {
          "x": 2020,
          "y": 780
        },
        "g-door": {
          "x": 2480,
          "y": 400
        },
        "g-ev": {
          "x": 2480,
          "y": 600
        },
        "g-cam": {
          "x": 2620,
          "y": 790
        },
        "u-valve": {
          "x": 260,
          "y": 1080
        },
        "u-washer": {
          "x": 520,
          "y": 1080
        },
        "u-leak": {
          "x": 520,
          "y": 1300
        },
        "u-vac": {
          "x": 260,
          "y": 1300
        },
        "o-lamp": {
          "x": 860,
          "y": 1080
        },
        "o-blinds": {
          "x": 1160,
          "y": 1080
        },
        "o-air": {
          "x": 1010,
          "y": 1300
        },
        "b-hum": {
          "x": 1600,
          "y": 1080
        },
        "b-fan": {
          "x": 1600,
          "y": 1300
        },
        "p-cam": {
          "x": 1880,
          "y": 1020
        },
        "p-lights": {
          "x": 2160,
          "y": 1300
        },
        "p-sprinkler": {
          "x": 2480,
          "y": 1150
        }
      },
      "sizes": {
        "hub": 56,
        "lr-l1": 32,
        "lr-l2": 32,
        "lr-l3": 32,
        "lr-tv": 40,
        "lr-spk": 34,
        "lr-motion": 28,
        "k-plug": 32,
        "k-lights": 34,
        "k-smoke": 30,
        "k-leak": 28,
        "k-speaker": 34,
        "k-temp": 28,
        "e-bell": 32,
        "e-lock": 32,
        "e-motion": 28,
        "g-door": 38,
        "g-ev": 34,
        "g-cam": 28,
        "u-valve": 32,
        "u-washer": 32,
        "u-leak": 28,
        "u-vac": 34,
        "o-lamp": 30,
        "o-blinds": 30,
        "o-air": 28,
        "b-hum": 28,
        "b-fan": 30,
        "p-cam": 28,
        "p-lights": 30,
        "p-sprinkler": 32
      },
      "styles": {},
      "legend": {
        "#84cc16": "Zigbee mesh",
        "#c084fc": "Thread",
        "#38bdf8": "Wi Fi",
        "#3b82f6": "Ethernet",
        "#f59e0b": "Automation link"
      },
      "rects": {
        "list": [
          {
            "id": "rect-ground-3",
            "x": 100,
            "y": 220,
            "width": 900,
            "height": 640,
            "color": "#3b82f6",
            "style": "filled",
            "lineStyle": "solid",
            "fillOpacity": 0.1,
            "borderWidth": 2,
            "notes": []
          },
          {
            "id": "rect-ground-6",
            "x": 1000,
            "y": 220,
            "width": 800,
            "height": 640,
            "color": "#f59e0b",
            "style": "filled",
            "lineStyle": "solid",
            "fillOpacity": 0.1,
            "borderWidth": 2,
            "notes": []
          },
          {
            "id": "rect-ground-9",
            "x": 1800,
            "y": 220,
            "width": 450,
            "height": 640,
            "color": "#a855f7",
            "style": "filled",
            "lineStyle": "solid",
            "fillOpacity": 0.1,
            "borderWidth": 2,
            "notes": []
          },
          {
            "id": "rect-ground-12",
            "x": 2250,
            "y": 220,
            "width": 450,
            "height": 640,
            "color": "#64748b",
            "style": "filled",
            "lineStyle": "solid",
            "fillOpacity": 0.1,
            "borderWidth": 2,
            "notes": []
          },
          {
            "id": "rect-ground-15",
            "x": 100,
            "y": 860,
            "width": 600,
            "height": 600,
            "color": "#14b8a6",
            "style": "filled",
            "lineStyle": "solid",
            "fillOpacity": 0.1,
            "borderWidth": 2,
            "notes": []
          },
          {
            "id": "rect-ground-18",
            "x": 700,
            "y": 860,
            "width": 700,
            "height": 600,
            "color": "#06b6d4",
            "style": "filled",
            "lineStyle": "solid",
            "fillOpacity": 0.1,
            "borderWidth": 2,
            "notes": []
          },
          {
            "id": "rect-ground-21",
            "x": 1400,
            "y": 860,
            "width": 400,
            "height": 600,
            "color": "#ec4899",
            "style": "filled",
            "lineStyle": "solid",
            "fillOpacity": 0.1,
            "borderWidth": 2,
            "notes": []
          },
          {
            "id": "rect-ground-23",
            "x": 1800,
            "y": 860,
            "width": 900,
            "height": 600,
            "color": "#22c55e",
            "style": "filled",
            "lineStyle": "solid",
            "fillOpacity": 0.1,
            "borderWidth": 2,
            "notes": []
          }
        ]
      },
      "texts": {
        "list": [
          {
            "id": "text-ground-1",
            "x": 60,
            "y": 100,
            "content": "Maple House: Ground Floor",
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
            "id": "text-ground-2",
            "x": 60,
            "y": 148,
            "content": "Rooms are zones, devices sit where they are mounted, lines show the radio mesh",
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
            "id": "text-ground-4",
            "x": 118,
            "y": 254,
            "content": "Living Room",
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
            "id": "text-ground-5",
            "x": 118,
            "y": 284,
            "content": "Movie scene, ceiling lights grouped",
            "fontSize": 15,
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
            "id": "text-ground-7",
            "x": 1018,
            "y": 254,
            "content": "Kitchen",
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
            "id": "text-ground-8",
            "x": 1018,
            "y": 284,
            "content": "Leak and smoke protection",
            "fontSize": 15,
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
            "id": "text-ground-10",
            "x": 1818,
            "y": 254,
            "content": "Entry",
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
            "id": "text-ground-11",
            "x": 1818,
            "y": 284,
            "content": "Front door",
            "fontSize": 15,
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
            "id": "text-ground-13",
            "x": 2268,
            "y": 254,
            "content": "Garage",
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
            "id": "text-ground-14",
            "x": 2268,
            "y": 284,
            "content": "EV charging",
            "fontSize": 15,
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
            "id": "text-ground-16",
            "x": 118,
            "y": 894,
            "content": "Utility",
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
            "id": "text-ground-17",
            "x": 118,
            "y": 924,
            "content": "Washer and water main",
            "fontSize": 15,
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
            "id": "text-ground-19",
            "x": 718,
            "y": 894,
            "content": "Office",
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
            "id": "text-ground-20",
            "x": 718,
            "y": 924,
            "content": "Focus mode",
            "fontSize": 15,
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
            "id": "text-ground-22",
            "x": 1418,
            "y": 894,
            "content": "Bath",
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
            "id": "text-ground-24",
            "x": 1818,
            "y": 894,
            "content": "Back Patio",
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
            "id": "text-ground-25",
            "x": 1818,
            "y": 924,
            "content": "Outdoor, irrigation zone 1",
            "fontSize": 15,
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
        "title": "Maple House Smart Home",
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
        "canvasTemplate": "blueprint",
        "motionTrailsEnabled": true,
        "motionTrailLength": 8,
        "motionTrailStyle": "solid",
        "motionTrailArrow": true,
        "showPortLabels": true,
        "snapToGrid": true,
        "canvasWidth": 4000,
        "canvasHeight": 3000,
        "layerNames": {
          "layer1": "Lighting",
          "layer2": "Security",
          "layer3": "Climate",
          "layer4": "Media"
        },
        "markDuplicateIps": false,
        "showHostedOnLinks": true,
        "autoPingEnabled": false,
        "autoPingInterval": 60
      }
    },
    {
      "id": "tab-smarthome-upstairs",
      "name": "Upstairs and Garden",
      "nodes": {
        "up-thermo": {
          "shape": "thermostat",
          "name": "Thermostat",
          "ip": "Thread, heat pump",
          "role": "",
          "tags": [
            "climate"
          ],
          "notes": [
            "<h3>Climate schedule</h3><table><thead><tr><th>Time</th><th>Heat</th><th>Cool</th></tr></thead><tbody><tr><td>06:30</td><td>20.5 C</td><td>25 C</td></tr><tr><td>09:00</td><td>18 C</td><td>27 C</td></tr><tr><td>17:00</td><td>20.5 C</td><td>25 C</td></tr><tr><td>22:30</td><td>18 C</td><td>24 C</td></tr></tbody></table>"
          ],
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
        "up-router": {
          "shape": "router",
          "name": "Upstairs Mesh Node",
          "ip": "Wi Fi 6E",
          "role": "",
          "tags": [],
          "notes": [],
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
        "pb-lamp1": {
          "shape": "smart-bulb",
          "name": "Bedside Left",
          "ip": "Zigbee",
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
          "groupId": "grp-bedside",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "pb-lamp2": {
          "shape": "smart-bulb",
          "name": "Bedside Right",
          "ip": "Zigbee",
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
          "groupId": "grp-bedside",
          "ping": {
            "enabled": false,
            "protocol": "http",
            "customUrl": "",
            "timeout": 3000,
            "status": "unknown",
            "lastCheck": null
          }
        },
        "pb-blinds": {
          "shape": "smart-plug",
          "name": "Bedroom Blinds",
          "ip": "Thread",
          "role": "",
          "tags": [],
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
        "pb-temp": {
          "shape": "sensor",
          "name": "Bedroom Temp",
          "ip": "Zigbee",
          "role": "",
          "tags": [],
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
        "pb-smoke": {
          "shape": "smoke-detector",
          "name": "Smoke Alarm",
          "ip": "Zigbee",
          "role": "",
          "tags": [],
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
          },
          "fovEnabled": true,
          "fovAngle": 360,
          "fovDistance": 110,
          "fovColor": "#ef4444",
          "fovOpacity": 12,
          "fovAnimationType": "pulse",
          "fovAnimate": false,
          "fovBorderColor": "#ef4444",
          "fovBorderOpacity": 40
        },
        "kr-night": {
          "shape": "smart-bulb",
          "name": "Night Light",
          "ip": "Zigbee",
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
        "kr-speaker": {
          "shape": "smart-speaker",
          "name": "Kids Speaker",
          "ip": "Wi Fi",
          "role": "",
          "tags": [],
          "notes": [],
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
        "kr-window": {
          "shape": "sensor",
          "name": "Window Contact",
          "ip": "Zigbee",
          "role": "",
          "tags": [],
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
        "gr-plug": {
          "shape": "smart-plug",
          "name": "Heater Plug",
          "ip": "Zigbee router",
          "role": "",
          "tags": [],
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
        "gr-window": {
          "shape": "sensor",
          "name": "Guest Window",
          "ip": "Zigbee",
          "role": "",
          "tags": [],
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
        "ba-fan": {
          "shape": "smart-plug",
          "name": "Bath Fan",
          "ip": "Zigbee switch",
          "role": "",
          "tags": [],
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
        "ba-hum": {
          "shape": "sensor",
          "name": "Humidity",
          "ip": "Zigbee",
          "role": "",
          "tags": [],
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
        "la-motion": {
          "shape": "motion-sensor",
          "name": "Landing Motion",
          "ip": "Zigbee",
          "role": "",
          "tags": [],
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
          },
          "fovEnabled": true,
          "fovAngle": 110,
          "fovDistance": 200,
          "fovRotation": 45,
          "fovColor": "#10b981",
          "fovOpacity": 15,
          "fovAnimationType": "pulse",
          "fovAnimate": true,
          "fovSpeed": 3,
          "fovBorderColor": "#10b981",
          "fovBorderOpacity": 50
        },
        "la-lights": {
          "shape": "smart-bulb",
          "name": "Stair Lights",
          "ip": "Zigbee",
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
        "gd-weather": {
          "shape": "sensor",
          "name": "Weather Station",
          "ip": "Wi Fi, rain and wind",
          "role": "",
          "tags": [],
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
        "gd-sprk2": {
          "shape": "sprinkler",
          "name": "Zone 2 Beds",
          "ip": "Drip",
          "role": "",
          "tags": [],
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
          },
          "fovEnabled": true,
          "fovAngle": 120,
          "fovDistance": 160,
          "fovRotation": 270,
          "fovColor": "#06b6d4",
          "fovOpacity": 20,
          "fovAnimationType": "spin",
          "fovAnimate": true,
          "fovSpeed": 6
        },
        "gd-sprk3": {
          "shape": "sprinkler",
          "name": "Zone 3 Lawn",
          "ip": "Rotor",
          "role": "",
          "tags": [],
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
          },
          "fovEnabled": true,
          "fovAngle": 270,
          "fovDistance": 130,
          "fovRotation": 270,
          "fovColor": "#06b6d4",
          "fovOpacity": 18,
          "fovAnimationType": "spin",
          "fovAnimate": true,
          "fovSpeed": 8
        },
        "gd-shedcam": {
          "shape": "camera",
          "name": "Shed Cam",
          "ip": "Wi Fi",
          "role": "",
          "tags": [],
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
          },
          "fovEnabled": true,
          "fovAngle": 85,
          "fovDistance": 260,
          "fovRotation": 315,
          "fovColor": "#f59e0b",
          "fovOpacity": 18,
          "fovAnimationType": "sweep",
          "fovAnimate": false,
          "fovBorderColor": "#f59e0b",
          "fovBorderOpacity": 60
        },
        "gd-ap": {
          "shape": "access-point",
          "name": "Garden AP",
          "ip": "Outdoor, Wi Fi 6",
          "role": "",
          "tags": [],
          "notes": [],
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
        "gd-lights": {
          "shape": "smart-plug",
          "name": "Path Lights",
          "ip": "Zigbee outdoor",
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
            "id": "edge-upstairs-19",
            "from": "gr-plug",
            "to": "gr-window",
            "width": 3,
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
            "id": "edge-upstairs-20",
            "from": "gr-plug",
            "to": "kr-night",
            "width": 3,
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
            "id": "edge-upstairs-21",
            "from": "kr-night",
            "to": "kr-window",
            "width": 3,
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
            "id": "edge-upstairs-22",
            "from": "kr-night",
            "to": "pb-lamp2",
            "width": 3,
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
            "id": "edge-upstairs-23",
            "from": "pb-lamp2",
            "to": "pb-lamp1",
            "width": 3,
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
            "id": "edge-upstairs-24",
            "from": "pb-lamp2",
            "to": "pb-smoke",
            "width": 3,
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
            "id": "edge-upstairs-25",
            "from": "pb-lamp1",
            "to": "pb-temp",
            "width": 3,
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
            "id": "edge-upstairs-26",
            "from": "up-thermo",
            "to": "pb-blinds",
            "width": 3,
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
            "id": "edge-upstairs-27",
            "from": "la-lights",
            "to": "gr-plug",
            "width": 3,
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
            "id": "edge-upstairs-28",
            "from": "la-lights",
            "to": "la-motion",
            "width": 3,
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
            "id": "edge-upstairs-29",
            "from": "la-motion",
            "to": "ba-hum",
            "width": 3,
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
            "id": "edge-upstairs-30",
            "from": "ba-hum",
            "to": "ba-fan",
            "width": 3,
            "color": "#84cc16",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dotted",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 2
          },
          {
            "id": "edge-upstairs-31",
            "from": "up-router",
            "to": "kr-speaker",
            "width": 3,
            "color": "#38bdf8",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-upstairs-32",
            "from": "up-router",
            "to": "gd-ap",
            "width": 3,
            "color": "#38bdf8",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-upstairs-33",
            "from": "gd-ap",
            "to": "gd-weather",
            "width": 3,
            "color": "#38bdf8",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-upstairs-34",
            "from": "gd-ap",
            "to": "gd-shedcam",
            "width": 3,
            "color": "#38bdf8",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-upstairs-35",
            "from": "la-lights",
            "to": "gd-lights",
            "width": 3,
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
            "id": "edge-upstairs-36",
            "from": "gd-ap",
            "to": "gd-sprk2",
            "width": 3,
            "color": "#38bdf8",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-upstairs-37",
            "from": "gd-ap",
            "to": "gd-sprk3",
            "width": 3,
            "color": "#38bdf8",
            "direction": "none",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "routing": "straight",
            "_pairIndex": 0,
            "_pairTotal": 1
          },
          {
            "id": "edge-upstairs-38",
            "from": "ba-hum",
            "to": "ba-fan",
            "width": 4,
            "color": "#f59e0b",
            "direction": "forward",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "solid",
            "routing": "straight",
            "label": "Over 70 percent: fan on",
            "_pairIndex": 1,
            "_pairTotal": 2
          },
          {
            "id": "edge-upstairs-39",
            "from": "gd-weather",
            "to": "gd-sprk3",
            "width": 4,
            "color": "#f59e0b",
            "direction": "forward",
            "type": "main",
            "notes": [],
            "fromPort": "",
            "toPort": "",
            "lineStyle": "dashed",
            "routing": "straight",
            "label": "Rain skips watering",
            "waypoints": [
              {
                "x": 2640,
                "y": 360
              },
              {
                "x": 2640,
                "y": 800
              }
            ],
            "_pairIndex": 0,
            "_pairTotal": 1
          }
        ]
      },
      "positions": {
        "up-thermo": {
          "x": 1350,
          "y": 1050
        },
        "up-router": {
          "x": 1000,
          "y": 1050
        },
        "pb-lamp1": {
          "x": 260,
          "y": 420
        },
        "pb-lamp2": {
          "x": 740,
          "y": 420
        },
        "pb-blinds": {
          "x": 500,
          "y": 330
        },
        "pb-temp": {
          "x": 500,
          "y": 640
        },
        "pb-smoke": {
          "x": 780,
          "y": 720
        },
        "kr-night": {
          "x": 1050,
          "y": 420
        },
        "kr-speaker": {
          "x": 1350,
          "y": 420
        },
        "kr-window": {
          "x": 1200,
          "y": 680
        },
        "gr-plug": {
          "x": 1750,
          "y": 420
        },
        "gr-window": {
          "x": 1750,
          "y": 680
        },
        "ba-fan": {
          "x": 260,
          "y": 1060
        },
        "ba-hum": {
          "x": 520,
          "y": 1060
        },
        "la-motion": {
          "x": 760,
          "y": 1180
        },
        "la-lights": {
          "x": 1700,
          "y": 1050
        },
        "gd-weather": {
          "x": 2380,
          "y": 360
        },
        "gd-sprk2": {
          "x": 2220,
          "y": 640
        },
        "gd-sprk3": {
          "x": 2540,
          "y": 800
        },
        "gd-shedcam": {
          "x": 2600,
          "y": 1300
        },
        "gd-ap": {
          "x": 2200,
          "y": 940
        },
        "gd-lights": {
          "x": 2300,
          "y": 1250
        }
      },
      "sizes": {
        "up-thermo": 40,
        "up-router": 36,
        "pb-lamp1": 28,
        "pb-lamp2": 28,
        "pb-blinds": 30,
        "pb-temp": 26,
        "pb-smoke": 26,
        "kr-night": 28,
        "kr-speaker": 30,
        "kr-window": 26,
        "gr-plug": 30,
        "gr-window": 26,
        "ba-fan": 28,
        "ba-hum": 26,
        "la-motion": 26,
        "la-lights": 30,
        "gd-weather": 32,
        "gd-sprk2": 28,
        "gd-sprk3": 28,
        "gd-shedcam": 28,
        "gd-ap": 30,
        "gd-lights": 28
      },
      "styles": {},
      "legend": {
        "#84cc16": "Zigbee mesh",
        "#c084fc": "Thread",
        "#38bdf8": "Wi Fi",
        "#f59e0b": "Automation link"
      },
      "rects": {
        "list": [
          {
            "id": "rect-upstairs-3",
            "x": 100,
            "y": 220,
            "width": 800,
            "height": 620,
            "color": "#8b5cf6",
            "style": "filled",
            "lineStyle": "solid",
            "fillOpacity": 0.1,
            "borderWidth": 2,
            "notes": []
          },
          {
            "id": "rect-upstairs-6",
            "x": 900,
            "y": 220,
            "width": 600,
            "height": 620,
            "color": "#ec4899",
            "style": "filled",
            "lineStyle": "solid",
            "fillOpacity": 0.1,
            "borderWidth": 2,
            "notes": []
          },
          {
            "id": "rect-upstairs-9",
            "x": 1500,
            "y": 220,
            "width": 500,
            "height": 620,
            "color": "#14b8a6",
            "style": "filled",
            "lineStyle": "solid",
            "fillOpacity": 0.1,
            "borderWidth": 2,
            "notes": []
          },
          {
            "id": "rect-upstairs-11",
            "x": 100,
            "y": 840,
            "width": 600,
            "height": 420,
            "color": "#06b6d4",
            "style": "filled",
            "lineStyle": "solid",
            "fillOpacity": 0.1,
            "borderWidth": 2,
            "notes": []
          },
          {
            "id": "rect-upstairs-13",
            "x": 700,
            "y": 840,
            "width": 1300,
            "height": 420,
            "color": "#64748b",
            "style": "filled",
            "lineStyle": "solid",
            "fillOpacity": 0.1,
            "borderWidth": 2,
            "notes": []
          },
          {
            "id": "rect-upstairs-16",
            "x": 2060,
            "y": 220,
            "width": 640,
            "height": 1240,
            "color": "#22c55e",
            "style": "filled",
            "lineStyle": "solid",
            "fillOpacity": 0.1,
            "borderWidth": 2,
            "notes": []
          }
        ]
      },
      "texts": {
        "list": [
          {
            "id": "text-upstairs-1",
            "x": 60,
            "y": 100,
            "content": "Maple House: Upstairs and Garden",
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
            "id": "text-upstairs-2",
            "x": 60,
            "y": 148,
            "content": "Bedrooms, climate and the garden",
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
            "id": "text-upstairs-4",
            "x": 118,
            "y": 254,
            "content": "Primary Bedroom",
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
            "id": "text-upstairs-5",
            "x": 118,
            "y": 284,
            "content": "Sleep scene at 22:30",
            "fontSize": 15,
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
            "id": "text-upstairs-7",
            "x": 918,
            "y": 254,
            "content": "Kids Room",
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
            "id": "text-upstairs-8",
            "x": 918,
            "y": 284,
            "content": "Night light, quiet hours",
            "fontSize": 15,
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
            "id": "text-upstairs-10",
            "x": 1518,
            "y": 254,
            "content": "Guest Room",
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
            "id": "text-upstairs-12",
            "x": 118,
            "y": 874,
            "content": "Primary Bath",
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
            "id": "text-upstairs-14",
            "x": 718,
            "y": 874,
            "content": "Landing",
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
            "id": "text-upstairs-15",
            "x": 718,
            "y": 904,
            "content": "Stairs and linen closet",
            "fontSize": 15,
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
            "id": "text-upstairs-17",
            "x": 2078,
            "y": 254,
            "content": "Garden",
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
            "id": "text-upstairs-18",
            "x": 2078,
            "y": 284,
            "content": "Irrigation zones 2 to 4, shed",
            "fontSize": 15,
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
            "id": "text-upstairs-40",
            "x": 100,
            "y": 1340,
            "content": "Scenes",
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
            "id": "text-upstairs-41",
            "x": 100,
            "y": 1380,
            "content": "Good morning: blinds open, heat to 20.5 C, kitchen speaker plays the news\nSleep: bedside lamps fade over 10 minutes, doors locked, cameras armed\nAway: everything off, vacuum runs, thermostat to eco",
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
        "title": "Maple House Smart Home",
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
        "canvasTemplate": "blueprint",
        "motionTrailsEnabled": true,
        "motionTrailLength": 8,
        "motionTrailStyle": "solid",
        "motionTrailArrow": true,
        "showPortLabels": true,
        "snapToGrid": true,
        "canvasWidth": 4000,
        "canvasHeight": 3000,
        "layerNames": {
          "layer1": "Lighting",
          "layer2": "Security",
          "layer3": "Climate",
          "layer4": "Media"
        },
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
      "timestamp": 1794457234279,
      "type": "export",
      "description": "Exported CSV: maple-house-smart-home.csv",
      "details": {},
      "tab": "Ground Floor"
    },
    {
      "timestamp": 1794457232812,
      "type": "import",
      "description": "Imported JSON: the-one-file-smarthome-demo.json (31 nodes, 29 connections)",
      "details": {},
      "tab": "Ground Floor"
    }
  ],
  "savedStyleSets": [],
  "recordings": [],
  "customLanguage": null
}
THEONEFILE_CONFIG-->

# Maple House Smart Home

> Exported from The One File on 2026-11-12T04:20:34.290Z

## Legend

- #84cc16: Zigbee mesh
- #c084fc: Thread
- #38bdf8: Wi Fi
- #3b82f6: Ethernet
- #f59e0b: Automation link

## Zone Legend

- #10b981: Motion sensor
- #ef4444: Smoke alarm
- #f59e0b: Camera view
- #06b6d4: Sprinkler

## Layers

- layer1: Lighting
- layer2: Security
- layer3: Climate
- layer4: Media

## Nodes

### hub
- **Name:** Home Hub
- **IP:** Zigbee, Thread, Wi Fi
- **Role:** Home Assistant
- **Shape:** hub
- **Tags:** core
- **Layer:** layer4
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 560, 470
- **Size:** 56
- **Notes:**
  - <h3>Home Hub</h3><p>Runs Home Assistant with a built in Zigbee and Thread radio.</p><ul><li>94 devices</li><li>31 automations</li><li>Nightly backup to the NAS</li></ul>

### lr-l1
- **Name:** Ceiling 1
- **IP:** Zigbee bulb
- **Role:** 
- **Shape:** smart-bulb
- **Tags:** lights
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-living-lights
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 260, 720
- **Size:** 32

### lr-l2
- **Name:** Ceiling 2
- **IP:** Zigbee bulb
- **Role:** 
- **Shape:** smart-bulb
- **Tags:** lights
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-living-lights
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 480, 720
- **Size:** 32

### lr-l3
- **Name:** Ceiling 3
- **IP:** Zigbee bulb
- **Role:** 
- **Shape:** smart-bulb
- **Tags:** lights
- **Layer:** layer1
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** grp-living-lights
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 700, 720
- **Size:** 32

### lr-tv
- **Name:** TV
- **IP:** Wi Fi
- **Role:** 
- **Shape:** smart-tv
- **Tags:** media
- **Layer:** layer4
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 860, 400
- **Size:** 40

### lr-spk
- **Name:** Soundbar
- **IP:** Wi Fi
- **Role:** 
- **Shape:** smart-speaker
- **Tags:** media
- **Layer:** layer4
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 860, 580
- **Size:** 34

### lr-motion
- **Name:** Living Motion
- **IP:** Zigbee
- **Role:** 
- **Shape:** motion-sensor
- **Tags:** _none_
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
- **Coverage Enabled:** true
- **Coverage Angle:** 110
- **Coverage Distance:** 200
- **Coverage Rotation:** 45
- **Coverage Color:** #10b981
- **Coverage Opacity:** 15
- **Coverage Animation Type:** pulse
- **Coverage Animate:** true
- **Coverage Speed:** 3
- **Coverage Border Color:** #10b981
- **Coverage Border Opacity:** 50
- **Position:** 160, 800
- **Size:** 28

### k-plug
- **Name:** Coffee Plug
- **IP:** Zigbee router
- **Role:** 
- **Shape:** smart-plug
- **Tags:** energy
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
- **Position:** 1150, 420
- **Size:** 32

### k-lights
- **Name:** Kitchen Lights
- **IP:** Zigbee
- **Role:** 
- **Shape:** smart-bulb
- **Tags:** lights
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
- **Position:** 1400, 420
- **Size:** 34

### k-smoke
- **Name:** Smoke Alarm
- **IP:** Zigbee
- **Role:** 
- **Shape:** smoke-detector
- **Tags:** safety
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
- **Coverage Enabled:** true
- **Coverage Angle:** 360
- **Coverage Distance:** 110
- **Coverage Color:** #ef4444
- **Coverage Opacity:** 12
- **Coverage Animation Type:** pulse
- **Coverage Animate:** false
- **Coverage Border Color:** #ef4444
- **Coverage Border Opacity:** 40
- **Position:** 1650, 420
- **Size:** 30

### k-leak
- **Name:** Sink Leak
- **IP:** Zigbee
- **Role:** 
- **Shape:** sensor
- **Tags:** safety
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
- **Position:** 1150, 720
- **Size:** 28

### k-speaker
- **Name:** Kitchen Speaker
- **IP:** Thread border router
- **Role:** 
- **Shape:** smart-speaker
- **Tags:** _none_
- **Layer:** layer4
- **MAC:** 
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Ping:** `{"enabled":false,"protocol":"http","customUrl":"","timeout":3000,"status":"unknown","lastCheck":null}`
- **Position:** 1400, 720
- **Size:** 34

### k-temp
- **Name:** Fridge Temp
- **IP:** Thread
- **Role:** 
- **Shape:** sensor
- **Tags:** _none_
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
- **Position:** 1650, 720
- **Size:** 28

### e-bell
- **Name:** Doorbell
- **IP:** Wi Fi, 2K
- **Role:** 
- **Shape:** doorbell
- **Tags:** camera
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
- **Coverage Enabled:** true
- **Coverage Angle:** 85
- **Coverage Distance:** 150
- **Coverage Rotation:** 0
- **Coverage Color:** #f59e0b
- **Coverage Opacity:** 18
- **Coverage Animation Type:** sweep
- **Coverage Animate:** false
- **Coverage Border Color:** #f59e0b
- **Coverage Border Opacity:** 60
- **Position:** 2160, 330
- **Size:** 32

### e-lock
- **Name:** Front Lock
- **IP:** Thread
- **Role:** 
- **Shape:** smart-lock
- **Tags:** security
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
- **Position:** 2020, 560
- **Size:** 32

### e-motion
- **Name:** Hall Motion
- **IP:** Zigbee
- **Role:** 
- **Shape:** motion-sensor
- **Tags:** _none_
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
- **Coverage Enabled:** true
- **Coverage Angle:** 110
- **Coverage Distance:** 200
- **Coverage Rotation:** 0
- **Coverage Color:** #10b981
- **Coverage Opacity:** 15
- **Coverage Animation Type:** pulse
- **Coverage Animate:** true
- **Coverage Speed:** 3
- **Coverage Border Color:** #10b981
- **Coverage Border Opacity:** 50
- **Position:** 2020, 780
- **Size:** 28

### g-door
- **Name:** Garage Door
- **IP:** Wi Fi relay
- **Role:** 
- **Shape:** garage
- **Tags:** security
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
- **Position:** 2480, 400
- **Size:** 38

### g-ev
- **Name:** EV Charger
- **IP:** Wi Fi, 11 kW
- **Role:** 
- **Shape:** smart-plug
- **Tags:** energy
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
- **Position:** 2480, 600
- **Size:** 34

### g-cam
- **Name:** Garage Cam
- **IP:** PoE
- **Role:** 
- **Shape:** camera
- **Tags:** _none_
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
- **Coverage Enabled:** true
- **Coverage Angle:** 85
- **Coverage Distance:** 230
- **Coverage Rotation:** 315
- **Coverage Color:** #f59e0b
- **Coverage Opacity:** 18
- **Coverage Animation Type:** sweep
- **Coverage Animate:** false
- **Coverage Border Color:** #f59e0b
- **Coverage Border Opacity:** 60
- **Position:** 2620, 790
- **Size:** 28

### u-valve
- **Name:** Water Main Valve
- **IP:** Zigbee
- **Role:** 
- **Shape:** smart-plug
- **Tags:** safety
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
- **Position:** 260, 1080
- **Size:** 32

### u-washer
- **Name:** Washer Plug
- **IP:** Zigbee router, power meter
- **Role:** 
- **Shape:** smart-plug
- **Tags:** energy
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
- **Position:** 520, 1080
- **Size:** 32

### u-leak
- **Name:** Washer Leak
- **IP:** Zigbee
- **Role:** 
- **Shape:** sensor
- **Tags:** safety
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
- **Position:** 520, 1300
- **Size:** 28

### u-vac
- **Name:** Robot Vacuum
- **IP:** Wi Fi
- **Role:** 
- **Shape:** vacuum
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
- **Position:** 260, 1300
- **Size:** 34

### o-lamp
- **Name:** Desk Lamp
- **IP:** Zigbee
- **Role:** 
- **Shape:** smart-bulb
- **Tags:** lights
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
- **Position:** 860, 1080
- **Size:** 30

### o-blinds
- **Name:** Office Blinds
- **IP:** Thread
- **Role:** 
- **Shape:** smart-plug
- **Tags:** _none_
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
- **Position:** 1160, 1080
- **Size:** 30

### o-air
- **Name:** Air Quality
- **IP:** Thread, CO2 and VOC
- **Role:** 
- **Shape:** sensor
- **Tags:** _none_
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
- **Position:** 1010, 1300
- **Size:** 28

### b-hum
- **Name:** Humidity
- **IP:** Zigbee
- **Role:** 
- **Shape:** sensor
- **Tags:** _none_
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
- **Position:** 1600, 1080
- **Size:** 28

### b-fan
- **Name:** Bath Fan
- **IP:** Zigbee switch
- **Role:** 
- **Shape:** smart-plug
- **Tags:** _none_
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
- **Position:** 1600, 1300
- **Size:** 30

### p-cam
- **Name:** Patio Cam
- **IP:** PoE
- **Role:** 
- **Shape:** camera
- **Tags:** _none_
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
- **Coverage Enabled:** true
- **Coverage Angle:** 85
- **Coverage Distance:** 300
- **Coverage Rotation:** 135
- **Coverage Color:** #f59e0b
- **Coverage Opacity:** 18
- **Coverage Animation Type:** sweep
- **Coverage Animate:** false
- **Coverage Border Color:** #f59e0b
- **Coverage Border Opacity:** 60
- **Position:** 1880, 1020
- **Size:** 28

### p-lights
- **Name:** String Lights
- **IP:** Outdoor plug
- **Role:** 
- **Shape:** smart-plug
- **Tags:** lights
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
- **Position:** 2160, 1300
- **Size:** 30

### p-sprinkler
- **Name:** Sprinkler Zone 1
- **IP:** Wi Fi controller
- **Role:** 
- **Shape:** sprinkler
- **Tags:** _none_
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
- **Coverage Enabled:** true
- **Coverage Angle:** 180
- **Coverage Distance:** 200
- **Coverage Rotation:** 270
- **Coverage Color:** #06b6d4
- **Coverage Opacity:** 20
- **Coverage Animation Type:** spin
- **Coverage Animate:** true
- **Coverage Speed:** 6
- **Position:** 2480, 1150
- **Size:** 32

## Connections

- hub --> lr-l1
  - **ID:** edge-ground-26
  - **Label:** 
  - **Color:** #84cc16
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- hub --> lr-l2
  - **ID:** edge-ground-27
  - **Label:** 
  - **Color:** #84cc16
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- hub --> lr-l3
  - **ID:** edge-ground-28
  - **Label:** 
  - **Color:** #84cc16
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- hub --> lr-motion
  - **ID:** edge-ground-29
  - **Label:** 
  - **Color:** #84cc16
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- hub --> lr-tv
  - **ID:** edge-ground-30
  - **Label:** 
  - **Color:** #38bdf8
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dashed
  - **Group ID:** 

- hub --> lr-spk
  - **ID:** edge-ground-31
  - **Label:** 
  - **Color:** #38bdf8
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dashed
  - **Group ID:** 

- hub --> k-plug
  - **ID:** edge-ground-32
  - **Label:** 
  - **Color:** #84cc16
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- k-plug --> k-lights
  - **ID:** edge-ground-33
  - **Label:** 
  - **Color:** #84cc16
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- k-plug --> k-leak
  - **ID:** edge-ground-34
  - **Label:** 
  - **Color:** #84cc16
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- k-lights --> k-smoke
  - **ID:** edge-ground-35
  - **Label:** 
  - **Color:** #84cc16
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- hub --> k-speaker
  - **ID:** edge-ground-36
  - **Label:** 
  - **Color:** #c084fc
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- k-speaker --> k-temp
  - **ID:** edge-ground-37
  - **Label:** 
  - **Color:** #c084fc
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- k-speaker --> o-blinds
  - **ID:** edge-ground-38
  - **Label:** 
  - **Color:** #c084fc
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- k-speaker --> o-air
  - **ID:** edge-ground-39
  - **Label:** 
  - **Color:** #c084fc
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- k-lights --> e-motion
  - **ID:** edge-ground-40
  - **Label:** 
  - **Color:** #84cc16
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- k-speaker --> e-lock
  - **ID:** edge-ground-41
  - **Label:** 
  - **Color:** #c084fc
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- e-lock --> e-bell
  - **ID:** edge-ground-42
  - **Label:** 
  - **Color:** #38bdf8
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dashed
  - **Group ID:** 

- g-door --> g-ev
  - **ID:** edge-ground-43
  - **Label:** 
  - **Color:** #38bdf8
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dashed
  - **Group ID:** 

- hub --> u-washer
  - **ID:** edge-ground-44
  - **Label:** 
  - **Color:** #84cc16
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- u-washer --> u-valve
  - **ID:** edge-ground-45
  - **Label:** 
  - **Color:** #84cc16
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- u-washer --> u-leak
  - **ID:** edge-ground-46
  - **Label:** 
  - **Color:** #84cc16
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- u-washer --> o-lamp
  - **ID:** edge-ground-47
  - **Label:** 
  - **Color:** #84cc16
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- o-lamp --> b-hum
  - **ID:** edge-ground-48
  - **Label:** 
  - **Color:** #84cc16
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- b-hum --> b-fan
  - **ID:** edge-ground-49
  - **Label:** 
  - **Color:** #84cc16
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dotted
  - **Group ID:** 

- u-leak --> u-valve
  - **ID:** edge-ground-50
  - **Label:** Leak closes valve
  - **Color:** #f59e0b
  - **Width:** 4
  - **Direction:** forward
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 
  - **Animate:** true
  - **Animation Style:** arrows
  - **Animation Speed:** 1.5

- e-bell --> lr-tv
  - **ID:** edge-ground-51
  - **Label:** Doorbell on TV
  - **Color:** #f59e0b
  - **Width:** 4
  - **Direction:** forward
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dashed
  - **Group ID:** 
  - **Waypoints:** 2160,300 860,300

- p-cam --> p-lights
  - **ID:** edge-ground-52
  - **Label:** 
  - **Color:** #38bdf8
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dashed
  - **Group ID:** 

- p-lights --> p-sprinkler
  - **ID:** edge-ground-53
  - **Label:** 
  - **Color:** #38bdf8
  - **Width:** 3
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** dashed
  - **Group ID:** 

- p-cam --> g-cam
  - **ID:** edge-ground-54
  - **Label:** PoE to garage switch
  - **Color:** #3b82f6
  - **Width:** 4
  - **Direction:** none
  - **Routing:** straight
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 

## Zones

### rect-ground-3
- **Position:** 100, 220
- **Size:** 900 x 640
- **Color:** #3b82f6
- **Style:** filled
- **Line Style:** solid
- **Border Color:** 
- **Border Width:** 2
- **Group ID:** 
- **Fill Opacity:** 0.1

### rect-ground-6
- **Position:** 1000, 220
- **Size:** 800 x 640
- **Color:** #f59e0b
- **Style:** filled
- **Line Style:** solid
- **Border Color:** 
- **Border Width:** 2
- **Group ID:** 
- **Fill Opacity:** 0.1

### rect-ground-9
- **Position:** 1800, 220
- **Size:** 450 x 640
- **Color:** #a855f7
- **Style:** filled
- **Line Style:** solid
- **Border Color:** 
- **Border Width:** 2
- **Group ID:** 
- **Fill Opacity:** 0.1

### rect-ground-12
- **Position:** 2250, 220
- **Size:** 450 x 640
- **Color:** #64748b
- **Style:** filled
- **Line Style:** solid
- **Border Color:** 
- **Border Width:** 2
- **Group ID:** 
- **Fill Opacity:** 0.1

### rect-ground-15
- **Position:** 100, 860
- **Size:** 600 x 600
- **Color:** #14b8a6
- **Style:** filled
- **Line Style:** solid
- **Border Color:** 
- **Border Width:** 2
- **Group ID:** 
- **Fill Opacity:** 0.1

### rect-ground-18
- **Position:** 700, 860
- **Size:** 700 x 600
- **Color:** #06b6d4
- **Style:** filled
- **Line Style:** solid
- **Border Color:** 
- **Border Width:** 2
- **Group ID:** 
- **Fill Opacity:** 0.1

### rect-ground-21
- **Position:** 1400, 860
- **Size:** 400 x 600
- **Color:** #ec4899
- **Style:** filled
- **Line Style:** solid
- **Border Color:** 
- **Border Width:** 2
- **Group ID:** 
- **Fill Opacity:** 0.1

### rect-ground-23
- **Position:** 1800, 860
- **Size:** 900 x 600
- **Color:** #22c55e
- **Style:** filled
- **Line Style:** solid
- **Border Color:** 
- **Border Width:** 2
- **Group ID:** 
- **Fill Opacity:** 0.1

## Text Labels

### text-ground-1
- **Position:** 60, 100
- **Content:** Maple House: Ground Floor
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

### text-ground-2
- **Position:** 60, 148
- **Content:** Rooms are zones, devices sit where they are mounted, lines show the radio mesh
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

### text-ground-4
- **Position:** 118, 254
- **Content:** Living Room
- **Font Size:** 24
- **Color:** #e2e8f0
- **Font Weight:** bold
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-ground-5
- **Position:** 118, 284
- **Content:** Movie scene, ceiling lights grouped
- **Font Size:** 15
- **Color:** #94a3b8
- **Font Weight:** normal
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-ground-7
- **Position:** 1018, 254
- **Content:** Kitchen
- **Font Size:** 24
- **Color:** #e2e8f0
- **Font Weight:** bold
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-ground-8
- **Position:** 1018, 284
- **Content:** Leak and smoke protection
- **Font Size:** 15
- **Color:** #94a3b8
- **Font Weight:** normal
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-ground-10
- **Position:** 1818, 254
- **Content:** Entry
- **Font Size:** 24
- **Color:** #e2e8f0
- **Font Weight:** bold
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-ground-11
- **Position:** 1818, 284
- **Content:** Front door
- **Font Size:** 15
- **Color:** #94a3b8
- **Font Weight:** normal
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-ground-13
- **Position:** 2268, 254
- **Content:** Garage
- **Font Size:** 24
- **Color:** #e2e8f0
- **Font Weight:** bold
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-ground-14
- **Position:** 2268, 284
- **Content:** EV charging
- **Font Size:** 15
- **Color:** #94a3b8
- **Font Weight:** normal
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-ground-16
- **Position:** 118, 894
- **Content:** Utility
- **Font Size:** 24
- **Color:** #e2e8f0
- **Font Weight:** bold
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-ground-17
- **Position:** 118, 924
- **Content:** Washer and water main
- **Font Size:** 15
- **Color:** #94a3b8
- **Font Weight:** normal
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-ground-19
- **Position:** 718, 894
- **Content:** Office
- **Font Size:** 24
- **Color:** #e2e8f0
- **Font Weight:** bold
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-ground-20
- **Position:** 718, 924
- **Content:** Focus mode
- **Font Size:** 15
- **Color:** #94a3b8
- **Font Weight:** normal
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-ground-22
- **Position:** 1418, 894
- **Content:** Bath
- **Font Size:** 24
- **Color:** #e2e8f0
- **Font Weight:** bold
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-ground-24
- **Position:** 1818, 894
- **Content:** Back Patio
- **Font Size:** 24
- **Color:** #e2e8f0
- **Font Weight:** bold
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

### text-ground-25
- **Position:** 1818, 924
- **Content:** Outdoor, irrigation zone 1
- **Font Size:** 15
- **Color:** #94a3b8
- **Font Weight:** normal
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
- **Group ID:** 

