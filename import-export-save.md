# Export and Import

| Format | Export | Import | Full Backup | Editable  |
|--------|--------|--------|-------------|---------------------|
| **HTML/Default** | Yes | Yes | Yes | Yes |
| **JSON** | Yes | Yes | Yes | Yes |
| **Markdown** | Yes | Yes | Yes | Yes |
| **CSV** | Yes | Yes | Yes | Yes |
| **PNG** | Yes | No | No | No |
| **SVG** | Yes | No | No | Yes |

## HTML (Save File)

### Use Cases

| Scenario | Recommendation |
|----------|----------------|
| Daily work and saving progress | Save HTML |
| Sharing with others | Save HTML |
| Offline use | Save HTML |
| Archival backup | Save HTML plus JSON |

## JSON Format

### Structure
```
{
  "nodeData": { ... },
  "edgeData": { "list": [ ... ] },
  "rectData": { "list": [ ... ] },
  "textData": { "list": [ ... ] },
  "edgeLegend": { ... },
  "nodePositions": { ... },
  "nodeSizes": { ... },
  "nodeStyles": { ... },
  "page": { ... },
  "canvas": { "zoom": 1, "panX": 0, "panY": 0 },
  "savedTopologyView": { ... },
  "documentTabs": [ ... ],
  "currentTabIndex": 0,
  "encryptedSections": { ... },
  "auditLog": [ ... ]
}
```

### Use Cases

| Scenario | Recommendation |
|----------|----------------|
| Full backup | JSON |
| Transfer between files | JSON |
| Programmatic access | JSON |
| API integration | JSON |

## Markdown Format

### Structure
```
<!--THEONEFILE_CONFIG
{ ... complete JSON backup ... }
THEONEFILE_CONFIG-->

# Topology Title

> Exported from The One File on 2025-01-15T10:30:00.000Z

## Legend

- #4fd1c5: Primary Links
- #f97316: Secondary Links

## Nodes

### node-id-here
- **Name:** Display Name
- **IP:** 10.0.0.1
- **Role:** Core Router
- **Shape:** router
- **Tags:** network; critical
- **Layer:** physical
- **MAC:** 00:11:22:33:44:55
- **Rack Unit:** 
- **U Height:** 1
- **Assigned Rack:** 
- **Rack Capacity:** 
- **Is Rack:** false
- **Locked:** false
- **Group ID:** 
- **Position:** 500, 300
- **Size:** 55
- **Notes:**
  - First note here
  - Second note here
- **Styles:** `{"all":{"circleColor":"#1e293b"}}`

## Connections

- source-node (port1) --> target-node (port2)
  - **ID:** edge-1234567890
  - **Label:** Connection Label
  - **Color:** #4fd1c5
  - **Width:** 4
  - **Direction:** none
  - **Routing:** curved
  - **Type:** main
  - **Line Style:** solid
  - **Group ID:** 
  - **Points:** 100,200 150,250 200,300
  - **Notes:**
    - Edge note here

## Zones

### rect-1234567890
- **Position:** 100, 100
- **Size:** 400 x 300
- **Color:** #f97316
- **Style:** filled
- **Line Style:** solid
- **Border Color:** 
- **Border Width:** 2
- **Notes:**
  - Zone note here

## Text Labels

### text-1234567890
- **Content:** Label text here
- **Position:** 500, 200
- **Font Size:** 18
- **Color:** #e2e8f0
- **Font Weight:** normal
- **Font Style:** normal
- **Text Align:** start
- **Text Decoration:** none
- **Background Color:** #000000
- **Background Enabled:** false
- **Opacity:** 1
```

### Special Characters

| Character | Export Format | Import Conversion |
|-----------|---------------|-------------------|
| Newline in text | `<br>` | Converted back to newline |
| Tags separator | Semicolon | Split into array |
| Notes separator | Indented list | Array of strings |

### Use Cases

| Scenario | Recommendation |
|----------|----------------|
| Version control (git) | Markdown |
| Text editor viewing | Markdown |
| Manual editing of topology | Markdown |
| Documentation generation | Markdown |
| Diff comparison between versions | Markdown |

## CSV

### Structure
```
#THEONEFILE_CONFIG:{ ... complete JSON backup ... }
#
# Topology Title - Node List
# Exported from The One File on 2025-01-15T10:30:00.000Z
# NOTE: CSV contains nodes only. Use Markdown or JSON for full topology.
#
name,ip,role,shape,tags,layer,mac,rackUnit,uHeight,assignedRack,rackCapacity,isRack,locked,groupId,x,y,size,notes,styles
Core Router,10.0.0.1,Router,router,network;critical,physical,00:11:22:33:44:55,,,,,false,false,,500,300,55,Note 1|Note 2,"{...}"
Web Server,10.0.1.10,Web Server,server,production,physical,,,,,,false,false,,700,400,50,,
```

### Columns

| Column | Required | Description | Format |
|--------|----------|-------------|--------|
| name | Yes | Display name of node | Text |
| ip | No | IP address | Text |
| role | No | Role or description | Text |
| shape | No | Node shape | circle, server, router, switch, firewall, cloud, database |
| tags | No | Tags for filtering | Semicolon separated |
| layer | No | Network layer | physical, logical, security, application |
| mac | No | MAC address | Text |
| rackUnit | No | Rack unit position | Text |
| uHeight | No | Height in rack units | Number |
| assignedRack | No | Rack node ID | Text |
| rackCapacity | No | Rack capacity | Number |
| isRack | No | Is this a rack node | true or false |
| locked | No | Movement locked | true or false |
| groupId | No | Group identifier | Text |
| x | No | Horizontal position | Number |
| y | No | Vertical position | Number |
| size | No | Node size | Number |
| notes | No | Node notes | Pipe separated |
| styles | No | Custom styles | JSON string |

### Use Cases

| Scenario | Recommendation |
|----------|----------------|
| Bulk node creation | CSV |
| Spreadsheet editing of nodes | CSV |
| Import from asset database | CSV |
| Quick node list for editing | CSV |
| Full backup with editable nodes | CSV |

### Minimal CSV Example
```
name,ip,role,shape
Router 1,10.0.0.1,Core Router,router
Switch 1,10.0.0.2,Distribution,switch
Server 1,10.0.1.10,Web Server,server
Firewall,10.0.0.254,Edge Firewall,firewall
```

### CSV with Positions
```
name,ip,shape,x,y,size
Router 1,10.0.0.1,router,500,200,60
Switch 1,10.0.0.2,switch,500,400,50
Server 1,10.0.1.10,server,300,600,50
Server 2,10.0.1.11,server,500,600,50
Server 3,10.0.1.12,server,700,600,50
```

### CSV with Tags and Notes
```
name,ip,role,shape,tags,layer,notes
Core Router,10.0.0.1,Primary Router,router,network;critical;core,physical,Main gateway|Managed by NetOps
Web Server 1,10.0.1.10,Production Web,server,production;web;critical,application,Apache 2.4|Ubuntu 22.04
DB Server,10.0.2.10,Primary Database,database,production;database,application,PostgreSQL 15
Dev Server,10.0.3.10,Development,server,development;non-critical,application,
```

## PNG Export

### Use Cases

| Scenario | Recommendation |
|----------|----------------|
| Documentation screenshots | PNG |
| Presentations | PNG |
| Email attachments | PNG |
| Quick sharing | PNG |

## SVG Export

### Use Cases

| Scenario | Recommendation |
|----------|----------------|
| Design tool editing | SVG |
| Large format printing | SVG |
| Scalable documentation | SVG |
| Custom styling | SVG |

## Print

Optimized print layout for physical documentation.

### Use Cases

| Scenario | Recommendation |
|----------|----------------|
| Physical documentation | Print |
| Meeting handouts | Print |
| Wall diagrams | Print |
| Offline reference | Print |