| ![The One File](assets/theonefile.jpg) |

# The One File - Network Topology Maker

In the end there can only be "The ONE File". A portable and completely self contained network topology builder.  
The canvas, the logic, the settings, your nodes, your connections, and your notes all live inside a single standalone HTML file.  
Any modern browser can open it without setup.

---

## Why It Exists

I wanted a tool that is:

- fully offline  
- portable  
- zero setup  
- stable  
- fast  
- dependable in emergencies 

Instead of building another hosted application, I built a file.

---

## What You Can Use It For

- Homelab mapping  
- Office network layouts  
- Rack diagrams  
- VLAN and subnet planning  
- Logical and physical maps  
- Encrypted break glass documentation  
- Offline or air gapped environments  
- Sharing a topology by sending a single file  

---

## Features
- Zero coding knowledge required    
- Zero config files

### Canvas and Navigation
- Large zoomable and pannable workspace  
- Minimap with viewport tracking  
- Works with touch and mobile  
- Clear grid and boundary indicators  

### Nodes
- Multiple shapes for common devices including servers, routers, switches, firewalls, and clouds  
- Editable name, IP, role, tags, and notes  
- Resizable with full styling controls  
- Custom fonts, colors, and text offsets  
- Per breakpoint styling for desktop, tablet, mobile, and fold layouts  

### Connections
- Smart routed lines  
- Multiple links between the same devices  
- Optional direction arrows  
- Custom width, color, and labels  
- Notes for VLANs, protocols, policies, and bandwidth  

### Free Draw
- Create custom polylines  
- Move and edit individual points  
- Useful for additional networks, zones, boundaries, etc

### Legend (Bottom left)
- Automatically built from line colors in use  
- Editable labels  
- note: only shows up after first line is generated.

### Save System
- Exports a brand new updated HTML file  
- All data is embedded in the file  
- Optional AES 256 GCM encryption for sensitive information  
- Browser native crypto only  
- No servers involved  

### Customization
- Full theme editor  

---

## Supported Browsers

- Chrome and Edge  
- Firefox  
- Safari desktop and mobile  
- Modern Android and iOS browsers  

If the browser is reasonably modern, it should work.

---

## File Structure

Everything is contained inside the single HTML file:

- CSS  
- JavaScript  
- Node data  
- Connection data  
- Style and layout settings  
- Encrypted payload when enabled  
