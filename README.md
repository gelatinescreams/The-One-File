![The One File](assets/theonefile.jpg)

# The One File: Network Topology Maker

In the end there can only be "The ONE File". A portable and completely self contained network topology builder. The canvas, the logic, the settings, your nodes, your connections, and your notes all live inside a single standalone HTML file. Any modern browser can open and edit it without any prior setup. (is the idea)

*Two editions are now available with 3.0. Both built from the same core design.*
- **the-one-file.html**
A fully self contained topology builder that runs anywhere as a single standalone HTML file and the core of theonefile-networkening.html

- **theonefile-networkening.html**
  Adds online features like live status/ping per node and icons from awesome libraries such as MDI, Simple Icons, Selfh.st. It functions as a bolt-on layer while keeping the core workflow unchanged. Still one file!

![The One File](assets/corporate.png) ![The One File](assets/homelab.png) ![The One File](assets/mobilepreviews.jpg)

## Version 3.5 : 12/2/25

- NEW 3.5 *Another major realease. Thank you to Discord testers!!*
- NEW 3.5 Add Text Labels Anywhere** Click the "T" button to place custom text annotations anywhere on your canvas with full styling control
- NEW 3.5 Draw Rectangles/Boxes** Create visual boundaries, zones, or highlighted areas with filled or outlined rectangles in any color
- NEW 3.5 Bulk Operations** Select multiple nodes at once with right click (or double-tap on mobile) and perform batch operations:
  - Align Left, Right, Top, or Bottom
  - Distribute Horizontally or Vertically
  - Clone all selected nodes
  - Delete in bulk
- NEW 3.5 Keyboard Shortcuts** Power user controls:
  - `Ctrl/Cmd + Z` Undo
  - `Ctrl/Cmd + Y` or `Ctrl/Cmd + Shift + Z` Redo
  - `Ctrl/Cmd + C` Copy node
  - `Ctrl/Cmd + V` Paste node
  - `Ctrl/Cmd + Plus` Zoom in
  - `Ctrl/Cmd + Minus` Zoom out
  - `Ctrl/Cmd + 0` Reset view
  - `Space + Drag` Pan canvas
- NEW 3.5 Mobile Gestures** Touch-optimized controls:
  - **Double-tap** to select multiple nodes
  - **Double-tap** to clone and align nodes
  - Resizable mobile footer with drag handle
  - Touch friendly bulk operations modal
- NEW 3.5 Per-Breakpoint Styling** Customize node appearance independently for Desktop, Tablet, Mobile, and Fold layouts
- NEW 3.5 Live node search with visual highlighting
- NEW 3.5 Added MAC field to node
- NEW 3.5 Added Rack field to node
- NEW 3.5 Live node search with visual highlighting
- NEW 3.1 Live Status Monitoring** *(networkening version only)*
- NEW 3.1 Real-time ping/status indicators on nodes
- NEW 3.1 Visual online/offline/checking indicators
- Online Demos:
- [the-one-file.html-corporate-demo.html](https://gelatinescreams.github.io/The-One-File/demos/the-one-file-corporate-demo.html)
- [the-one-file.html-homelab-demo.html](https://gelatinescreams.github.io/The-One-File/demos/the-one-file-homelab-demo.html)
#
- [theonefile-networkening-corporate-demo.html](https://gelatinescreams.github.io/The-One-File/demos/theonefile-networkening-corporate-demo.html)
- [theonefile-networkening-homelab-demo.html](https://gelatinescreams.github.io/The-One-File/demos/theonefile-networkening-homelab-demo.html)

## Online vs Offline

| Feature | theonefile.html | theonefile-networkening.html |
|---------|---------|--------|
| All core features | ✓ | ✓ |
| Create/edit/save topologies | ✓ | ✓ |
| Shapes, lines, styling | ✓ | ✓ |
| **Add text labels anywhere** | ✓ | ✓ |
| **Draw rectangles/boxes** | ✓ | ✓ |
| **Free draw custom lines** | ✓ | ✓ |
| **Keyboard shortcuts** | ✓ | ✓ |
| Encryption, export | ✓ | ✓ |
| Bulk operations | ✓ | ✓ |
| Multi select | ✓ | ✓ |
| Per device styling | ✓ | ✓ |
| Mobile optimized | ✓ | ✓ |
| Offline only | ✓ |  |
| No dependencies | ✓ |  |
| **[MDI Icons](https://pictogrammers.com/library/mdi/)**       |  | ✓ |
| **[Simple Icons](https://simpleicons.org/?q=ping)**   |  | ✓ |
| **[Selfh.st Icons](https://selfh.st/icons/)** |  | ✓ |
| **Auto Status Checking** |  | ✓ |
| **Live Ping/Health Status** |  | ✓ |

# Demos

#### Online:
- [the-one-file-corporate-demo.html](https://gelatinescreams.github.io/The-One-File/demos/the-one-file-corporate-demo.html)
- [the-one-file-homelab-demo.html](https://gelatinescreams.github.io/The-One-File/demos/the-one-file-homelab-demo.html)
- [theonefile-networkening-corporate-demo.html](https://gelatinescreams.github.io/The-One-File/demos/theonefile-networkening-corporate-demo.html)
- [theonefile-networkening-homelab-demo.html](https://gelatinescreams.github.io/The-One-File/demos/theonefile-networkening-homelab-demo.html)

#### Download:

- [the-one-file.html](https://github.com/user-attachments/files/23866860/the-one-file.html)
- [theonefile-networkening.html](https://github.com/user-attachments/files/23866861/theonefile-networkening.html)
- [the-one-file-corporate-demo.html](https://github.com/user-attachments/files/23866862/the-one-file-corporate-demo.html)
- [the-one-file-homelab-demo.html](https://github.com/user-attachments/files/23866863/the-one-file-homelab-demo.html)
- [theonefile-networkening-corporate-demo.html](https://github.com/user-attachments/files/23866864/theonefile-networkening-corporate-demo.html)
- [theonefile-networkening-homelab-demo.html](https://github.com/user-attachments/files/23866865/theonefile-networkening-homelab-demo.html)

## Why It Exists

I wanted a tool that is:

- fully offline
- portable
- zero setup
- stable
- fast
- dependable in emergencies

Instead of building another hosted application, I built a file.

## What You Can Use It For
- Homelab mapping  
- Office network layouts  
- Rack diagrams  
- VLAN and subnet planning  
- Mind Maps and flowcharts
- Annotated network documentation with labels and zones
- Logical and physical maps  
- Encrypted break glass documentation  
- Offline or air gapped environments  
- Sharing a topology by sending a single file

## Features
- Zero coding knowledge required    
- Zero config files
- Draw anywhere: add text labels, boxes, and custom lines to annotate your topology
- Full keyboard shortcut support for power users
- Touch optimized mobile interface with gesture support

### Canvas and Navigation
- Large zoomable and pannable workspace  
- Minimap with viewport tracking  
- Works with touch and mobile  
- Clear grid and boundary indicators
- Precise zoom controls with level display
- Right-click context menu for quick actions
- **Free Draw Mode** Draw custom polylines, rectangles, and text labels anywhere:
  - Custom lines with points you place
  - Rectangles (filled or outlined) for zones/boundaries
  - Text labels with full styling (font, size, color, weight, alignment)
  - Customizable colors, line styles (solid/dashed/dotted), and arrows
- Keyboard shortcuts for power users (undo/redo, copy/paste, zoom controls)

### Nodes
- Multiple shapes for common devices including servers, routers, switches, firewalls, and clouds  
- *Icon shapes from MDI, Simple Icons, and Selfh.st available in the theonefile-networkening.html version*
- Editable name, IP, role, tags, and notes
- *Editable icon shapes from MDI, Simple Icons, and Selfh.st available in the theonefile-networkening.html version*
- Resizable with full styling controls  
- Custom fonts, colors, and text offsets  
- **Per breakpoint styling** for desktop, tablet, mobile, and fold layouts : customize appearance independently for each screen size
- **Right-click to clone** nodes with smart positioning
- **Multi-select support** with click-drag or right-click selection

### Bulk Operations
- **Multi-select nodes** for batch operations
- **Bulk Align**: Align selected nodes left, right, top, or bottom
- **Bulk Distribute**: Evenly space nodes horizontally or vertically
- **Bulk Clone**: Duplicate multiple nodes at once
- **Bulk Delete**: Remove multiple nodes simultaneously
- **Desktop and mobile toolbars** optimized for each platform
- Visual selection indicators and count display

### Network Monitoring *(theonefile-networkening.html only)*
- **Live status indicators** on nodes (online/offline/checking)
- **Manual ping/status check** for individual nodes
- **Auto Status Checking** with configurable intervals (5-3600 seconds)
- Status check scheduling with next check timer
- Last run timestamp tracking
- Per-node ping enable/disable settings
- Visual ping indicators with color coding

### Connections
- Smart routed lines between nodes
- Multiple links between the same devices  
- Optional direction arrows  
- Custom width, color, and labels  
- Port labels (e.g., eth0, gi0/1)
- Notes for VLANs, protocols, policies, and bandwidth  

### Legend (Bottom left)
- Can be hidden on both desktop and mobile
- Automatically built from line colors in use  
- Editable labels  
- note: only shows up after first line is generated.

### Save System
- Exports a brand new updated HTML file  
- All data is embedded in the file  
- Optional AES 256 GCM encryption for sensitive information  
- Browser native crypto only  
- No servers involved  
- *Version theonefile-networkening.html uses 3 server calls from cdn.jsdelivr.net to load icons*

### Mobile Experience
- **Completely rewritten mobile UI** in version 3.0
- **Resizable mobile footer** with drag handle for custom panel sizing
- **Touch-optimized controls** throughout the interface
- **Mobile bulk operations modal** for efficient multi-node editing
- **Double-tap gestures**:
  - Double-tap to select multiple nodes (equivalent to right-click on desktop)
  - Double-tap to clone and align nodes
- Responsive layout that adapts to screen orientation
- Optimized for phones, tablets, and foldable devices

### Keyboard Shortcuts
| Shortcut | Action |
|----------|--------|
| `Ctrl/Cmd + Z` | Undo |
| `Ctrl/Cmd + Y` | Redo |
| `Ctrl/Cmd + Shift + Z` | Redo (alternative) |
| `Ctrl/Cmd + C` | Copy selected node |
| `Ctrl/Cmd + V` | Paste node |
| `Ctrl/Cmd + Plus` | Zoom in |
| `Ctrl/Cmd + Minus` | Zoom out |
| `Ctrl/Cmd + 0` | Reset view |
| `Space + Drag` | Pan canvas |
| `Scroll` | Zoom in/out |

### Customization
- 100% control theme editor
- Per-breakpoint node styling for responsive designs
- Custom color schemes and backgrounds
- Adjustable panel sizes and layouts

## Supported Browsers

- Chrome and Edge  
- Firefox  
- Safari desktop and mobile  
- Modern Android and iOS browsers  

If the browser is reasonably modern, it should work.

## Credits

Icon support for theonefile-networkening.html version powered by:
- [Selfh.st Icons](https://selfh.st/icons/) : Self-hosted app icons by the selfh.st community
- [Material Design Icons](https://pictogrammers.com/library/mdi/) : 7,000+ open source icons by Pictogrammers
- [Simple Icons](https://simpleicons.org/) : Free SVG icons for popular brands

Thank you to all the icon creators and maintainers for making these resources freely available.
