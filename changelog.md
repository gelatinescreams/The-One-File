#### CHANGE LOG
**We are very close to 4.0 Stable, community! Thank you to all the testers. We are making this for all of us :)**

### Version 3.9.9.5 : 12/14/25 The ports enhancements update
* **Port connections section in node/rack panel** : See all ports connected to a device at a glance
* **Click to edit unassigned ports** : Assign ports directly from the devices
* **Port JumpTO** : Click ↗ to jump to that connection on canvas and highlight it
* **Edge color indicators** : Added color codes to the dedicated port view for easy reference
* **Duplicate port warning** : Added a vert simply alert when assigning a port already in use on that device
* **Squashed port bugs** : Squashed some small related ports bugs

### Version 3.9.9.4 : 12/14/25 Further fixes towards 4.0 Stable
* Fixed an issue where entering rack view would freeze the canvas on mobile
* Fixed an issue where node creation could be interrupted in rare cases
* Fixed pedantic HTML sanitations for inputs
* Added a function to sanitize inputs

### Version 3.9.9.3 : 12/13/25 Added Advanced Ports View
* Fixed [#27](https://github.com/gelatinescreams/The-One-File/issues/27)** thanks to [@lehnerpat](https://github.com/lehnerpat) for debugging
* Fixed an issue where modals were not closing correctly in the background

### Version 3.9.9.2 : 12/11/25 Added Advanced Ports View
* **Added New Ports View [#25](https://github.com/gelatinescreams/The-One-File/issues/25)** thanks to [@mohacc2008-ctrl](https://github.com/mohacc2008-ctrl) for the request
* **Squashed Bugs**
* * Fixed a bug where deleted tabs were not leaving the old canvas view
* * Fixed a bug where foldables and some tablets showed desktop elements
* * Started to refactor a few core elements for future updates

##### Version 3.9.9.1 : 12/10/25 Getting close to 4.0 Stable!
* **Fixed Search [#24](https://github.com/gelatinescreams/The-One-File/issues/24)**
* **Upgraded and fixed the undo system**
* * Edit node name/IP now undoable
* * Edit/delete/add tags now undoable
* * Edit/delete notes now undoable
* * Resize node (slider + reset) now undoable
* * Change shape now undoable
* * Style changes (colors, fonts, borders) now undoable
* * Edit width/color/direction/style now undoable
* * Delete edge now undoable
* * Edit/delete edge notes now undoable
* * Drag custom edge points now undoable
* * Edit color/border-color/border-width/style now undoable
* * Delete zone now undoable
* * Delete zone notes now undoable
* * All 9 text properties (font-size, color, weight, style, align, decoration, bg-color, bg-enabled, opacity) now undoable

* **Squashed Bugs**
* * On mobile/tablet, users could still drag canvas elements (nodes, rectangles) even when View Only mode is enabled.
* * Ctrl+A (Select All) now shows correct total count (was only counting nodes)
* * (Shift multi select) Marquee select no longer accumulates between selections
* * Misc code refinement

##### Version 3.9.9 : 12/10/25 Hotfix release for desktop multi select
* **Added back mobile core functions from updating the audit system

##### Version 3.9.8.1 : 12/10/25 Hotfix release for desktop multi select
* **fixed a bug where mutli select with shift on desktop counted all entities it crossed

##### Version 3.9.8 : 12/10/25 View only mode + multi select for desktop

* **Added View Only Mode in Settings** Disables all editing while keeping pan and zoom
* * Click or tap any canvas item five times to inspect its details while in View Only Mode
* **Upgraded and fixed the Audit log.** Moved it to the stored JSON. Audit log now transfers with the save!
* * Added smart migration to merge old localStorage audit with new JSON storage
* **Added new core shapes to both versions.**
* **New desktop mutli entity select option added.** [#21](https://github.com/gelatinescreams/The-One-File/issues/21)  + more : Special thanks to [@mitchplze](https://github.com/mitchplze)
* * Hold shift and click+drag on empty canvas to select multiple items at once
* * Selection box colors can be customized in Settings

##### Version 3.9.7 : 12/9/25 Squashing Bugs

* **Special thanks to @mitchplze for testing and reporting on some of these fixes**
* **Bug Fixes**
* * Fixed duplicate buttons appearing in saved files after multiple saves
* * Fixed toolbars staying in desktop layout when resizing window to mobile size
* * Fixed duplicate import button in Settings
* * Removed unused code to reduce file size
* * Zone line style (solid, dashed, dotted) can now be changed after creation. 
* **Squashing more bugs** [#21](https://github.com/gelatinescreams/The-One-File/issues/21)  + more : Special thanks to [@mitchplze](https://github.com/mitchplze)
* **Networkening Edition Fixes:**
* * Dropdown now shows "Custom Icon" when a web icon is selected. [#19](https://github.com/gelatinescreams/The-One-File/issues/19)
* * Switching to any core shape automatically clears the web icon [#19](https://github.com/gelatinescreams/The-One-File/issues/19)
* * Web icons keep their original colors until you change them [#19](https://github.com/gelatinescreams/The-One-File/issues/19)
* * Fixed web icon colors persisting when selecting a new icon. New icons now display their natural colors instead of inheriting previous custom colors. [#19](https://github.com/gelatinescreams/The-One-File/issues/19)
* * Fixed selfh.st icon search to only show icons that have SVG versions available. (for editability) [#19](https://github.com/gelatinescreams/The-One-File/issues/19)

##### Version 3.9.6 : 12/8/25 Rack canvas fixes

* **Can now view and edit nodes that are inside a given rack just by selecting a rack and using the sidebar / mobile footer**
* **Updated all keyboard shortcuts to work with new canvas draw tools**
  * Fixed a bug where cloning racks with nodes inside would not clone the nodes
  * Fixed a bug where deleting nodes and racks via the information panel was broken
  * Fixed a bug where nodes were created at the bottom of canvas in rack view regardless of user view
* **They will now generate in the center of users view**
  * Fixed a bug where page titles were overriden by tab titles
  * Fixed a bug where canvas information panel from previous tabs would stay selected after tab switch 

##### Version 3.9.5 : 12/7/25 The Styles Update!

* **Added all available styling options to settings**
* **Canvas Styling** Added seperated styling for the main canvas and rack view canvases
  * Added additional syling options to free draw tools

##### Version 3.9.4 : 12/6/25 Canvas bug fixes

* **Help Tab** Added keyboard and mouse how:to in ?help
* **Various bug fixes including**
  * Added additional styling options for free draw tools
  * Fixed a bug where cloned nodes inside racks would clone to main canvas
  * Fixed a bug where free drawn rectangle zones would not allow outlined style
  * Fixed a bug where free drawn lines were not draggable after creation
  * Fixed a bug where free drawn lines were not editable after creation
  * Fixed a bug where free drawn rectangle zones were not editable after creation
  * Fixed a bug where free drawn rectangles zones had no custom styling inputs
  * Fixed a bug where free drawn tools were not grouped correctly with nodes and racks
  
##### Version 3.9.3 : 12/5/25 Mobile bug fixes

* **NEW 3.9.3** Mobile fixes. 
* **Various bug fixes including**
  * Rewrote every mobile touch event
  * Cleaned mobile core
  
##### Version 3.9.2 : 12/5/25 Bug fixes

* **NEW 3.9.2** Styles per tab! You can now set different styles for each topology tab.
* **Various bug fixes including**
  * Fixed a bug where rack and node colors were not applying correctly
  * Added node and rack border along with fill to icons
  * Fixed a bug where rack view can get stuck
  * Fixed a bug where rack height and rack unit got swapped causing drag errors in rack view
  * Fixed a bug where lines could be added to a node when the node was inside a rack
  * Fixed a bug where lines would persist after a node is added to a rack
  * Fixed various dragging and dropping bugs
  * Changed the icons to not animate on desktop (this was implemented in version .2, well before the style sidebar)

##### Version 3.9 : 12/4/25

* **NEW 3.9** Tabs, snapshots, action audits and notes! (encrypted also)
  * Tabs are now implemented. This allows unlimited locations of topologies, still one file!
* **NEW 3.9** General topology notes are now implemented. You can also encrypt per note.
* **NEW 3.9** Snapshots are now implemeted. Auto save and manual save is available.
* **NEW 3.9** Action audits are now implemeted. This allows you to audit whether or not the file has been tampered in an easy to read log.
  * *Note: Both snapshots and audits are local browser only and do not trasnfer to another device. This feature is coming in 4.0*
* **NEW 3.7** The Rackening!!
  * Add any rack size from 6-48 and open it as its own canvas with U slot placement of nodes, new and existing, enabling unlimited hierarchical rack layouts.
* **NEW 3.7** Layers upon layers!!
  * Choose between physical, logical, security and application layers for anything and easily toggle visibility between them.
* **NEW 3.7** Added Racks and individual rack canvasses!
* **NEW 3.7** *Major workflow enhancement release with full keyboard control and mobile optimization*
* **NEW 3.7** The Rackening!!
  * Add any rack size from 6-48 and open it as its own canvas with U slot placement of nodes, new and existing, enabling unlimited hierarchical rack layouts.
* **NEW 3.7** Layers upon layers!!
  * Choose between physical, logical, security and application layers for anything and easily toggle visibility between them.
* **NEW 3.7** Added Racks and individual rack canvasses!
* **NEW 3.7** *Major workflow enhancement release with full keyboard control and mobile optimization*

##### Version 3.7 - 12/3/25
* **NEW 3.7 Advanced Keyboard Navigation**
  * **Arrow Keys** Move selected nodes 1 pixel in any direction for precise positioning
  * **Shift + Arrow Keys** Move selected nodes 10 pixels for faster adjustments
  * **Tab** Cycle forward through all nodes in current view
  * **Shift + Tab** Cycle backward through all nodes in current view
  * **F** Focus camera on selected node(s) with automatic zoom and centering
* **NEW 3.7 Node Lock System** Prevent accidental movement of positioned nodes
  * Lock individual nodes or multiple nodes at once
  * Visual lock indicator on locked nodes
  * Locked nodes cannot be moved by dragging or keyboard
  * Works with multi selection for batch operations
  * Lock status persists in saved files
* **NEW 3.7 Node Grouping System** Move related nodes together as a unit
  * Group multiple nodes to move them as a single unit
  * Visual group indicator (dashed outline) on grouped nodes
  * Drag any group member and all nodes in the group move together
  * Groups respect lock status (locked nodes stay in place)
  * Create and dissolve groups dynamically with keyboard shortcut
  * Group membership persists in saved files
* **NEW 3.7 Enhanced Mobile Experience**
  * **Double tap empty space to exit rack view** Quick navigation without button press
  * **Lock Toggle button** in mobile multi select menu for easy locking on touch devices
  * **Group Toggle button** in mobile multi select menu for easy grouping on mobile
  * Haptic feedback (vibration) for double tap actions on supported devices
  * Smart gesture detection (pan vs tap) prevents accidental actions
* **NEW 3.7 Rack View Improvements**
  * Nodes created while in rack view automatically assign to that rack
  * Drawing tools (free draw, rectangles, text) properly disabled in rack view with clear feedback
  * Improved workflow prevents accidentally placing elements in wrong view
* **A more detailed list of changes is included below**
  * [Change Log](changelog.md)

##### Version 3.5.1 - 12/2/25
- **NEW 3.5.1** Small style fixes and mobile refactoring

##### Version 3.5 - 12/2/25
- **NEW 3.5** *Another major release. Thank you to Discord testers!!*
- **NEW 3.5 Add Text Labels Anywhere** Click the "T" button to place custom text annotations anywhere on your canvas with full styling control
- **NEW 3.5 Draw Rectangles/Boxes** Create visual boundaries, zones, or highlighted areas with filled or outlined rectangles in any color
* **NEW 3.5 Bulk Operations** Select multiple nodes at once with right click (or double tap on mobile) and perform batch operations:
  * Align Left, Right, Top, or Bottom
  * Distribute Horizontally or Vertically
  * Clone all selected nodes
  * Delete in bulk
* **NEW 3.5 Keyboard Shortcuts** Power user controls:
  * `Ctrl/Cmd + Z` Undo
  * `Ctrl/Cmd + Y` or `Ctrl/Cmd + Shift + Z` Redo
  * `Ctrl/Cmd + C` Copy node
  * `Ctrl/Cmd + V` Paste node
  * `Ctrl/Cmd + Plus` Zoom in
  * `Ctrl/Cmd + Minus` Zoom out
  * `Ctrl/Cmd + 0` Reset view
  * `Space + Drag` Pan canvas
- **NEW 3.5 Mobile Gestures** Touch optimized controls:
  - **Double tap** to select multiple nodes
  - **Double tap** to clone and align nodes
  - Resizable mobile footer with drag handle
  - Touch friendly bulk operations modal
- **NEW 3.5 Per Breakpoint Styling** Customize node appearance independently for Desktop, Tablet, Mobile, and Fold layouts
- **NEW 3.5 Live node search with visual highlighting**
- **NEW 3.5 Added MAC field to node**
- **NEW 3.5 Added Rack field to node**
- **NEW 3.5 Live node search with visual highlighting**
- **NEW 3.5 Upgraded Military Grade Encryption** AES 256 GCM encryption with PBKDF2 key derivation (200,000 iterations)
  - Browser native encryption, zero server involvement
  - Password protect sensitive network documentation
  - Non recoverable (no backdoors, your data stays truly private)
  - Perfect for break glass documentation with credentials
- NEW 3.1 Live Status Monitoring *(networkening version only)*
- NEW 3.1 Real time ping/status indicators on nodes *(networkening version only)*
- NEW 3.1 Visual online/offline/checking indicators *(networkening version only)*

##### Version 3.0 - 12/1/25
- NEW 3.0 Total mobile rewrite for core the-one-file.html
- NEW 3.0 Total css rewrite for core the-one-file.html
- NEW 3.0 : Ping/Live status for nodes added to theonefile-networkening.html
- Click here for a full online demo of the theonefile-networkening.html
- [Click here for a full online demo of the theonefile-networkening-corporate-demo.html](https://gelatinescreams.github.io/The-One-File/demos/theonefile-networkening-corporate-demo.html)
- [Click here for a full online demo of the theonefile-networkening-homelab-demo.html](https://gelatinescreams.github.io/The-One-File/demos/theonefile-networkening-homelab-demo.html)
- NEW 2.8 : Icon SEARCH with live preview
- Seperate online features version to include icons - OPTIONAL
- Use theonefile-networkening.html for this version


##### Version 2.8 - 11/29/25 The One File: The Networkening update!
- Totally collapsible mobile interface
- Mobile core added for future features
- NEW 2.8 : Icon SEARCH with live preview
- Seperate online features version to include icons - OPTIONAL
- Use theonefile-networkening.html for this version
- Icon support added (MDI, Simple Icons, Selfh.st)

##### Version 2.5 - 11/25/25 The One File: The Networkening update!
- NEW 2.5 : Icon SEARCH with live preview