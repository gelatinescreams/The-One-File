#### CHANGE LOG
**4.0.0 Stable is here community! Thank you to all the testers, downloaders and shooting stars. We are making this for all of us :)**

### Version Version 4.0.0 /\ 1/6/26 4.0.0 Stable + TheOneFile_Verse
* **4.0.0 Stable! Thank you to everyone!**
* **TheOneFile_Verse launch** This realtime collaborative wrapper thats easily deployable with docker lets multiple users edit the same networks, smart homes, mind maps, infrastructure, or anything with nodes and connections....together!
* [More information on TheOneFile_Verse](https://github.com/gelatinescreams/The-One-File/tree/main/theonefile_verse)
* **Fixed an issue where node and racks did not display correctly in print export**
* **See more changes in the [changelog.md](changelog.md)**
* **I am working on new demos with all the included features**

### Version 3.9.9.9 /\ 12/29/25 Upgraded Animations, minimap and editable options
* **Coverage zones now work on 11 device types**
  * Camera, CCTV, Doorbell
  * Motion Sensor, Smoke Detector
  * Access Point, WiFi, Router
  * Sensor, IoT, Sprinkler

* **Added new editable Detection Zone properties**
  * Inner Radius : Add inner dead spots to zones
  * Opacity : Control zone fill transparency
  * Gradient Fade : Zone fades from center to edge
  * Border Color : Separate color for zone outline
  * Border Width : Thickness of zone outline
  * Border Style : Solid, dashed, or dotted outlines
  * Border Opacity : Transparency of zone outline

* **Added text labels to coverage zones**
* **Added editable text labels properties to coverage zones**

* **Added animation types**
  * Sweep : Pan back and forth
  * Pulse : Breathing/scale effect
  * Rings : Expanding circles emanating outward
  * Spin : Continuous rotation

* **Added Zone Presets**
  * Security Cam, PTZ Cam, Motion Detect
  * WiFi Strong, WiFi Extended
  * Smoke Alarm, Sprinkler Arc
* **Save your own custom presets!**

* **Added new Bulk Operations for zones**
  * Bulk Copy : Copy zone style from first selected node
  * Bulk Paste : Apply copied style to all selected nodes
  * Bulk Toggle : Enable/disable zones on all selected nodes
  
* **Updated Line legend to includes zones**
  * Auto generated legend showing zone colors
  * Editable labels for each zone color
  * Click color swatch to select nodes with that zone color for faster editing

* **New Main Settings : Animations & Zones**
  * Master toggles (all animations, all zones)
  * Type toggles (sweep, pulse, rings, spin, connections)
  * Category toggles (cameras, doorbells, motion sensors, smoke detectors, wifi/AP/router, sensors/IoT, sprinklers)

* **Minimap Improvements**
  * Removed all animations and coverage zones from minimap (performance improvemnet and useless visually)
  * Simplified node shapes in minimap
  * Circles for regular nodes
  * Squares for racks
  * Outlined diamonds for animatable devices
  * Added wall rectangles from free draw to minimap
  * Added orthogonal routing display to minimap
  * Fixed: resizing nodes now updates minimap immediately

* **Welcome Message addition**
  * Click or tap anywhere to dismiss early.

* **Improved: HTTP Ping / Status Monitoring for Networkening edition**
  * More reliable detection that now uses image load method to verify server actually responds with valid content. Built in fetch fallback for edge cases.
  * Added response time tracking (e.g., "47ms")
  * Batched checking now checks nodes in groups of 5 for faster bulk checks without overwhelming the network
  * Added advanced timeout handling
  
* **General Bug Fixes**  

### Version 3.9.9.8 /\ 12/22/25 Animations, walls, settings, themes and tidying up for 4.0
* **Theme System Overhaul**
  * Added 8 preset themes organized by category
  * Save your own custom themes for easy tab theming
* **Animated Connections with Flow**
  * Show which way data is flowing for all, some, or any amount of custom connections
  * Includes options for all the flow settings
* **CCTV/Camera nodes now have FOV Cone options for both stationary and PTZ cameras**
  * Cone can be animated and animation carry over to minimap
* **Added 13 new device icons in a new "Smart Home" dropdown category:**
  * Thermostat, Video Doorbell, Smart Lock, Smart Bulb, Smart Plug, Smart Speaker, Smart TV, Smart Hub, Smoke Detector, Motion Sensor, Garage Door, Sprinkler, Robot Vacuum
* **Bug fixes for Core + Networkening Editions**
  * Removed unused code
  * Fixed rotate actions and added -360 degrees on canvas assets
  * Added defensive checks to prevent potential very edge case crashes
  * Replaced port map links with buttons for better UI on both desktop and mobile
  * Camera FOV cones render on the minimap with synchronized animation
  * Line (✏️), Rectangle (▭), and Text (T) tool buttons now pulse with glow animation when active to add visual feedback so users know to click "Done" to exit drawing mode
  * Resize Handles now scale with border width(s)
  * Fixed a memory leak where pressing Escape to close the Rack Unit or U Height editor could cause erratic behavior after repeated use
  * Port Map Export: Fixed CSV export producing malformed files when device names contained quotes or special characters
  * Undo now works after importing JSON files
  * Markdown import now validates connections and invalid links are skipped instead of creating broken edges
  * Welcome message no longer disappears after saving and refreshing
* **Bug fixes for Networkening Edition**
  * Removed localStorage icon caching
  * Old exported cached icons are automatically cleaned up on first load

### Version 3.9.9.7 /\ 12/19/25 Import/export, saving and updates for editors
* **Improved the import/export system**  [read more: import-export-save.md](import-export-save.md)
* **Added markdown export and import**  Ala, Git versioning!
  * Edit and create in your favorite markdown editor
  * This also allows git versioning!
* **Added csv export and import**  
  * Edit and create in your favorite csv editor
* **Added print option**  
  * Removes the background and makes the entire canvas print friendly
* **New import/Export mobile menu**  
* **Bug Fixes**  
  * Fixed minimap rendering nodes twice (performance)
  * Fixed event listener memory leak in edge drag handlers
  * Fixed Mac keyboard shortcuts (SORRY APPLE)

### Version 3.9.9.6 /\ 12/17/25 Stretching version numbers AND lines too!
* **Big performance update**
* **Orthogonal routing update** [changelog.md](changelog.md)
  * New orthogonal routing option draws clean 90 degree angle connections
  * Three routing styles available: Orthogonal, Curved, and Straight
  * Change between all of them in the settings at any time OR mix and match them   
* **Auto Recovery**
  * If your browser crashes or you accidentally close the tab, your work is saved in your local browser
  * If you want to clear this cache, use the Clear All option in settings
* **Enhanced Search** : Search now zooms in and out of the canvas automatically to group found items
* **Mobile Undo** : Add three finder tap anywhere on the canvas for undo on mobile devices
* **Performance Under The Hood**
  * Multiple rapid changes are now batched into single redraws
  * Minimap updates are throttled during pan and zoom
  * Drop shadows and pulse animations automatically disabled when zoomed out below 50 percent
  * Mouse and touch pan handlers optimized to prevent layout thrashing
  * CSS containment added to panels and viewport for faster rendering
  * Undo performance updates
  * Minimap performance updates
  * Custom Orthogonal gap function : edges show gaps where they cross other orthogonal edges
  * Refactored update/import function
  * Refactored background grid for performance
  
### Version 3.9.9.5 /\ 12/14/25 The ports enhancements update
* **Port connections section in node/rack panel** : See all ports connected to a device at a glance
* **Click to edit unassigned ports** : Assign ports directly from the devices
* **Port JumpTO** : Click ↗ to jump to that connection on canvas and highlight it
* **Edge color indicators** : Added color codes to the dedicated port view for easy reference
* **Duplicate port warning** : Added a vert simply alert when assigning a port already in use on that device
* **Squashed port bugs** : Squashed some small related ports bugs

### Version 3.9.9.4 /\ 12/14/25 Further fixes towards 4.0 Stable
* Fixed an issue where entering rack view would freeze the canvas on mobile
* Fixed an issue where node creation could be interrupted in rare cases
* Fixed pedantic HTML sanitations for inputs
* Added a function to sanitize inputs

### Version 3.9.9.3 /\ 12/13/25 Added Advanced Ports View
* Fixed [#27](https://github.com/gelatinescreams/The-One-File/issues/27)** thanks to [@lehnerpat](https://github.com/lehnerpat) for debugging
* Fixed an issue where modals were not closing correctly in the background

### Version 3.9.9.2 /\ 12/11/25 Added Advanced Ports View
* **Added New Ports View [#25](https://github.com/gelatinescreams/The-One-File/issues/25)** thanks to [@mohacc2008-ctrl](https://github.com/mohacc2008-ctrl) for the request
* **Squashed Bugs**
* * Fixed a bug where deleted tabs were not leaving the old canvas view
* * Fixed a bug where foldables and some tablets showed desktop elements
* * Started to refactor a few core elements for future updates

##### Version 3.9.9.1 /\ 12/10/25 Getting close to 4.0 Stable!
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
* * Edit color/border color/border width/style now undoable
* * Delete zone now undoable
* * Delete zone notes now undoable
* * All 9 text properties (font size, color, weight, style, align, decoration, bg color, bg enabled, opacity) now undoable

* **Squashed Bugs**
* * On mobile/tablet, users could still drag canvas elements (nodes, rectangles) even when View Only mode is enabled.
* * Ctrl+A (Select All) now shows correct total count (was only counting nodes)
* * (Shift multi select) Marquee select no longer accumulates between selections
* * Misc code refinement

##### Version 3.9.9 /\ 12/10/25 Hotfix release for desktop multi select
* **Added back mobile core functions from updating the audit system

##### Version 3.9.8.1 /\ 12/10/25 Hotfix release for desktop multi select
* **fixed a bug where mutli select with shift on desktop counted all entities it crossed

##### Version 3.9.8 /\ 12/10/25 View only mode + multi select for desktop

* **Added View Only Mode in Settings** Disables all editing while keeping pan and zoom
* * Click or tap any canvas item five times to inspect its details while in View Only Mode
* **Upgraded and fixed the Audit log.** Moved it to the stored JSON. Audit log now transfers with the save!
* * Added smart migration to merge old localStorage audit with new JSON storage
* **Added new core shapes to both versions.**
* **New desktop mutli entity select option added.** [#21](https://github.com/gelatinescreams/The-One-File/issues/21)  + more : Special thanks to [@mitchplze](https://github.com/mitchplze)
* * Hold shift and click+drag on empty canvas to select multiple items at once
* * Selection box colors can be customized in Settings

##### Version 3.9.7 /\ 12/9/25 Squashing Bugs

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

##### Version 3.9.6 /\ 12/8/25 Rack canvas fixes

* **Can now view and edit nodes that are inside a given rack just by selecting a rack and using the sidebar / mobile footer**
* **Updated all keyboard shortcuts to work with new canvas draw tools**
  * Fixed a bug where cloning racks with nodes inside would not clone the nodes
  * Fixed a bug where deleting nodes and racks via the information panel was broken
  * Fixed a bug where nodes were created at the bottom of canvas in rack view regardless of user view
* **They will now generate in the center of users view**
  * Fixed a bug where page titles were overriden by tab titles
  * Fixed a bug where canvas information panel from previous tabs would stay selected after tab switch 

##### Version 3.9.5 /\ 12/7/25 The Styles Update!

* **Added all available styling options to settings**
* **Canvas Styling** Added seperated styling for the main canvas and rack view canvases
  * Added additional syling options to free draw tools

##### Version 3.9.4 /\ 12/6/25 Canvas bug fixes

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
  
##### Version 3.9.3 /\ 12/5/25 Mobile bug fixes

* **NEW 3.9.3** Mobile fixes. 
* **Various bug fixes including**
  * Rewrote every mobile touch event
  * Cleaned mobile core
  
##### Version 3.9.2 /\ 12/5/25 Bug fixes

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

##### Version 3.9 /\ 12/4/25

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

##### Version 3.7 /\ 12/3/25
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

##### Version 3.5.1 /\ 12/2/25
- **NEW 3.5.1** Small style fixes and mobile refactoring

##### Version 3.5 /\ 12/2/25
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

##### Version 3.0 /\ 12/1/25
- NEW 3.0 Total mobile rewrite for core the-one-file.html
- NEW 3.0 Total css rewrite for core the-one-file.html
- NEW 3.0 : Ping/Live status for nodes added to theonefile-networkening.html
- Click here for a full online demo of the theonefile-networkening.html
- [Click here for a full online demo of the theonefile-networkening-corporate-demo.html](https://gelatinescreams.github.io/The-One-File/demos/theonefile-networkening-corporate-demo.html)
- [Click here for a full online demo of the theonefile-networkening-homelab-demo.html](https://gelatinescreams.github.io/The-One-File/demos/theonefile-networkening-homelab-demo.html)
- NEW 2.8 : Icon SEARCH with live preview
- Seperate online features version to include icons - OPTIONAL
- Use theonefile-networkening.html for this version


##### Version 2.8 /\ 11/29/25 The One File: The Networkening update!
- Totally collapsible mobile interface
- Mobile core added for future features
- NEW 2.8 : Icon SEARCH with live preview
- Seperate online features version to include web incons (OPTIONAL)
- Use theonefile-networkening.html for this version
- Icon support added (MDI, Simple Icons, Selfh.st)

##### Version 2.5 /\ 11/25/25 The One File: The Networkening update!
- NEW 2.5 : Icon SEARCH with live preview