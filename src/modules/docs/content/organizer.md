# Organizer

The Organizer is your testing notebook — a place to park interesting requests, track what you've looked at, and keep notes, grouped into collections. It's how you stay on top of a target instead of losing track of half-tested endpoints.

## Collections

The left sidebar holds **collections** — buckets for organizing items however you like (by feature area, by attack class, by "to do later"). The **+** button creates a new collection; each shows its item count. The `Default` collection is always there.

## Items

An item is a saved request — method, URL, host. You add items two ways:

- **Add Item** in the toolbar creates a blank one to fill in.
- **Right-click → send to Organizer** from any other module saves that request straight into the active collection.

## Tracking state

Each item carries:

- **Status** — `New`, `In Progress`, `Done`, or `Ignored`. Filter the list by status with the buttons above it.
- **Color** — a colored left-border tag (red / orange / green / blue / purple) for visual grouping.
- **Collection** — move an item between collections from its detail pane.
- **Notes** — a free-text field for whatever you need to remember about this item.

Select an item to edit all of this in the detail panel. The item also records which tool it came from.

> The Organizer is for your *workflow* — what to test and what you've found informally. Confirmed vulnerabilities belong in [Findings](page:findings).
