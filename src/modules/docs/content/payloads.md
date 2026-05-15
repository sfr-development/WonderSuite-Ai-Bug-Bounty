# Payloads

The Payloads module is WonderSuite's local payload arsenal — a searchable, categorised library of attack strings pulled from **SecLists** and **PayloadsAllTheThings**. It's the ammunition store for the [Intruder](page:intruder), [Repeater](page:repeater), and manual testing.

## Downloading the arsenal

On a fresh install the library isn't on disk yet. The sidebar lists every category — a grey folder icon means *not downloaded*, a green one means *ready*.

- **Download All** (toolbar) pulls every category in one go.
- Or download a single category with its inline **Download** button.

The toolbar pill shows the running total: payload count and downloaded/total categories. The base directory where payloads live is shown at the bottom of the sidebar.

## Browsing a category

Click a downloaded category to open it. Payloads are paged (200 per page) with **Prev / Next** navigation; the header shows the page and total count.

Each payload row has three actions:

- **Copy** — copy the payload to the clipboard.
- **Send to Repeater** — opens it in the [Repeater](page:repeater) as a request parameter.
- **Send to Intruder** — opens it in the [Intruder](page:intruder), wrapped in `§…§` position markers, ready to fire.

## Searching

The search box runs across **every** category at once — type a query and press Enter. Results show the matching payload and which category it came from, with the same Copy / Repeater / Intruder actions.

## Category info

Categories with an **info** icon open a reference card explaining the vulnerability class: what it is, where to inject it, annotated example payloads, notable real-world cases, and mitigation guidance. The example payloads in the card are also directly copyable and sendable. It's a built-in primer for each attack type — useful when you want context before firing payloads.
