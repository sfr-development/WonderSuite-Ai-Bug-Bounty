# Comparer

The Comparer is a focused diff tool. Drop two pieces of text — typically two HTTP responses — into it and it highlights exactly what changed. It's the fastest way to answer "did my payload actually change anything?"

## Using it

1. Paste content into **Item 1** and **Item 2**, or send requests/responses here from another module's context menu (you can target the left or right side).
2. Pick a diff **mode**:
   - **words** — word-level inline diff; best for spotting small changes inside otherwise similar responses.
   - **lines** — line-level diff; best for structural changes across larger bodies.
3. Click **Compare**.

## Reading the result

The diff view marks every change:

- **Added** — present in Item 2 but not Item 1.
- **Removed** — present in Item 1 but not Item 2.
- **Equal** — unchanged.

The result header shows the counts: `+added`, `-removed`, `=equal`.

## Toolbar

- **Swap** — exchanges Item 1 and Item 2.
- **Clear** — empties both sides.

## When to use it

- Compare the response to a valid request vs. one with a payload — does the injection change the output?
- Compare an authenticated vs. unauthenticated response to the same endpoint — what does auth actually gate?
- Compare two near-identical tokens or responses to find the one differing byte.
- Diff a baseline response against an error response to isolate the leaked detail.

For comparing live requests you're actively editing, use the [Repeater](page:repeater); the Comparer is for static side-by-side analysis.
