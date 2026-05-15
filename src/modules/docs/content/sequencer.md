# Sequencer

The Sequencer analyses the **randomness quality** of tokens — session IDs, CSRF tokens, password-reset tokens, API keys. If a token is predictable, an attacker can forge it; the Sequencer is how you measure that.

Open it with <kbd>Ctrl+8</kbd>.

## Loading tokens

Paste tokens into the input panel, **one per line** — you need at least two to analyse, and many more for meaningful statistics. The header shows how many are loaded.

- **Generate Sample** drops in 20 random hex tokens so you can see how the module behaves.
- Sending a request/response here from another module auto-extracts `Set-Cookie` / `Cookie` token values.

Click **Analyze** to run the full battery.

## Summary

The headline is **Effective Entropy** — a 0–100 % score with a rating:

| Rating | Meaning |
|---|---|
| **Excellent** (>90 %) | Cryptographically strong; no usable bias. |
| **Reasonable** (>70 %) | Acceptable, minor bias. |
| **Poor** (>40 %) | Predictable patterns — investigate. |
| **Critical** (≤40 %) | Seriously weak; likely forgeable. |

Alongside it: token count, average length, unique character count, exact duplicates, and collision rate.

## Distribution

A bar chart of character frequency across all tokens, against the expected uniform line. A truly random token uses every character about equally — tall spikes or gaps mean bias.

## FIPS Tests

The four **FIPS 140-2** statistical randomness tests, each with a PASS/FAIL and the underlying figure (these run when there are more than 100 bits of hex data):

- **Monobit Test** — are there roughly equal 1s and 0s?
- **Poker Test** — are 4-bit groups evenly distributed (χ²)?
- **Runs Test** — are runs of identical bits the expected length?
- **Long Run Test** — is the longest run within bounds (≤26)?

A FAIL on any test is a strong signal the token generator is not cryptographically sound.

## Bit Analysis

Per-position entropy — how much each character position varies across all tokens. Positions that are always the same (a fixed prefix, a static segment) show low entropy (red); fully random positions show high entropy (green). This pinpoints *which part* of a token is weak.
