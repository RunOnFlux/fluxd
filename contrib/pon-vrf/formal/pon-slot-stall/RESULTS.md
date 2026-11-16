# pon-slot-stall

**Question.** Can one block leave every honest node unable to mint a valid block, and for how long?

**Stage reached:** written, sanity, red-first, hardened clean, guards red, each rule removed in turn. Run 2026-11-15, `tla2tools.jar` sha256 `ab323b79802aedc3…` ([`../../README.md`](../../README.md)), constants `MaxSlot = 14`, `MaxHeight = 6`, `MaxAhead = 11`.

The rules this serves are in `src/pon/`; [`../../README.md`](../../README.md) says which.

## The world

- Honest nodes share one tip and stamp a block with the current slot.
- One other node stamps any slot, from the present one to `MaxAhead` slots on.
- A receiver takes a block whose slot is at most `Drift` slots ahead of its clock; a block further ahead may be taken later, when the clock reaches it, if it still extends the tip (`TakeHeld`, which TLC need not take: a refused block that is never offered again is the same run).
- A block follows its parent: in a later slot with `SlotRule`, in the same slot or later without it.
- `stalled` counts the consecutive slots at whose start no honest block could be valid on the tip.

fluxd as built: `Drift = 10` (`CheckBlockHeader`, 300 s for a PoN block) and no slot rule (`ContextualCheckBlockHeader` requires only a later time than the parent's).

## Cells

| Cell | `Drift` | `SlotRule` | Invariant | Wanted | Result | Distinct states |
|---|---|---|---|---|---|---|
| `sanity` | 10 | no | `NoBlocks` | violation | violation | 2 |
| `built` | 10 | no | `StallBounded` (1) | violation | violation | 335 at the stop |
| `built-shared` | 10 | no | `OneBlockASlot` | violation | violation | 18 at the stop |
| `slot-rule-only` | 10 | yes | `StallBounded` (1) | violation | violation | 150 at the stop |
| `time-bound-only` | 0 | no | `OneBlockASlot` | violation | violation | 41 at the stop |
| `time-bound-only-stall` | 0 | no | `StallBounded` (0) | clean | clean, queue 0 | 65,230 |
| `hardened` | 0 | yes | `StallBounded` (0), `OneBlockASlot` | clean | clean, queue 0 | 26,520 |
| `guard-full` | 0 | yes | `ChainNeverFull` | violation | violation | 3,915 at the stop |
| `guard-held` | 0 | yes | `NothingHeld` | violation | violation | 4 |
| `guard-held-taken` | 0 | yes | `HeldNeverTaken` | violation | violation | 75 at the stop |

## The trace of `built`

```
State 1: Init        now = 1  tipSlot = 0  height = 0  stalled = 0
State 2: OtherMint   now = 1  tipSlot = 4  height = 1  stalled = 0
State 3: Tick        now = 2  tipSlot = 4  height = 1  stalled = 1
State 4: Tick        now = 3  tipSlot = 4  height = 1  stalled = 2
```

One node stamps its block three slots ahead and every receiver takes it. An honest block is stamped with the present slot, which is earlier than its parent's, so none is valid until the clock reaches slot 4. With `Drift = 10` the same run stalls for ten slots. This is the mainnet event: in blocks 3,108,599 to 3,128,598 nine blocks stamped about 300 s after their parent, all from the collateral `638d9da904…:0`, and four stamped 120 s after, all from `c861997076…:0`, each followed by the next block 9 s later in the same slot.

`slot-rule-only` gives the same trace: the slot rule does nothing about a block from the future.

## What the cells show

- **The clock bound is what ends the stall.** With `Drift = 0` no reachable state has a slot in which honest nodes cannot mint, with the slot rule or without it.
- **The slot rule is what makes one block a slot hold.** With the clock bound alone two blocks share a slot (`time-bound-only`).
- **Neither rule stops the chain.** On the hardened constants the chain fills (`guard-full`), a block from the future is received (`guard-held`) and is taken once its slot arrives (`guard-held-taken`).

## Abstractions

- **Time is whole slots.** A tolerance of a few seconds inside a slot is `Drift = 0` here: the model does not show a block stamped seconds ahead at a slot boundary. That case is arithmetic: a block at most T seconds ahead bars honest blocks for at most T seconds.
- **Honest nodes share one tip.** Forks between honest nodes, late delivery and fork choice are not modelled. The stall needs none of them.
- **Honest clocks agree.** A slow or fast honest clock is the other node's move.
- **Eligibility is free.** Any node may mint in any slot; the model asks what can be valid, not how often.
- **The target is not modelled.**
