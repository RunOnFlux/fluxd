# pon-withhold-target

**Question.** When the target moves by the chain's own draws, can a node whose draws are never better than the honest nodes' get them to leave their chain for its own, by withholding blocks, building a branch in private and releasing it?

**Stage reached:** written, sanity, red-first, hardened clean, guards red, mutated (the delay removed, the weight changed, the epoch counted in blocks). Run 2026-11-16 (`eclipse-temurin:21-jre`, 12 workers), `tla2tools.jar` sha256 `ab323b79802aedc3…` ([`../../README.md`](../../README.md)), all 32 cells in one run.

The rules this serves are in `src/pon/`; [`../../README.md`](../../README.md) says which. How often a luckier branch wins is not a question for a model; [`../../sim/epoch_weight_sim.py`](../../sim/epoch_weight_sim.py) measures it.

## The world

- **Draws.** Each slot the world gives the honest nodes one draw (their best) and the adversary one draw (its best), or none. A draw is an output y; it is eligible under a target T when y < T, and its band is 8 − ⌊8y / T⌋. Targets are 8, 16 and 32; a chain starts at 16.
- **The honest chain.** Each slot the honest draw mints on it when it is eligible and the tip is in an earlier slot. This is a duty: the slot does not end until it is done.
- **The adversary** may publish its draw on the honest chain in its turn (a better draw goes first), fork a private branch off the honest chain, extend it with its draw, release it, or abandon it. A block of the current slot is not released ahead of a better honest draw. The honest nodes move to a released branch that is heavier and covers no more than `MaxDepth` slots.
- **The target** moves one level when an epoch closes: looser when 4 times the epoch's mean winning output (an empty slot counted as the target) is half as much again as the target, tighter when it is 0.7 of it.

The toggles:

| | |
|---|---|
| `EpochBy` | `blocks`: an epoch is 3 blocks of the chain. `slots`: 3 slots, the same slots on every chain |
| `Delay` | with epochs in slots: an epoch's target is moved by the epoch before the last, not by the last |
| `WorkRule` | `band`: the band. `bandOverTarget`: the band times 32 / T. `flatOverTarget`: 8 more than the band, times 32 / T. `gradedOverTarget`: (2T − y) × 1024 / T², which is (2 − y/T) / T with no rounding: the design's rule |
| `Emergency` | a block signed by the emergency key may fill a slot of the honest chain that the honest draw cannot. It has the work of the best draw and counts in the epoch's sum as an empty slot |
| `TieRule` | `hash`: between equal chains the adversary wins, as it would by remaking its block until its hash is the lower. `output`: the lower tip output wins |
| `Dominated` | `draws`: every slot the adversary's draw is absent or worse than the honest draw. `slots`: that, and the honest draw is eligible on the honest chain in every slot. `no`: any draws |

Three sizes of constants, all with `EpochLen = 3` and `MaxDepth = 4`: **L** is 10 slots with draws {1, 15, 20}; **M** is 7 slots with {1, 4, 15, 20}; **F** is 7 slots with {1, 4, 5, 15, 20}; **S** is 5 slots with {1, 4, 15, 20}.

## Cells

Every cell but the guards checks `HonestNeverLeave` unless another invariant is named.

| Cell | Size | Epochs | Work | Dominated | Wanted | Result | Distinct states |
|---|---|---|---|---|---|---|---|
| `sanity` (`NoBlocks`) | L | slots, delayed | band / T | slots | violation | violation | 11 |
| `fixed-hash` | F | target fixed | band, tie to the hash | draws | violation | violation | 2,990 at the stop |
| `fixed-output` | F | target fixed | band | draws | clean | clean, queue 0 | 21,787,973 |
| `fixed-output-guard` (`BranchNeverAhead`) | F | target fixed | band | draws | violation | violation | 1,436 at the stop |
| `blocks-bot-slots` | M | blocks | band / T | slots | violation | violation | 30,942 at the stop |
| `blocks-flat-draws` | M | blocks | flat / T | draws | violation | violation | 438,252 at the stop |
| `blocks-flat-slots` | M | blocks | flat / T | slots | — | clean, queue 0 | 4,176,653 |
| `slots-band-slots` | L | slots | band | slots | violation | violation | 5,214 at the stop |
| `slots-band-draws` | L | slots | band | draws | violation | violation | 27,663 at the stop |
| `slots-bot-slots` | L | slots | band / T | slots | violation | violation | 74,120 at the stop |
| `slots-bot-draws` | L | slots | band / T | draws | violation | violation | 8,520,640 at the stop |
| `slots-flat-slots` | L | slots | flat / T | slots | — | clean, queue 0 | 12,671,601 |
| `slots-flat-draws` | L | slots | flat / T | draws | violation | violation | 451,716 at the stop |
| `slots-graded-slots` | L | slots | graded / T | slots | — | clean, queue 0 | 12,678,339 |
| `slots-graded-draws` | L | slots | graded / T | draws | violation | violation | 474,725 at the stop |
| `delayed-band-slots` | L | slots, delayed | band | slots | clean | clean, queue 0 | 2,990,616 |
| `delayed-bot-slots` | L | slots, delayed | band / T | slots | clean | clean, queue 0 | 3,016,176 |
| `delayed-flat-slots` | L | slots, delayed | flat / T | slots | clean | clean, queue 0 | 3,016,176 |
| `delayed-graded-slots` | L | slots, delayed | graded / T | slots | clean | clean, queue 0 | 3,016,176 |
| `delayed-band-draws` | L | slots, delayed | band | draws | clean | clean, queue 0 | 30,409,070 |
| `delayed-bot-draws` | L | slots, delayed | band / T | draws | clean | clean, queue 0 | 30,512,607 |
| `delayed-flat-draws` | L | slots, delayed | flat / T | draws | clean | clean, queue 0 | 30,532,662 |
| `delayed-graded-draws` | L | slots, delayed | graded / T | draws | clean | clean, queue 0 | 30,530,007 |
| `delayed-graded-draws-emergency` | L | slots, delayed, emergency blocks | graded / T | draws | clean | clean, queue 0, 24 min 57 s | 183,047,434 |
| `guard-NeverForks` | L | slots, delayed | band / T | slots | violation | violation | 35 at the stop |
| `guard-TargetNeverLoosens` | L | slots, delayed | band / T | slots | violation | violation | 17,803 at the stop |
| `guard-TargetNeverTightens` | L | slots, delayed | band / T | slots | violation | violation | 13,761 at the stop |
| `guard-BranchNeverAhead` | L | slots, delayed | band / T | slots | violation | violation | 446 at the stop |
| `guard-NoEmergencyBlock` | L | slots, delayed, emergency blocks | graded / T | draws | violation | violation | 216 at the stop |
| `slots-same-target` (`BranchCarriesTheSameTarget`) | S | slots | band / T | no | violation | violation | 50,283 at the stop |
| `delayed-same-target` (`BranchCarriesTheSameTarget`) | S | slots, delayed | band / T | no | clean | clean, queue 0 | 6,617,384 |
| `free-switch` | L | slots, delayed | band / T | no | violation | violation | 2,635 at the stop |

Ties go to the lower output in every cell but `fixed-hash`. The `draws` cells are past the size a cell should be (10 million states); each ran in under five minutes but the one with emergency blocks.

## The traces

Each line is a slot: the honest draw, the adversary's draw, and what was minted. Work is in the cell's own units.

**`fixed-hash`: a tie that goes to the lower hash goes to whoever remakes its block.**

```
slot 1   honest 4, adversary 5   the adversary forks before the slot's block and mints 5 in private (band 6)
                                 the honest draw mints 4 (band 6)
                                 the two chains are equal; the adversary releases, and the honest nodes move
```

A worse draw in the same band replaces the better one. With the lower output winning the tie (`fixed-output`) no such state exists, and the branch does draw level (`fixed-output-guard`).

**`blocks-bot-slots`: a shorter branch stays in the old epoch.**

```
slot 1   honest 4                mints, T = 16
slot 2   honest 1                mints, T = 16
slot 3   honest 15, adversary 20 the adversary forks before the slot's block
                                 the honest draw mints 15 (band 1, work 2); the honest chain's third block
                                 closes its epoch (4, 1, 15) and its target loosens to 32
slot 4   honest 1, adversary 4   the adversary mints 4 on its branch: its third block, still at T = 16,
                                 band 6, work 12
                                 the honest draw mints 1 at T = 32: band 8, work 8
                                 private 12 against 2 + 8; the honest nodes move
```

The adversary's draw is the worse one in both slots. Its branch is a block behind, so it is still in the epoch the honest chain has left, at the tighter target, where a block weighs twice as much.

**`slots-bot-slots`: a branch loosens its own target by leaving a slot empty.**

```
slots 1, 2   honest 1, 1         mint, T = 16
slot 3   honest 15, adversary 20 the adversary forks before the slot's block; the honest draw mints 15 (work 2)
                                 the epoch closes: the honest chain's sum is 1 + 1 + 15 and its target holds at 16;
                                 the branch's is 1 + 1 + 16 (the empty slot) and its target loosens to 32
slots 4–6 honest 15, adversary 20  the honest draw mints at T = 16: band 1, work 2, three times
                                 the adversary mints 20 at T = 32: band 3, work 3, three times
                                 private 9 against 2 + 6; the honest nodes move
```

A draw of 20 outweighs a draw of 15 because each is graded against its own chain's target, and eight bands fall from 8 to 1 faster than the looser target takes away.

**`slots-flat-draws`: the same, through eligibility.**

```
slots 1–3  honest 1, 1, 1        mint; the adversary forks before slot 3's block
                                 the honest chain's epoch sum is 3 and its target tightens to 8;
                                 the branch's is 1 + 1 + 16 and its target loosens to 32
slots 4–6  honest 15, adversary 20  15 is not eligible under 8: the honest chain mints nothing
                                 20 is eligible under 32: the adversary mints three blocks
                                 the honest nodes move
```

With a flatter weight the last trace's trade no longer pays (`slots-flat-slots`, clean), and what is left is a branch that mints where the honest chain cannot.

## What the cells show

- **Under one target, with a tie settled by the lower output, a node that is never luckier never wins** (`fixed-output`).
- **A tie settled by the lower block hash is the adversary's** (`fixed-hash`).
- **A target that a branch sets for itself inside the reorganisation depth breaks that**, whichever way the epoch is counted and under every weight tried, except the flat and the graded weights under the stricter condition (`blocks-…`, `slots-…`).
- **Counting the epoch in slots and moving the target by the epoch before the last closes it.** A branch then carries the honest chain's target for as long as it is within `MaxDepth` slots of its fork (`delayed-same-target`), and under all four weights and both conditions no reachable state has the honest nodes leaving (`delayed-…`), with emergency blocks filling slots or without. The same constants with the delay removed are red.
- **The clean cells' world is not idle:** a branch forms, draws level with the honest chain inside the depth, and the target both loosens and tightens (`guard-…`). With any draws allowed, a luckier branch wins (`free-switch`).

## Abstractions

- **The target has three levels a factor of two apart and moves a whole level at a time.** The rule it stands for moves a quarter of the way an epoch. The model's target is the easier one to push.
- **The honest nodes are one party with one chain and one draw a slot.** Delivery among them is not modelled; that is [`../pon-chain-weight`](../pon-chain-weight/RESULTS.md) and [`../pon-epoch-weight`](../pon-epoch-weight/RESULTS.md).
- **One private branch at a time**, forked from the honest tip. A branch off an older block is a branch forked then and kept; several at once are not modelled.
- **The adversary's draw for a slot is the same on both chains.** Past an epoch boundary the two chains have different seeds and so different draws.
- **`MaxDepth` is in slots**, where `MAX_REORG_LENGTH` is 40 blocks. With a 60-slot epoch the delay holds the two targets equal for at least 61 slots after a fork; 40 blocks span more only when 22 or more of those slots are empty.
- **`hash` gives every tie to the adversary.**
- **An emergency block is minted or not as the checker chooses**, only where the honest draw cannot mint, and never on the private branch.
- **What a branch does past `MaxDepth` is not shown.** With the depth lifted and the delay on, a 9-slot run of 22,409,039 states found no winning branch; the same run without the delay found none either, so those constants could not have shown one.
- **Ten slots, three or four epochs, three to five draw values.**
