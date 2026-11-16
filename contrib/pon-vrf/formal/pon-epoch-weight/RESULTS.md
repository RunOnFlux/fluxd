# pon-epoch-weight

**Question.** When a block's work comes from its band and its target, and the target moves at an epoch boundary, do nodes that hold the same blocks still hold the same tip?

**Stage reached:** written, sanity, red-first, hardened clean, guards red. Run 2026-11-16 (`eclipse-temurin:21-jre`, 12 workers), `tla2tools.jar` sha256 `ab323b79802aedc3…` ([`../../README.md`](../../README.md)).

It is [`../pon-chain-weight`](../pon-chain-weight/RESULTS.md) with two things added: a target level on every block that the chain's own blocks decide, and a forger. The rules it serves are in `src/pon/`; [`../../README.md`](../../README.md) says which. What a node gains by withholding is a different question and a different model: [`../pon-withhold-target`](../pon-withhold-target/RESULTS.md).

## The world

- A block has a parent, a slot, a band (1 or 2) and a target level (0, 1 or 2; higher is looser). Its work is its band times 4, 2 or 1 by level.
- An epoch is 2 blocks. A block carries its parent's level, except the first of an epoch, which carries one level looser when the epoch before it has 2 or more poor blocks and empty slots, and one tighter when it has none.
- A node mints at most one block a slot, on its own tip, in a later slot, stamped with the rule's level.
- **The forger** makes a block on any existing block, in the current slot, with either band, at the rule's level or at a false one. Nobody holds it until it is received. This is a second block on a parent, a branch off an old block, and a false target.
- A block reaches a node only by `Receive`, once its parent is there, in any order, or never. With `CheckTarget` a block whose level is not the rule's is refused.
- A node holds the chain with the most work it knows; between equal chains, the tip with the lower id.

## Cells

| Cell | Nodes, slots, blocks | Forger | `CheckTarget` | Invariant | Wanted | Result | Distinct states |
|---|---|---|---|---|---|---|---|
| `sanity` | 2, 3, 5 | yes | yes | `NoBlocks` | violation | violation | 2 |
| `no-target-check` | 2, 3, 5 | yes | no | `HeldTargetsFollowTheRule` | violation | violation | 318 at the stop |
| `hardened` | 2, 3, 5 | yes | yes | `SameBlocksSameTip`, `HoldsTheHeaviest`, `OneBlockASlot`, `HeldTargetsFollowTheRule` | clean | clean, queue 0, 1 h 12 min | 200,446,305 |
| `guard-switch` | 2, 3, 5 | yes | yes | `NeverSwitches` | violation | violation | 181 at the stop |
| `guard-target` | 2, 3, 5 | yes | yes | `TargetNeverMoves` | violation | violation | 38,595 at the stop |
| `guard-branches` | 2, 3, 5 | yes | yes | `BranchesAgreeOnTarget` | violation | violation, 8 min 52 s | 39,167,156 at the stop |
| `three-nodes` | 3, 4, 4 | no | yes | the four of `hardened` | clean | clean, queue 0, 1 min 54 s | 6,270,388 |

`hardened` is far past the size a cell should be (10 million states, 30 minutes). It was let run because its guards need five blocks: two branches that carry different targets at one height take five.

## The trace of `no-target-check`

```
State 2: Forge(0, 1, 2)   level = <<2, 0, 0, 0, 0>>  band = <<1, 0, 0, 0, 0>>  known = <<{}, {}>>
State 3: Receive(1, 1)    tip = <<1, 0>>             known = <<{1}, {}>>
```

The first block of a chain carries level 2 where the rule gives 1, and node 1 takes it as its tip. Nothing but the check on receipt stands between a node and a block that names its own target.

## The trace of `guard-branches`

```
State 4:  Mint(1,1)       blocks 1, 2 on one chain, both poor
State 5:  Forge(1, 2, 1)  block 3 on block 1, band 2
State 8:  Mint(1,1)       block 4 on block 3: the epoch 1, 3 has one poor block, level stays 1
State 9:  Forge(2, 1, 2)  block 5 on block 2: the epoch 1, 2 has two poor blocks, level 2
State 10: Receive(1,5)    node 1 holds blocks 4 and 5, both at height 3, at levels 1 and 2
```

Two branches off one block reach the same height with different targets, each the rule's own. The clean cell's world holds this state.

## What the cells show

- **Same blocks, same tip, with work that depends on the chain behind a block.** A block's work is fixed by the block and its ancestors, so the order in which blocks arrive changes nothing: no reachable state has two nodes with the same blocks and different tips, and every node holds the heaviest chain it knows.
- **The target a block carries has to be checked against the chain it is on.** Without the check a node holds a block with a false target.
- **Branches disagree on the target**, and the rules above still hold.
- **One block a slot holds on every chain**, the forger's included.

## Abstractions

- **Epochs are counted in blocks.** The properties here rest only on a block's target being a function of its ancestors, which is as true of epochs counted in slots, with or without a delay.
- **A band does not depend on the target.** Any block may have either band at any level; eligibility is not modelled. That link is `pon-withhold-target`.
- **Two bands, three levels, a factor of two between levels.**
- **A block's id stands for its hash.**
- **The forger tries one false level beside the right one**, not both.
- **No clock bound, no depth limit.** The first is `pon-slot-stall`.
- **Five blocks, three slots, two nodes; four blocks, four slots, three nodes without the forger.**
