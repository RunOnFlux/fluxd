# pon-chain-weight

**Question.** When the heavier chain wins, do nodes that hold the same blocks hold the same tip?

**Stage reached:** written, sanity, red-first, hardened clean, guards red. Run 2026-11-15 (`eclipse-temurin:21-jre`, 12 workers), `tla2tools.jar` sha256 `ab323b79802aedc3…` ([`../../README.md`](../../README.md)), constants `Node = {1, 2, 3}`, `MaxSlot = 4`, `MaxBlock = 4`, `MaxWeight = 2`.

The rules this serves are in `src/pon/`; [`../../README.md`](../../README.md) says which.

## The world

- A block has a parent, a slot and a weight of 1 or 2.
- A node mints at most one block a slot, on its own tip, in a later slot than that tip.
- A block reaches another node only by `Receive`, one block at a time, once its parent is there, in any order, or never. A node that keeps a branch to itself and a network split are both TLC declining to deliver.
- A node holds the heaviest chain it knows. `TieRule` settles equal weights: `"held"` keeps the chain it has, `"id"` takes the tip with the lower id, as a lower block hash would be.

## Cells

| Cell | `TieRule` | Invariant | Wanted | Result | Distinct states |
|---|---|---|---|---|---|
| `sanity` | held | `NoBlocks` | violation | violation | 2 |
| `tie-held` | held | `SameBlocksSameTip` | violation | violation | 513 at the stop |
| `hardened` | id | `SameBlocksSameTip`, `HoldsTheHeaviest`, `OneBlockASlot` | clean | clean, queue 0, 58 s | 6,271,924 |
| `guard-switch` | id | `NeverSwitches` | violation | violation | 70 at the stop |
| `guard-fork` | id | `NoFork` | violation | violation | 27 at the stop |
| `guard-agree` | id | `NeverAgreeOnThree` | violation | violation | 22,277 at the stop |
| `late-branch` | id | `LateBranchNeverWins` | violation | violation | 7,271 at the stop |

## The trace of `tie-held`

```
State 2: Mint(1,1)      tip = <<1, 0, 0>>  known = <<{1}, {}, {}>>
State 3: Mint(3,1)      tip = <<1, 0, 2>>  known = <<{1}, {}, {2}>>
State 4: Receive(1,2)   tip = <<1, 0, 2>>  known = <<{1, 2}, {}, {2}>>
State 5: Receive(3,1)   tip = <<1, 0, 2>>  known = <<{1, 2}, {}, {1, 2}>>
```

Nodes 1 and 3 each mint a block of weight 1 in the same slot. Each receives the other's, finds the weights equal, and keeps its own. They hold the same two blocks and different tips, and nothing they hold will ever move either.

## What the cells show

- **A tie has to be settled the same way on every node.** With the lower id winning, no reachable state has two nodes with the same blocks and different tips, and every node holds the heaviest chain it knows.
- **One block a slot holds on every chain**, by the slot rule on minting.
- **The rule does not keep a late branch out** (`late-branch`): a node leaves its tip for a branch whose tip is two or more slots old and which it did not mint. A heavier branch wins whenever it arrives. The weights make one rare (`reorg_sim.py`); `MAX_REORG_LENGTH` bounds its depth.
- The clean cell's world forks (`guard-fork`), reorganises (`guard-switch`) and reaches a block in slot 3 that all three nodes hold as tip (`guard-agree`).

## Abstractions

- **Weights are 1 and 2.** The design's are eight values from a 256-bit output, where a tie is rarer; the tie rule is the same.
- **A block's id stands for its hash:** lower id, lower hash. Ids are given in the order blocks are made, which a hash is not; the rule needs only that all nodes order two tips alike.
- **Any node may mint in any slot, at either weight.** Eligibility, the claim and the turn are not modelled.
- **No clock bound, no depth limit, no node that mints two blocks in one slot.** The first is `pon-slot-stall`.
- **Four blocks, four slots, three nodes.**
