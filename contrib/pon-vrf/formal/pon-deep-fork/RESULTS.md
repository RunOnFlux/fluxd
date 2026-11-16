# pon-deep-fork

**Question.** If an old fork is judged by the work in a window after it, in place of the work of the whole chain, do nodes that hold the same blocks still hold the same tip?

**Stage reached:** written, sanity, red-first, hardened clean, guards red. Run 2026-11-16 (`eclipse-temurin:21-jre`, 12 workers), `tla2tools.jar` sha256 `ab323b79802aedc3…` ([`../../README.md`](../../README.md)), constants `Node = {1, 2, 3}`, `MaxSlot = 4`, `MaxBlock = 4`, `MaxWeight = 2`, `Depth = 1`, `Window = 2`.

Why the question exists: a chain judged by its whole work can be outweighed, months later, by a private chain whose maker pays itself every block's node rewards and turns them into more nodes ([`../../sim/deep_fork_sim.py`](../../sim/deep_fork_sim.py)). Ouroboros Genesis answers that attack by judging a deep fork on the slots just after it ([Badertscher, Gaži, Kiayias, Russell, Zikas, CCS 2018](https://par.nsf.gov/servlets/purl/10099211), Figure 7, `maxvalid-bg`).

## The world

[`../pon-chain-weight`](../pon-chain-weight/RESULTS.md)'s: a block has a parent, a slot and a weight of 1 or 2; a node mints at most one block a slot on its own tip, in a later slot; a block reaches a node only by `Receive`, once its parent is there, in any order, or never.

`ForkRule` is how a node chooses:

- **`total`**: the chain with the most weight; between equal chains, the lower tip id.
- **`local`**: `maxvalid-bg`, with weight for length. A node judges an arriving chain against the one it holds. If the two fork at most `Depth` blocks back on the held chain, the heavier wins. If deeper, the arriving chain wins only with strictly more weight in the first `Window` slots after the fork.
- **`descent`**: one rule, from the blocks alone. Start at genesis; at every block with more than one child, take the child whose best descendant chain has the most weight in the first `Window` slots after that block; between equal children, the lower id. The block reached is the tip.

## Cells

| Cell | `ForkRule` | Invariant | Wanted | Result | Distinct states |
|---|---|---|---|---|---|
| `sanity` | descent | `NoBlocks` | violation | violation | 2 |
| `local` | local | `SameBlocksSameTip` | violation | violation | 26,619 at the stop |
| `total` | total | `SameBlocksSameTip`, `OneBlockASlot` | clean | clean, queue 0, 29 s | 6,271,924 |
| `descent` | descent | `SameBlocksSameTip`, `OneBlockASlot`, `YoungForksGoToTheHeaviest` | clean | clean, queue 0, 4 min 9 s | 6,197,776 |
| `guard-switch` | descent | `NeverSwitches` | violation | violation | 81 at the stop |
| `guard-window` | descent | `AlwaysTheHeaviest` | violation | violation | 6,780 at the stop |

## The trace of `local`

```
State 2: Mint(1,1)      block 1, slot 1, weight 1        tip = <<1, 0, 0>>
State 3: Mint(2,2)      block 2, slot 1, weight 2        tip = <<1, 2, 0>>
State 4: Receive(2,1)   node 2 keeps block 2 (heavier)   known = <<{1}, {1, 2}, {}>>
State 6: Mint(1,1)      block 3 on block 1, slot 2       tip = <<3, 2, 0>>
State 7: Receive(1,2)   node 1 keeps block 3             known = <<{1, 2, 3}, {1, 2}, {}>>
State 8: Receive(2,3)   node 2 keeps block 2             known = <<{1, 2, 3}, {1, 2, 3}, {}>>
```

Chains 1–3 and 2 both weigh 2. Node 1 holds two blocks past the fork, which is deeper than `Depth`, so it judges by the window: equal, and the arriving chain needs strictly more. Node 2 holds one block past the fork, so it judges by total weight: equal, and block 3 does not have the lower id. Each keeps its own. The rule asks a different question depending on which chain a node already holds.

## The trace of `guard-window`

```
State 2: Mint(2,1)      block 1, slot 1, weight 1
State 5: Mint(1,2)      block 2 on genesis, slot 3, weight 2     tip = <<2, 1, 0>>
State 6: Receive(1,1)   node 1 leaves block 2 for block 1        tip = <<1, 1, 0>>
```

Block 2 is the heavier and is outside the two-slot window after genesis, so it counts for nothing at that fork. This is the rule doing what it is for: work added long after a fork does not decide it.

## What the cells show

- **`maxvalid-bg` as written leaves nodes with the same blocks on different tips.** It compares against the chain held and keeps the held chain on a tie.
- **A window rule that is a function of the blocks alone does not.** With `descent`, no reachable state has two nodes with the same blocks and different tips.
- **While every block is inside every fork's window, `descent` is the heaviest-chain rule** (`YoungForksGoToTheHeaviest`). A fork younger than the window is judged exactly as now.
- **Past the window the two rules part** (`guard-window`), by design.

## Abstractions

- **Weights are 1 and 2; a block's id stands for its hash.**
- **No target.** The window is of use only if both branches of a fork agree on who is eligible inside it; that is [`../pon-withhold-target`](../pon-withhold-target/RESULTS.md)'s delayed target, and its guarantee covers 61 slots, not a window of days. Past that the comparison is of work under each branch's own target.
- **No depth limit.** A running fluxd node refuses a reorganisation deeper than `MAX_REORG_LENGTH` whatever the rule; with it, nodes with the same blocks can differ under any of the three rules.
- **How long the window should be is not a question for this model.** `deep_fork_sim.py` measures it.
- **A branch built inside a window and delivered later** still wins that fork under `descent`. How likely a minority is to out-work the network over a window is the simulation's question.
- **Four blocks, four slots, three nodes.**
