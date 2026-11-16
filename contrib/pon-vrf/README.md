# PoN-VRF: models and simulations of how nodes take turns to mint

What the slot rules of `UPGRADE_PON_VRF` rest on, beside their gtests: TLA+ models that
search every interleaving of a small world for a state a rule is meant to exclude, and
simulations that measure how often things happen at mainnet's size. Neither is built or
run by any build target.

A model shows that a rule holds in the model, at its bounds, under the abstractions its
`RESULTS.md` lists. It says nothing of the code: the gtests in `src/gtest/test_pon.cpp` are
what tie the code to the rule, and the target, the work of a block and the turn are checked
there against values worked by `sim/epoch_weight_sim.py`'s own functions.

## The rules, and what serves each

| Rule (`src/pon/`) | Model | Simulation |
|---|---|---|
| One block a slot (`IsLaterSlotThan`); a block not stamped ahead of the clock (`IsStampedAheadOfClock`) | `formal/pon-slot-stall` | |
| The tie between equal chains (`IsWorseBlockIndex`, `ComparePonForkChoice`) | `formal/pon-chain-weight`, `formal/pon-withhold-target` (`fixed-hash`) | |
| The target moved by the winning draws of the epoch before the last (`GetPonVrfBits`, `PonVrfNextTarget`) | `formal/pon-withhold-target`, `formal/pon-epoch-weight` | `sim/epoch_weight_sim.py` (`target`, `nudge`, `first`, `emergency`, `raise`) |
| The work of a block (`PonVrfBlockWork`) | `formal/pon-epoch-weight`, `formal/pon-withhold-target` | `sim/epoch_weight_sim.py` (`long`, `reorg`, `shock`), `sim/reorg_sim.py` |
| The claim and the turn (`AcceptPonClaim`, `PonVrfMintSecond`, `PonVrfTurnSeconds`) | | `sim/claim_sim.py` |
| The epoch seed from the window's VRF outputs (`GetEpochSeed`) | | `sim/seed_choice_sim.py` |
| A chain shown to a node that is syncing: not addressed by these rules | `formal/pon-deep-fork` | `sim/deep_fork_sim.py` |

## Running a model

Each model directory holds one `.tla`, one `.cfg` a cell, and `RESULTS.md`: the question, the
world, every cell with its constants and state count, the traces of the cells that must
fail, and the abstractions.

```sh
contrib/pon-vrf/run-tlc.sh <model directory> <cell> [<cell> ...]
```

It needs Java 21 and `tla2tools.jar` in the model directory or named by `TLA2TOOLS`. The
results were produced with the build whose sha256 is
`ab323b79802aedc3203b3f9af37c6aca3ed43f4e0225b36f2aa77b26de46c05f`; the checker's prerelease
tag republishes its asset, so another build may count states differently. A cell that is
meant to fail exits non-zero with its trace; a clean cell ends
`Model checking completed. No error has been found.` with no states left on its queue. The
largest cells take 25 minutes to over an hour on twelve cores and tens of gigabytes of disk.

## Running a simulation

```sh
python3 contrib/pon-vrf/sim/epoch_weight_sim.py [part ...]
```

Python 3 with the standard library only. `epoch_weight_sim.py` keeps outputs and targets as
256-bit integers and applies the rule's own arithmetic; `deep_fork_sim.py` imports it. The
longer parts use twenty processes for some minutes.
