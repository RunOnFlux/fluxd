"""Secret draws announced at the slot's start: how often do two nodes mint for one slot?

Each slot the live eligible nodes draw u uniform in [0, 1) (the VRF output over the target).
A node may stamp its block no earlier than WAIT + SPREAD * u seconds into the slot. At the
slot's start it announces its draw; an announcement reaches another node after a network delay.
A node mints at its own time unless a block for the slot has reached it. Each better draw it
has heard puts its turn back: the best is given GRACE after its own time, the next GRACE after
that, and so on.

  no announcements   the branch as built, shifted by WAIT: a node knows only its own draw.
  announcements      as above.

The delay of a message is BASE + an exponential of mean MEAN, and with chance TAIL it is
uniform in 3 to 12 s instead. Mainnet 2026-11-15: 97.3% of 2,019 blocks connected on one node
within 1 s of their stamp, and 142 of 142 on each of two home-network nodes; peers' round
trips 38 to 182 ms.

Run: uv run --no-project claim_sim.py
"""

import math
import random

WAIT, SPREAD, GRACE, SLOT_END = 4.0, 20.0, 4.0, 29.0


def poisson(rng: random.Random, mean: float) -> int:
    limit, k, prod = math.exp(-mean), 0, rng.random()
    while prod > limit:
        k += 1
        prod *= rng.random()
    return k


def delay(rng: random.Random, base: float, mean: float, tail: float) -> float:
    if rng.random() < tail:
        return rng.uniform(3.0, 12.0)
    return base + rng.expovariate(1 / mean)


def slot(rng, lam, live, announce, base, mean, tail, skew, absent):
    """Returns the number of blocks minted for one slot."""
    k = poisson(rng, live * lam)
    if k == 0:
        return 0
    draws = sorted(rng.random() for _ in range(k))
    clock = [rng.gauss(0, skew) for _ in range(k)]            # each node's clock error
    legal = [WAIT + SPREAD * u + c for u, c in zip(draws, clock)]
    silent = [rng.random() < absent for _ in range(k)]        # announces, then never mints
    claim = [[delay(rng, base, mean, tail) + clock[j] for _ in range(k)] for j in range(k)]
    block = [[delay(rng, base, mean, tail) for _ in range(k)] for j in range(k)]
    minted: dict[int, float] = {}
    # Nodes act in the order of the time each would mint; a node's decision uses what has
    # reached it by then.
    for _ in range(k):
        best_i, best_t = None, None
        for i in range(k):
            if i in minted or silent[i]:
                continue
            t = legal[i]
            if announce:
                turn = None                                    # when the node before is overdue
                for j in range(i):                             # better draws, best first
                    if claim[j][i] <= t:
                        turn = max(legal[j], turn if turn is not None else legal[j]) + GRACE
                        t = max(t, turn)
            if best_t is None or t < best_t:
                best_i, best_t = i, t
        if best_i is None or best_t > SLOT_END:
            break
        heard_block = any(m + block[j][best_i] <= best_t for j, m in minted.items())
        if heard_block:
            silent[best_i] = True                              # stands down
        else:
            minted[best_i] = best_t
    return len(minted)


def run(label, *, slots=300_000, lam=10.0, live=0.89, announce=True, base=0.15, mean=0.25,
        tail=0.005, skew=0.5, absent=0.0, seed=5):
    rng = random.Random(seed)
    empty = multi = 0
    for _ in range(slots):
        n = slot(rng, lam, live, announce, base, mean, tail, skew, absent)
        empty += n == 0
        multi += n > 1
    print(f"{label:<58} two or more blocks {100 * multi / slots:6.3f}%   no block {100 * empty / slots:6.3f}%")


def main() -> None:
    print("-- 10 eligible a slot, 89% live, delay 0.15 s + exp(0.25 s), 0.5% of messages 3 to 12 s late")
    run("no announcements (a node knows only its own draw)", announce=False)
    run("announcements")
    print("\n-- how late messages can be")
    for tail in (0.0, 0.002, 0.01, 0.03, 0.10):
        run(f"announcements, {100 * tail:g}% of messages 3 to 12 s late", tail=tail)
    print("\n-- a slower network (delay 0.5 s + exp(0.8 s))")
    run("no announcements", announce=False, base=0.5, mean=0.8)
    run("announcements", base=0.5, mean=0.8)
    print("\n-- clocks further apart (standard deviation 1.5 s)")
    run("announcements", skew=1.5)
    print("\n-- nodes that announce and never mint")
    for absent in (0.11, 0.30):
        run(f"announcements, {100 * absent:g}% announce and stay silent", absent=absent)
    print("\n-- how many eligible a slot")
    for lam in (5.0, 7.0, 10.0, 15.0):
        run(f"announcements, {lam:g} eligible a slot", lam=lam)


if __name__ == "__main__":
    main()
