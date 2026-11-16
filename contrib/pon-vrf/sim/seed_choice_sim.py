"""What an operator gains by choosing an epoch's seed.

An epoch's seed is the hash of the VRF outputs of a window of 60 blocks (GetEpochSeed). The
maker of a window block can publish it or not, and an operator with several eligible nodes
in a slot can choose which one mints, so an operator that makes the last j blocks of a window
has 2^j seeds to choose between; one that does not make the last block has no choice, since
the outputs after its own are not its to know. It makes the last j blocks and not the one
before with chance a^j (1 - a), a being its share of the live eligible nodes.

A seed fixes every node's draws for an epoch of 60 slots. Each slot the honest nodes' best
draw and the operator's best draw are the first points of two Poisson processes on [0, 1),
of rates 9.21 (1 - a) and 9.21 a. A block weighs 2 - u.

  none    the seed is whatever it is
  own     of the seeds it may choose between, the operator takes the one under which its own
          draws weigh the most over the epoch (it cannot see the others' draws)
  all     it takes the one that gives it the most chances to replace k slots' blocks: more
          than it can know, an upper bound

Counted: the operator's share of the epoch's blocks, and chances a day to replace the blocks
of k consecutive slots inside the epoch.

Run on a server: python3 seed_choice_sim.py
"""

import math
import random
from multiprocessing import Pool

LAM, LIVE, EPOCH, EPOCHS_A_DAY = 9.21, 0.89, 60, 48
KS = (3, 6, 12, 20)
SHARES = (0.052, 0.171, 0.258)


def first(rng, rate):
    u = -math.log(1.0 - rng.random()) / rate
    return u if u < 1.0 else None


def epoch(rng, a):
    """One seed: (the operator's weight, its blocks, its chances by k)."""
    h = [first(rng, LAM * (1 - a)) for _ in range(EPOCH)]
    o = [first(rng, LAM * a) for _ in range(EPOCH)]
    gh = [0.0 if x is None else 2.0 - x for x in h]
    go = [0.0 if x is None else 2.0 - x for x in o]
    blocks = sum(1 for x, y in zip(o, h) if x is not None and (y is None or x < y))
    chances = []
    for k in KS:
        c = 0
        dh = sum(gh[:k])
        do = sum(go[:k])
        if do > dh:
            c += 1
        for s in range(1, EPOCH - k + 1):
            dh += gh[s + k - 1] - gh[s - 1]
            do += go[s + k - 1] - go[s - 1]
            if do > dh + 1e-12:
                c += 1
        chances.append(c)
    return sum(go), blocks, chances


def run(args):
    f, seed, n = args
    rng = random.Random(seed)
    a = f / (LIVE * (1 - f) + f)
    tot = {m: [0, [0] * len(KS)] for m in ("none", "own", "all")}
    for _ in range(n):
        j = 0
        while rng.random() < a and j < 6:
            j += 1
        seeds = [epoch(rng, a) for _ in range(2 ** j)]
        none = seeds[0]
        own = max(seeds, key=lambda e: e[0])
        for m, e in (("none", none), ("own", own)):
            tot[m][0] += e[1]
            for i in range(len(KS)):
                tot[m][1][i] += e[2][i]
        tot["all"][0] += max(e[1] for e in seeds)
        for i in range(len(KS)):
            tot["all"][1][i] += max(e[2][i] for e in seeds)
    return f, n, tot


def main():
    per, tasks = 100000, 40
    with Pool(20) as pool:
        res = pool.map(run, [(f, 100 * i + 3, per) for f in SHARES for i in range(tasks)])
    for f in SHARES:
        n = 0
        agg = {m: [0, [0] * len(KS)] for m in ("none", "own", "all")}
        for g, m, tot in res:
            if g != f:
                continue
            n += m
            for mode in agg:
                agg[mode][0] += tot[mode][0]
                for i in range(len(KS)):
                    agg[mode][1][i] += tot[mode][1][i]
        a = f / (LIVE * (1 - f) + f)
        print(f"\nshare {100 * f:.1f}% of nodes, {100 * a:.1f}% of live; {n} epochs; it chooses the seed in {100 * a:.1f}% of them")
        for mode in ("none", "own", "all"):
            b, c = agg[mode]
            print(f"  {mode:5} blocks {100 * b / (n * EPOCH):5.2f}% of slots;  chances a day: "
                  + "  ".join(f"k={k}: {EPOCHS_A_DAY * c[i] / n:.4g}" for i, k in enumerate(KS)))


if __name__ == "__main__":
    main()
