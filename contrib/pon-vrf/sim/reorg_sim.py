"""How often can an operator replace the last k blocks, under different ways of weighing chains?

Each slot a Poisson number of nodes (mean LAM) is eligible, each with a draw u uniform in
[0, 1) (its VRF output over the target). A node belongs to the operator with chance f; an
honest node is live with chance 0.89, the operator's always. The operator withholds every
block and builds a private chain from its own best draw in each slot; the public chain gets
the best live honest draw. The count is of spans in which the private chain would win, as
opportunities a day (2880 slots).

  as built     more blocks wins; with equal blocks the chain whose tip has the lower draw wins
               (CBlockIndexWorkComparator, ComparePonForkChoice).
  weighted     a block of draw u has the weight given; the heavier chain wins, and a tie
               stays with the chain already held.

Run: uv run --no-project reorg_sim.py
"""

import math
import random

LAM, LIVE, DAY = 10.0, 0.89, 2880
WEIGHTS = {
    "6 - 5u": lambda u: 6 - 5 * u,
    "2 - u": lambda u: 2 - u,
    "8 steps": lambda u: 8 - int(8 * u),
    "1/(u + 0.05)": lambda u: 1 / (u + 0.05),
    # the draw in absolute terms, in bits: a block by one of N nodes under a target of
    # LAM / N of the range weighs log2(N / LAM) more than its draw's own bits
    "bits of the draw": lambda u: math.log2(6956 / LAM) - math.log2(max(u, 2 ** -24)),
}


def poisson(rng, mean):
    limit, k, prod = math.exp(-mean), 0, rng.random()
    while prod > limit:
        k += 1
        prod *= rng.random()
    return k


def span(rng, f, k):
    priv, pub = [], []
    for _ in range(k):
        a = b = None
        for _ in range(poisson(rng, LAM)):
            u = rng.random()
            if rng.random() < f:
                a = u if a is None else min(a, u)
            elif rng.random() < LIVE:
                b = u if b is None else min(b, u)
        priv.append(a)
        pub.append(b)
    return priv, pub


def main():
    rng = random.Random(3)
    trials = 300_000
    names = list(WEIGHTS)
    print(f"{'share':>6} {'depth':>5} {'as built':>9} " + " ".join(f"{n:>13}" for n in names))
    for f in (0.052, 0.171, 0.258):
        for k in (3, 6, 12, 20, 40):
            tip = 0
            wins = dict.fromkeys(names, 0)
            for _ in range(trials):
                priv, pub = span(rng, f, k)
                nb = sum(x is not None for x in priv)
                mb = sum(x is not None for x in pub)
                lp = next((x for x in reversed(priv) if x is not None), 2)
                lq = next((x for x in reversed(pub) if x is not None), 2)
                tip += nb > mb or (nb == mb and nb > 0 and lp < lq)
                for n, w in WEIGHTS.items():
                    wins[n] += sum(w(x) for x in priv if x is not None) > sum(w(x) for x in pub if x is not None)
            fmt = lambda c: f"{DAY * c / trials:.3g}" if c else f"<{DAY / trials:.2g}"
            print(f"{100 * f:>5.1f}% {k:>5} {fmt(tip):>9} " + " ".join(f"{fmt(wins[n]):>13}" for n in names), flush=True)


if __name__ == "__main__":
    main()
