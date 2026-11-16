"""A deep private fork, judged two ways: by total work, and by the work in a window after the fork.

The public chain is minted by the honest live nodes; the private chain by an operator alone,
from the public chain's state at the fork. Both use the delayed target and the graded weight
of epoch_weight_sim.py.

  bleed     on its own chain the operator is paid every block's node rewards and turns each
            COLLATERAL FLUX into one more node
  outage    the fork is placed where 90% of the honest nodes go offline for 12 hours

For each case: the day the private chain's total work since the fork passes the public
chain's, and the private chain's work in the first W slots after the fork as a share of the
public chain's, for several W.

Run on a server: python3 deep_fork_sim.py
"""

import random
from multiprocessing import Pool

from epoch_weight_sim import DAY, LIVE, N, Chain, best_under, t_for

REWARD = 13.5            # FLUX a block to nodes: 1 + 3.5 + 9 of an initial 14 (GetFluxnodeSubsidy)
COLLATERAL = 1000        # FLUX for one more draw (V2_FLUXNODE_COLLAT_CUMULUS)
WINDOWS = (120, 2880, 7 * 2880, 14 * 2880, 30 * 2880)
DAYS = 420


def run(args):
    f, bleed, outage, seed = args
    rng = random.Random(seed)
    honest, own = N * LIVE * (1 - f), N * f
    t0 = t_for(honest + own)
    pub, prv = Chain("delayed", t0), Chain("delayed", t0)
    purse = 0.0
    crossed = None
    at = {}
    for s in range(DAYS * DAY):
        h = honest * (0.1 if outage and s < 12 * 120 else 1.0)
        pub.slot(s, best_under(rng, h, pub.t))
        if prv.slot(s, best_under(rng, own, prv.t)) and bleed:
            purse += REWARD
            while purse >= COLLATERAL:
                purse -= COLLATERAL
                own += 1
        if s + 1 in WINDOWS:
            at[s + 1] = 100 * prv.wg / pub.wg
        if crossed is None and s > DAY and prv.wg > pub.wg:
            crossed = s / DAY
    return f, bleed, outage, crossed, at, own, 100 * prv.wg / pub.wg


def main():
    tasks = [(f, b, o, 11) for f in (0.052, 0.171, 0.258) for b, o in ((False, False), (True, False), (False, True), (True, True))]
    with Pool(12) as pool:
        res = pool.map(run, tasks)
    print(f"{DAYS} days after the fork; windows in slots: " + ", ".join(str(w) for w in WINDOWS))
    for f, bleed, outage, crossed, at, own, final in res:
        name = ("bleed" if bleed else "no bleed") + (", fork at an outage" if outage else "")
        cross = f"total work passes the public chain's on day {crossed:.0f}" if crossed else f"total work never passes it ({final:.1f}% at the end)"
        print(f"  share {100 * f:4.1f}%  {name:28}  nodes at the end {own:8.0f}  {cross}")
        print("        work in the window as a share of the public chain's: " + "  ".join(f"{w}: {at[w]:6.1f}%" for w in WINDOWS))


if __name__ == "__main__":
    main()
