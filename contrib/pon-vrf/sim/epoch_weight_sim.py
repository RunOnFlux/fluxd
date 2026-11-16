"""The target moved by the winning draws, and a block's work, in the integer arithmetic of the rule.

Outputs and targets are 256-bit integers. A slot has a Poisson number of live eligible nodes;
the best output mints. An empty slot counts as an output equal to the target.

  target      T' = min(2T, (3T + 921 * sum / (100 * slots)) / 4), then rounded as nBits rounds it.
              sum is the epoch's winning outputs with each empty slot as T. All divisions floor.
  epochs      "blocks": 60 blocks of the chain.  "slots": 60 slots, the same on every chain.
              "delayed": slots, and sum is that of the epoch before the one that just ended.
  work        band     8 - min(7, y / (T / 8 + 1))                      (target fixed)
              band/T   band * P(T)             P(T) = (2^256 - 1) / ((T >> 32) + 1)
              (2-u)/T  ((2T - y) << 16) / T * P(T)

Parts:
  target   steady state and outages, per epoch rule
  nudge    the public target when an operator withholds every block
  long     an operator minting alone for 10 days from the public chain's target
  reorg    opportunities a day for an operator to replace the last k slots' blocks, forking at
           every slot; honest nodes live 89% of the time, the operator's always
  shock    the same in the 6 hours after 90% of all nodes go offline, the operator's too
  first    the day after activation, the target starting from the confirmed-node count
  emergency  every node offline for 6 hours with an emergency block in every slot (its slot
           counts as empty), then all back; and 6 nodes left of 6,956
  raise    an operator alone for 10 days that mints only draws under a share x of its target,
           to hold its own target tight

Run on a server: python3 epoch_weight_sim.py [part ...]
"""

import math
import random
import sys
from multiprocessing import Pool

MAX = (1 << 256) - 1
N, LIVE, EPOCH, DAY = 6956, 0.89, 60, 2880
LAM_X100 = 921
KS = (1, 2, 3, 6, 12, 20, 40)
SHARES = (0.052, 0.171, 0.258)


def compact(t):
    """The value nBits holds for t: three bytes of mantissa, as arith_uint256::GetCompact."""
    size = (t.bit_length() + 7) // 8
    if size <= 3:
        return t
    mant = t >> (8 * (size - 3))
    if mant & 0x800000:
        mant >>= 8
        size += 1
    return mant << (8 * (size - 3))


def next_target(t, total, slots):
    return compact(min(MAX, 2 * t, (3 * t + LAM_X100 * total // (100 * slots)) // 4))


def proof(t):
    return MAX // ((t >> 32) + 1)


def band(y, t):
    return 8 - min(7, y // (t // 8 + 1))


def graded(y, t):
    return ((2 * t - y) << 16) // t


def poisson(rng, mean):
    if mean > 60:
        return max(0, round(rng.gauss(mean, math.sqrt(mean))))
    limit, k, prod = math.exp(-mean), 0, rng.random()
    while prod > limit:
        k += 1
        prod *= rng.random()
    return k


def best_under(rng, nodes, cap):
    """The lowest output under cap among `nodes` nodes, or None."""
    k = poisson(rng, nodes * cap / MAX)
    if not k:
        return None
    return min(rng.randrange(cap) for _ in range(min(k, 400)))


class Chain:
    """A chain's target state. mode is "blocks", "slots", "delayed" or "fixed"."""
    __slots__ = ("mode", "t", "es", "en", "eb", "gap", "pe", "wb", "wg", "nb")

    def __init__(self, mode, t):
        self.mode, self.t = mode, t
        self.es = self.en = self.eb = self.gap = 0
        self.pe = t * 100 * EPOCH // LAM_X100          # the sum that leaves t where it is
        self.wb = self.wg = self.nb = 0

    def copy(self):
        c = Chain(self.mode, self.t)
        c.es, c.en, c.eb, c.gap, c.pe = self.es, self.en, self.eb, self.gap, self.pe
        return c

    def slot(self, s, y):
        """Slot s with best output y (or None). Returns True when a block is minted."""
        by_slots = self.mode in ("slots", "delayed")
        if by_slots and s % EPOCH == 0 and s:
            self.t = next_target(self.t, self.pe if self.mode == "delayed" else self.es, EPOCH)
            self.pe, self.es = self.es, 0
        t = self.t
        if y is None or y >= t:
            if by_slots:
                self.es += t
            else:
                self.gap += 1
            return False
        self.nb += 1
        if self.mode == "fixed":
            self.wb += band(y, t)
            self.wg += graded(y, t)
            return True
        p = proof(t)
        self.wb += band(y, t) * p
        self.wg += graded(y, t) * p
        if by_slots:
            self.es += y
        else:
            self.es += y + self.gap * t
            self.en += self.gap + 1
            self.gap = 0
            self.eb += 1
            if self.eb == EPOCH:
                self.t = next_target(t, self.es, self.en)
                self.es = self.en = self.eb = 0
        return True


def t_for(nodes_live):
    return compact(min(MAX, MAX * LAM_X100 // (100 * int(nodes_live))))


# ---------------------------------------------------------------- target

def target_run(args):
    mode, live_at, days, seed = args
    rng = random.Random(seed)
    c = Chain(mode, t_for(live_at(0)))
    out = []
    for s in range(days * DAY):
        live = live_at(s)
        y = best_under(rng, live, min(MAX, c.t))
        minted = c.slot(s, y)
        out.append((minted, live * c.t / MAX))
    return out


def summarise(out, lo, hi):
    w = out[lo:hi]
    empty = 100 * (1 - sum(m for m, _ in w) / len(w))
    lam = sorted(l for _, l in w)
    return f"empty {empty:6.2f}%  live eligible: min {lam[0]:6.2f} median {lam[len(lam) // 2]:6.2f} max {lam[-1]:7.2f}"


def back_in_band(out, start, lo=6.0, hi=14.0):
    for i in range(start, len(out) - 240):
        if all(lo <= l <= hi for _, l in out[i:i + 240:20]):
            return round((i - start) / 120, 1)
    return None


def steady(s):
    return int(N * LIVE)


def outage(share):
    t0, t1 = 5 * DAY, 5 * DAY + 12 * 120
    return lambda s: int(N * LIVE * ((1 - share) if t0 <= s < t1 else 1))


def doubled(s):
    return int(N * LIVE * (2 if s >= 5 * DAY else 1))


def part_target():
    t0, t1 = 5 * DAY, 5 * DAY + 12 * 120
    for mode in ("blocks", "slots", "delayed"):
        print(f"\n== target, epochs in {mode}")
        o = target_run((mode, steady, 30, 1))
        print("  steady, 30 days            " + summarise(o, DAY, len(o)))
        for share in (0.5, 0.9, 0.99):
            o = target_run((mode, outage(share), 12, 1))
            print(f"  {int(100 * share)}% offline: first hour    " + summarise(o, t0, t0 + 120))
            print("      hours 1 to 6           " + summarise(o, t0 + 120, t0 + 720))
            print("      the day after return   " + summarise(o, t1, t1 + DAY))
            print(f"      back between 6 and 14: {back_in_band(o, t0)} h after it starts, {back_in_band(o, t1)} h after it ends")
        o = target_run((mode, doubled, 12, 1))
        print("  node count doubles, day after " + summarise(o, 5 * DAY, 6 * DAY))
        print(f"      back between 6 and 14: {back_in_band(o, 5 * DAY)} h after")


# ---------------------------------------------------------------- nudge

def nudge_run(args):
    mode, f, withhold, seed = args
    rng = random.Random(seed)
    honest, own = N * LIVE * (1 - f), N * f
    c = Chain(mode, t_for(honest + own))
    tot, n = 0.0, 0
    for s in range(30 * DAY):
        y = best_under(rng, honest if withhold else honest + own, c.t)
        c.slot(s, y)
        if s >= DAY:
            tot += c.t / MAX
            n += 1
    return mode, f, withhold, tot / n


def part_nudge(pool):
    print("\n== nudge: the public target, mean over 29 days, an operator withholding every block against minting")
    res = pool.map(nudge_run, [(m, f, w, 5) for m in ("blocks", "slots", "delayed") for f in SHARES for w in (False, True)])
    for m in ("blocks", "slots", "delayed"):
        for f in SHARES:
            a = next(r[3] for r in res if r[:3] == (m, f, False))
            b = next(r[3] for r in res if r[:3] == (m, f, True))
            print(f"  {m:7} share {100 * f:4.1f}%: target {100 * (b / a - 1):+5.1f}% looser; the operator's nodes are {100 * f / (LIVE * (1 - f) + f):4.1f}% of live nodes")


# ---------------------------------------------------------------- long

def long_run(args):
    mode, f, seed = args
    rng = random.Random(seed)
    honest, own = N * LIVE * (1 - f), N * f
    t0 = t_for(honest + own)
    pub, prv = Chain(mode, t0), Chain(mode, t0)
    pb = vb = 0                         # band alone
    tmax = t0
    for s in range(10 * DAY):
        y = best_under(rng, honest, pub.t)
        t = pub.t
        if pub.slot(s, y):
            pb += band(y, t)
        y = best_under(rng, own, prv.t)
        t = prv.t
        if prv.slot(s, y):
            vb += band(y, t)
        tmax = max(tmax, prv.t)
    return (mode, f, prv.nb, pub.nb, tmax / t0, 100 * vb / pb, 100 * prv.wb / pub.wb, 100 * prv.wg / pub.wg)


def part_long(pool):
    print("\n== long: an operator alone for 10 days; its chain's weight as a share of the public chain's")
    for r in pool.map(long_run, [(m, f, 9) for m in ("blocks", "slots", "delayed") for f in SHARES + (0.40,)]):
        print(f"  {r[0]:7} share {100 * r[1]:4.1f}%: blocks {r[2]} against {r[3]}; its target reached {r[4]:5.1f}x;  band alone {r[5]:6.1f}%  band/T {r[6]:5.1f}%  (2-u)/T {r[7]:5.1f}%")


# ---------------------------------------------------------------- first, emergency

def part_first():
    listed = N
    t0 = compact(MAX // (100 * listed) * LAM_X100)
    print("\n== first: the day after activation, the target starting from the confirmed-node count")
    for mode in ("delayed",):
        rng = random.Random(21)
        c = Chain(mode, t0)
        out = []
        for s in range(DAY):
            live = int(N * LIVE)
            out.append((c.slot(s, best_under(rng, live, c.t)), live * c.t / MAX))
        for name, lo, hi in (("the first hour", 0, 120), ("hours 1 to 6", 120, 720), ("hours 6 to 24", 720, DAY)):
            print(f"  {name:14} " + summarise(out, lo, hi))


def part_emergency():
    print("\n== emergency: a slot with an emergency block counts as empty in the epoch's sum")
    for name, left in (("every node offline for 6 hours, then all back", 0), ("6 nodes left of 6,956 for 24 hours", 6)):
        rng = random.Random(22)
        t0 = t_for(N * LIVE)
        c = Chain("delayed", t0)
        gone = 6 * 120 if left == 0 else DAY
        out = []
        for s in range(DAY + gone + DAY):
            live = int(N * LIVE) if (s < DAY or s >= DAY + gone) else left
            out.append((c.slot(s, best_under(rng, live, c.t) if live else None), live * c.t / MAX, c.t / t0))
        o2 = [(m, l) for m, l, _ in out]
        print(f"  {name}")
        for h in (1, 2, 3, 4, 6, 12, 24):
            if h * 120 <= gone:
                w = out[DAY + (h - 1) * 120: DAY + h * 120]
                print(f"      hour {h:2}: node blocks in {100 * sum(m for m, _, _ in w) / 120:5.1f}% of slots; target {w[-1][2]:8.1f}x the start; live eligible {w[-1][1]:5.2f}")
        if left == 0:
            print(f"      after they return: {summarise(o2, DAY + gone, DAY + gone + 120)}")
            print(f"      back between 6 and 14 live eligible {back_in_band(o2, DAY + gone)} h after")


# ---------------------------------------------------------------- raise

def raise_run(args):
    f, x, seed = args
    rng = random.Random(seed)
    honest, own = N * LIVE * (1 - f), N * f
    t0 = t_for(honest + own)
    pub, prv = Chain("delayed", t0), Chain("delayed", t0)
    tmin = tmax = t0
    for s in range(10 * DAY):
        pub.slot(s, best_under(rng, honest, pub.t))
        y = best_under(rng, own, prv.t)
        if y is not None and y * 100 >= x * prv.t:
            y = None
        prv.slot(s, y)
        tmin, tmax = min(tmin, prv.t), max(tmax, prv.t)
    return f, x, prv.nb, tmin / t0, tmax / t0, 100 * prv.wg / pub.wg


def part_raise(pool):
    print("\n== raise: an operator alone for 10 days, minting only draws under x% of its own target")
    for f, x, nb, lo, hi, share in pool.map(raise_run, [(f, x, 9) for f in SHARES for x in (100, 50, 25, 10, 5)]):
        print(f"  share {100 * f:4.1f}%  x = {x:3}%: blocks {nb:6}; its target between {lo:5.2f}x and {hi:7.1f}x the fork's; work {share:5.1f}% of the public chain's")


# ---------------------------------------------------------------- reorg

def reorg_run(args):
    mode, f, seed, slots, shock = args
    rng = random.Random(seed)
    honest_n, own = N * LIVE * (1 - f), N * f
    t0 = t_for(honest_n + own)
    main = Chain(mode, t0)
    horizon = KS[-1]
    hs, as_ = [], []                 # per slot: best honest output under 2T, best own under 4T
    snaps = []                       # the main chain's state before each slot
    wins = {(r, k): 0 for r in ("band", "graded") for k in KS}
    ties = {k: 0 for k in KS}
    starts = 0
    warm = 3 * EPOCH
    total = warm + slots + horizon
    for s in range(total):
        up = 0.1 if shock and s >= warm else 1.0
        h = best_under(rng, honest_n * up, min(MAX, 2 * main.t))
        a = best_under(rng, own * up, min(MAX, 4 * main.t))
        hs.append(h)
        as_.append(a)
        snaps.append(main.copy())
        best = h if a is None else a if h is None else min(h, a)
        main.slot(s, best)
    for s0 in range(warm, warm + slots):
        pub, prv = snaps[s0].copy(), snaps[s0].copy()
        starts += 1
        for i in range(horizon):
            s = s0 + i
            pub.slot(s, hs[s])
            prv.slot(s, as_[s])
            if i + 1 in wins_k:
                k = i + 1
                if prv.nb:
                    if prv.wb > pub.wb:
                        wins[("band", k)] += 1
                    elif prv.wb == pub.wb:
                        ties[k] += 1
                    if prv.wg > pub.wg:
                        wins[("graded", k)] += 1
    return mode, f, shock, starts, wins, ties


wins_k = set(KS)
MODES = ("fixed", "blocks", "slots", "delayed")


def part_reorg(pool, shock=False):
    seeds, slots = (2000, 720) if shock else (160, 25000)
    title = "shock: the 6 hours after 90% of all nodes go offline" if shock else "reorg: steady"
    print(f"\n== {title}; opportunities a day to replace the blocks of the last k slots")
    print("   fixed = one target, the band alone (as ruled) and 2-u; blocks, slots, delayed = the moving target, band/T and (2-u)/T")
    tasks = [(m, f, 1000 * i + 7, slots, shock) for m in MODES for f in SHARES for i in range(seeds)]
    agg = {}
    for mode, f, sh, starts, wins, ties in pool.imap_unordered(reorg_run, tasks, chunksize=4):
        a = agg.setdefault((mode, f), [0, {}, {}])
        a[0] += starts
        for key, v in wins.items():
            a[1][key] = a[1].get(key, 0) + v
        for key, v in ties.items():
            a[2][key] = a[2].get(key, 0) + v
    print(f"   {'':6} {'share':>6} {'k':>3} {'band':>10} {'band tie':>10} {'2-u':>10}   (starts)")
    for f in SHARES:
        for k in KS:
            for mode in MODES:
                st, w, t = agg[(mode, f)]
                r = lambda c: f"{DAY * c / st:.3g}" if c else f"<{DAY / st:.2g}"
                print(f"   {mode:7} {100 * f:5.1f}% {k:>3} {r(w[('band', k)]):>10} {r(t[k]):>10} {r(w[('graded', k)]):>10}   ({st})", flush=True)


def main():
    parts = sys.argv[1:] or ["target", "nudge", "long", "reorg", "shock", "first", "emergency", "raise"]
    with Pool(20) as pool:
        if "target" in parts:
            part_target()
        if "nudge" in parts:
            part_nudge(pool)
        if "long" in parts:
            part_long(pool)
        if "reorg" in parts:
            part_reorg(pool)
        if "shock" in parts:
            part_reorg(pool, shock=True)
        if "first" in parts:
            part_first()
        if "emergency" in parts:
            part_emergency()
        if "raise" in parts:
            part_raise(pool)


if __name__ == "__main__":
    main()
