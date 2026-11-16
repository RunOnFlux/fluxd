---------------------------- MODULE PonWithhold ----------------------------
(* Can a node whose draws are never better than the honest nodes' get the
   honest nodes to leave their chain for its own, by withholding blocks,
   building a branch in private and releasing it?

   Each slot the world gives the honest nodes one draw (their best) and the
   adversary one draw (its best), or none. A draw is an output y; it is
   eligible under a target T when y < T, and its band is 8 - floor(8y / T).

   The honest nodes hold one chain, pub. Each slot their draw mints on it when
   it is eligible and the tip is in an earlier slot: this is a duty, the slot
   does not end until it is done. The adversary may publish its own draw on
   pub in its turn (a better draw goes first), keep a private branch priv
   forked from pub, extend priv with its draw, and release priv; the honest
   nodes move to priv when it is the heavier and covers no more than MaxDepth
   slots.

   A chain is carried as a summary: its work, its target, the running epoch
   (blocks, slots, sum of winning outputs with an empty slot counted as the
   target), the sum of the epoch before, the slot and output of its tip.

   MoveTarget   the target moves when an epoch completes
   EpochBy      "blocks": an epoch is EpochLen blocks of the chain
                "slots": an epoch is EpochLen slots, the same slots on every
                chain; an epoch with no block in it counts as all empty
   Delay        with epochs in slots: the target of an epoch is moved by the
                sum of the epoch before the last, not of the last
   WorkRule     "band": a block's work is its band
                "bandOverTarget": its band times 32 / T
                "flatOverTarget": 8 more than its band, times 32 / T
                "gradedOverTarget": (2T - y) times 1024 / T^2, which is
                (2 - y/T) / T with no rounding
   Emergency    a block signed by the emergency key may fill a slot of the
                honest chain that the honest draw cannot; it has the work of
                the best draw and counts in the epoch's sum as an empty slot
   TieRule      "hash": between equal chains the lower block hash wins, which
                the adversary can always arrange by remaking its block
                "output": the lower tip output wins
   Dominated    "no": any draws
                "draws": every slot the adversary's draw is absent or worse
                than the honest draw
                "slots": that, and the honest draw is eligible on the honest
                chain in every slot *)
EXTENDS Naturals

CONSTANTS MaxSlot, EpochLen, EpochBy, Delay, MaxDepth, Draws,
          MoveTarget, WorkRule, TieRule, Dominated, Emergency

No == 99
Lambda == 4
TMin == 8
TMax == 32
TStart == 16

VARIABLES now, hd, ad,      \* the slot and its two draws
          pub, priv,        \* chain summaries
          forked, forkSlot, \* a private branch exists; the first slot it may differ in
          padd, hadd,       \* blocks added to priv and to pub since the fork
          aPub, aPriv,      \* the adversary's draw is used on pub, on priv, this slot
          switched,         \* the honest nodes have left their chain for a released branch
          loosened,         \* a release gave them a looser target than the chain they left
          emerged           \* an emergency block has been minted
vars == <<now, hd, ad, pub, priv, forked, forkSlot, padd, hadd, aPub, aPriv, switched, loosened, emerged>>

Min(a, b) == IF a < b THEN a ELSE b
Max(a, b) == IF a > b THEN a ELSE b

Eligible(y, T) == y # No /\ y < T
Band(y, T) == 8 - ((8 * y) \div T)
Work(y, T) == IF WorkRule = "band" THEN Band(y, T)
              ELSE IF WorkRule = "bandOverTarget" THEN Band(y, T) * (32 \div T)
              ELSE IF WorkRule = "flatOverTarget" THEN (8 + Band(y, T)) * (32 \div T)
              ELSE (2 * T - y) * (1024 \div (T * T))

\* The target an epoch's draws ask for is Lambda times their mean; the target
\* moves one level toward it when it is half as far again, or 0.7 as far.
NextT(T, es, en) == IF ~MoveTarget THEN T
                    ELSE IF 2 * Lambda * es >= 3 * T * en THEN Min(2 * T, TMax)
                    ELSE IF 10 * Lambda * es <= 7 * T * en THEN Max(T \div 2, TMin)
                    ELSE T

\* An epoch sum that leaves the starting target where it is.
Neutral == (TStart * EpochLen) \div Lambda

Genesis == [work |-> 0, T |-> TStart, eb |-> 0, es |-> 0, en |-> 0, pe |-> Neutral,
            last |-> 0, tipY |-> 0]

\* Chain c with a block of output y in slot s, epochs counted in blocks.
AddByBlocks(c, y, s) ==
    LET gap == s - c.last - 1
        es2 == c.es + y + gap * c.T
        en2 == c.en + gap + 1
        roll == c.eb + 1 = EpochLen
    IN [work |-> c.work + Work(y, c.T),
        T    |-> IF roll THEN NextT(c.T, es2, en2) ELSE c.T,
        eb   |-> IF roll THEN 0 ELSE c.eb + 1,
        es   |-> IF roll THEN 0 ELSE es2,
        en   |-> IF roll THEN 0 ELSE en2,
        pe   |-> c.pe,
        last |-> s,
        tipY |-> y]

Ep(s) == IF s = 0 THEN 0 ELSE (s - 1) \div EpochLen

\* Close an epoch whose sum is cur, then k more epochs with no block in them.
RECURSIVE Roll(_, _, _, _)
Roll(T, pe, cur, k) ==
    LET t == NextT(T, IF Delay THEN pe ELSE cur, EpochLen)
    IN IF k = 0 THEN [T |-> t, pe |-> cur] ELSE Roll(t, cur, EpochLen * t, k - 1)

\* The same, epochs counted in slots. When the block is in a later epoch
\* than the tip, the tip's epoch closes with its remaining slots empty and
\* each epoch between them is all empty.
AddBySlots(c, y, s) ==
    IF Ep(s) = Ep(c.last)
    THEN [work |-> c.work + Work(y, c.T), T |-> c.T, eb |-> 0,
          es |-> c.es + y + (s - c.last - 1) * c.T, en |-> 0, pe |-> c.pe,
          last |-> s, tipY |-> y]
    ELSE LET rest == (Ep(c.last) + 1) * EpochLen - c.last
             r == Roll(c.T, c.pe, c.es + rest * c.T, Ep(s) - Ep(c.last) - 1)
             lead == s - Ep(s) * EpochLen - 1
         IN [work |-> c.work + Work(y, r.T), T |-> r.T, eb |-> 0,
             es |-> lead * r.T + y, en |-> 0, pe |-> r.pe,
             last |-> s, tipY |-> y]

Add(c, y, s) == IF EpochBy = "blocks" THEN AddByBlocks(c, y, s) ELSE AddBySlots(c, y, s)

\* Chain c with an emergency block in slot s (epochs in slots): the work of
\* the best draw, and the slot's share of the sum that of an empty slot.
AddEmergency(c, s) ==
    LET t == AddBySlots(c, 0, s).T
        a == AddBySlots(c, t, s)
    IN [a EXCEPT !.work = c.work + Work(0, t), !.tipY = 0]

\* The target a block minted on c in slot s would carry.
TargetAt(c, s) == IF EpochBy = "blocks" THEN c.T ELSE AddBySlots(c, 0, s).T

HonestCanMint == now > 0 /\ Eligible(hd, TargetAt(pub, now)) /\ pub.last < now

Init == /\ now = 0 /\ hd = No /\ ad = No
        /\ pub = Genesis /\ priv = Genesis
        /\ forked = FALSE /\ forkSlot = 0 /\ padd = 0 /\ hadd = 0
        /\ aPub = FALSE /\ aPriv = FALSE
        /\ switched = FALSE /\ loosened = FALSE /\ emerged = FALSE

Tick == /\ now < MaxSlot
        /\ ~HonestCanMint
        /\ \E h \in Draws \cup {No}, a \in Draws \cup {No} :
              /\ Dominated = "draws" => (a = No \/ (h # No /\ a > h))
              /\ Dominated = "slots" => (h # No /\ h < TargetAt(pub, now + 1) /\ (a = No \/ a > h))
              /\ hd' = h /\ ad' = a
        /\ now' = now + 1
        /\ aPub' = FALSE /\ aPriv' = FALSE
        /\ UNCHANGED <<pub, priv, forked, forkSlot, padd, hadd, switched, loosened, emerged>>

HonestMint == /\ HonestCanMint
              /\ pub' = Add(pub, hd, now)
              /\ hadd' = IF forked THEN hadd + 1 ELSE hadd
              /\ UNCHANGED <<now, hd, ad, priv, forked, forkSlot, padd, aPub, aPriv, switched, loosened, emerged>>

\* The emergency key fills a slot the honest draw cannot.
EmergencyMint == /\ Emergency /\ EpochBy = "slots"
                 /\ now > 0 /\ pub.last < now
                 /\ ~Eligible(hd, TargetAt(pub, now))
                 /\ pub' = AddEmergency(pub, now)
                 /\ hadd' = IF forked THEN hadd + 1 ELSE hadd
                 /\ emerged' = TRUE
                 /\ UNCHANGED <<now, hd, ad, priv, forked, forkSlot, padd, aPub, aPriv, switched, loosened>>

\* The adversary publishes on the honest tip, in its turn.
AdvPub == /\ now > 0 /\ ~aPub
          /\ Eligible(ad, TargetAt(pub, now)) /\ pub.last < now
          /\ ~Eligible(hd, TargetAt(pub, now)) \/ ad < hd
          /\ pub' = Add(pub, ad, now)
          /\ aPub' = TRUE
          /\ hadd' = IF forked THEN hadd + 1 ELSE hadd
          /\ UNCHANGED <<now, hd, ad, priv, forked, forkSlot, padd, aPriv, switched, loosened, emerged>>

\* A branch forked now may differ from pub from the slot after pub's tip.
Fork == /\ ~forked /\ now > 0
        /\ priv' = pub /\ forked' = TRUE /\ padd' = 0 /\ hadd' = 0
        /\ forkSlot' = pub.last + 1
        /\ UNCHANGED <<now, hd, ad, pub, aPub, aPriv, switched, loosened, emerged>>

AdvPriv == /\ forked /\ ~aPriv
           /\ Eligible(ad, TargetAt(priv, now)) /\ priv.last < now
           /\ priv' = Add(priv, ad, now)
           /\ aPriv' = TRUE /\ padd' = padd + 1
           /\ UNCHANGED <<now, hd, ad, pub, forked, forkSlot, hadd, aPub, switched, loosened, emerged>>

Heavier == \/ priv.work > pub.work
           \/ /\ priv.work = pub.work
              /\ \/ TieRule = "hash"
                 \/ TieRule = "output" /\ priv.tipY < pub.tipY

\* A block of this slot is not valid before its turn, and a better honest
\* draw has minted by then.
InTurn == priv.last < now \/ ~HonestCanMint \/ ad < hd

Release == /\ forked /\ padd > 0 /\ hadd > 0
           /\ now + 1 - forkSlot <= MaxDepth
           /\ Heavier /\ InTurn
           /\ pub' = priv
           /\ forked' = FALSE
           /\ switched' = TRUE
           /\ loosened' = (loosened \/ TargetAt(priv, now) > TargetAt(pub, now))
           /\ UNCHANGED <<now, hd, ad, priv, forkSlot, padd, hadd, aPub, aPriv, emerged>>

Abandon == /\ forked
           /\ forked' = FALSE
           /\ UNCHANGED <<now, hd, ad, pub, priv, forkSlot, padd, hadd, aPub, aPriv, switched, loosened, emerged>>

Done == /\ now = MaxSlot /\ ~HonestCanMint
        /\ UNCHANGED vars

Next == Tick \/ HonestMint \/ EmergencyMint \/ AdvPub \/ Fork \/ AdvPriv \/ Release \/ Abandon \/ Done

\* Safety
HonestNeverLeave == ~switched
\* Within MaxDepth slots of its fork a branch carries the honest chain's target.
BranchCarriesTheSameTarget ==
    (forked /\ now + 1 - forkSlot <= MaxDepth) => TargetAt(priv, now) = TargetAt(pub, now)

\* Guards: each must be violated
NoBlocks == pub.work = 0
NeverForks == ~forked
TargetNeverLoosens == pub.T <= TStart
TargetNeverTightens == pub.T >= TStart
BranchTargetNeverDiffers == ~(forked /\ now > 0 /\ TargetAt(priv, now) # TargetAt(pub, now))
BranchNeverAhead == ~(forked /\ padd > 0 /\ hadd > 0 /\ now + 1 - forkSlot <= MaxDepth
                      /\ priv.work >= pub.work)
ReleaseNeverLoosens == ~loosened
NoEmergencyBlock == ~emerged
=============================================================================
