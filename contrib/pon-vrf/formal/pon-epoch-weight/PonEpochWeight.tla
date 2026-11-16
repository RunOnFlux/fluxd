--------------------------- MODULE PonEpochWeight ---------------------------
(* PonChainWeight with a target that moves at an epoch boundary and a block's
   work taken from its band and its target.

   A block has a parent, a slot, a band (1 or 2) and a target level (0, 1, 2;
   a higher level is a looser target). An epoch is EpochLen blocks. A block
   carries its parent's level, except the first of an epoch, which carries the
   level the epoch before it gives: one looser when that epoch's poor blocks
   and empty slots number EpochLen or more, one tighter when it has none.

   A node mints at most one block a slot, on its own tip, in a later slot,
   stamped with the level the rule gives. With Forger, blocks also appear on
   any existing block with any band, at the rule's level or at a false one,
   held by nobody: a second block on a parent, a branch off an old block, a
   false target. A node takes
   a block once it has the parent and, with CheckTarget, only when the level
   it carries is the rule's. A node holds the chain with the most work it
   knows; between equal chains, the tip with the lower id.

   WorkRule  "band": a block's work is its band
             "bandOverTarget": its band times 4, 2 or 1 by level *)
EXTENDS Naturals, FiniteSets

CONSTANTS Node, MaxSlot, MaxBlock, EpochLen, WorkRule, CheckTarget, Forger

None == 0
StartLevel == 1
MaxLevel == 2

VARIABLES now, parent, slotOf, band, level, made, known, tip, minted, switched
vars == <<now, parent, slotOf, band, level, made, known, tip, minted, switched>>

Block == 1..MaxBlock

SlotAt(b) == IF b = None THEN 0 ELSE slotOf[b]
LevelAt(b) == IF b = None THEN StartLevel ELSE level[b]

RECURSIVE Height(_)
Height(b) == IF b = None THEN 0 ELSE 1 + Height(parent[b])

\* Poor blocks and empty slots in the k blocks ending at b.
RECURSIVE Bad(_, _)
Bad(b, k) == IF k = 0 \/ b = None THEN 0
             ELSE (IF band[b] = 1 THEN 1 ELSE 0)
                  + (slotOf[b] - SlotAt(parent[b]) - 1)
                  + Bad(parent[b], k - 1)

\* The level a child of p carries.
Expected(p) == IF p = None \/ Height(p) % EpochLen # 0 THEN LevelAt(p)
               ELSE IF Bad(p, EpochLen) >= EpochLen
                    THEN (IF level[p] < MaxLevel THEN level[p] + 1 ELSE level[p])
               ELSE IF Bad(p, EpochLen) = 0
                    THEN (IF level[p] > 0 THEN level[p] - 1 ELSE level[p])
               ELSE level[p]

Mult(l) == IF l = 0 THEN 4 ELSE IF l = 1 THEN 2 ELSE 1
Work(b) == IF WorkRule = "band" THEN band[b] ELSE band[b] * Mult(level[b])

RECURSIVE ChainWork(_)
ChainWork(b) == IF b = None THEN 0 ELSE Work(b) + ChainWork(parent[b])

RECURSIVE OnChain(_, _)
OnChain(a, b) == IF b = None THEN a = None
                 ELSE IF a = b THEN TRUE ELSE OnChain(a, parent[b])

Better(a, b) == \/ ChainWork(a) > ChainWork(b)
                \/ /\ ChainWork(a) = ChainWork(b)
                   /\ a # None /\ (b = None \/ a < b)

Choose(n, b) == IF Better(b, tip[n]) THEN b ELSE tip[n]

Init == /\ now = 1
        /\ parent = [b \in Block |-> None]
        /\ slotOf = [b \in Block |-> 0]
        /\ band = [b \in Block |-> 0]
        /\ level = [b \in Block |-> 0]
        /\ made = 0
        /\ known = [n \in Node |-> {}]
        /\ tip = [n \in Node |-> None]
        /\ minted = [n \in Node |-> 0]
        /\ switched = FALSE

Mint(n, w) == /\ made < MaxBlock
              /\ minted[n] < now
              /\ SlotAt(tip[n]) < now
              /\ made' = made + 1
              /\ parent' = [parent EXCEPT ![made + 1] = tip[n]]
              /\ slotOf' = [slotOf EXCEPT ![made + 1] = now]
              /\ band' = [band EXCEPT ![made + 1] = w]
              /\ level' = [level EXCEPT ![made + 1] = Expected(tip[n])]
              /\ known' = [known EXCEPT ![n] = @ \cup {made + 1}]
              /\ tip' = [tip EXCEPT ![n] = made + 1]
              /\ minted' = [minted EXCEPT ![n] = now]
              /\ UNCHANGED <<now, switched>>

Forge(p, w, l) == /\ Forger
                  /\ made < MaxBlock
                  /\ SlotAt(p) < now
                  /\ made' = made + 1
                  /\ parent' = [parent EXCEPT ![made + 1] = p]
                  /\ slotOf' = [slotOf EXCEPT ![made + 1] = now]
                  /\ band' = [band EXCEPT ![made + 1] = w]
                  /\ level' = [level EXCEPT ![made + 1] = l]
                  /\ UNCHANGED <<now, known, tip, minted, switched>>

Receive(n, b) == /\ b \in 1..made
                 /\ b \notin known[n]
                 /\ parent[b] = None \/ parent[b] \in known[n]
                 /\ CheckTarget => level[b] = Expected(parent[b])
                 /\ known' = [known EXCEPT ![n] = @ \cup {b}]
                 /\ tip' = [tip EXCEPT ![n] = Choose(n, b)]
                 /\ switched' = (switched \/ (Choose(n, b) = b /\ ~OnChain(tip[n], b)))
                 /\ UNCHANGED <<now, parent, slotOf, band, level, made, minted>>

Tick == /\ now < MaxSlot
        /\ now' = now + 1
        /\ UNCHANGED <<parent, slotOf, band, level, made, known, tip, minted, switched>>

Done == /\ now = MaxSlot
        /\ UNCHANGED vars

Next == \/ \E n \in Node, w \in 1..2 : Mint(n, w)
        \/ \E p \in 0..made, w \in 1..2 :
              \E l \in {Expected(p), (Expected(p) + 1) % (MaxLevel + 1)} : Forge(p, w, l)
        \/ \E n \in Node, b \in Block : Receive(n, b)
        \/ Tick
        \/ Done

\* Safety
SameBlocksSameTip == \A n, m \in Node : known[n] = known[m] => tip[n] = tip[m]
HoldsTheHeaviest == \A n \in Node : \A b \in known[n] : ChainWork(b) <= ChainWork(tip[n])
OneBlockASlot == \A a, b \in 1..made : (a # b /\ OnChain(a, b)) => slotOf[a] # slotOf[b]
HeldTargetsFollowTheRule == \A n \in Node : \A b \in known[n] : level[b] = Expected(parent[b])

\* Guards: each must be violated
NoBlocks == made = 0
NeverSwitches == ~switched
TargetNeverMoves == \A n \in Node : \A b \in known[n] : level[b] = StartLevel
BranchesAgreeOnTarget == \A n \in Node : \A a, b \in known[n] :
                            Height(a) = Height(b) => level[a] = level[b]
=============================================================================
