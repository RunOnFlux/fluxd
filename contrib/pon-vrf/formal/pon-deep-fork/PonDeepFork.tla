---------------------------- MODULE PonDeepFork ----------------------------
(* Three ways to choose between chains, and whether nodes that hold the same
   blocks then hold the same tip whatever order the blocks arrived in.

   The world is PonChainWeight's: a block has a parent, a slot and a weight; a
   node mints at most one block a slot on its own tip, in a later slot; blocks
   reach other nodes one at a time, in any order, or never.

   ForkRule
     "total"    the chain with the most weight; equal chains, the lower tip id
     "local"    Ouroboros Genesis' maxvalid-bg, judged against the chain a node
                holds: a chain that forks from it at most Depth blocks back
                wins by total weight; one that forks deeper wins only with
                strictly more weight in the first Window slots after the fork
     "descent"  from genesis, at every block with more than one child, take
                the child whose best descendant chain has the most weight in
                the first Window slots after that block; equal, the lower id *)
EXTENDS Naturals, FiniteSets

CONSTANTS Node, MaxSlot, MaxBlock, MaxWeight, ForkRule, Depth, Window

None == 0

VARIABLES now, parent, slotOf, weight, made, known, tip, minted, switched
vars == <<now, parent, slotOf, weight, made, known, tip, minted, switched>>

Block == 1..MaxBlock

SlotAt(b) == IF b = None THEN 0 ELSE slotOf[b]

RECURSIVE ChainWeight(_)
ChainWeight(b) == IF b = None THEN 0 ELSE weight[b] + ChainWeight(parent[b])

RECURSIVE OnChain(_, _)
OnChain(a, b) == IF a = None THEN TRUE
                 ELSE IF b = None THEN FALSE
                 ELSE IF a = b THEN TRUE ELSE OnChain(a, parent[b])

\* The last block the chains of a and b share.
RECURSIVE Fork(_, _)
Fork(a, b) == IF OnChain(a, b) THEN a ELSE Fork(parent[a], b)

\* Blocks on the chain of b after base.
RECURSIVE BlocksAfter(_, _)
BlocksAfter(b, base) == IF b = base THEN 0 ELSE 1 + BlocksAfter(parent[b], base)

\* Weight on the chain of b after base, in slots up to limit.
RECURSIVE WeightUpTo(_, _, _)
WeightUpTo(b, base, limit) ==
    IF b = base THEN 0
    ELSE (IF slotOf[b] <= limit THEN weight[b] ELSE 0) + WeightUpTo(parent[b], base, limit)

InWindow(b, base) == WeightUpTo(b, base, SlotAt(base) + Window)

HeavierTotal(a, b) == \/ ChainWeight(a) > ChainWeight(b)
                      \/ ChainWeight(a) = ChainWeight(b) /\ a # None /\ (b = None \/ a < b)

\* "local": does a node holding tip t move to b?
MovesLocal(b, t) ==
    LET base == Fork(t, b)
    IN IF BlocksAfter(t, base) <= Depth THEN HeavierTotal(b, t)
       ELSE InWindow(b, base) > InWindow(t, base)

\* "descent": the tip a set of blocks gives.
Children(x, set) == {c \in set : parent[c] = x}
Under(c, set) == {d \in set : OnChain(c, d)}
SetMax(S) == CHOOSE m \in S : \A o \in S : o <= m
Score(c, x, set) == SetMax({InWindow(d, x) : d \in Under(c, set)})
Pick(x, set) ==
    CHOOSE c \in Children(x, set) :
        \A o \in Children(x, set) :
            \/ Score(c, x, set) > Score(o, x, set)
            \/ Score(c, x, set) = Score(o, x, set) /\ c <= o
RECURSIVE Descend(_, _)
Descend(x, set) == IF Children(x, set) = {} THEN x ELSE Descend(Pick(x, set), set)

NewTip(n, b) ==
    IF ForkRule = "total" THEN (IF HeavierTotal(b, tip[n]) THEN b ELSE tip[n])
    ELSE IF ForkRule = "local" THEN (IF MovesLocal(b, tip[n]) THEN b ELSE tip[n])
    ELSE Descend(None, known[n] \cup {b})

Init == /\ now = 1
        /\ parent = [b \in Block |-> None]
        /\ slotOf = [b \in Block |-> 0]
        /\ weight = [b \in Block |-> 0]
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
              /\ weight' = [weight EXCEPT ![made + 1] = w]
              /\ known' = [known EXCEPT ![n] = @ \cup {made + 1}]
              /\ tip' = [tip EXCEPT ![n] = made + 1]
              /\ minted' = [minted EXCEPT ![n] = now]
              /\ UNCHANGED <<now, switched>>

Receive(n, b) == /\ b \in 1..made
                 /\ b \notin known[n]
                 /\ parent[b] = None \/ parent[b] \in known[n]
                 /\ known' = [known EXCEPT ![n] = @ \cup {b}]
                 /\ tip' = [tip EXCEPT ![n] = NewTip(n, b)]
                 /\ switched' = (switched \/ ~OnChain(tip[n], NewTip(n, b)))
                 /\ UNCHANGED <<now, parent, slotOf, weight, made, minted>>

Tick == /\ now < MaxSlot
        /\ now' = now + 1
        /\ UNCHANGED <<parent, slotOf, weight, made, known, tip, minted, switched>>

Done == /\ now = MaxSlot
        /\ UNCHANGED vars

Next == \/ \E n \in Node, w \in 1..MaxWeight : Mint(n, w)
        \/ \E n \in Node, b \in Block : Receive(n, b)
        \/ Tick
        \/ Done

\* Safety
SameBlocksSameTip == \A n, m \in Node : known[n] = known[m] => tip[n] = tip[m]
OneBlockASlot == \A a, b \in 1..made : (a # b /\ OnChain(a, b)) => slotOf[a] # slotOf[b]
\* While every block is inside the window of every fork, the window rule is the total rule.
YoungForksGoToTheHeaviest ==
    now <= Window => \A n \in Node : \A b \in known[n] : ChainWeight(b) <= ChainWeight(tip[n])

\* Guards: each must be violated
NoBlocks == made = 0
NeverSwitches == ~switched
\* A node holds a tip that is not the heaviest chain it knows: the window decided.
AlwaysTheHeaviest == \A n \in Node : \A b \in known[n] : ChainWeight(b) <= ChainWeight(tip[n])
=============================================================================
