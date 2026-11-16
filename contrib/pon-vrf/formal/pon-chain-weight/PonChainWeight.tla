--------------------------- MODULE PonChainWeight ---------------------------
(* Do nodes that hold the same blocks hold the same tip, when the heavier chain
   wins?

   A block has a parent, a slot and a weight. A node mints at most one block a
   slot, on its own tip, in a later slot than that tip (the slot rule). Blocks
   reach other nodes one at a time, in any order, or never: a node that keeps
   its blocks to itself and a network split are the same thing here. A node
   holds the heaviest chain it knows.

   TieRule says what a node does between two chains of equal weight:
     "held"  it keeps the one it has;
     "id"    it takes the one whose tip has the lower id (as a lower block hash
             would be). *)
EXTENDS Naturals, FiniteSets

CONSTANTS Node, MaxSlot, MaxBlock, MaxWeight, TieRule

None == 0

VARIABLES now,        \* the current slot
          parent,     \* parent[b]: block id, or None for a child of genesis
          slotOf,     \* slotOf[b]
          weight,     \* weight[b]
          made,       \* how many blocks exist; ids are 1..made
          known,      \* known[n]: the block ids node n has
          tip,        \* tip[n]: a block id, or None for genesis
          minted,     \* minted[n]: the last slot n minted in
          switched    \* TRUE once some node left a tip for another branch
vars == <<now, parent, slotOf, weight, made, known, tip, minted, switched>>

Block == 1..MaxBlock

RECURSIVE ChainWeight(_)
ChainWeight(b) == IF b = None THEN 0 ELSE weight[b] + ChainWeight(parent[b])

RECURSIVE OnChain(_, _)
OnChain(a, b) == IF b = None THEN a = None
                 ELSE IF a = b THEN TRUE ELSE OnChain(a, parent[b])

SlotAt(b) == IF b = None THEN 0 ELSE slotOf[b]

Better(a, b) == \/ ChainWeight(a) > ChainWeight(b)
                \/ /\ ChainWeight(a) = ChainWeight(b)
                   /\ TieRule = "id"
                   /\ a # None /\ (b = None \/ a < b)

\* The tip a node holds after learning block b: b if its chain is better.
Choose(n, b) == IF Better(b, tip[n]) THEN b ELSE tip[n]

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

\* Node n receives block b, whose parent it has.
Receive(n, b) == /\ b \in 1..made
                 /\ b \notin known[n]
                 /\ parent[b] = None \/ parent[b] \in known[n]
                 /\ known' = [known EXCEPT ![n] = @ \cup {b}]
                 /\ tip' = [tip EXCEPT ![n] = Choose(n, b)]
                 /\ switched' = (switched \/ (Choose(n, b) = b /\ ~OnChain(tip[n], b)))
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
HoldsTheHeaviest == \A n \in Node : \A b \in known[n] : ChainWeight(b) <= ChainWeight(tip[n])
OneBlockASlot == \A a, b \in 1..made : (a # b /\ OnChain(a, b)) => slotOf[a] # slotOf[b]

\* Guards: each must be violated
NoBlocks == made = 0
NeverSwitches == ~switched
NoFork == \A a, b \in 1..made : a = b \/ OnChain(a, b) \/ OnChain(b, a)
NeverAgreeOnThree == ~(\E b \in 1..made : slotOf[b] >= 3 /\ \A n \in Node : tip[n] = b)
\* A branch kept back and then delivered does displace a tip: it is not prevented.
LateBranchNeverWins == ~(\E n \in Node : switched /\ tip[n] # None /\ slotOf[tip[n]] < now - 1 /\ minted[n] < slotOf[tip[n]])
=============================================================================
