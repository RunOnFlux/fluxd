---------------------------- MODULE PonSlotStall ----------------------------
(* Can one block leave every honest node unable to mint?

   Honest nodes share one tip. An honest block is stamped with the current
   slot. One other node may stamp a block with any slot, the present one
   included. A receiver takes a block whose slot is at most Drift slots ahead
   of its own clock, and holds it otherwise until the clock reaches it. A
   block must follow its parent: in a later slot under SlotRule, in the same
   slot or later without it (a later time within one slot).

   stalled counts the consecutive slots at whose start no honest block could
   be valid on the tip. *)
EXTENDS Naturals

CONSTANTS MaxSlot,      \* the horizon, in slots
          MaxHeight,    \* blocks on the chain
          MaxAhead,     \* how far ahead of the clock the other node may stamp
          Drift,        \* slots a block may be ahead of the receiver's clock
          SlotRule,     \* TRUE: a block is in a later slot than its parent
          Bound         \* the stall the property allows, in slots

None == 0

VARIABLES now,          \* the current slot
          height,       \* the honest tip's height
          tipSlot,      \* the slot the honest tip is stamped with
          held,         \* the slot of a block received ahead of the clock, or None
          heldParent,   \* the height that block extends
          stalled,      \* consecutive slots with no valid honest block possible
          shared        \* TRUE once two blocks on the chain share a slot
vars == <<now, height, tipSlot, held, heldParent, stalled, shared>>

Follows(s, parentSlot) == IF SlotRule THEN s > parentSlot ELSE s >= parentSlot

CanMint(slot) == Follows(slot, tipSlot)

Init == /\ now = 1
        /\ height = 0
        /\ tipSlot = None
        /\ held = None
        /\ heldParent = 0
        /\ stalled = 0
        /\ shared = FALSE

Extend(s) == /\ height' = height + 1
             /\ tipSlot' = s
             /\ shared' = (shared \/ s = tipSlot)

HonestMint == /\ height < MaxHeight
              /\ CanMint(now)
              /\ Extend(now)
              /\ UNCHANGED <<now, held, heldParent, stalled>>

\* The other node stamps slot s. Receivers take it now or hold it.
OtherMint(s) == /\ height < MaxHeight
                /\ held = None
                /\ Follows(s, tipSlot)
                /\ IF s <= now + Drift
                     THEN /\ Extend(s)
                          /\ UNCHANGED <<held, heldParent>>
                     ELSE /\ held' = s
                          /\ heldParent' = height
                          /\ UNCHANGED <<height, tipSlot, shared>>
                /\ UNCHANGED <<now, stalled>>

\* A held block whose slot the clock has reached: taken if it still extends the tip.
TakeHeld == /\ held # None
            /\ held <= now + Drift
            /\ IF heldParent = height /\ Follows(held, tipSlot) /\ height < MaxHeight
                 THEN Extend(held)
                 ELSE UNCHANGED <<height, tipSlot, shared>>
            /\ held' = None
            /\ heldParent' = 0
            /\ UNCHANGED <<now, stalled>>

Tick == /\ now < MaxSlot
        /\ now' = now + 1
        /\ stalled' = IF Follows(now + 1, tipSlot) THEN 0 ELSE stalled + 1
        /\ UNCHANGED <<height, tipSlot, held, heldParent, shared>>

Done == /\ now = MaxSlot
        /\ UNCHANGED vars

Next == \/ HonestMint
        \/ \E s \in now..(now + MaxAhead) : OtherMint(s)
        \/ TakeHeld
        \/ Tick
        \/ Done

\* Safety
StallBounded == stalled <= Bound
OneBlockASlot == ~shared

\* Guards: each must be violated
NoBlocks == height = 0
ChainNeverFull == height < MaxHeight
NothingHeld == held = None
HeldNeverTaken == ~(held # None /\ held <= now + Drift /\ heldParent = height /\ Follows(held, tipSlot))
=============================================================================
