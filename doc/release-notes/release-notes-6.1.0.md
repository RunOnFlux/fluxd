Changelog
=========

Tadeas Kmenta (6):
      use crosscompile for arm
      fix make release script
      fix man-pages script
      fix travis packing
      make-release.py: Versioning changes for 6.1.0.
      make-release.py: Updated manpages for 6.1.0.

Tadeas Kmenta (4):
      arm arch adjust token
      rename batch 1
      renames
      rename gitian

Tom Moulton (36):
      Issue #170 initial task
      handle rest of push_back(Pair( to pushKV
      zelnode to fluxnode
      Zelnode to Fluxnode
      Final zelnode to fluxnode changes
      finish rpc call duplicating and renaming
      fix bug in issue 175 - testing required
      first round of zelcash changes
      clean up rpc name changes, more renaming
      odd no changes
      node rank 0 is highest not 1
      fix typo in conflict resolution, also ran gtest
      rename rpc functions to flux so zel is only in wrappers
      use __func__ for function name
      allow building on Ubuntu21.10
      do not rename files in data sir yet, they need to be migrated
      Revert some zel changes we are not ready for
      Added Flux Dev Copyright to src and src/rpc
      Add Flux Copyright to all files with no existing LICENSE or COPYING file
      Update generated Copyright message
      Fix copyright added out of order
      Fix LICENSE and COPYING
      Fix (C) to (c) like the other notices
      Added runtime error if not fFluxnode for good measure, other RPC calls use it too
      Make bui8ld targets flux based
      gtest now runs as flux-gtest and passes
      missed automake zel to flux
      point to runonflux github
      Update travis.yml some missed zelcash->flux comments (mostly) Update Copyright on edited files
      rename bitcoin cpp files to flux
      debug
      make sure fluxd is built
      Can not strip arm images
      Remove incorect throw errors
      rename rcp/zelnode.cpp to fluxnode.cpp
      zelcash package to flux, update year, github issue link

Jeremy "Blondfrogs" Anderson (13):
      Fix network not populating on flux node list when using multiport
      Add blondfrogs flux-seeder to mainnet chainparams
      Stop spam on useless logs
      Add ability to create snapshots
      Height and Timestamp are both accepted for snapshot call
      Patch boost thread_data for ubuntu 21.10 build
      Sendfrom rpc, now works with given address
      Add rpc for consolidating utxo from a single address
      Add index check
      Fix sendfrom, sendmany
      Fix rename on existing configuration flag
      Add ban for unprocessable transactions
      Ability for mempool to remove transactions that fail block validity

johnhanlon86 (2):
      Updated Zel/Zelcash to Flux in comments only. Some old URLs also updated.
      Updated ReadMe.

