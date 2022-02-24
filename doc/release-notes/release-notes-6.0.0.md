Changelog
=========

Tadeas Kmenta (2):
      make-release.py: Versioning changes for 6.0.0.
      make-release.py: Updated manpages for 6.0.0.

Jeremy "Blondfrogs" Anderson (17):
      rebuild zelnodedb now using correct tier amount looping
      Add new zelnode amounts, and check the amounts when started
      Enforce collateral checks, update node cache data to include collateral when added as a new start node
      Add testnet chainparams for halving, update protocol version, add halving upgrade
      Only expire nodes based on collateral during the transition period
      Change min and max confirmation requirements, add new rpc call to get migration count
      Fix getstartlist rpc
      Add branchId
      Add version to metrics screen, update copywrite year
      Add P2SH fluxnode
      Make checks safer
      Update rpc calls to fetch correct p2sh address
      Don't DOS peers while syncing because of tx
      Don't request tx while in initial download
      Add mainnet halving activation dates and block heights
      Start halving fork block#1076532
      Increase IP size

