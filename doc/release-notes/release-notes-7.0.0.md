Changelog
=========

Tadeas Kmenta (3):
      Update .travis.yml
      make-release.py: Versioning changes for 7.0.0.
      make-release.py: Updated manpages for 7.0.0.

Tadeas Kmenta (1):
      update download url

Tom Moulton (2):
      Revert "Revert "Patch boost thread_data for ubuntu 21.10 build""
      Updated test code to use additional coins to test limits of MAX_MONEY all GTests now pass again 100%

Jeremy "Blondfrogs" Anderson (34):
      Start P2SH fluxnodes
      Add support for new fluxnode tx format, create fork code
      Add all core checks for P2SH nodes
      Add Google Test for P2SH nodes
      Tests, and fixes
      Add better logging
      Make comparison == instead of XOR
      Build rpc calls for building, signing, sending p2shnode start transactions
      Add descriptions to new rpc calls
      Update timestamp to match block hash timestamp
      Remove XOR
      Rename 1
      Rename 2
      Rename 3
      Remove collateralpubkey in p2sh start txes
      Remove collateralpub req when p2sh, add additional checks
      Add latest benchmark key
      Set new testnet chainparams for 1 minute blocks
      Add new testnet block into chainparams
      upgrade.cpp
      Update proto version, and testnet blockchain checks
      Add rawtransaction json
      Remove maptxheighttracker, add some logging
      Remove DosHeights tracker map
      Make a uint so we can use the 8th bit
      Not change type, do bitmask check
      Update timestamp for new publickey
      Flux defaults to version 5 tx
      Fix rpc bug, fix regtest
      GTests now pass 100%
      Update MAX_MONEY to correct value
      Createconfirmationtransaction now gets fluxbench sign, and broadcasts
      Final timestamp, blockheight for P2SH Fork
      add back inital blockchain sync check

