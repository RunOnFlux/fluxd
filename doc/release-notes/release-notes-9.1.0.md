Changelog
=========

David White (6):
      fix: detect corrupt block index entries during load (#276)
      fix: null-terminate readlink buffer before dirname call (#275)
      listfluxnodedelegates rpc (#271)
      Feature: zmq realtime events (#273)
      fix: port Bitcoin Core network resilience to prevent p2p stalls (#274)
      Clean up PR #278 review findings (#279)

Jeremy Anderson (4):
      Compact Headers & Compact Blocks - BIP 152 Implementation (#266)
      Batch write fluxnode db (#269)
      Write to disk on next block after tip disconnected (#244)
      Perf/ibd speedups (#277)

Tadeas Kmenta (3):
      improve delegates starting (#270)
      make-release.py: Versioning changes for 9.1.0.
      make-release.py: Updated manpages for 9.1.0.

Jeremy "Blondfrogs" Anderson (16):
      Upgrade to C++17 and remove Boost dependencies (Phase 1 & 2)
      Remove Boost dependencies Phase 3
      Remove Boost dependencies Phase 4
      Remove Boost dependencies Phase 5
      Remove Boost dependencies Phase 6
      Remove Boost dependencies Phase 7
      Upgrade to C++20, Remove Boost dependencies Phase 8
      Remove Boost dependencies Phase 9
      Remove Boost build code
      Upgrade OpenSSL from 1.1.1a to 3.5.4 LTS
      Update and fix for github build
      Add extra signature checks
      Block sig checks more robust
      Make emergency checks more robust
      Make p2p fluxnode transactions more robust
      Remove Boost dependencies from post-branch tests

