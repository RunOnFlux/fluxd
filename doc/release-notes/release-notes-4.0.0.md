Jeremy "Blondfrogs" Anderson (39):
      Fix wallet finding ZelNode vin
      Fix gbt transactions
      Fix migration tool not finding default address private key
      Zcash Merge Fixes
      Add ZelNode fork code
      Benchmarking - ZelBenchd
      Deterministic ZelNodes
      Fix Broken gtests
      Fix blocks not being recjected if not paying out nodes (deterministic)
      Fix payouts (deterministic)
      Update mempool zelnode tx tracking (deterministic)
      Fix ZelNode comparator (deterministic)
      Fix Windows build (deterministic)
      Fix ZelNode confirm tx sig failure (deterministic)
      Fix Zelnode tx failing on out of order blocks (deterministic)
      More future block checks (deterministic)
      Move deterministic ZeLnode database with cointips databases (deterministic)
      Update some zelnode rpc calls for deterministic
      Fix GetNextPayment loop bug (deterministic)
      Update min chain work for mainnet (deterministic)
      Update rpc calls, fix typo (deterministic)
      Fix available coins not showing up
      Update getzelnodeoutput to return outs at all depths
      update rpc calls
      update rpc data for zelnode and zelmate
      update listzelnodeconfs
      update error messages on zelnode failure to start
      only show confirmed nodes in zelnode list rpc
      fix broken gtests (again)
      Move ZelNode ints from int64_t to unit32_t
      Add ip address to zelnode update transactions
      fix zelnode check if statement
      add ip address to confirm transaction
      add multiple pathing for zelbenchd and cli
      add zelbench pathing checks in init
      stop old zelnode messages after upgrade goes live
      Remove ip from start tx
      add comment zelnode code

Tadeas Kmenta (20):
      Extend RPC
      Add confirmations, time to z_listreceivedbyaddress
      Correct sapling confs and time
      add blockinformation to zelnode txs
      fix zelnode update_type in rpc
      Minor corrections
      make collateral in viewdeterministic full length
      add GetTxHash, GetTxIndex to COutPoint viewdeterministiczelnodelist, filtering, txhash, txindex, help
      add network information to viewdet list
      add checkpoint, add activations heights correct net for testnet correct deprecation make testnet closer to mainnet
      Rename benchmard to zelbenchd
      fix wrong file name
      fix comma typo
      update mainnet testnet benchmarks pub keys
      mine new testnet
      fix testnet checkpoint
      testnet - lower activation blocks
      remove bench stuff
      updating ip address
      set actviation on 18th of March

Miles Manley (7):
      Zcash Upstream port
      Release notes, Versioning, naming
      Kamata Network Upgrade
      Set configure.ac v4.0.0
      Update libsodium install path - to work for macOS builds
      Kamata Readme
      Kamata Release notes
