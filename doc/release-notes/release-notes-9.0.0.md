Changelog
=========

Tadeas Kmenta (2):
      make-release.py: Versioning changes for 9.0.0.
      make-release.py: Updated manpages for 9.0.0.

Tom Moulton (1):
      Fix ubuntu upgrade24 (#238)

Jeremy "Blondfrogs" Anderson (44):
      All the core PON logic
      Network configuration for PON
      PON block structure extenstions
      PON validation and consensus integration
      Update RPC, and block creation logic of PON
      Update make file and depends libevent
      Update transactiondb logic, snapshot bug, fluxnode PON checks
      Update test, add PON tests
      Fix chainparams
      Remove duplicate, commented out, not needed
      Add dev payment enforcement
      Add stricter checks for dev fun amount
      Add delegates to start transactions
      Add delegates gtest
      Update confirm and expiration heights for new block time
      Update const variables for new PON block timing
      Remove not needed function
      Make sure headers can sync without failing  because of signatures
      Add timestamp verification
      Update protocol version
      Add emergenecy block production mechanism
      Add dev payout addresses, add testnet bypass
      Update qa test to python3, get emergency block test working
      Make sure we have the same branchid
      Add additional logging, and extra cache validation
      Add delegate rpc calls, fix benchmark bypass on testnet
      Allow fluxnode management calls to happen more often
      make difficulty adjustmnet smoother, fix txdb checks, add bett PON hash validation logic
      Update Emergency Block to bypass hash check
      Update ponLimits in chainparams
      update time in pon minter to use GetTime()
      Add timing randomization to pon minter
      Fix testnet diff check for fork range
      Check for edgecase when devpayout address, is also running a fluxnode, not double counting amounts
      Fix rpc calls create valid delegates update transactions for p2sh, and normal nodes
      Add delegate info to cacheing system
      add rpc to start a p2sh fluxnode as a delegate
      Update rpcs calls
      Delegrate rpc calls support vps publickey
      Update minter
      Clean up from devleopment and testing
      Clean up couple more items
      Final Code Review Completed, add last items
      Update release height for PON

