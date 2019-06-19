Notable Zel changes
===============

New PoW algo: ZelHash
------------------------------------------
ZelHash is a modified varient of Equihash 125_4 (more info and links to paper here)

ZelNodes 
---------------------------------------
Restructured zelnode winner votes from casting 30 votes to 10 votes per zelnode tier.
Votes are only cast and accept by zelnodes of the same tier e.g. (Basic are voting for Basic’s)
Moved required zelnodes votes for mandatory payout checks from 16 to 6 votes
Update zelnode sync to retry more effectively when failing to sync
Added additional logging to help trace why some nodes are failing to sync the zelnode data


Upstream Zcash - v2.0.5-2
------------------------------------------
Upstreamed Zcash including from v2.0.3 up to v2.0.5-2

Changelog 
=========

Jeremy "Blondfrogs" (2)
      ZelNodes fix
      GetBlockTemplate fix

Miles Manley (3)
      Upstream Zcash
      Docs
      Testnet
      
Wilke "Lollidieb" Trei (1)
      Implementation of ZelHash

Notable Zcash changes
===============


Sprout note validation bug fixed in wallet
------------------------------------------
We include a fix for a bug in the Zcashd wallet which could result in Sprout
z-addresses displaying an incorrect balance. Sapling z-addresses are not
impacted by this issue. This would occur if someone sending funds to a Sprout
z-address intentionally sent a different amount in the note commitment of a
Sprout output than the value provided in the ciphertext (the encrypted message
from the sender).

Users should install this update and then rescan the blockchain by invoking
“zelcashd -rescan”. Sprout address balances shown by the zelcashd wallet should
then be correct.

Thank you to Alexis Enston for bringing this to our attention.

[Security Announcement 2019-03-19](https://z.cash/support/security/announcements/security-announcement-2019-03-19/)

[Pull request](https://github.com/zcash/zcash/pull/3897)

Miner address selection behaviour fixed
---------------------------------------
Zcash inherited a bug from upstream Bitcoin Core where both the internal miner
and RPC call `getblocktemplate` would use a fixed transparent address, until RPC
`getnewaddress` was called, instead of using a new transparent address for each
mined block.  This was fixed in Bitcoin 0.12 and we have now merged the change.

Miners who wish to use the same address for every mined block, should use the
`-mineraddress` option. 

[Mining Guide](https://zcash.readthedocs.io/en/latest/rtd_pages/zcash_mining_guide.html)


New consensus rule: Reject blocks that violate turnstile (Testnet only)
-----------------------------------------------------------------------
Testnet nodes will now enforce a consensus rule which marks blocks as invalid
if they would lead to a turnstile violation in the Sprout or Sapling value
pools. The motivations and deployment details can be found in the accompanying
[ZIP draft](https://github.com/zcash/zips/pull/210).

The consensus rule will be enforced on mainnet in a future release.

[Pull request](https://github.com/zcash/zcash/pull/3885)


Changelog
=========

Braydon Fuller (1):
      tests: adds unit test for IsPayToPublicKeyHash method

Dimitris Apostolou (1):
      Electric Coin Company

Eirik Ogilvie-Wigley (41):
      Rename methods to include Sprout
      Add benchmark for decrypting sapling notes
      Move reusable Sapling test setup to utiltest
      Move test SaplingNote creation to utiltest
      Add test method for generating master Sapling extended spending keys
      Include Sapling transactions in increment note witness benchmark
      Prevent header from being included multiple times
      benchmarks do not require updating network parameters
      FakeCoinsViewDB can inherit directly from CCoinsView
      Add a method for generating a test CKey
      Change to t->z transaction and create separate benchmark for sapling
      Renaming and other minor cleanup
      Improve some error messages when building a transaction fails
      Add missing author aliases
      Split test in to multiple parts
      Use a custom error type if creating joinsplit descriptions fails
      Rename and update comment
      Add rpc to enable and disable Sprout to Sapling migration
      Move migration logic to ChainTip
      Documentation cleanup
      Additional locking and race condition prevention
      Refactor wait_and_assert_operationid_status to allow returning the result
      Set min depth when selecting notes to migrate
      Check for full failure message in test case
      Add migration options to conf file
      Create method for getting HD seed in RPCs
      Add rpc to get Sprout to Sapling migration status
      Fix help message
      Test migration using both the parameter and the default Sapling address
      Fix typos and update documentation
      use -valueBalance rather than vpub_new to calculate migrated amount
      Do not look at vin/vout when determining migration txs and other cleanup
      Calculate the number of confimations in the canonical way
      Do not throw an exception if HD Seed is not found when exporting wallet
      make-release.py: Versioning changes for 2.0.5-rc1.
      make-release.py: Updated manpages for 2.0.5-rc1.
      make-release.py: Updated release notes and changelog for 2.0.5-rc1.
      Notable changes for v2.0.5
      Add missing word to release notes
      make-release.py: Versioning changes for 2.0.5.
      make-release.py: Updated manpages for 2.0.5.

Gareth Davies (2):
      Correcting logo on README
      Adding addressindex.h to Makefile.am

Ian Munoz (1):
      add curl to package list for gitian lxc container

Jack Grigg (15:
      Add Sapling benchmarks to benchmark runner
      test: Fetch coinbase address from coinbase UTXOs
      test: Make expected_utxos optional in get_coinbase_address()
      Add comments
      Move utiltest.cpp from wallet to common
      Move payment disclosure code and tests into wallet
      remove extra hyphen
      Add Sprout support to TransactionBuilder
      depends: Use full path to cargo binary
      depends: Generalise the rust package cross-compilation functions
      depends: Add rust-std hash for aarch64-unknown-linux-gnu
      depends: Compile bdb with --disable-atomics on aarch64
      depends: Update .gitignore
      configure: Guess -march for libsnark OPTFLAGS instead of hard-coding
      Add Blossom to upgrade list
      init: Fix new HD seed generation for previously-encrypted wallet

Jonas Schnelli (4):
      detach wallet from miner
      fix GetScriptForMining() CReserveKey::keepKey() issue
      add CReserveScript to allow modular script keeping/returning
      miner: rename UpdateRequestCount signal to ResetRequestCount

Jonathan "Duke" Leto (2):
      Backport size_on_disk to RPC call getblockchaininfo.
      Add size_on_disk test

Larry Ruane (6):
      fix enable-debug build DB_COINS undefined
      add -addressindex changes for bitcore insight block explorer
      add -spentindex changes for bitcore insight block explorer
      Update boost from v1.69.0 to v1.70.0. #3947
      add -timestampindex for bitcore insight block explorer
      3873 z_setmigration cli bool enable arg conversion

Marius Kjærstad (2):
      Update COPYRIGHT_YEAR in clientversion.h to 2019
      Update _COPYRIGHT_YEAR in configure.ac to 2019

Mary Moore-Simmons (1):
      Creates checklist template for new PRs being opened and addresses Str4d's suggestion for using GitHub handles

Paige Peterson (1):
      redirect and update source documentation

Pieter Wuille (1):
      Simplify DisconnectBlock arguments/return value

Sean Bowe (13):
      (testnet) Fall back to hardcoded shielded pool balance to avoid reorgs.
      (testnet) Reject blocks that result in turnstile violations
      (testnet/regtest) Avoid mining transactions that would violate the turnstile.
      Fix tallying for Sprout/Sapling value pools.
      Consolidate logic to enable turnstile auditing for testnet/regtest/mainnet.
      Use existing chainparams variable
      Add newlines to turntile log messages for miner
      Check blockhash of fallback block for Sprout value pool balance
      Change SproutValuePoolCheckpointEnabled to ZIP209Activated
      Only enforce Sapling turnstile if balance values have been populated.
      Do not enable ZIP209 on regtest right now.
      (minor) Remove added newline.
      (wallet) Check that the commitment matches the note plaintext provided by the sender.

Simon Liu (14):
      Update nMinimumChainWork using block 497000.
      Add checkpoint for block 497000.
      Update release notes for 2.0.4
      make-release.py: Versioning changes for 2.0.4-rc1.
      make-release.py: Updated manpages for 2.0.4-rc1.
      make-release.py: Updated release notes and changelog for 2.0.4-rc1.
      Fix typo in release notes.
      make-release.py: Versioning changes for 2.0.4.
      make-release.py: Updated manpages for 2.0.4.
      Add testnet and regtest experimental feature: -developersetpoolsizezero
      Add qa test for experimental feature: -developersetpoolsizezero
      Enable ZIP209 on mainnet and set fallback Sprout pool balance.
      Enable experimental feature -developersetpoolsizezero on mainnet.
      Update chain work and checkpoint using block 525000.

Taylor Hornby (8):
      Update OpenSSL from 1.1.0h to 1.1.1a. #3786
      Update boost from v1.66.0 to v1.69.0. #3786
      Update Rust from v1.28.0 to v1.32.0. #3786
      Update Proton from 0.17.0 to 0.26.0. #3816, #3786
      Patch Proton for a minimal build. #3786
      Fix proton patch regression. #3916
      Fix OpenSSL reproducible build regression
      Patch out proton::url deprecation as workaround for build warnings

sandakersmann (1):
      Update of copyright year to 2019

zebambam (3):
      Minor speling changes
      Added documentation warnings about DNS rebinding attacks, issue #3841
      Added responsible disclosure statement for issue #3869

