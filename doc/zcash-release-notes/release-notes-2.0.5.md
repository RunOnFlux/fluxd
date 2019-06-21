Notable changes
===============

Sprout to Sapling Migration Tool
--------------------------------
This release includes the addition of a tool that will enable users to migrate
shielded funds from the Sprout pool to the Sapling pool while minimizing
information leakage. 

The migration can be enabled using the RPC `z_setmigration` or by including
`-migration` in the `zcash.conf` file. Unless otherwise specified funds will be
migrated to the wallet's default Sapling address; it is also possible to set the 
receiving Sapling address using the `-migrationdestaddress` option in `zcash.conf`.

See [ZIP308](https://github.com/zcash/zips/blob/master/zip-0308.rst) for full details. 


New consensus rule: Reject blocks that violate turnstile
--------------------------------------------------------
In the 2.0.4 release the consensus rules were changed on testnet to enforce a
consensus rule which marks blocks as invalid if they would lead to a turnstile
violation in the Sprout or Shielded value pools.
**This release enforces the consensus rule change on mainnet**

The motivations and deployment details can be found in the accompanying
[ZIP draft](https://github.com/zcash/zips/pull/210) and
[PR 3968](https://github.com/zcash/zcash/pull/3968).

Developers can use a new experimental feature `-developersetpoolsizezero` to test
Sprout and Sapling turnstile violations. See [PR 3964](https://github.com/zcash/zcash/pull/3964) for more details.


64-bit ARMv8 support
--------------------
Added ARMv8 (AArch64) support. This enables users to build zcash on even more
devices.

For information on how to build see the [User Guide](https://zcash.readthedocs.io/en/latest/rtd_pages/user_guide.html#build)

Users on the Zcash forum have reported successes with both the Pine64 Rock64Pro
and Odroid C2 which contain 4GB and 2GB of RAM respectively.

Just released, the Odroid N2 looks like a great solution with 4GB of RAM. The
newly released Jetson Nano Developer Kit from Nvidia (also 4GB of RAM) is also
worth a look. The NanoPC-T3 Plus is another option but for the simplest/best
experience choose a board with 4GB of RAM. Just make sure before purchase that
the CPU supports the 64-bit ARMv8 architecture.

Changelog
=========

Braydon Fuller (1):
      tests: adds unit test for IsPayToPublicKeyHash method

Dimitris Apostolou (1):
      Electric Coin Company

Eirik0 (27):
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

Gareth Davies (1):
      Adding addressindex.h to Makefile.am

Ian Munoz (1):
      add curl to package list for gitian lxc container

Jack Grigg (9):
      Add Sprout support to TransactionBuilder
      depends: Use full path to cargo binary
      depends: Generalise the rust package cross-compilation functions
      depends: Add rust-std hash for aarch64-unknown-linux-gnu
      depends: Compile bdb with --disable-atomics on aarch64
      depends: Update .gitignore
      configure: Guess -march for libsnark OPTFLAGS instead of hard-coding
      Add Blossom to upgrade list
      init: Fix new HD seed generation for previously-encrypted wallets

Larry Ruane (6):
      fix enable-debug build DB_COINS undefined
      add -addressindex changes for bitcore insight block explorer
      add -spentindex changes for bitcore insight block explorer
      Update boost from v1.69.0 to v1.70.0. #3947
      add -timestampindex for bitcore insight block explorer
      3873 z_setmigration cli bool enable arg conversion

Marius Kjærstad (1):
      Update _COPYRIGHT_YEAR in configure.ac to 2019

Mary Moore-Simmons (1):
      Creates checklist template for new PRs being opened and addresses Str4d's suggestion for using GitHub handles

Simon Liu (5):
      Add testnet and regtest experimental feature: -developersetpoolsizezero
      Add qa test for experimental feature: -developersetpoolsizezero
      Enable ZIP209 on mainnet and set fallback Sprout pool balance.
      Enable experimental feature -developersetpoolsizezero on mainnet.
      Update chain work and checkpoint using block 525000.

Jack Grigg (1):
      remove extra hyphen

zebambam (1):
      Minor speling changes

