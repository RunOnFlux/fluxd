Compiling/running automated tests
---------------------------------

Automated tests will be automatically compiled if dependencies were met in configure
and tests weren't explicitly disabled.

There are two scripts for running tests:

* ``qa/flux/full_test_suite.py``, to run the main test suite
* ``uv run pytest rpc-tests/`` from the ``qa/`` directory, to run the RPC tests
  (see ``qa/rpc-tests/README.md``).

The main test suite uses two different testing frameworks. Tests using the Boost
framework are under ``src/test/``; tests using the Google Test/Google Mock
framework are under ``src/gtest/`` and ``src/wallet/gtest/``. The latter framework
is preferred for new Flux unit tests.

RPC tests are implemented in Python under the ``qa/rpc-tests/`` directory.
