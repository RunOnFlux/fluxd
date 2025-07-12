AUTOMAKE_OPTIONS = foreign
AM_DEFAULT_SOURCE_EXT = .cpp

AM_CPPFLAGS = -I$(top_builddir)/src

noinst_LIBRARIES = libfluxsign.a
libfluxsign_a_SOURCES = fluxsign.cpp

bin_PROGRAMS = fluxsign_test
fluxsign_test_SOURCES = fluxsign_test.cpp fluxsign.h
fluxsign_test_DEPENDENCIES = libfluxsign.a
fluxsign_test_LDADD = libfluxsign.a \
    $(top_builddir)/src/libbitcoin_server.a \
    $(top_builddir)/src/libbitcoin_common.a \
    $(top_builddir)/src/secp256k1/libsecp256k1.la \
    $(top_builddir)/src/libbitcoin_util.a \
    $(top_builddir)/src/libbitcoin_wallet.a \
    $(top_builddir)/src/crypto/libbitcoin_crypto.a \
    $(SSL_LIBS) $(BOOST_LIBS) \
    $(top_builddir)/src/libflux.a $(LIBFLUX_LIBS) -lstdc++
