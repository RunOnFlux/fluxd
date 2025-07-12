AUTOMAKE_OPTIONS = foreign
AM_DEFAULT_SOURCE_EXT = .cpp

libfluxsign_a_CPPFLAGS = -I$(top_builddir)/src

noinst_LIBRARIES = libfluxsign.a
libfluxsign_a_SOURCES = fluxsign.cpp

bin_PROGRAMS = fluxsign_test
flux_sign_test_SOURCES = fluxsign_test.cpp fluxsign.h
flux_sign_test_LDADD = libfluxsign.a \
    $(top_builddir)/src/libbitcoin_server.a \
    $(top_builddir)/src/libbitcoin_common.a \
    $(top_builddir)/src/secp256k1/libsecp256k1.la \
    $(top_builddir)/src/libbitcoin_util.a \
    $(top_builddir)/src/libbitcoin_wallet.a \
    $(top_builddir)/src/libbitcoin_crypto.a \
    $(SSL_LIBS) $(BOOST_LIBS) \
    $(top_builddir)/src/libflux.a $(LIBFLUX_LIBS) -lstdc++

