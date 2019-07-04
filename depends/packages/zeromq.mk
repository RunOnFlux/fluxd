package=zeromq
$(package)_version=4.3.1
$(package)_download_path=https://github.com/zeromq/libzmq/releases/download/v$($(package)_version)/
$(package)_file_name=$(package)-$($(package)_version).tar.gz
$(package)_sha256_hash=acb8d8123f22451f43287e4e053ff52e9bce5aa24b748b314ca43d8114e9b939

define $(package)_set_vars
  $(package)_config_opts=--without-documentation --disable-shared --disable-curve
  $(package)_config_opts_linux=--with-pic
  $(package)_cxxflags=-std=c++11
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE) src/libzmq.la
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install-libLTLIBRARIES install-includeHEADERS install-pkgconfigDATA
endef

define $(package)_postprocess_cmds
  rm -rf bin share
endef
