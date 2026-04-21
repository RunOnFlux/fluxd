package=jemalloc
$(package)_version=5.3.0
$(package)_download_path=https://github.com/jemalloc/jemalloc/releases/download/$($(package)_version)
$(package)_file_name=$(package)-$($(package)_version).tar.bz2
$(package)_sha256_hash=2db82d1e7119df3e71b7640219b6dfe84789bc0537983c3b7ac4f7189aecfeaa

define $(package)_config_cmds
  $($(package)_autoconf) --enable-static --disable-shared
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
