package=boost
$(package)_version=1_83_0
$(package)_download_path=https://boostorg.jfrog.io/artifactory/main/release/1.83.0/source
$(package)_file_name=$(package)_$($(package)_version).tar.bz2
$(package)_sha256_hash=6478edfe2f3305127cffe8caf73ea0176c53769f4bf1585be237eb30798c3b8e
$(package)_patches=darwin.diff
$(package)_patches_darwin=darwin.diff
$(package)_patches_linux=

define $(package)_set_vars
endef

define $(package)_preprocess_cmds
  echo "Boost preprocessing - no patches needed for this platform"
endef

define $(package)_preprocess_cmds_darwin
  patch -p1 < $($(package)_patch_dir)/darwin.diff
endef

define $(package)_config_cmds
  echo "Header-only install, skipping bootstrap"
endef

define $(package)_build_cmds
  echo "Header-only install, skipping build"
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/include && \
  cp -r boost $($(package)_staging_prefix_dir)/include
endef
