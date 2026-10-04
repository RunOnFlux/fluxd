# `xcrun -f clang` resolves to the real compiler inside XcodeDefault.xctoolchain,
# not the /usr/bin/clang shim. The shim is what normally exports SDKROOT before
# exec'ing the compiler; invoked directly the driver does not locate the macOS
# SDK on its own, so the link step fails with "ld: library 'System' not found".
# Every package built for the build machine (native_*) uses these, so pin the
# sysroot explicitly rather than relying on the shim's environment.
darwin_SDK_PATH:=$(shell xcrun --show-sdk-path)

build_darwin_CC:=$(shell xcrun -f clang) -isysroot $(darwin_SDK_PATH)
build_darwin_CXX:=$(shell xcrun -f clang++) -isysroot $(darwin_SDK_PATH)
build_darwin_AR:=$(shell xcrun -f ar)
build_darwin_RANLIB:=$(shell xcrun -f ranlib)
build_darwin_STRIP:=$(shell xcrun -f strip)
build_darwin_OTOOL:=$(shell xcrun -f otool)
build_darwin_NM:=$(shell xcrun -f nm)
build_darwin_INSTALL_NAME_TOOL:=$(shell xcrun -f install_name_tool)
build_darwin_SHA256SUM = shasum -a 256
build_darwin_DOWNLOAD = curl --location --fail --connect-timeout $(DOWNLOAD_CONNECT_TIMEOUT) --retry $(DOWNLOAD_RETRIES) -o

# config.sub canonicalises Apple Silicon to aarch64; Apple's toolchain spells the
# same CPU arm64. Passing the triple explicitly means an Apple Silicon machine
# can still produce an x86_64 build (HOST=x86_64-apple-darwin) and vice versa,
# instead of silently building whatever the host CPU happens to be.
darwin_TARGET=$(subst aarch64,arm64,$(firstword $(subst -, ,$(canonical_host))))-apple-darwin

#darwin host on darwin builder. overrides darwin host preferences.
darwin_CC:=$(shell xcrun -f clang) -target $(darwin_TARGET) -mmacosx-version-min=$(OSX_MIN_VERSION) -isysroot $(darwin_SDK_PATH)
darwin_CXX:=$(shell xcrun -f clang++) -target $(darwin_TARGET) -mmacosx-version-min=$(OSX_MIN_VERSION) -stdlib=libc++ -isysroot $(darwin_SDK_PATH)
darwin_AR:=$(shell xcrun -f ar)
darwin_RANLIB:=$(shell xcrun -f ranlib)
darwin_STRIP:=$(shell xcrun -f strip)
darwin_LIBTOOL:=$(shell xcrun -f libtool)
darwin_OTOOL:=$(shell xcrun -f otool)
darwin_NM:=$(shell xcrun -f nm)
darwin_INSTALL_NAME_TOOL:=$(shell xcrun -f install_name_tool)
darwin_native_toolchain=
