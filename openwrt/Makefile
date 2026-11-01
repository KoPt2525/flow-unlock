# OpenWrt SDK package for flow-local.
#
# NOTE: this Makefile is a reference for building via the OpenWrt build system.
# It requires the SDK's Go toolchain (lang/golang) to be >= 1.24 (goproxy
# v1.9.2 requirement). If your SDK ships an older Go, cross-compile on a dev
# machine with ./build.sh and install with ./install.sh instead.
#
# To use: place this directory inside package/network/flow-local in the SDK,
# keeping the Go sources at the repository root (one level above this file).

include $(TOPDIR)/rules.mk

PKG_NAME:=flow-local
PKG_VERSION:=0.1.0
PKG_RELEASE:=1
PKG_LICENSE:=MIT

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

GO_PKG:=flow-local
GO_PKG_BUILD_PKG:=flow-local

include $(INCLUDE_DIR)/package.mk
include ../../lang/golang/golang-package.mk

define Package/flow-local
  SECTION:=net
  CATEGORY:=Network
  TITLE:=Flow local test proxy (MITM patch for Google Flow)
  DEPENDS:=@(arm||aarch64||mips||mipsel||mips64||mips64el||i386||x86_64)
endef

define Package/flow-local/description
  MITM proxy that patches the Google Flow frontend bundle to disable the
  regional /unsupported-country redirect and returns the tab to the Flow home
  page. Requires the Go toolchain >= 1.24.
endef

define Build/Prepare
	$(call Build/Prepare/Default)
	mkdir -p $(PKG_BUILD_DIR)/src/flow-local
	cp -r $(CURDIR)/.. $(PKG_BUILD_DIR)/src/flow-local/
endef

define Package/flow-local/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(GO_PKG_BUILD_BIN_DIR)/flow-local $(1)/usr/bin/flow-local
	$(INSTALL_DIR) $(1)/etc/init.d $(1)/etc/config
	$(INSTALL_BIN) ./files/etc/init.d/flow-local $(1)/etc/init.d/flow-local
	$(INSTALL_CONF) ./files/etc/config/flow-local $(1)/etc/config/flow-local
endef

$(eval $(call BuildPackage,flow-local))
