#
# Top level makefile for example application
#

include $(TOPDIR)/rules.mk

PKG_NAME:=maclist
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

include $(INCLUDE_DIR)/package.mk

define Package/maclist
  SECTION:=utils
  DEPENDS:=+libsqlite3 +libpthread +libcurl +libjson-c
  CATEGORY:=Utilities
  TITLE:=maclist -- prints maclist 1 to 99
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Build/Configure
endef

TARGET_CFLAGS += $(FPIC)

define Package/maclist/install
	$(INSTALL_DIR) $(1)/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/maclist $(1)/bin/
endef

$(eval $(call BuildPackage,maclist))
