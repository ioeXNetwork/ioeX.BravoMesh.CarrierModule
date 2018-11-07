include environ/$(HOST)-$(ARCH).mk
include environ/gitlab.mk

GITLAB_PACKAGE_NAME   = c-toxcore
GITLAB_PACKAGE_URL    = http://$(GITLAB_USERNAME):$(GITLAB_PASSWORD)@git.pin2wall.com/P2PNetwork/$(GITLAB_PACKAGE_NAME).git
GITLAB_PACKAGE_BRANCH = v0.6.0
SRC_DIR        = $(DEPS_DIR)/$(GITLAB_PACKAGE_NAME)

CONFIG_COMMAND = $(shell scripts/toxcore.sh "command" $(HOST) $(ARCH) $(HOST_COMPILER))
CONFIG_OPTIONS = --prefix=$(DIST_DIR) \
        --with-dependency-search=$(DIST_DIR) \
        --enable-static \
        --disable-shared \
        --disable-ntox \
        --disable-daemon \
        --disable-tests \
        --disable-testing \
        --disable-av

define configure
    if [ ! -e $(SRC_DIR)/configure ]; then \
        cd $(SRC_DIR) && ./autogen.sh; \
    fi
    cd $(SRC_DIR) && CFLAGS="${CFLAGS} -fvisibility=hidden -DELASTOS_BUILD" $(CONFIG_COMMAND) $(CONFIG_OPTIONS)
endef

include modules/rules.mk


