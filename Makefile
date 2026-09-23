# ****************************************************************************
#    ZKNOX
#    (c) 2025 ZKNOX SAS.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ****************************************************************************

ifeq ($(BOLOS_SDK),)
$(error Environment variable BOLOS_SDK is not set)
endif

include $(BOLOS_SDK)/Makefile.target

########################################
#        Mandatory configuration       #
########################################
# Application name
APPNAME = "ZKNOX"

# Application version
APPVERSION_M = 0
APPVERSION_N = 1
APPVERSION_P = 0
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

# Expose MAJOR/MINOR/PATCH as compile-time defines so handler_version.c
# can return them as 3 bytes in the GET_VERSION response (INS=0x03).
DEFINES += APPVERSION_M=$(APPVERSION_M)
DEFINES += APPVERSION_N=$(APPVERSION_N)
DEFINES += APPVERSION_P=$(APPVERSION_P)

# Application source files
APP_SOURCE_PATH += src

# ── ZKNOX libC submodule — Backend toggle ───────────────────────────
# BACKEND selects how big-number / Montgomery arithmetic is executed:
#
#   cx
#     Use the Ledger SDK syscalls (cx_bn_* / cx_mont_*) via the zkn_bn.h
#     router macros. Leverages the BOLOS secure-element primitives.
#
#   sw (default)
#     Use the pure-software implementation (zkn_bn_sw.c, ARM ASM via
#     zkn_mont256_arm32.S). No BOLOS BN pool pressure. Useful for:
#       - debugging when BOLOS BN pool overflow is suspected
#       - cross-validating against the cx backend (run both, compare)
#       - targeting non-Ledger ARM platforms from the same code
#
# Usage:
#   make                   → BACKEND=sw
#   make BACKEND=cx        → BOLOS syscalls
#
BACKEND ?= sw

ifeq ($(BACKEND),cx)
    DEFINES += ZKN_BN_BACKEND_LEDGER
else ifeq ($(BACKEND),sw)
    DEFINES += ZKN_BN_BACKEND_SW
    DEFINES += ZKN_RNG_BOLOS
else
    $(error Invalid BACKEND=$(BACKEND). Use BACKEND=cx or BACKEND=sw)
endif

# Announce backend ONCE per top-level make invocation. The SDK
# re-evaluates this Makefile in sub-makes; the guard variable
# (exported to the environment) prevents duplicate banners.
ifndef ZKNOX_BACKEND_ANNOUNCED
    ifeq ($(BACKEND),cx)
        $(info ZKNOX backend: cx_bn_* / cx_mont_* via Ledger SDK syscalls (hard))
    else
        $(info ZKNOX backend: zkn_bn_sw / zkn_mont256_arm32 pure software (soft))
    endif
    export ZKNOX_BACKEND_ANNOUNCED := 1
endif

# ── ZKNOX_DEBUG toggle ──────────────────────────────────────────────
# Gates the test and introspection surface: BLIND_SIGN_NO_DISPLAY (0x02),
# SIGN_WITH_PRIVKEY (0x50), and the two DKG INSes that export secrets
# (0x68, 0x69). Production (MODE=prod, the default) defines none of them.
#
# Ledger's VS Code extension expresses its Build Mode selector as DEBUG=1
# rather than passing this app's MODE variable. Map that standard selector
# when MODE was not supplied explicitly, so choosing "Debug" in the
# extension actually builds the debug APDU surface the test suites need.
ifeq ($(DEBUG),1)
    MODE ?= debug
else
    MODE ?= prod
endif
ifeq ($(MODE),debug)
    DEFINES += ZKNOX_DEBUG
    DEFINES += ZKNOX_MODE_DEBUG
else ifeq ($(MODE),prod)
    # No debug INSes. ZKNOX_MODE_PROD is set so constants.h can hard-#error
    # on a stray `-DZKNOX_DEBUG` that would otherwise smuggle the raw-privkey
    # and no-UI-sign handlers into a production binary.
    DEFINES += ZKNOX_MODE_PROD
else
    $(error Invalid MODE=$(MODE). Use MODE=prod (default) or MODE=debug)
endif
ifndef ZKNOX_MODE_ANNOUNCED
    $(info ZKNOX mode: $(MODE)$(if $(filter debug,$(MODE)), — debug-only INSes enabled,))
    export ZKNOX_MODE_ANNOUNCED := 1
endif

# ── ZKN_FROST toggle ────────────────────────────────────────────────
# Threshold signing: the VSS/DKG ceremony (0x60-0x6b bar the two DEBUG
# ones) and FROST on its output (0x70-0x72). Independent of MODE, because
# the two answer different questions: MODE says whether the test and
# introspection INSes are present, FROST says whether the ceremony is.
#
# Key extraction (DKG_DEBUG_SKSHARE, DKG_DEBUG_COMM_PRIVKEY) stays behind
# ZKNOX_DEBUG whatever FROST is set to.
#
# Debug defaults to the ceremony-enabled test surface. Production always
# defaults to FROST=0 and currently refuses FROST=1 — the blocking list in
# src/zkn_features.h must be cleared before threshold authority can ship.
# The safe development combinations remain expressible:
#     make MODE=debug FROST=0    debug surface without the ceremony
#     make MODE=debug FROST=1    debug ceremony / signing tests
ifeq ($(MODE),debug)
    FROST ?= 1
else
    FROST ?= 0
endif
ifeq ($(FROST),1)
    ifeq ($(MODE),prod)
        $(error MODE=prod FROST=1 is disabled: see the BLOCKING list in src/zkn_features.h)
    endif
    DEFINES += ZKN_FROST
endif
ifndef ZKNOX_FROST_ANNOUNCED
    $(info ZKNOX frost: $(if $(filter 1,$(FROST)),on — VSS/DKG + FROST signing,off))
    export ZKNOX_FROST_ANNOUNCED := 1
endif

# Bind every SDK artifact to the complete security-relevant configuration.
# Ledger's Makefile.target initially derives these as build/<target>/{obj,...};
# overriding the derived directories before Makefile.standard_app is included
# prevents a BACKEND/MODE/FROST switch from reusing stale object files.
TARGET_BUILD_DIR := build/$(TARGET)/$(BACKEND)/$(MODE)/frost-$(FROST)
BIN_DIR          := $(TARGET_BUILD_DIR)/bin
OBJ_DIR          := $(TARGET_BUILD_DIR)/obj
DBG_DIR          := $(TARGET_BUILD_DIR)/dbg
DEP_DIR          := $(TARGET_BUILD_DIR)/dep
GEN_SRC_DIR      := $(TARGET_BUILD_DIR)/gen_src

# NOTE: no source exclusion here — the SDK has no APP_SOURCES_EXCLUDE variable,
# so any such line is a no-op. Host-only files under src/zknox/ exclude
# themselves via #ifdef ZKN_HOST_TESTS / #ifdef ZKN_HOST_BUILD.
# ────────────────────────────────────────────────────────────────────

# Application icons following guidelines:
# https://developers.ledger.com/docs/embedded-app/design-requirements/#device-icon
ICON_NANOX = icons/app_zknox_14px.gif
ICON_NANOSP = icons/app_zknox_14px.gif
ICON_STAX = icons/app_zknox_32px.gif
ICON_FLEX = icons/app_zknox_40px.gif
ICON_APEX_P = icons/app_zknox_32px_apex.png

ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_NANOX TARGET_NANOS2))
    ICON_HOME_NANO = glyphs/home_zknox_14px.gif
endif

# Application allowed derivation curves.
#
# ed25519 covers both the twisted-Edwards signing key and the DKG transport
# identity. secp256k1 is deliberately absent: this app signs nothing on a
# secp256k1 curve, so BOLOS itself refuses any such derivation, independently
# of the firmware.
CURVE_APP_LOAD_PARAMS = ed25519

# Application allowed derivation paths.
#
#   44'/1984'   signing key (twisted Edwards)
#   421'/1984'  DKG transport identity (Ed25519), never exported
#
# 1984' is the ZKNOX namespace coin type; the exact path constants live in
# the libC (src/zknox/src/keys/zkn_keyderivation.h) so that every ZKNOX app
# derives the same key from the same seed for a given account index. The
# host supplies only the account index — the path itself is firmware-fixed
# and fully hardened.
# 44' spending, 420' viewing (exported for scanning + 0zk address), 421' DKG comm.
PATH_APP_LOAD_PARAMS = "44'/1984'" "420'/1984'" "421'/1984'"

VARIANT_PARAM = COIN
VARIANT_VALUES = BOL

# Use ARM Thumb-2 ASM for zkn_mont256 core functions.
DEFINES += ZKN_MONT256_ASM

########################################
#     Application custom permissions   #
########################################
#HAVE_APPLICATION_FLAG_DERIVE_MASTER = 1
#HAVE_APPLICATION_FLAG_GLOBAL_PIN = 1
#HAVE_APPLICATION_FLAG_BOLOS_SETTINGS = 1
#HAVE_APPLICATION_FLAG_LIBRARY = 1

########################################
# Application communication interfaces #
########################################
ENABLE_BLUETOOTH = 1
#ENABLE_NFC = 1
ENABLE_NBGL_FOR_NANO_DEVICES = 1

########################################
#         NBGL custom features         #
########################################
ENABLE_NBGL_QRCODE = 1
#ENABLE_NBGL_KEYBOARD = 1
#ENABLE_NBGL_KEYPAD = 1

########################################
#          Features disablers          #
########################################
#DISABLE_STANDARD_APP_FILES = 1

# Custom CA private key for sideloading without device confirmation.
SCP_PRIVKEY ?=
ifneq ($(SCP_PRIVKEY),)
    APP_LOAD_PARAMS += --rootPrivateKey $(SCP_PRIVKEY)
endif

include $(BOLOS_SDK)/Makefile.standard_app

# ── ZKNOX defines (must come AFTER include) ─────────────────────────
# The SDK's `DEFINES` -> `-D...` translation happens inside
# Makefile.standard_app. For safety against SDK quirks, ALSO inject the
# backend selector into CFLAGS directly here so the preprocessor sees the
# right backend define unconditionally.
ifeq ($(BACKEND),cx)
    CFLAGS  += -DZKN_BN_BACKEND_LEDGER
else
    CFLAGS  += -DZKN_BN_BACKEND_SW
endif
CFLAGS  += -DZKN_MONT256_ASM

# Same belt-and-braces for ZKNOX_DEBUG: inject into CFLAGS directly so
# DEFINES propagation through the SDK can't accidentally drop it.
ifeq ($(MODE),debug)
    CFLAGS  += -DZKNOX_DEBUG
endif

# Ledger VS Code extension compatibility. The extension's Load task is fixed
# to build/<target>/bin/app.{apdu,elf}, while the security-relevant build
# outputs above are intentionally isolated by backend/mode/FROST. Stage a
# fresh copy after every successful default build; the namespaced BIN_DIR
# remains the source of truth.
LEDGER_EXTENSION_BIN_DIR := build/$(TARGET)/bin
.PHONY: ledger-extension-artifacts
default: ledger-extension-artifacts
ledger-extension-artifacts: $(BIN_TARGETS)
	@mkdir -p "$(LEDGER_EXTENSION_BIN_DIR)"
	@cp "$(BIN_DIR)/app.elf" "$(LEDGER_EXTENSION_BIN_DIR)/app.elf"
	@cp "$(BIN_DIR)/app.apdu" "$(LEDGER_EXTENSION_BIN_DIR)/app.apdu"
	@printf 'backend=%s\nmode=%s\nfrost=%s\n' \
		'$(BACKEND)' '$(MODE)' '$(FROST)' \
		> "$(LEDGER_EXTENSION_BIN_DIR)/configuration.txt"
	@echo "[CP] $(BIN_DIR)/app.{elf,apdu} => $(LEDGER_EXTENSION_BIN_DIR)/"

# Reproducible release metadata. Invoke `make artifact-manifest` after a
# firmware build; the output lives beside the ELF in the configuration-bound
# BIN_DIR, so it cannot be mistaken for another backend/mode/FROST artifact.
.PHONY: artifact-manifest
artifact-manifest: all
	@test -f "$(BIN_DIR)/app.elf"
	@{ \
		printf 'target=%s\n' '$(TARGET)'; \
		printf 'backend=%s\n' '$(BACKEND)'; \
		printf 'mode=%s\n' '$(MODE)'; \
		printf 'frost=%s\n' '$(FROST)'; \
		printf 'commit=%s\n' "$$(git rev-parse HEAD)"; \
		printf 'zknox_commit=%s\n' "$$(git -C src/zknox rev-parse HEAD)"; \
		printf 'elf_sha256=%s\n' "$$(sha256sum '$(BIN_DIR)/app.elf' | cut -d ' ' -f 1)"; \
	} > "$(BIN_DIR)/artifact-manifest.txt"
	@echo "Wrote $(BIN_DIR)/artifact-manifest.txt"
