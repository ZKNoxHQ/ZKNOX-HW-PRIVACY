# ══════════════════════════════════════════════════════════════════════
#  sim/Makefile — host-side APDU simulator for the ZKNOX app
#  SIM_VERSION 0.4.3
#
#  Compiles the REAL dispatcher + production handlers against a minimal
#  Ledger-SDK shim and vendored crypto (trezor-crypto, orlp-ed25519).
#  CLEAR_SIGN (0x11) and all ZKNOX_DEBUG INS are excluded.
#
#    make          → build/prod/apdu_sim   (stdin/stdout hex, ligne à ligne)
#    make test     → self-test KAT
#    make test-sim-js → suite JS existante contre le simulateur
# ══════════════════════════════════════════════════════════════════════
APP   ?= ../
ZKNOX ?= $(APP)/src/zknox
MODE  ?= prod
ifeq ($(MODE),debug)
    FROST ?= 1
else
    FROST ?= 0
endif

# Objects and the host ZKNOX archive are security-configuration-specific.
# The stable build/{prod,debug}/apdu_sim path is staged below for existing
# scripts and documentation.
BUILD        := build/.config/$(MODE)/frost-$(FROST)
OUTPUT       := build/$(MODE)
ZKNOX_LIB    := $(BUILD)/libzknox.a
.DEFAULT_GOAL := all

# Fresh clone without --recurse-submodules leaves src/zknox/ empty, and ZKNOX
# headers/sources are referenced from VPATH, INC, and APP_SRCS below. Init the
# submodule at parse time so those all resolve against a populated tree.
ifeq ($(wildcard $(ZKNOX)/Makefile),)
$(info sim: initializing $(ZKNOX) submodule...)
$(shell git -C $(APP) submodule update --init --recursive >&2)
endif

CC      ?= cc
CFLAGS  += -O2 -g -Wall -Wno-unused-parameter -Wno-unused-function
ifeq ($(MODE),debug)
    CFLAGS += -DZKNOX_MODE_DEBUG -DZKNOX_DEBUG
else
    CFLAGS += -DZKNOX_MODE_PROD
endif
# ZKN_FROST is independent of MODE — see the app Makefile. Mirrored here so
# the simulator can exercise MODE=debug FROST=0 and MODE=prod FROST=1, which
# is the only way to find out whether the split actually holds.
ifeq ($(FROST),1)
    CFLAGS += -DZKN_FROST
endif
CFLAGS  += -DAES_VAR -DZKN_BN_BACKEND_SW -DUSE_ETHEREUM=0 -DUSE_KECCAK=1 -DAPPVERSION_M=0 -DAPPVERSION_N=0 -DAPPVERSION_P=2 -DAPPNAME=\"RAILGUN\"
# 7702 fixed path prefix — MUST mirror the app Makefile DEFINES
CFLAGS  += -DPATH_7702_L0_H=0x8000002Cu -DPATH_7702_L1_H=0x8000003Cu
CFLAGS  += -DPATH_7702_L2_H=0x800007C0u -DPATH_7702_L3_H=0x80001E16u

CFLAGS += -DSIM_VERSION=\"0.4.3\"
CFLAGS += -include shim/include/sim_compat.h

INC := -Ishim/include -Ivendor/trezor -Ivendor/ed25519 -Ivendor/aes \
       -I$(APP)/src -I$(APP)/src/handler -I$(APP)/src/apdu \
       -I$(APP)/src/ui -I$(APP)/src/ui/action -I$(APP)/src/helper -I$(APP)/src/transaction -I$(APP)/src/note \
       -I$(ZKNOX)/src/common -I$(ZKNOX)/src/bn -I$(ZKNOX)/src/compat \
       -I$(ZKNOX)/src/zkn_mont -I$(ZKNOX)/src/bls12381 -I$(ZKNOX)/src/ecc \
       -I$(ZKNOX)/src/hash -I$(ZKNOX)/src/mpt -I$(ZKNOX)/src/keys \
       -I$(ZKNOX)/src/threshold -I$(ZKNOX)/src/aes

APP_SRCS := \
    $(APP)/src/apdu/dispatcher.c \
    $(APP)/src/handler/handler_version.c \
    $(APP)/src/handler/handler_keys.c \
    $(APP)/src/handler/handler_sign.c \
    $(APP)/src/handler/handler_railgun_address.c \
    $(APP)/src/handler/sign_7702_auth.c \
    $(APP)/src/handler/sign_tx_hash.c \
    $(APP)/src/handler/known_7702_delegates.c \
    $(APP)/src/ui/action/validate.c \
    $(APP)/src/helper/send_response.c \
    $(ZKNOX)/src/keys/zkn_keyderivation.c

ifeq ($(MODE),debug)
APP_SRCS += \
    $(APP)/src/handler/handler_poseidon.c \
    $(APP)/src/handler/handler_keccak256.c \
    $(APP)/src/handler/handler_blake512.c \
    $(APP)/src/handler/handler_scalar_mul.c \
    $(APP)/src/handler/handler_encrypt_note.c \
    $(APP)/src/handler/handler_frost.c \
    $(APP)/src/handler/handler_dkg.c \
    $(APP)/src/handler/handler_frost_sign.c \
    $(APP)/src/handler/handler_gcm_test.c \
    $(APP)/src/handler/frost.c \
    $(APP)/src/handler/get_vss.c \
    $(APP)/src/note/zkn_note_encrypt.c \
    $(ZKNOX)/src/ecc/zkn_frost.c \
    $(ZKNOX)/src/ecc/zkn_tEdwards.c \
    $(ZKNOX)/src/keys/zkn_ed25519_scalar.c \
    $(ZKNOX)/src/keys/zkn_ed25519_ecdh.c \
    $(ZKNOX)/src/aes/zkn_aes_gcm.c
endif

SIM_SRCS := \
    src/main.c \
    shim/shim_crypto.c \
    shim/shim_io.c \
    shim/sim_ui.c \
    shim/sim_stubs.c \
    shim/shim_crypto_ext.c

VENDOR_SRCS := \
    vendor/trezor/bignum.c vendor/trezor/ecdsa.c vendor/trezor/secp256k1.c \
    vendor/trezor/hmac.c vendor/trezor/hmac_drbg.c vendor/trezor/rfc6979.c \
    vendor/trezor/sha2.c vendor/trezor/sha3.c vendor/trezor/memzero.c \
    vendor/trezor/hasher.c vendor/trezor/address.c vendor/trezor/base58.c vendor/trezor/ripemd160.c vendor/trezor/blake256.c vendor/trezor/blake2b.c vendor/trezor/groestl.c \
    vendor/ed25519/fe.c vendor/ed25519/ge.c vendor/ed25519/sc.c \
    vendor/ed25519/sha512.c \
    vendor/aes/aescrypt.c vendor/aes/aeskey.c vendor/aes/aestab.c \
    vendor/aes/aes_modes.c vendor/aes/gf128mul.c vendor/aes/aesgcm.c

OBJS := $(patsubst %.c,$(BUILD)/%.o,$(notdir $(APP_SRCS) $(SIM_SRCS) $(VENDOR_SRCS)))
VPATH := $(sort $(dir $(APP_SRCS) $(SIM_SRCS) $(VENDOR_SRCS)))

.PHONY: all
all: $(OUTPUT)/apdu_sim

# Preserve the public simulator path while keeping its inputs isolated.
$(OUTPUT)/apdu_sim: $(BUILD)/apdu_sim
	@mkdir -p $(OUTPUT)
	@cp $< $@
	@echo "  CP   $< -> $@"

$(BUILD)/apdu_sim: $(OBJS) $(ZKNOX_LIB)
	@echo "  LD   $@"
	@$(CC) $(OBJS) $(ZKNOX_LIB) -o $@

$(BUILD)/%.o: %.c Makefile
	@mkdir -p $(BUILD)
	@echo "  CC   $<"
	@$(CC) $(CFLAGS) $(INC) -c $< -o $@

# libC has a single fixed build/ output directory and does not know about the
# simulator configuration. Build it with the selected gates, then immediately
# copy the archive into this simulator configuration before another mode can
# replace the shared output.
ZKNOX_INPUTS := $(ZKNOX)/Makefile \
                $(wildcard $(ZKNOX)/make/*.mk) \
                $(wildcard $(ZKNOX)/src/*/*.c) \
                $(wildcard $(ZKNOX)/src/*/*.h)
$(ZKNOX_LIB): Makefile $(ZKNOX_INPUTS)
	@mkdir -p $(BUILD)
	$(MAKE) -C $(ZKNOX) clean
	$(MAKE) -C $(ZKNOX) ZKNOX_DEBUG=$(if $(filter debug,$(MODE)),1,0) ZKN_FROST=$(FROST)
	@cp $(ZKNOX)/build/libzknox.a $@

.PHONY: test test-sim-js clean
test: $(OUTPUT)/apdu_sim
	./test/selftest.sh

# Exécute la suite JS existante contre le simulateur. Chaque test spawn
# lui-même le binaire (SIM_BIN) et lui pipe les APDUs en hex: pas de
# serveur, pas de port, pas de dépendance transport.
JS ?= $(APP)/js
test-sim-js:
	$(MAKE) MODE=debug
	@set -e; \
	SIM_BIN=$(CURDIR)/build/debug/apdu_sim; export SIM_BIN; \
	unset LIBC; \
	cd $(JS) && \
	for f in keys 0zk-address 0zk-derivations annotation-data \
	         encrypt-note sign scalar-mul poseidon; do \
	    echo "== test/$$f.test.js"; \
	    node --test test/$$f.test.js || exit 1; \
	done && \
	node test/test_7702_address.cjs --sign --auth --random 3

clean:
	rm -rf $(BUILD)
	rm -f $(OUTPUT)/apdu_sim
