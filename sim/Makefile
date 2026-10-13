# ══════════════════════════════════════════════════════════════════════
#  sim/Makefile — host-side APDU simulator for the ZKNOX app
#  SIM_VERSION 0.5.0
#
#  Compiles the REAL dispatcher + production handlers against a minimal
#  Ledger-SDK shim and vendored crypto (trezor-crypto, orlp-ed25519).
#  CLEAR_SIGN (0x11) and all ZKNOX_DEBUG INS are excluded.
#
#    make          → build/prod/apdu_sim   (stdin/stdout hex, ligne à ligne)
#    make test     → self-test KAT
#    make test-sim-rs → suite Rust rs/ contre le simulateur
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
# SAN=1 builds the simulator's own sources under AddressSanitizer and
# UndefinedBehaviorSanitizer. The objects go to their own directory, so a
# sanitized and a plain build can live side by side; libzknox is built by its
# own Makefile and is not instrumented, which still leaves ASan watching every
# heap access the app sources and the shim make.
ifeq ($(SAN),1)
    BUILD    := $(BUILD)-san
    OUTPUT   := $(OUTPUT)-san
endif
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
# Mirrors the app Makefile: APPNAME and the version the GET_* handlers return.
CFLAGS  += -DAES_VAR -DZKN_BN_BACKEND_SW -DUSE_ETHEREUM=0 -DUSE_KECCAK=1 -DAPPVERSION_M=0 -DAPPVERSION_N=1 -DAPPVERSION_P=0 -DAPPNAME=\"ZKNOX\"

CFLAGS += -DSIM_VERSION=\"0.5.0\"
CFLAGS += -include shim/include/sim_compat.h
ifeq ($(SAN),1)
    # shift-base is excluded: vendor/ed25519 shifts negative ints on purpose
    # (fe.c:714 and friends), which is UB by the letter of C and benign on
    # two's-complement. Everything else is fatal, so a finding in the app
    # sources, the shim or libzknox fails the run instead of scrolling past.
    SAN_FLAGS := -fsanitize=address,undefined -fno-sanitize=shift-base \
                 -fno-omit-frame-pointer -fno-sanitize-recover=undefined
    CFLAGS    += $(SAN_FLAGS)
    LDFLAGS   += $(SAN_FLAGS)
endif
# Anything a caller wants on top, without clobbering the flags above.
CFLAGS  += $(EXTRA_CFLAGS)
LDFLAGS += $(EXTRA_LDFLAGS)

INC := -Isrc -Ishim/include -Ivendor/trezor -Ivendor/ed25519 -Ivendor/aes \
       -I$(APP)/src -I$(APP)/src/handler -I$(APP)/src/apdu \
       -I$(APP)/src/ui -I$(APP)/src/ui/action -I$(APP)/src/helper \
       -I$(ZKNOX)/src/common -I$(ZKNOX)/src/bn -I$(ZKNOX)/src/compat \
       -I$(ZKNOX)/src/zkn_mont -I$(ZKNOX)/src/bls12381 -I$(ZKNOX)/src/ecc \
       -I$(ZKNOX)/src/hash -I$(ZKNOX)/src/mpt -I$(ZKNOX)/src/keys \
       -I$(ZKNOX)/src/threshold -I$(ZKNOX)/src/aes

# This app's production surface. The RAILGUN-only sources the simulator used
# to compile (7702 auth, tx hash, delegates, note encryption) have no
# counterpart here, so they are gone rather than stubbed.
APP_SRCS := \
    $(APP)/src/apdu/dispatcher.c \
    $(APP)/src/handler/handler_version.c \
    $(APP)/src/handler/handler_keys.c \
    $(APP)/src/handler/handler_sign.c \
    $(APP)/src/handler/handler_railgun_address.c \
    $(APP)/src/ui/action/validate.c \
    $(APP)/src/helper/send_response.c \
    $(ZKNOX)/src/keys/zkn_keyderivation.c

# The DKG and FROST handlers are gated on FROST, not on MODE, exactly as in
# the app Makefile — that is what makes MODE=prod FROST=1 testable here.
ifeq ($(FROST),1)
APP_SRCS += \
    $(APP)/src/handler/handler_dkg.c \
    $(APP)/src/handler/handler_frost_sign.c \
    $(ZKNOX)/src/ecc/zkn_frost.c \
    $(ZKNOX)/src/ecc/zkn_tEdwards.c \
    $(ZKNOX)/src/keys/zkn_ed25519_scalar.c \
    $(ZKNOX)/src/keys/zkn_ed25519_ecdh.c \
    $(ZKNOX)/src/aes/zkn_aes_gcm.c
endif

SIM_SRCS := \
    src/sim_core.c \
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

# main.c is the line-protocol front-end and the only object the library does
# not want: `lib` archives everything else so a caller can link the simulator
# and provide its own front-end (rs/crates/zknox-sim).
MAIN_SRC := src/main.c

OBJS := $(patsubst %.c,$(BUILD)/%.o,$(notdir $(APP_SRCS) $(SIM_SRCS) $(VENDOR_SRCS)))
MAIN_OBJ := $(patsubst %.c,$(BUILD)/%.o,$(notdir $(MAIN_SRC)))
VPATH := $(sort $(dir $(APP_SRCS) $(SIM_SRCS) $(VENDOR_SRCS) $(MAIN_SRC)))

.PHONY: all
all: $(OUTPUT)/apdu_sim

# Preserve the public simulator path while keeping its inputs isolated.
$(OUTPUT)/apdu_sim: $(BUILD)/apdu_sim
	@mkdir -p $(OUTPUT)
	@cp $< $@
	@echo "  CP   $< -> $@"

$(BUILD)/apdu_sim: $(MAIN_OBJ) $(OBJS) $(ZKNOX_LIB)
	@echo "  LD   $@"
	@$(CC) $(MAIN_OBJ) $(OBJS) $(ZKNOX_LIB) $(LDFLAGS) -o $@

# One archive holding the simulator, the app sources and libzknox, for a
# caller that links instead of spawning. Merged rather than handed over as
# two archives because the dependency runs both ways — libzknox calls the
# shim's cx_* functions and the shim calls libzknox — and a linker resolves
# that within one archive but not across two in a single pass.
AR ?= ar
SIM_LIB := $(BUILD)/libzknoxsim.a

.PHONY: lib
lib: $(SIM_LIB)
	@echo "$(SIM_LIB)"

$(SIM_LIB): $(OBJS) $(ZKNOX_LIB)
	@echo "  AR   $@"
	@rm -f $@
	@printf 'create %s\n' $@ > $(BUILD)/libzknoxsim.mri
	@printf 'addmod %s\n' $(OBJS) >> $(BUILD)/libzknoxsim.mri
	@printf 'addlib %s\n' $(ZKNOX_LIB) >> $(BUILD)/libzknoxsim.mri
	@printf 'save\nend\n' >> $(BUILD)/libzknoxsim.mri
	@$(AR) -M < $(BUILD)/libzknoxsim.mri
	@$(AR) s $@

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

.PHONY: test test-sim-rs clean
test: $(OUTPUT)/apdu_sim
	SIM=$(OUTPUT)/apdu_sim ./test/selftest.sh

# Exécute la suite Rust (rs/crates/hw-tests) contre le simulateur. Chaque
# binaire de test spawn lui-même le simulateur : pas de serveur, pas de port,
# pas de conteneur. Le câblage SIM_BIN côté JS n'existe pas dans ce dépôt.
test-sim-rs:
	$(MAKE) MODE=debug
	cd $(APP)/rs && cargo test -p zknox-hw-tests -- --test-threads=1

clean:
	rm -rf $(BUILD)
	rm -f $(OUTPUT)/apdu_sim
