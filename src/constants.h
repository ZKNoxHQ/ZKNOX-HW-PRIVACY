#pragma once

/*
 * Build-mode guard.
 *
 * ZKNOX_MODE_PROD / ZKNOX_MODE_DEBUG are mutually-exclusive tokens set by
 * the Makefile's MODE switch. ZKNOX_DEBUG must never be live while
 * ZKNOX_MODE_PROD is in effect: it would smuggle the raw-privkey,
 * no-UI-sign and key-export INSes into a production binary.
 */
#if defined(ZKNOX_MODE_PROD) && defined(ZKNOX_DEBUG)
#error "MODE=prod build has ZKNOX_DEBUG defined — debug INSes would ship. \
Remove the stray -DZKNOX_DEBUG (CFLAGS, included header, or Makefile edit) \
or build with MODE=debug explicitly."
#endif
#if !defined(ZKNOX_MODE_PROD) && !defined(ZKNOX_MODE_DEBUG)
#error "Neither ZKNOX_MODE_PROD nor ZKNOX_MODE_DEBUG is defined. The build \
must go through the Makefile (MODE=debug | MODE=prod) so the prod/debug \
separation is enforced."
#endif

/**
 * Instruction class of the application.
 */
#define CLA 0xE0

/**
 * Length of APPNAME variable in the Makefile.
 */
#define APPNAME_LEN (sizeof(APPNAME) - 1)

/**
 * Length of MAJOR_VERSION || MINOR_VERSION || PATCH_VERSION.
 */
#define APPVERSION_LEN 3

/**
 * Maximum length of application name.
 */
#define MAX_APPNAME_LEN 64

/**
 * Size of the deferred-signing payload staged in G_context before user
 * approval: account(4 BE) || msg(32).
 */
#define SIGN_PAYLOAD_LEN 36

/**
 * Length of an EdDSA-Poseidon signature: R8x(32) || R8y(32) || S(32).
 */
#define EDDSA_POSEIDON_SIG_LEN 96
