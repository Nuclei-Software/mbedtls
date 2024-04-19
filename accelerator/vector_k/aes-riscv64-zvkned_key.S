.text

################################################################################
# int rv64i_zvkned_set_encrypt_key(const unsigned char *userKey, const int bits,
#                                  AES_KEY *key)
# int rv64i_zvkned_set_decrypt_key(const unsigned char *userKey, const int bits,
#                                  AES_KEY *key)

.p2align 3
.globl rv64i_zvkned_set_encrypt_key
.type rv64i_zvkned_set_encrypt_key,@function
rv64i_zvkned_set_encrypt_key:

    # Get proper routine for key size
    li t1, 256
    beq a1, t1, zvkned_aes256_expand_key
    li t1, 128
    beq a1, t1, zvkned_aes128_expand_key


.size rv64i_zvkned_set_encrypt_key,.-rv64i_zvkned_set_encrypt_key
.p2align 3
.globl rv64i_zvkned_set_decrypt_key
.type rv64i_zvkned_set_decrypt_key,@function
rv64i_zvkned_set_decrypt_key:

    # Get proper routine for key size
    li t1, 256
    beq a1, t1, zvkned_aes256_expand_key
    li t1, 128
    beq a1, t1, zvkned_aes128_expand_key

.size rv64i_zvkned_set_decrypt_key,.-rv64i_zvkned_set_decrypt_key

#   extern "C" void
#   zvkned_aes128_expand_key(
#       char dest_key[176],  // a2
#       const char key[16]   // a0
#   );
#   a2=dest_key, a0=key
#
.balign 4
.global zvkned_aes128_expand_key
zvkned_aes128_expand_key:
    # 4: number of 4B elements (4B*4 = 16B = 128b)
    # e32: vector of 32b/4B elements
    # m1: LMUL=4  (allows for VLEN=32)
    # ta: tail agnostic (don't care about those elements)
    # ma: mask agnostic (don't care about those elements)
    # x0 is not written, we known the number of vector elements, 4.
    vsetivli x0, 4, e32, m4, ta, ma   # Vectors of 8b

    # Note that this version interleaves the key schedule instructions
    # and storing the resulting round keys, while always using the same
    # vector register. Depending on micro-architecture (latencies,
    # in order vs. out of order, renaming limits, etc), it could
    # be beneficial to use more registers push stores further from
    # the key schedule logic.

    # Load user key from `key`, all 16B at once
    vle32.v v4, (a0)
    # v4 contains the evolving key state during expansion.

    # Initial word, copy the input key.
    vse32.v v4, (a2)  # w[0,3] expanded word (== input key)
    # Round 1
    vaeskf1.vi v4, v4, 1
    # Move dest by 128b (4 * 32b  words)
    add a2, a2, 16
    vse32.v v4, (a2)  # Round 1 expanded key
    # Round 2
    vaeskf1.vi v4, v4, 2
    add a2, a2, 16
    vse32.v v4, (a2)
    #
    vaeskf1.vi v4, v4, 3
    add a2, a2, 16
    vse32.v v4, (a2)
    #
    vaeskf1.vi v4, v4, 4
    add a2, a2, 16
    vse32.v v4, (a2)
    #
    vaeskf1.vi v4, v4, 5
    add a2, a2, 16
    vse32.v v4, (a2)
    #
    vaeskf1.vi v4, v4, 6
    add a2, a2, 16
    vse32.v v4, (a2)
    #
    vaeskf1.vi v4, v4, 7
    add a2, a2, 16
    vse32.v v4, (a2)
    #
    vaeskf1.vi v4, v4, 8
    add a2, a2, 16
    vse32.v v4, (a2)
    #
    vaeskf1.vi v4, v4, 9
    add a2, a2, 16
    vse32.v v4, (a2)
    #
    vaeskf1.vi v4, v4, 10
    add a2, a2, 16
    vse32.v v4, (a2)

    ret
# zvkned_aes128_expand_key


# zvkned_aes256_expand_key
#
# Given a 256 bit (32 bytes) key, expand it to the 60*4 byte
# format (14+1 rounds) that is used during AES-256 encryption.
#
# The key is provided at 'key', and the expansion written at 'dest_key'.
#
# 'key' and 'dest_key' should be 8-bytes aligned if the target processor
# does not support unaligned vle64/vse64 vector accesses.
#
# C/C++ Signature
#   extern "C" void
#   zvkned_aes256_expand_key(
#       char dest_key[240],   // a2
#       const char key[32]    // a0
#   );
#   a2=dest_key, a0=key
#
.balign 4
.global zvkned_aes256_expand_key
zvkned_aes256_expand_key:
    # 4: number of 4B elements (4B*4 = 16B = 128b)
    # e32: vector of 32b/4B elements
    # m1: LMUL=4  (allows for VLEN=32)
    # ta: tail agnostic (don't care about those elements)
    # ma: mask agnostic (don't care about those elements)
    # x0 is not written, we known the number of vector elements, 2.
    vsetivli x0, 4, e32, m4, ta, ma   # Vectors of 4B

    # Load user key from `key`, all 16B at once
    vle32.v v4, (a0)
    addi a0, a0, 16
    vle32.v v8, (a0)
    addi a0, a0, 16

    # v4 and v8 contain the evolving key state during expansion,
    # alternating holding key[i] and key[i-1] as inputs to vaesfk.

    # For the initial 2 4-words, we copy the input key.
    # Round 0 expanded key, w[0, 3] (== input key LO).
    vse32.v v4, (a2)
    add a2, a2, 16
    # Round 1 expanded key, w[4, 7] (== input key HI)
    vse32.v v8, (a2)
    add a2, a2, 16
    # Round 2 expanded key, w[8, 13].
    vaeskf2.vi v4, v8, 2
    vse32.v v4, (a2)
    add a2, a2, 16
    # Round 3 expanded key, w[12, 15].
    vaeskf2.vi v8, v4, 3
    vse32.v v8, (a2)
    add a2, a2, 16
    # Round 4 expanded key, w[16, 19].
    vaeskf2.vi v4, v8, 4
    vse32.v v4, (a2)
    add a2, a2, 16
    # Round 5 expanded key, w[20, 23].
    vaeskf2.vi v8, v4, 5
    vse32.v v8, (a2)
    add a2, a2, 16
    # Round 6 expanded key, w[24, 27].
    vaeskf2.vi v4, v8, 6
    vse32.v v4, (a2)
    add a2, a2, 16
    # Round 7 expanded key, w[28, 31].
    vaeskf2.vi v8, v4, 7
    vse32.v v8, (a2)
    add a2, a2, 16
    # Round 8 expanded key, w[32, 35].
    vaeskf2.vi v4, v8, 8
    vse32.v v4, (a2)
    add a2, a2, 16
    # Round 9 expanded key, w[36, 39].
    vaeskf2.vi v8, v4, 9
    vse32.v v8, (a2)
    add a2, a2, 16
    # Round 10 expanded key, w[40, 43].
    vaeskf2.vi v4, v8, 10
    vse32.v v4, (a2)
    add a2, a2, 16
    # Round 11 expanded key, w[44, 47].
    vaeskf2.vi v8, v4, 11
    vse32.v v8, (a2)
    add a2, a2, 16
    # Round 12 expanded key, w[48, 51].
    vaeskf2.vi v4, v8, 12
    vse32.v v4, (a2)
    add a2, a2, 16
    # Round 13 expanded key, w[52, 55].
    vaeskf2.vi v8, v4, 13
    vse32.v v8, (a2)
    add a2, a2, 16
    # Round 14 expanded key, w[56, 59].
    vaeskf2.vi v4, v8, 14
    vse32.v v4, (a2)
    add a2, a2, 16

    ret
# zvkned_aes256_expand_key