.text
.p2align 3

#define SYM_FUNC_START(name) \
    .globl name           ;  \
    name:

#define SYM_FUNC_END(name) \
    .size name, . - name

// void sm4_expandkey_zksed_zvkb(const u8 user_key[16], u32 rkey_enc[32],
//				 u32 rkey_dec[32]);
SYM_FUNC_START(sm4_expandkey_zvksed_zvkb)
	vsetivli	zero, 4, e32, m1, ta, ma

	// Load the user key.
	vle32.v		v1, (a0)
	vrev8.v		v1, v1

	// XOR the user key with the family key.
	la		t0, FAMILY_KEY
	vle32.v		v2, (t0)
	vxor.vv		v1, v1, v2

	// Compute the round keys.  Store them in forwards order in rkey_enc
	// and in reverse order in rkey_dec.
	addi		a2, a2, 31*4
	li		t0, -4
	.set		i, 0
.rept 8
	vsm4k.vi	v1, v1, i
	vse32.v		v1, (a1)	// Store to rkey_enc.
	vsse32.v	v1, (a2), t0	// Store to rkey_dec.
.if i < 7
	addi		a1, a1, 16
	addi		a2, a2, -16
.endif
	.set		i, i + 1
.endr

	ret
SYM_FUNC_END(sm4_expandkey_zvksed_zvkb)

// void sm4_crypt_zvksed_zvkb(const u32 rkey[32], const u8 in[16], u8 out[16]);
SYM_FUNC_START(sm4_crypt_zvksed_zvkb)
	vsetivli	zero, 4, e32, m1, ta, ma

	// Load the input data.
	vle32.v		v1, (a1)
	vrev8.v		v1, v1

	// Do the 32 rounds of SM4, 4 at a time.
	.set		i, 0
.rept 8
	vle32.v		v2, (a0)
	vsm4r.vs	v1, v2
.if i < 7
	addi		a0, a0, 16
.endif
	.set		i, i + 1
.endr

	// Store the output data (in reverse element order).
	vrev8.v		v1, v1
	li		t0, -4
	addi		a2, a2, 12
	vsse32.v	v1, (a2), t0

	ret
SYM_FUNC_END(sm4_crypt_zvksed_zvkb)

.section ".rodata"
.p2align 2
.type FAMILY_KEY, @object
FAMILY_KEY:
	.word 0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC
.size FAMILY_KEY, . - FAMILY_KEY
