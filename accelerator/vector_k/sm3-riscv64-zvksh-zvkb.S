.text

#define STATEP		a0
#define DATA		a1
#define NUM_BLOCKS	a2

#define STATE		v0	// LMUL=2
#define PREV_STATE	v2	// LMUL=2
#define W0		v4	// LMUL=2
#define W1		v6	// LMUL=2
#define VTMP		v8	// LMUL=2

#define SYM_FUNC_START(name) \
    .globl name           ;  \
    name:

#define SYM_FUNC_END(name) \
    .size name, . - name

.macro	sm3_8rounds	i, w0, w1
	// Do 4 rounds using W_{0+i}..W_{7+i}.
	vsm3c.vi	STATE, \w0, \i + 0
	vslidedown.vi	VTMP, \w0, 2
	vsm3c.vi	STATE, VTMP, \i + 1

	// Compute W_{4+i}..W_{11+i}.
	vslidedown.vi	VTMP, \w0, 4
	vslideup.vi	VTMP, \w1, 4

	// Do 4 rounds using W_{4+i}..W_{11+i}.
	vsm3c.vi	STATE, VTMP, \i + 2
	vslidedown.vi	VTMP, VTMP, 2
	vsm3c.vi	STATE, VTMP, \i + 3

.if \i < 28
	// Compute W_{16+i}..W_{23+i}.
	vsm3me.vv	\w0, \w1, \w0
.endif
	// For the next 8 rounds, w0 and w1 are swapped.
.endm

// void sm3_transform_zvksh_zvkb(u32 state[8], const u8 *data, int num_blocks);
SYM_FUNC_START(sm3_transform_zvksh_zvkb)

	// Load the state and endian-swap each 32-bit word.
	vsetivli	zero, 8, e32, m2, ta, ma
	vle32.v		STATE, (STATEP)
	vrev8.v		STATE, STATE

.Lnext_block:
	addi		NUM_BLOCKS, NUM_BLOCKS, -1

	// Save the previous state, as it's needed later.
	vmv.v.v		PREV_STATE, STATE

	// Load the next 512-bit message block into W0-W1.
	vle32.v		W0, (DATA)
	addi		DATA, DATA, 32
	vle32.v		W1, (DATA)
	addi		DATA, DATA, 32

	// Do the 64 rounds of SM3.
	sm3_8rounds	0, W0, W1
	sm3_8rounds	4, W1, W0
	sm3_8rounds	8, W0, W1
	sm3_8rounds	12, W1, W0
	sm3_8rounds	16, W0, W1
	sm3_8rounds	20, W1, W0
	sm3_8rounds	24, W0, W1
	sm3_8rounds	28, W1, W0

	// XOR in the previous state.
	vxor.vv		STATE, STATE, PREV_STATE

	// Repeat if more blocks remain.
	bnez		NUM_BLOCKS, .Lnext_block

	// Store the new state and return.
	vrev8.v		STATE, STATE
	vse32.v		STATE, (STATEP)
	ret
SYM_FUNC_END(sm3_transform_zvksh_zvkb)
