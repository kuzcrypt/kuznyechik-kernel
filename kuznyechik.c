#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/crypto.h>
#include <linux/types.h>


/* Internal union representing 128-bit data structure. */
union w128_t {
	uint64_t q[2];
	uint8_t  b[16];
};

struct kuznyechik_subkeys {
	union w128_t ek[10];
	union w128_t dk[10];
};

/* S-box */
static const uint8_t kuz_pi[256] = {
	0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16,
	0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
	0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA,
	0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
	0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21,
	0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
	0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0,
	0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
	0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB,
	0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
	0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12,
	0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
	0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7,
	0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
	0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E,
	0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
	0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9,
	0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
	0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC,
	0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
	0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44,
	0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
	0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F,
	0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
	0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7,
	0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
	0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE,
	0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
	0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B,
	0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
	0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0,
	0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6,
};

/* Inverse S-box */
static const uint8_t kuz_pi_inv[256] = {
	0xA5, 0x2D, 0x32, 0x8F, 0x0E, 0x30, 0x38, 0xC0,
	0x54, 0xE6, 0x9E, 0x39, 0x55, 0x7E, 0x52, 0x91,
	0x64, 0x03, 0x57, 0x5A, 0x1C, 0x60, 0x07, 0x18,
	0x21, 0x72, 0xA8, 0xD1, 0x29, 0xC6, 0xA4, 0x3F,
	0xE0, 0x27, 0x8D, 0x0C, 0x82, 0xEA, 0xAE, 0xB4,
	0x9A, 0x63, 0x49, 0xE5, 0x42, 0xE4, 0x15, 0xB7,
	0xC8, 0x06, 0x70, 0x9D, 0x41, 0x75, 0x19, 0xC9,
	0xAA, 0xFC, 0x4D, 0xBF, 0x2A, 0x73, 0x84, 0xD5,
	0xC3, 0xAF, 0x2B, 0x86, 0xA7, 0xB1, 0xB2, 0x5B,
	0x46, 0xD3, 0x9F, 0xFD, 0xD4, 0x0F, 0x9C, 0x2F,
	0x9B, 0x43, 0xEF, 0xD9, 0x79, 0xB6, 0x53, 0x7F,
	0xC1, 0xF0, 0x23, 0xE7, 0x25, 0x5E, 0xB5, 0x1E,
	0xA2, 0xDF, 0xA6, 0xFE, 0xAC, 0x22, 0xF9, 0xE2,
	0x4A, 0xBC, 0x35, 0xCA, 0xEE, 0x78, 0x05, 0x6B,
	0x51, 0xE1, 0x59, 0xA3, 0xF2, 0x71, 0x56, 0x11,
	0x6A, 0x89, 0x94, 0x65, 0x8C, 0xBB, 0x77, 0x3C,
	0x7B, 0x28, 0xAB, 0xD2, 0x31, 0xDE, 0xC4, 0x5F,
	0xCC, 0xCF, 0x76, 0x2C, 0xB8, 0xD8, 0x2E, 0x36,
	0xDB, 0x69, 0xB3, 0x14, 0x95, 0xBE, 0x62, 0xA1,
	0x3B, 0x16, 0x66, 0xE9, 0x5C, 0x6C, 0x6D, 0xAD,
	0x37, 0x61, 0x4B, 0xB9, 0xE3, 0xBA, 0xF1, 0xA0,
	0x85, 0x83, 0xDA, 0x47, 0xC5, 0xB0, 0x33, 0xFA,
	0x96, 0x6F, 0x6E, 0xC2, 0xF6, 0x50, 0xFF, 0x5D,
	0xA9, 0x8E, 0x17, 0x1B, 0x97, 0x7D, 0xEC, 0x58,
	0xF7, 0x1F, 0xFB, 0x7C, 0x09, 0x0D, 0x7A, 0x67,
	0x45, 0x87, 0xDC, 0xE8, 0x4F, 0x1D, 0x4E, 0x04,
	0xEB, 0xF8, 0xF3, 0x3E, 0x3D, 0xBD, 0x8A, 0x88,
	0xDD, 0xCD, 0x0B, 0x13, 0x98, 0x02, 0x93, 0x80,
	0x90, 0xD0, 0x24, 0x34, 0xCB, 0xED, 0xF4, 0xCE,
	0x99, 0x10, 0x44, 0x40, 0x92, 0x3A, 0x01, 0x26,
	0x12, 0x1A, 0x48, 0x68, 0xF5, 0x81, 0x8B, 0xC7,
	0xD6, 0x20, 0x0A, 0x08, 0x00, 0x4C, 0xD7, 0x74
};

/* Linear vector from sect 5.1.2 */
static const uint8_t kuz_lvec[16] = {
	0x94, 0x20, 0x85, 0x10, 0xC2, 0xC0, 0x01, 0xFB,
	0x01, 0xC0, 0xC2, 0x10, 0x85, 0x20, 0x94, 0x01
};

static int kuz_initialized = 0;

/* Lookup tables */
static uint64_t kuz_pil_enc[16][256][2];
static uint64_t kuz_l_dec[16][256][2];
static uint64_t kuz_pil_dec[16][256][2];

static void kuz_init(void);

/* ************************************************************* */

/* poly multiplication mod p(x) = x^8 + x^7 + x^6 + x + 1 */
static uint8_t kuz_mul_gf256(uint8_t x, uint8_t y)
{
	uint8_t z = 0;
	while (y) {
		if (y & 1) z ^= x;
		x = (x << 1) ^ (x & 0x80 ? 0xC3 : 0x00);
		y >>= 1;
	}
	return z;
}

/* (slow) linear operation l */
static void kuz_l(union w128_t *w)
{
	int i, j;
	uint8_t x;
	for (j = 0; j < 16; j++) {
		/* An LFSR with 16 elements from GF(2^8) */
		x = w->b[15]; /* since lvec[15] = 1 */
		for (i = 14; i >= 0; i--) {
			w->b[i + 1] = w->b[i];
			x ^= kuz_mul_gf256(w->b[i], kuz_lvec[i]);
		}
		w->b[0] = x;
	}
}

/* inverse of linear operation l */
static void kuz_l_inv(union w128_t *w)
{
	int i, j;
	uint8_t x;
	for (j = 0; j < 16; j++) {
		x = w->b[0];
		for (i = 0; i < 15; i++) {
			w->b[i] = w->b[i + 1];
			x ^= kuz_mul_gf256(w->b[i], kuz_lvec[i]);
		}
		w->b[15] = x;
	}
}


/* ************************************************************* */

/* key schedule */
static int kuznyechik_set_key(struct crypto_tfm *tfm,
			      const u8 *key, unsigned int keylen)
{
	struct kuznyechik_subkeys *subkeys = crypto_tfm_ctx(tfm);
	int i, j;
	union w128_t c, x, y, z;

	if (!kuz_initialized) {
		kuz_init();
	}

	for (i = 0; i < 16; i++) {
		/* this will be have to changed for little-endian systems */
		x.b[i] = key[i];
		y.b[i] = key[i + 16];
	}

	subkeys->ek[0].q[0] = x.q[0];
	subkeys->ek[0].q[1] = x.q[1];
	subkeys->ek[1].q[0] = y.q[0];
	subkeys->ek[1].q[1] = y.q[1];

	for (i = 1; i <= 32; i++) {

		/* C Value */
		c.q[0] = 0;
		c.q[1] = 0;
		c.b[15] = i; /* load round in lsb */
		kuz_l(&c);

		z.q[0] = x.q[0] ^ c.q[0];
		z.q[1] = x.q[1] ^ c.q[1];
		for (j = 0; j < 16; j++)
			z.b[j] = kuz_pi[z.b[j]];
		kuz_l(&z);
		z.q[0] ^= y.q[0];
		z.q[1] ^= y.q[1];

		y.q[0] = x.q[0];
		y.q[1] = x.q[1];

		x.q[0] = z.q[0];
		x.q[1] = z.q[1];

		if ((i & 7) == 0) {
			subkeys->ek[(i >> 2)].q[0] = x.q[0];
			subkeys->ek[(i >> 2)].q[1] = x.q[1];
			subkeys->ek[(i >> 2) + 1].q[0] = y.q[0];
			subkeys->ek[(i >> 2) + 1].q[1] = y.q[1];
		}
	}
	for (i = 0; i < 10; i++) {
		subkeys->dk[i] = subkeys->ek[i];
		if (i) kuz_l_inv(&subkeys->dk[i]);
	}
	return 0;

}

/* encrypt the block */
static void kuznyechik_encrypt(struct crypto_tfm *tfm,
			       u8 *out, const u8 *in)
{
	struct kuznyechik_subkeys *subkeys = crypto_tfm_ctx(tfm);
	unsigned int i;

	union w128_t x, y;
	x.q[0] = ((uint64_t *) in)[0];
	x.q[1] = ((uint64_t *) in)[1];

	for (i = 0; i < 9; i++) {
		x.q[0] ^= subkeys->ek[i].q[0];
		x.q[1] ^= subkeys->ek[i].q[1];
		y.q[0]=	kuz_pil_enc[ 0][((uint8_t *) &x)[ 0]][0] ^
			kuz_pil_enc[ 1][((uint8_t *) &x)[ 1]][0] ^
			kuz_pil_enc[ 2][((uint8_t *) &x)[ 2]][0] ^
			kuz_pil_enc[ 3][((uint8_t *) &x)[ 3]][0] ^
			kuz_pil_enc[ 4][((uint8_t *) &x)[ 4]][0] ^
			kuz_pil_enc[ 5][((uint8_t *) &x)[ 5]][0] ^
			kuz_pil_enc[ 6][((uint8_t *) &x)[ 6]][0] ^
			kuz_pil_enc[ 7][((uint8_t *) &x)[ 7]][0] ^
			kuz_pil_enc[ 8][((uint8_t *) &x)[ 8]][0] ^
			kuz_pil_enc[ 9][((uint8_t *) &x)[ 9]][0] ^
			kuz_pil_enc[10][((uint8_t *) &x)[10]][0] ^
			kuz_pil_enc[11][((uint8_t *) &x)[11]][0] ^
			kuz_pil_enc[12][((uint8_t *) &x)[12]][0] ^
			kuz_pil_enc[13][((uint8_t *) &x)[13]][0] ^
			kuz_pil_enc[14][((uint8_t *) &x)[14]][0] ^
			kuz_pil_enc[15][((uint8_t *) &x)[15]][0];
		y.q[1]=	kuz_pil_enc[ 0][((uint8_t *) &x)[ 0]][1] ^
			kuz_pil_enc[ 1][((uint8_t *) &x)[ 1]][1] ^
			kuz_pil_enc[ 2][((uint8_t *) &x)[ 2]][1] ^
			kuz_pil_enc[ 3][((uint8_t *) &x)[ 3]][1] ^
			kuz_pil_enc[ 4][((uint8_t *) &x)[ 4]][1] ^
			kuz_pil_enc[ 5][((uint8_t *) &x)[ 5]][1] ^
			kuz_pil_enc[ 6][((uint8_t *) &x)[ 6]][1] ^
			kuz_pil_enc[ 7][((uint8_t *) &x)[ 7]][1] ^
			kuz_pil_enc[ 8][((uint8_t *) &x)[ 8]][1] ^
			kuz_pil_enc[ 9][((uint8_t *) &x)[ 9]][1] ^
			kuz_pil_enc[10][((uint8_t *) &x)[10]][1] ^
			kuz_pil_enc[11][((uint8_t *) &x)[11]][1] ^
			kuz_pil_enc[12][((uint8_t *) &x)[12]][1] ^
			kuz_pil_enc[13][((uint8_t *) &x)[13]][1] ^
			kuz_pil_enc[14][((uint8_t *) &x)[14]][1] ^
			kuz_pil_enc[15][((uint8_t *) &x)[15]][1];
		x = y;
	}
	((uint64_t *) out)[0] = x.q[0] ^ subkeys->ek[9].q[0];
	((uint64_t *) out)[1] = x.q[1] ^ subkeys->ek[9].q[1];
}

/* decrypt the block */
static void kuznyechik_decrypt(struct crypto_tfm *tfm,
			       u8 *out, const u8 *in)
{
	struct kuznyechik_subkeys *subkeys = crypto_tfm_ctx(tfm);
	unsigned int i;

	union w128_t  x, y;
	x.q[0] = ((uint64_t *) in)[0];
	x.q[1] = ((uint64_t *) in)[1];
	y.q[0]=	kuz_l_dec[ 0][((uint8_t *) &x)[ 0]][0] ^
		kuz_l_dec[ 1][((uint8_t *) &x)[ 1]][0] ^
		kuz_l_dec[ 2][((uint8_t *) &x)[ 2]][0] ^
		kuz_l_dec[ 3][((uint8_t *) &x)[ 3]][0] ^
		kuz_l_dec[ 4][((uint8_t *) &x)[ 4]][0] ^
		kuz_l_dec[ 5][((uint8_t *) &x)[ 5]][0] ^
		kuz_l_dec[ 6][((uint8_t *) &x)[ 6]][0] ^
		kuz_l_dec[ 7][((uint8_t *) &x)[ 7]][0] ^
		kuz_l_dec[ 8][((uint8_t *) &x)[ 8]][0] ^
		kuz_l_dec[ 9][((uint8_t *) &x)[ 9]][0] ^
		kuz_l_dec[10][((uint8_t *) &x)[10]][0] ^
		kuz_l_dec[11][((uint8_t *) &x)[11]][0] ^
		kuz_l_dec[12][((uint8_t *) &x)[12]][0] ^
		kuz_l_dec[13][((uint8_t *) &x)[13]][0] ^
		kuz_l_dec[14][((uint8_t *) &x)[14]][0] ^
		kuz_l_dec[15][((uint8_t *) &x)[15]][0];
	y.q[1]=	kuz_l_dec[ 0][((uint8_t *) &x)[ 0]][1] ^
		kuz_l_dec[ 1][((uint8_t *) &x)[ 1]][1] ^
		kuz_l_dec[ 2][((uint8_t *) &x)[ 2]][1] ^
		kuz_l_dec[ 3][((uint8_t *) &x)[ 3]][1] ^
		kuz_l_dec[ 4][((uint8_t *) &x)[ 4]][1] ^
		kuz_l_dec[ 5][((uint8_t *) &x)[ 5]][1] ^
		kuz_l_dec[ 6][((uint8_t *) &x)[ 6]][1] ^
		kuz_l_dec[ 7][((uint8_t *) &x)[ 7]][1] ^
		kuz_l_dec[ 8][((uint8_t *) &x)[ 8]][1] ^
		kuz_l_dec[ 9][((uint8_t *) &x)[ 9]][1] ^
		kuz_l_dec[10][((uint8_t *) &x)[10]][1] ^
		kuz_l_dec[11][((uint8_t *) &x)[11]][1] ^
		kuz_l_dec[12][((uint8_t *) &x)[12]][1] ^
		kuz_l_dec[13][((uint8_t *) &x)[13]][1] ^
		kuz_l_dec[14][((uint8_t *) &x)[14]][1] ^
		kuz_l_dec[15][((uint8_t *) &x)[15]][1];
	x = y;

	for (i = 9; i > 1; i--) {
		x.q[0] ^= subkeys->dk[i].q[0];
		x.q[1] ^= subkeys->dk[i].q[1];
		y.q[0]=	kuz_pil_dec[ 0][((uint8_t *) &x)[ 0]][0] ^
			kuz_pil_dec[ 1][((uint8_t *) &x)[ 1]][0] ^
			kuz_pil_dec[ 2][((uint8_t *) &x)[ 2]][0] ^
			kuz_pil_dec[ 3][((uint8_t *) &x)[ 3]][0] ^
			kuz_pil_dec[ 4][((uint8_t *) &x)[ 4]][0] ^
			kuz_pil_dec[ 5][((uint8_t *) &x)[ 5]][0] ^
			kuz_pil_dec[ 6][((uint8_t *) &x)[ 6]][0] ^
			kuz_pil_dec[ 7][((uint8_t *) &x)[ 7]][0] ^
			kuz_pil_dec[ 8][((uint8_t *) &x)[ 8]][0] ^
			kuz_pil_dec[ 9][((uint8_t *) &x)[ 9]][0] ^
			kuz_pil_dec[10][((uint8_t *) &x)[10]][0] ^
			kuz_pil_dec[11][((uint8_t *) &x)[11]][0] ^
			kuz_pil_dec[12][((uint8_t *) &x)[12]][0] ^
			kuz_pil_dec[13][((uint8_t *) &x)[13]][0] ^
			kuz_pil_dec[14][((uint8_t *) &x)[14]][0] ^
			kuz_pil_dec[15][((uint8_t *) &x)[15]][0];
		y.q[1]=	kuz_pil_dec[ 0][((uint8_t *) &x)[ 0]][1] ^
			kuz_pil_dec[ 1][((uint8_t *) &x)[ 1]][1] ^
			kuz_pil_dec[ 2][((uint8_t *) &x)[ 2]][1] ^
			kuz_pil_dec[ 3][((uint8_t *) &x)[ 3]][1] ^
			kuz_pil_dec[ 4][((uint8_t *) &x)[ 4]][1] ^
			kuz_pil_dec[ 5][((uint8_t *) &x)[ 5]][1] ^
			kuz_pil_dec[ 6][((uint8_t *) &x)[ 6]][1] ^
			kuz_pil_dec[ 7][((uint8_t *) &x)[ 7]][1] ^
			kuz_pil_dec[ 8][((uint8_t *) &x)[ 8]][1] ^
			kuz_pil_dec[ 9][((uint8_t *) &x)[ 9]][1] ^
			kuz_pil_dec[10][((uint8_t *) &x)[10]][1] ^
			kuz_pil_dec[11][((uint8_t *) &x)[11]][1] ^
			kuz_pil_dec[12][((uint8_t *) &x)[12]][1] ^
			kuz_pil_dec[13][((uint8_t *) &x)[13]][1] ^
			kuz_pil_dec[14][((uint8_t *) &x)[14]][1] ^
			kuz_pil_dec[15][((uint8_t *) &x)[15]][1];
		x = y;
	}
	x.q[0] ^= subkeys->dk[1].q[0];
	x.q[1] ^= subkeys->dk[1].q[1];
	for (i = 0; i < 16; i++) {
		((uint8_t *) &x)[i] = kuz_pi_inv[((uint8_t *) &x)[i]];
	}
	x.q[0] ^= subkeys->dk[0].q[0];
	x.q[1] ^= subkeys->dk[0].q[1];

	((uint64_t *) out)[0] = x.q[0];
	((uint64_t *) out)[1] = x.q[1];
}


/* ************************************************************* */

/* initialize lookup tables */
static void kuz_init()
{
	int i, j;
	union w128_t x;

	for (i = 0; i < 16; i++) {
		for (j = 0; j < 256; j++) {
			x.q[0] = 0;
			x.q[1] = 0;
			x.b[i] = kuz_pi[j];
			kuz_l(&x);

			kuz_pil_enc[i][j][0] = x.q[0];
			kuz_pil_enc[i][j][1] = x.q[1];

			x.q[0] = 0;
			x.q[1] = 0;
			x.b[i] = j; // kuz_pi[j];
			kuz_l_inv(&x);

			kuz_l_dec[i][j][0] = x.q[0];
			kuz_l_dec[i][j][1] = x.q[1];

			x.q[0] = 0;
			x.q[1] = 0;
			x.b[i] = kuz_pi_inv[j];
			kuz_l_inv(&x);

			kuz_pil_dec[i][j][0] = x.q[0];
			kuz_pil_dec[i][j][1] = x.q[1];
		}
	}
	kuz_initialized = 1;
}


static struct crypto_alg kuznyechik_alg = {
	.cra_name		=	"kuznyechik",
	.cra_flags		=	CRYPTO_ALG_TYPE_CIPHER,
	.cra_blocksize		=	16,
	.cra_ctxsize		=	sizeof(struct kuznyechik_subkeys),
	.cra_alignmask		=	3,
	.cra_module		=	THIS_MODULE,
	.cra_u			=	{ .cipher = {
	.cia_min_keysize	=	32,
	.cia_max_keysize	=	32,
	.cia_setkey		= 	kuznyechik_set_key,
	.cia_encrypt		=	kuznyechik_encrypt,
	.cia_decrypt		=	kuznyechik_decrypt } }
};


static int __init kuznyechik_mod_init(void)
{
	return crypto_register_alg(&kuznyechik_alg);
}


static void __exit kuznyechik_mod_fini(void)
{
	crypto_unregister_alg(&kuznyechik_alg);
}


module_init(kuznyechik_mod_init);
module_exit(kuznyechik_mod_fini);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("128bit cipher as specified in GOST R 34-12.2015");
MODULE_ALIAS_CRYPTO("kuznyechik");
//MODULE_ALIAS_CRYPTO("kuznechik");
//MODULE_ALIAS_CRYPTO("grasshopper");
