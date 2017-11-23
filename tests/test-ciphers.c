#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/if_alg.h>

static uint8_t test_key[32] = {
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
};

static uint8_t test_pt[48] = {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
	0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
	0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
	0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88
};

static uint8_t test_iv[16] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};

#ifndef AF_ALG
	#define AF_ALG 38
#endif
#ifndef SOL_ALG
	#define SOL_ALG 279
#endif

static int crypt(int sd, uint8_t *out, uint8_t *in, unsigned int nbytes,
		 uint8_t *iv, unsigned int ivlen, uint32_t action)
{
	struct msghdr msgh = {};
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct af_alg_iv *aiv;
	uint8_t msgbuf[512] = {};

	msgh.msg_control = msgbuf;
	msgh.msg_controllen = CMSG_SPACE(4);
	if (ivlen)
		msgh.msg_controllen += CMSG_SPACE(ivlen + 4);

	cmsg = CMSG_FIRSTHDR(&msgh);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(uint32_t *) CMSG_DATA(cmsg) = action;

	if (ivlen) {
		cmsg = CMSG_NXTHDR(&msgh, cmsg);
		cmsg->cmsg_level = SOL_ALG;
		cmsg->cmsg_type = ALG_SET_IV;
		cmsg->cmsg_len = CMSG_LEN(ivlen + 4);
		aiv = (void *) CMSG_DATA(cmsg);
		aiv->ivlen = ivlen;
		memcpy(aiv->iv, test_iv, ivlen);
	}

	iov.iov_base = in;
	iov.iov_len = nbytes;
	msgh.msg_iov = &iov;
	msgh.msg_iovlen = 1;

	if (sendmsg(sd, &msgh, 0) == -1)
		return errno;

	if (read(sd, out, nbytes) == -1)
		return errno;

	return 0;
}

static int crypt_and_verify(int sd, uint8_t *out, uint8_t *in,
			    uint8_t *expected, unsigned int nbytes, uint8_t *iv,
			    unsigned int ivlen, uint32_t action)
{
	int i, ret;

	if ((ret = crypt(sd, out, in, nbytes, iv, ivlen, action)) != 0)
		return ret;

	for (i = 0; i < nbytes; i++)
		if (out[i] != expected[i])
			return -2;

	return 0;
}

static int test_cipher(const char *algname, uint8_t *expected, uint8_t *iv,
		       unsigned int ivlen)
{
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type   = "skcipher",
	};
	int sd[2] = {-1, -1};
	int ret = -1;
	uint8_t encbuf[512] = {};
	uint8_t decbuf[512] = {};

	snprintf(sa.salg_name, sizeof(sa.salg_name), "ecb(%s)", algname);

	if ((sd[0] = socket(AF_ALG, SOCK_SEQPACKET, 0)) == -1)
		goto out;

	if (bind(sd[0], (struct sockaddr *) &sa, sizeof(sa)) != 0)
		goto close_sd0;


	/* Set key */
	setsockopt(sd[0], SOL_ALG, ALG_SET_KEY, test_key, sizeof(test_key));
	if ((sd[1] = accept(sd[0], NULL, 0)) == -1)
		goto close_sd0;

	/* Test encryption */
	if ((ret = crypt_and_verify(sd[1], encbuf, test_pt, expected,
		sizeof(test_pt), iv, ivlen, ALG_OP_ENCRYPT)) != 0)
		goto close_sd1;

	/* Test decryption */
	if ((ret = crypt_and_verify(sd[1], decbuf, encbuf, test_pt,
		sizeof(test_pt), iv, ivlen, ALG_OP_DECRYPT)) != 0)
		goto close_sd1;

close_sd1:
	close(sd[1]);
close_sd0:
	close(sd[0]);
out:
	return ret;
}

int main(int argc, const char *argv)
{
	int ret = 0;
	uint8_t kuznyechik_ecb_ct[48] = {
		0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30,
		0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd,
		0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30,
		0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd,
		0x7f, 0x67, 0x9d, 0x90, 0xbe, 0xbc, 0x24, 0x30,
		0x5a, 0x46, 0x8d, 0x42, 0xb9, 0xd4, 0xed, 0xcd
	};
	uint8_t magma_ecb_ct[48] = {
		0xa7, 0x74, 0xd4, 0x98, 0x4a, 0x0e, 0x52, 0xd2,
		0xcb, 0xe0, 0x25, 0x52, 0x2c, 0xf7, 0x2e, 0x0b,
		0xa7, 0x74, 0xd4, 0x98, 0x4a, 0x0e, 0x52, 0xd2,
		0xcb, 0xe0, 0x25, 0x52, 0x2c, 0xf7, 0x2e, 0x0b,
		0xa7, 0x74, 0xd4, 0x98, 0x4a, 0x0e, 0x52, 0xd2,
		0xcb, 0xe0, 0x25, 0x52, 0x2c, 0xf7, 0x2e, 0x0b
	};

	if ((ret = test_cipher("kuznyechik", kuznyechik_ecb_ct, NULL, 0)) != 0)
		goto out;

	if ((ret = test_cipher("magma", magma_ecb_ct, NULL, 0)) != 0)
		goto out;

out:
	printf((ret == 0)
		? "\x1b[32mOK\x1b[0m\n"
		: "\x1b[31mError %d\x1b[0m\n", ret);

	return ret;
}
