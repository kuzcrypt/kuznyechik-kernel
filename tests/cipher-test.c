#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <linux/if_alg.h>
#include <sys/param.h>
#include <string.h>
#include <strings.h>

#ifndef AF_ALG
#define AF_ALG 38
#endif
#ifndef SOL_ALG
#define SOL_ALG 279
#endif


static uint8_t cipher_test_key[32] = {
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
	0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef
};

static uint8_t cipher_test_pt[48] = {
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
	0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
	0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88,
	0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x00,
	0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88
};

static uint8_t cipher_test_iv[16] = {
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
};


static int crypto_cipher_test(char *cipher, int keylen, int blocklen, int ivlen, const char *expected)
{

	int sd[2] = {-1, -1};
	unsigned int i;

	struct msghdr msg = {};
	struct cmsghdr *cmsg;
	struct iovec iov;
	struct sockaddr_alg sa = {
		.salg_family = AF_ALG,
		.salg_type   = "skcipher",
	};
	memcpy(sa.salg_name, cipher, strlen(cipher) + 1);

	if ((sd[0] = socket(AF_ALG, SOCK_SEQPACKET, 0)) == -1) {
		goto failed;
	}
	if (bind(sd[0], (struct sockaddr *) &sa, sizeof(sa)) != 0) {
		goto failed;
	}
	setsockopt(sd[0], SOL_ALG, ALG_SET_KEY, cipher_test_key, keylen); /* Set key */
	if ((sd[1] = accept(sd[0], NULL, 0)) == -1) {
		goto failed;
	}

	uint8_t msgbuf[512] = {},
		encbuf[512] = {},
		decbuf[512] = {};
	msg.msg_control = msgbuf;
	msg.msg_controllen = CMSG_SPACE(4);
	if (ivlen) {
		msg.msg_controllen += CMSG_SPACE(ivlen+4);
	}



	/* --- Test encryption --------------------------------------- */

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(__u32 *)CMSG_DATA(cmsg) = ALG_OP_ENCRYPT;

	if (ivlen) {
		cmsg = CMSG_NXTHDR(&msg, cmsg);
		cmsg->cmsg_level = SOL_ALG;
		cmsg->cmsg_type = ALG_SET_IV;
		cmsg->cmsg_len = CMSG_LEN(ivlen+4);
		struct af_alg_iv *iv = (void *)CMSG_DATA(cmsg);
		iv->ivlen = ivlen;
		memcpy(iv->iv, cipher_test_iv, ivlen);
	}

	iov.iov_base = cipher_test_pt;
	iov.iov_len = sizeof(cipher_test_pt);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	sendmsg(sd[1], &msg, 0);
	read(sd[1], encbuf, sizeof(cipher_test_pt));


	/* Test decryption --------------------------------------- */

	cmsg = CMSG_FIRSTHDR(&msg);
	cmsg->cmsg_level = SOL_ALG;
	cmsg->cmsg_type = ALG_SET_OP;
	cmsg->cmsg_len = CMSG_LEN(4);
	*(__u32 *)CMSG_DATA(cmsg) = ALG_OP_DECRYPT;

	if (ivlen) {
		cmsg = CMSG_NXTHDR(&msg, cmsg);
		cmsg->cmsg_level = SOL_ALG;
		cmsg->cmsg_type = ALG_SET_IV;
		cmsg->cmsg_len = CMSG_LEN(ivlen+4);
		struct af_alg_iv *iv = (void *)CMSG_DATA(cmsg);
		iv->ivlen = ivlen;
		memcpy(iv->iv, cipher_test_iv, ivlen);
	}

	iov.iov_base = encbuf;
	iov.iov_len = sizeof(cipher_test_pt);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	sendmsg(sd[1], &msg, 0);
	read(sd[1], decbuf, sizeof(cipher_test_pt));

	printf("%s:%s", cipher, "                  " + strlen(cipher));

	for (i = 0; i < sizeof(cipher_test_pt); i++) {
		printf("%02x", cipher_test_pt[i]);
		if ((i+1) % blocklen == 0) {
			printf(" ");
		}
	}

	printf(" (original)\n                   ");
	memset(msgbuf, 0, sizeof msgbuf);
	for (i = 0; i < sizeof(cipher_test_pt); i++) {
		sprintf(msgbuf + strlen(msgbuf), "%02x", encbuf[i]);
		if ((i+1) % blocklen == 0) {
			sprintf(msgbuf + strlen(msgbuf), " ");
		}
	}
	for (i = 0; i < strlen(expected); i++) {
		if (expected[i] == msgbuf[i]) {
			printf("\e[32;1m%c\e[0m", msgbuf[i]);
		} else {
			printf("\e[31;1m%c\e[0m", msgbuf[i]);
		}
	}

	printf("  (encrypted)\n                   ");
	for (i = 0; i < sizeof(cipher_test_pt); i++) {
		printf("%02x", decbuf[i]);
		if ((i+1) % blocklen == 0) {
			printf(" ");
		}
	}
	printf(" (decrypted)\n\n");

	close(sd[1]);
	close(sd[0]);
	return 0;

	failed:

		printf("\e[31;1m%s:%sAn error occured when opening crypto socket.\n",
			cipher, "                  " + strlen(cipher));
		if (!strncmp(cipher, "xts", 3) && blocklen != 16)
			printf("                   XTS mode requires blocksize == 16 B (%d B given).\n", blocklen);
		printf("\e[0m\n");
		return -1;
}



int main (int argc, char **argv)
{

	crypto_cipher_test("ecb(kuznyechik)", 32, 16, 0,  "7f679d90bebc24305a468d42b9d4edcd 7f679d90bebc24305a468d42b9d4edcd 7f679d90bebc24305a468d42b9d4edcd");
	crypto_cipher_test("cbc(kuznyechik)", 32, 16, 16, "470108c90e9bdaf60cc7446b5bf3c39b 85e5377c2b96abe265aa172958019d02 7d674621724181ef8412ed2774d2ec7d");
	crypto_cipher_test("ctr(kuznyechik)", 32, 16, 16, "ab6943098fcd63b1d28fed6b26e85edc 7e6677244d2bda780696bfc29f6acfe1 64b18062c785dbb7e95c07378daf75fe");
//	crypto_cipher_test("xts(kuznyechik)", 64, 16, 16, "be6cff9aab3e2448c081c933b15b9f9c 8bb5ed5bd5f812e6b8c1145823ef2d3c 47182fc6159a69ede376806d4112d1cf");

	printf("                   -------------------------------------------\n\n");
	crypto_cipher_test("ecb(magma)", 32, 8, 0, "a774d4984a0e52d2 cbe025522cf72e0b a774d4984a0e52d2 cbe025522cf72e0b a774d4984a0e52d2 cbe025522cf72e0b");
	crypto_cipher_test("cbc(magma)", 32, 8, 8, "ea1fbca6a8009abf b73e10fc007c2930 8370e469c075690b b2965efc51b2fcea 3468898d5e4fb956 0686a8bba594edf2");
	crypto_cipher_test("ctr(magma)", 32, 8, 8, "176ffa923be317b3 11122474a8752a51 ec592fdb2ddbe2ad 286e3b9200fd0afb 0d0a283651c5332f 173e220c0b81a369");

//	printf("                   -------------------------------------------\n\n");
//	crypto_cipher_test("xts(aes)", 32, 16, 16);
//	crypto_cipher_test("xts(twofish)", 32, 16, 16);

	return 0;
}
