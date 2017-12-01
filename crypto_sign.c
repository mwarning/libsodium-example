
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "sodium.h"

#define MAX_MSG_LEN 64


int sign(uint8_t sm[], const uint8_t m[], const int mlen, const uint8_t sk[]) {
	unsigned long long smlen;

	if( crypto_sign(sm,&smlen, m, mlen, sk) == 0) {
		return smlen;
	} else {
		return -1;
	}
}

int verify(uint8_t m[], const uint8_t sm[], const int smlen, const uint8_t pk[]) {
	unsigned long long mlen;

	if( crypto_sign_open(m, &mlen, sm, smlen, pk) == 0) {
		return mlen;
	} else {
		return -1;
	}
}

int main() {
	uint8_t sk[crypto_sign_SECRETKEYBYTES];
	uint8_t pk[crypto_sign_PUBLICKEYBYTES];
	uint8_t sm[MAX_MSG_LEN+crypto_sign_BYTES];
	uint8_t m[MAX_MSG_LEN+crypto_sign_BYTES];

	memset(m, '\0', MAX_MSG_LEN);
	int mlen = snprintf(m, MAX_MSG_LEN, "%s", "Hello World!");

	int rc = crypto_sign_keypair(pk, sk);
	if(rc < 0) {
		return 1;
	}

	int smlen = sign(sm, m, mlen, sk);
	if(smlen < 0) {
		return 1;
	}

	mlen = verify(m, sm, smlen, pk);
	if(mlen < 0) {
		return 1;
	}

	printf("Verified!\n");
	return 0;
}
