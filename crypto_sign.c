
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "sodium.h"

typedef unsigned char UCHAR;
 
#define MAX_MSG_LEN 64


int sign(UCHAR sm[], const UCHAR m[], const int mlen, const UCHAR sk[]) {
	unsigned long long smlen;
	
	if( crypto_sign(sm,&smlen, m, mlen, sk) == 0) {
		return smlen;
	} else {
		return -1;
	}
}

int verify(UCHAR m[], const UCHAR sm[], const int smlen, const UCHAR pk[]) {
	unsigned long long mlen;

	if( crypto_sign_open(m, &mlen, sm, smlen, pk) == 0) {
		return mlen;
	} else {
		return -1;
	}
}

int main() {
	UCHAR sk[crypto_sign_SECRETKEYBYTES];
	UCHAR pk[crypto_sign_PUBLICKEYBYTES];
	UCHAR sm[MAX_MSG_LEN+crypto_sign_BYTES];
	UCHAR m[MAX_MSG_LEN+crypto_sign_BYTES];

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
