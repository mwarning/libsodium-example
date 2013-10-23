
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>

#include <sodium.h>
//#include "nacl/crypto_box.h" //for libnacl


/*
* This example shows how to get the public key from the private key
* (for crypto_box_* and crypto_sign_* keys)
*/

typedef unsigned char UCHAR;

char* to_hex( char hex[], const UCHAR bin[], size_t length )
{
	int i;
	UCHAR *p0 = (UCHAR *)bin;
	char *p1 = hex;

	for( i = 0; i < length; i++ ) {
		snprintf( p1, 3, "%02x", *p0 );
		p0 += 1;
		p1 += 2;
	}

	return hex;
}

int crypto_box_recover_public_key(UCHAR secret_key[]) {
	UCHAR public_key[crypto_sign_PUBLICKEYBYTES];
	char phexbuf[2*crypto_sign_PUBLICKEYBYTES+1];

	crypto_scalarmult_curve25519_base( public_key, secret_key );
	
	printf("recovered public_key: %s\n", to_hex(phexbuf, public_key, crypto_sign_PUBLICKEYBYTES));
}

void crypto_box_example()
{
	UCHAR public_key[crypto_box_PUBLICKEYBYTES];
	UCHAR secret_key[crypto_box_SECRETKEYBYTES];
	char phexbuf[2*crypto_box_PUBLICKEYBYTES+1];
	char shexbuf[2*crypto_box_SECRETKEYBYTES+1];

	crypto_box_keypair(public_key, secret_key);
	
	printf("public_key: %s\n", to_hex(phexbuf, public_key, crypto_box_PUBLICKEYBYTES));
	printf("secret_key: %s\n", to_hex(shexbuf, secret_key,  crypto_box_SECRETKEYBYTES));
	
	crypto_box_recover_public_key(secret_key);
}

int crypto_sign_recover_public_key(UCHAR secret_key[]) {
	UCHAR public_key[crypto_sign_PUBLICKEYBYTES];
	char phexbuf[2*crypto_sign_PUBLICKEYBYTES+1];

	memcpy(public_key, secret_key+crypto_sign_PUBLICKEYBYTES, crypto_sign_PUBLICKEYBYTES);
	
	printf("recovered public_key: %s\n", to_hex(phexbuf, public_key, crypto_sign_PUBLICKEYBYTES));
}


void crypto_sign_example()
{
	UCHAR public_key[crypto_sign_PUBLICKEYBYTES];
	UCHAR secret_key[crypto_sign_SECRETKEYBYTES];
	char phexbuf[2*crypto_sign_PUBLICKEYBYTES+1];
	char shexbuf[2*crypto_sign_SECRETKEYBYTES+1];

	crypto_sign_keypair(public_key, secret_key);
	
	printf("public_key: %s\n", to_hex(phexbuf, public_key, crypto_sign_PUBLICKEYBYTES));
	printf("secret_key: %s\n", to_hex(shexbuf, secret_key,  crypto_sign_SECRETKEYBYTES));
	
	crypto_sign_recover_public_key(secret_key);
}

int main( int argc, char **argv )
{
	printf("\ncrypto_sign_example:\n");
	crypto_sign_example();

	printf("\ncrypto_box_example:\n");
	crypto_box_example();
}
