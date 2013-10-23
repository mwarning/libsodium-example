
all:
	gcc crypto_box.c -lsodium -o crypto_box
	gcc crypto_sign.c -lsodium -o crypto_sign
	gcc crypto_priv2pub.c -lsodium -o crypto_priv2pub
