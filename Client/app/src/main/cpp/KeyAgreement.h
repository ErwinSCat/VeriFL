#ifndef _KEYAGREEMENT_H
#define _KEYAGREEMENT_H

#include "Config.h"

#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <assert.h>
#include <string.h>

class KeyAgreement
{
public:
	BN_CTX *ctx;
	EC_GROUP *curve;
	BIGNUM *q;

	BIGNUM *priv_key;
	EC_POINT *pub_key;

public:
	KeyAgreement();
	~KeyAgreement();
	
	// Generate a new key pair
	void KeyGen();

	// Compute a agreed key
	// Assert len(secret) = 48 bytes
	void Agree(unsigned char *secret, 
		const EC_POINT *peer_pub_key);
};

void _test_KeyAgreement();

#endif