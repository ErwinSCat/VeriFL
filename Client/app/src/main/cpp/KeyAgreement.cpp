#include "KeyAgreement.h"

KeyAgreement::KeyAgreement()
{
	ctx = BN_CTX_new();
	curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	q = BN_new();
	EC_GROUP_get_order(curve, q, ctx);

	priv_key = BN_new();
	pub_key = EC_POINT_new(curve);
}

KeyAgreement::~KeyAgreement()
{
	EC_POINT_free(pub_key);
	BN_free(priv_key);

	BN_free(q);
	EC_GROUP_free(curve);
	BN_CTX_free(ctx);
}

void KeyAgreement::KeyGen()
{
	BN_rand_range(priv_key, q);
	EC_POINT_mul(curve, pub_key, priv_key, NULL, NULL, ctx);
}

void KeyAgreement::Agree(unsigned char *secret, 
		const EC_POINT *peer_pub_key)
{
	EC_POINT *temp = EC_POINT_new(curve);
	unsigned char *buffer = NULL;

	EC_POINT_mul(curve, temp, NULL, peer_pub_key, priv_key, ctx);
	size_t len = EC_POINT_point2buf(curve, temp,
		POINT_CONVERSION_COMPRESSED, &buffer, ctx);
	SHA384(buffer, len, secret);

	OPENSSL_free(buffer);
	EC_POINT_free(temp);
}

void _test_KeyAgreement()
{
	KeyAgreement Alice, Bob;
	Alice.KeyGen();
	Bob.KeyGen();

	unsigned char Alice_secret[_AGREED_KEY_SIZE];
	unsigned char Bob_secret[_AGREED_KEY_SIZE];

	Alice.Agree(Alice_secret, Bob.pub_key);

	for (int i = 0; i < 1000; ++i)
		Bob.Agree(Bob_secret, Alice.pub_key);

	assert( strncmp((char *)Alice_secret, (char *)Bob_secret, _AGREED_KEY_SIZE) == 0 );
}