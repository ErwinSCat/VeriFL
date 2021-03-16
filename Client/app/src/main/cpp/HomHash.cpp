#include "HomHash.h"

HomHash::HomHash(int d)
{
	this->d = d;
	ctx = BN_CTX_new();

	curve = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	g0 = EC_POINT_dup(EC_GROUP_get0_generator(curve), curve);
	g.resize(d);
	for (int i = 0; i < d; ++i)
		g[i] = EC_POINT_new(curve);

	q = BN_new();
	EC_GROUP_get_order(curve, q, ctx);

	HGen();
}

HomHash::~HomHash()
{
	BN_free(q);
	for (int i = 0; i < d; ++i)
		EC_POINT_free(g[i]);

	EC_POINT_free(g0);
	EC_GROUP_free(curve);
	BN_CTX_free(ctx);
}

void HomHash::HGen()
{
	unsigned char ciphertext[32];
	int clen;

	// Use AES-CTR mode as PRG
	BIGNUM *x = BN_new();
	int lsb = 0;
	EVP_CIPHER_CTX *cipher_ctx = EVP_CIPHER_CTX_new();
	EVP_EncryptInit_ex(cipher_ctx, EVP_aes_256_ctr(), NULL,
		_homhash_seed_key, _homhash_seed_iv);

	for (int i = 0; i < d; ++i)
	{
		do 	// Loop until find d different points (with overwhelming probability)
		{
			EVP_EncryptUpdate(cipher_ctx, ciphertext, &clen, _homhash_seed_plaintext, 32);
			BN_bin2bn(ciphertext, 32, x);
		} while (EC_POINT_set_compressed_coordinates_GFp(curve,
			g[i], x, lsb, ctx) == 0);
	}

	EVP_CIPHER_CTX_free(cipher_ctx);
	BN_free(x);
}

void HomHash::Hash(EC_POINT *hash,
	const vector<BIGNUM *> &vec)
{
	EC_POINT *temp = EC_POINT_new(curve);
	assert( vec.size() <= d );

	for (int i = 0; i < vec.size(); ++i)
	{
		EC_POINT_mul(curve, temp, NULL, g[i], vec[i], ctx);
		EC_POINT_add(curve, hash, hash, temp, ctx);
	}

	EC_POINT_free(temp);
}

void HomHash::Hash(EC_POINT *hash,
	const vector<unsigned long> &vec)
{
	vector<BIGNUM *> bn_vec(vec.size());
	for (int i = 0; i < vec.size(); ++i)
	{
		bn_vec[i] = BN_new();
		BN_set_word(bn_vec[i], vec[i]);
	}

	Hash(hash, bn_vec);

	for (int i = 0; i < vec.size(); ++i)
		BN_free(bn_vec[i]);
}

void HomHash::Eval(EC_POINT *res,
	const vector<EC_POINT *> &hashes,
	const vector<BIGNUM *> &alphas)
{
	EC_POINT *temp = EC_POINT_new(curve);
	size_t l = hashes.size();

	for (int i = 0; i < l; ++i)
	{
		EC_POINT_mul(curve, temp, NULL, hashes[i], alphas[i], ctx);
		EC_POINT_add(curve, res, res, temp, ctx);
	}

	EC_POINT_free(temp);
}

void _test_HomHash()
{
	const int logR = 24;
	const int d = 100;
	const int batch = 10;

	HomHash hh(d);
	BN_CTX *ctx = BN_CTX_new();

	vector<EC_POINT *> hashes(batch);
	vector<BIGNUM *> alphas(batch);
	for (int i = 0; i < batch; ++i)
	{
		hashes[i] = EC_POINT_new(hh.curve);
		alphas[i] = BN_new();
	}

	vector<BIGNUM *> my_vec(d), agg_vec(d);
	for (int i = 0; i < d; ++i)
	{
		my_vec[i] = BN_new();
		agg_vec[i] = BN_new();
	}

	for (int i = 0; i < batch; ++i)
	{
		for (int j = 0; j < d; ++j)
			BN_rand(my_vec[j], logR, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);

		hh.Hash(hashes[i], my_vec);
		BN_rand_range(alphas[i], hh.q);

		for (int j = 0; j < d; ++j)
		{
			BN_mod_mul(my_vec[j], my_vec[j], alphas[i], hh.q, ctx);
			BN_mod_add(agg_vec[j], agg_vec[j], my_vec[j], hh.q, ctx);
		}
	}

	EC_POINT *agg_hash = EC_POINT_new(hh.curve);
	EC_POINT *ver_agg_hash = EC_POINT_new(hh.curve);
	hh.Eval(agg_hash, hashes, alphas);
	hh.Hash(ver_agg_hash, agg_vec);

	assert( EC_POINT_cmp(hh.curve, agg_hash, ver_agg_hash, ctx) == 0 );

	EC_POINT_free(ver_agg_hash);
	EC_POINT_free(agg_hash);
	for (int i = 0; i < d; ++i)
	{
		BN_free(my_vec[i]);
		BN_free(agg_vec[i]);
	}
	for (int i = 0; i < batch; ++i)
	{
		BN_free(alphas[i]);
		EC_POINT_free(hashes[i]);
	}
	BN_CTX_free(ctx);

}