#include "SecretShare.h"

SecretShare::SecretShare()
{
	p = BN_new();
	BN_hex2bn(&p, "EB24862D14F93010BA4267549AE549A239FB9805DC25CA9144E789436B0443A836ED");
	ctx = BN_CTX_new();
}

SecretShare::~SecretShare()
{
	BN_CTX_free(ctx);
	BN_free(p);
}

void SecretShare::Share(vector<SharedVal> &shares, 
		int t, const vector<int> &pids,
		const BIGNUM *secret)
{
	int N = pids.size();

	vector<BIGNUM *> poly_coeff(t);
	poly_coeff[0] = BN_dup(secret);
	for (int i = 1; i < t; ++i)
	{
		poly_coeff[i] = BN_new();
		BN_rand_range(poly_coeff[i], p);
	}

	BIGNUM *x = BN_new();
	for (int i = 0; i < N; ++i)
	{
		BN_set_word(x, pids[i]);
		shares[i].pid = pids[i];
		BN_copy(shares[i].val, poly_coeff[t - 1]);
		for (int j = t - 1; j >= 1; --j)
		{
			BN_mod_mul(shares[i].val, shares[i].val, x,
				p, ctx);
			BN_mod_add(shares[i].val, shares[i].val, poly_coeff[j - 1],
				p, ctx);
		}
	}

	BN_free(x);
	for (int i = 0; i < t; ++i)
		BN_free(poly_coeff[i]);
}

void SecretShare::Combine(BIGNUM *secret,
		int t,
		const vector<SharedVal> &shares)
{
	vector<BIGNUM *> x(t);
	for (int i = 0; i < t; ++i)
	{
		x[i] = BN_new();
		BN_set_word(x[i], shares[i].pid);
	}

	vector<BIGNUM *> prod(t);
	BIGNUM *temp1 = BN_new();
	BIGNUM *temp2 = BN_new();
	for (int j = 0; j < t; ++j)
	{
		prod[j] = BN_new();
		BN_one(prod[j]);
		for (int i = 0; i < t; ++i)
		{
			if (i != j)
			{
				BN_mod_sub(temp1, x[j], x[i], p, ctx);
				BN_mod_inverse(temp1, temp1, p, ctx);
				BN_zero(temp2);
				BN_mod_sub(temp2, temp2, x[i], p, ctx);
				BN_mod_mul(temp1, temp1, temp2, p, ctx);
				BN_mod_mul(prod[j], prod[j], temp1, p, ctx);
			}
		}
	}

	BN_zero(secret);
	for (int i = 0; i < t; ++i) 
	{
		BN_mod_mul(temp1, prod[i], shares[i].val, p, ctx);
		BN_mod_add(secret, secret, temp1, p, ctx);
	}

	for (int i = 0; i < t; ++i)
	{
		BN_free(prod[i]);
		BN_free(x[i]);
	}
	BN_free(temp1);
	BN_free(temp2);
}

void _test_SecretShare()
{
	const int t = 300, N = 1000;
	SecretShare ss;
	vector<SharedVal> shares(N);
	vector<int> pids(N);
	for (int i = 0; i < N; ++i)
		pids[i] = i + 1;

	BIGNUM *secret = BN_new();
	BIGNUM *rec_secret = BN_new();

	BN_rand_range(secret, ss.p);

	ss.Share(shares, t, pids, secret);
	ss.Combine(rec_secret, t, shares);

	assert( BN_cmp(secret, rec_secret) == 0 );

	BN_free(rec_secret);
	BN_free(secret);
}