#ifndef _HOMHASH_H
#define _HOMHASH_H

#include "Config.h"

#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

#include <vector>
#include <sstream>
#include <fstream>
using namespace std;

#include <assert.h>

class HomHash
{
private:
	int d;
	BN_CTX *ctx;

public:
	EC_GROUP *curve;
	EC_POINT *g0;
	vector<EC_POINT *> g;
	BIGNUM *q;
	
public:
	HomHash(int d);
	~HomHash();

	// Generate points
	void HGen();

	// Compute homomorphic hash
	void Hash(EC_POINT *hash,
		const vector<BIGNUM *> &vec);
	void Hash(EC_POINT *hash,
		const vector<unsigned long> &vec);
	
	// Linear combination of hashes
	void Eval(EC_POINT *res,
		const vector<EC_POINT *> &hashes,
		const vector<BIGNUM *> &alphas);
};

void _test_HomHash();

#endif