#ifndef _SECRETSHARE_H
#define _SECRETSHARE_H

#include "Config.h"

#include <openssl/rand.h>
#include <openssl/bn.h>

#include <vector>
#include <set>
using namespace std;

#include <assert.h>

class SharedVal
{
public:
	int pid;
	BIGNUM *val;

public:
	SharedVal() { val = BN_new(); }
	~SharedVal() { BN_free(val); }

	SharedVal& operator=(const SharedVal &share)
	{
		this->pid = share.pid;
		BN_copy(this->val, share.val);
		return *this;
	}
};

class SecretShare
{
public:
	BIGNUM *p;
	BN_CTX *ctx;

public:
	SecretShare();
	~SecretShare();
	
	// Share a secret value
	void Share(vector<SharedVal> &shares, 
		int t, const vector<int> &pids,
		const BIGNUM *secret);

	// Reconstruct secret from shares
	void Combine(BIGNUM *secret,
		int t,
		const vector<SharedVal> &shares);
};

void _test_SecretShare();

#endif