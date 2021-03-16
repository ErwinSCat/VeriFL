#ifndef _SERVERCONTEXT_H
#define _SERVERCONTEXT_H

#include <openssl/bn.h>

#include <vector>
#include <set>
using namespace std;

#include <math.h>

#include "Config.h"
#include "Utils.h"
#include "ServerMsgFormat.h"

#include "SecretShare.h"
#include "KeyAgreement.h"
#include "Cipher.h"

#include <assert.h>

class ServerContext
{
public:
	const int logR;
	const int d;
	const int t;
	const int N;
	const int batch;

	int curr_epoch;

	const int n_bytes_agg_bound;
	const BN_ULONG modB;

	SecretShare ss;
	KeyAgreement mask;

	BN_CTX *ctx;

	vector<EC_POINT *> mpk;					// For current epoch only
	vector<BN_ULONG> epoch_result;			// For current epoch only

	vector<SharedVal> *b_shares_arr;
	vector<SharedVal> *msk_shares_arr;
	vector<BIGNUM *> b_arr;
	vector<int> b_shares_size;
	vector<int> msk_shares_size;

	vector<bool> U2;
	vector<bool> U3;

	vector<int> U2_size;
	vector<int> U3_size;

	vector<bool> U4;

	set<int> V1;

	vector<SharedVal> *h_shares_arr;
	vector<SharedVal> *r_shares_arr;
	vector<int> h_shares_size;
	vector<int> r_shares_size;

public:
	ServerContext(int logR, int d, int t, int N, int batch);
	~ServerContext();

	void UpdateKeys(const MaskKey &maskKey);
	void UpdateU2(const int pid);
	void UpdateInput(const MaskedInput &maskedInput);
	void UpdateMaskShares(const MaskShares &maskShares);
	int FinalResult(unsigned char *buffer);
	
	void UpdateV1(const int pid);
	void UpdateDecomStrShares(const DecomStrShares &decomStrShares);
	int FinalDecomStr(unsigned char *buffer);
};

#endif