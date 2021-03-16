#ifndef _CONTEXT_H
#define _CONTEXT_H

#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/ec.h>

#include <vector>
#include <set>
using namespace std;

#include <math.h>

#include "Config.h"
#include "Utils.h"
#include "MsgFormat.h"

#include "HomHash.h"
#include "Commitment.h"
#include "SecretShare.h"
#include "KeyAgreement.h"
#include "Cipher.h"

class Context
{
public:
	const int logR;
	const int d;
	const int t;
	const int N;
	const int pid;			// For client, it is counted from 1 to N
	const int batch;
	
	int curr_epoch;

	const int n_bytes_agg_bound;
	const BN_ULONG modB;

	// Client interfaces
	static HomHash hh;		// Implemented with ANSI X9.62 Prime 256v1 curve
							//   (128-bits security).
							// Length of hash: _ECC_POINT_SIZE bytes (point compression)
	
	Commitment com;			// Implemented with folklore hash commitment
							//   with SHA-256.
							// Length of opening string (with message): _ECC_POINT_SIZE*2 bytes
	
	SecretShare ss;			// Standard Shamir secret sharing with field size
							//   set to be able to accomodate _ECC_POINT_SIZE-bytes message.
							// Field size: _SHARE_FIELD_SIZE bytes
	
	KeyAgreement enc, mask;	// Implemented with ANSI X9.62 Prime 256v1 curve
							//   (128-bits security).
							// Length of private key: _SYM_KEY_SIZE bytes
							// Length of public key:  _ECC_POINT_SIZE bytes (point compression)

	Cipher cipher;			// Symmetric encryption scheme.
	
	BN_CTX *ctx;

	vector<unsigned char *> sym_key;			// For current epoch only
	vector<unsigned char *> mak;				// For current epoch only

	vector<BN_ULONG> my_vec;					// For current epoch only
	BIGNUM *b;									// For current epoch only
	
	vector<EC_POINT *> epoch_hash;
	vector<unsigned char *> my_open_str;
	
	vector<bool> U2;
	vector<bool> U3;

	vector<int> exclusive_U2_size;
	vector<int> exclusive_U3_size;

	vector<unsigned char *> com_str;
	vector<unsigned char *> Ctxt;				// For current epoch only
	vector<unsigned char *> open_str_share;

	vector<BIGNUM *> alpha;
	vector<BIGNUM *> comb_result;

	set<int> V1;

public:
	Context(int logR, int d, int t, int N, int pid, int batch);
	~Context();

	// Client interfaces
	int AdvertiseKeys(unsigned char *buffer);

	int ShareMetadata(unsigned char *buffer,
		const Round_1_Msg &round_1_msg);

	int MaskedInputCollection(unsigned char *buffer,
		const Round_2_Msg &round_2_msg);

	int Unmasking(unsigned char *buffer,
		const Round_3_Msg &round_3_msg);
	
	void ReceiveResult(const Epoch_Result_Msg &epoch_result_msg);

	int Decommitting(unsigned char *buffer);

	int DroppedDecommitting(unsigned char *buffer,
		const Ver_Round_1_Msg &ver_round_1_msg);

	bool BatchChecking(const Ver_Round_2_Msg &ver_round_2_msg);

	// Debug Interfaces
	void _rand_input();
	int _compute_multiplied_input(unsigned char *buffer,
		int scalar);
};

#endif