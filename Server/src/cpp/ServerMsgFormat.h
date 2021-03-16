#ifndef _SERVERMSGFORMAT_H
#define _SERVERMSGFORMAT_H

#include <openssl/bn.h>
#include <openssl/ec.h>

#include "Utils.h"
#include "SecretShare.h"

class MaskKey
{
public:
	int my_pid;
	EC_POINT *my_mpk;

public:
	MaskKey(EC_GROUP *mpk_curve,
		unsigned char *message_buffer)
	{
		BN_CTX *ctx = BN_CTX_new();
		BIGNUM *temp = BN_new();
		int offset = 0;
		offset += decodePid(my_pid, message_buffer + offset);
		offset += _ECC_POINT_SIZE;		// Skip encryption key

		my_mpk = EC_POINT_new(mpk_curve);
		BN_bin2bn(message_buffer + offset, _ECC_POINT_SIZE, temp);
		EC_POINT_bn2point(mpk_curve, temp, my_mpk, ctx);
		offset += _ECC_POINT_SIZE;

		BN_free(temp);
		BN_CTX_free(ctx);
	}
	~MaskKey()
	{
		EC_POINT_free(my_mpk);
	}
};

class MaskedInput
{
public:
	int my_pid;
	vector<BN_ULONG> my_maskedInput;

public:
	MaskedInput(int d,
		int n_bytes_agg_bound,
		unsigned char *message_buffer)
	{
		my_maskedInput.resize(d);

		int offset = 0;
		offset += decodePid(my_pid, message_buffer + offset);

		for (int i = 0; i < d; ++i)
		{
			my_maskedInput[i]
				= uchar2ulong(message_buffer + offset, n_bytes_agg_bound);
			offset += n_bytes_agg_bound;
		}
	}
};

class MaskShares
{
public:
	int my_pid;
	BIGNUM *my_b;
	int exclusive_U3_size;
	int dropped_size;

	vector<int> exclusive_U3_pids;
	vector<SharedVal> exclusive_U3_shares;

	vector<int> dropped_pids;
	vector<SharedVal> dropped_shares;

public:
	MaskShares(int exclusive_U2_size,
		int exclusive_U3_size,
		unsigned char *message_buffer)
		: exclusive_U3_size(exclusive_U3_size),
		  dropped_size(exclusive_U2_size - exclusive_U3_size)
	{
		exclusive_U3_pids.resize(exclusive_U3_size);
		exclusive_U3_shares.resize(exclusive_U3_size);
		
		if (dropped_size != 0)
		{
			dropped_pids.resize(dropped_size);
			dropped_shares.resize(dropped_size);
		}

		int offset = 0;
		offset += decodePid(my_pid, message_buffer + offset);

		my_b = BN_new();
		BN_bin2bn(message_buffer + offset, _SHARE_FIELD_SIZE, my_b);
		offset += _SHARE_FIELD_SIZE;

		for (int i = 0; i < exclusive_U3_size; ++i)
		{
			offset += decodePid(exclusive_U3_pids[i], message_buffer + offset);

			exclusive_U3_shares[i].pid = my_pid;
			BN_bin2bn(message_buffer + offset, _SHARE_FIELD_SIZE, exclusive_U3_shares[i].val);
			offset += _SHARE_FIELD_SIZE;
		}

		for (int i = 0; i < dropped_size; ++i)
		{
			offset += decodePid(dropped_pids[i], message_buffer + offset);

			dropped_shares[i].pid = my_pid;
			BN_bin2bn(message_buffer + offset, _SHARE_FIELD_SIZE, dropped_shares[i].val);
			offset += _SHARE_FIELD_SIZE;
		}
	}
	~MaskShares()
	{
		BN_free(my_b);
	}
};

class DecomStrShares
{
public:
	int my_pid;
	int dropped_size;
	vector<int> dropped_pids;
	vector<SharedVal> dropped_h_shares;
	vector<SharedVal> dropped_r_shares;

public:
	DecomStrShares(int dropped_size,
		unsigned char *message_buffer)
		: dropped_size(dropped_size)
	{
		dropped_pids.resize(dropped_size);
		dropped_h_shares.resize(dropped_size);
		dropped_r_shares.resize(dropped_size);

		int offset = 0;
		offset += decodePid(my_pid, message_buffer + offset);

		for (int i = 0; i < dropped_size; ++i)
		{
			offset += decodePid(dropped_pids[i], message_buffer + offset);

			dropped_h_shares[i].pid = my_pid;
			BN_bin2bn(message_buffer + offset, _SHARE_FIELD_SIZE, dropped_h_shares[i].val);
			offset += _SHARE_FIELD_SIZE;

			dropped_r_shares[i].pid = my_pid;
			BN_bin2bn(message_buffer + offset, _SHARE_FIELD_SIZE, dropped_r_shares[i].val);
			offset += _SHARE_FIELD_SIZE;
		}
	}
};

#endif