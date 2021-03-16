#ifndef _MSGFORMAT_H
#define _MSGFORMAT_H

#include <openssl/bn.h>
#include <openssl/ec.h>

#include <vector>
using namespace std;

#include "Utils.h"

#include <string.h>

#include <iostream>

class Round_1_Msg
{
public:
	int exclusive_U1_size;
	vector<int> pids;
	vector<EC_POINT *> pks;
	vector<EC_POINT *> mpks;

public:
	Round_1_Msg(int my_pid,
		int exclusive_U1_size,
		EC_GROUP *pk_curve, EC_GROUP *mpk_curve,
		unsigned char *message_buffer)
		: exclusive_U1_size(exclusive_U1_size)
	{
		pids.resize(exclusive_U1_size);
		pks.resize(exclusive_U1_size);
		mpks.resize(exclusive_U1_size);

		BN_CTX *ctx = BN_CTX_new();
		BIGNUM *temp = BN_new();
		int offset = 0, pid;
		for (int i = 0; i < exclusive_U1_size; ++i)
		{
			offset += decodePid(pid, message_buffer + offset);
			if (pid == my_pid)		// Skip my message
			{
				offset += (_ECC_POINT_SIZE*2);
				i--;
				continue;
			}

			pids[i] = pid;
			
			pks[i] = EC_POINT_new(pk_curve);
			BN_bin2bn(message_buffer + offset, _ECC_POINT_SIZE, temp);
			EC_POINT_bn2point(pk_curve, temp, pks[i], ctx);
			offset += _ECC_POINT_SIZE;

			mpks[i] = EC_POINT_new(mpk_curve);
			BN_bin2bn(message_buffer + offset, _ECC_POINT_SIZE, temp);
			EC_POINT_bn2point(mpk_curve, temp, mpks[i], ctx);
			offset += _ECC_POINT_SIZE;
		}
		BN_free(temp);
		BN_CTX_free(ctx);
	}
	~Round_1_Msg()
	{
		for (int i = 0; i < exclusive_U1_size; ++i)
		{
			EC_POINT_free(pks[i]);
			EC_POINT_free(mpks[i]);
		}
	}
};

class Round_2_Msg
{
public:
	int exclusive_U2_size;
	vector<int> pids;
	vector<unsigned char *> commitment;
	vector<unsigned char *> ctxt;

public:
	Round_2_Msg(int exclusive_U2_size,
		unsigned char *message_buffer)
		: exclusive_U2_size(exclusive_U2_size)
	{
		pids.resize(exclusive_U2_size);
		commitment.resize(exclusive_U2_size);
		ctxt.resize(exclusive_U2_size);

		int offset = 0;
		for (int i = 0; i < exclusive_U2_size; ++i)
		{
			offset += decodePid(pids[i], message_buffer + offset);

			commitment[i] = new unsigned char[_COMMITMENT_SIZE];
			memcpy(commitment[i], message_buffer + offset, _COMMITMENT_SIZE);
			offset += _COMMITMENT_SIZE;

			ctxt[i] = new unsigned char[_SYM_CIPHERTEXT_SIZE];
			memcpy(ctxt[i], message_buffer + offset, _SYM_CIPHERTEXT_SIZE);
			offset += _SYM_CIPHERTEXT_SIZE;
		}
	}
	~Round_2_Msg()
	{
		for (int i = 0; i < exclusive_U2_size; ++i)
		{
			delete[] commitment[i];
			delete[] ctxt[i];
		}
	}
};

class Round_3_Msg
{
public:
	int exclusive_U3_size;
	vector<int> pids;

public:
	Round_3_Msg(int my_pid,
		int exclusive_U3_size,
		unsigned char *message_buffer)
		: exclusive_U3_size(exclusive_U3_size)
	{
		pids.resize(exclusive_U3_size);

		int offset = 0, pid;
		for (int i = 0; i < exclusive_U3_size; ++i)
		{
			offset += decodePid(pid, message_buffer + offset);
			if (pid == my_pid)		// Skip my message
			{
				i--;
				continue;
			}
			pids[i] = pid;
		}
	}
};

class Epoch_Result_Msg
{
public:
	int d;
	vector<BIGNUM *> epoch_result;

public:
	Epoch_Result_Msg(int d,
		int n_bytes_agg_bound,
		unsigned char *message_buffer)
		: d(d)
	{
		epoch_result.resize(d);

		int offset = 0;
		for (int i = 0; i < d; ++i)
		{
			epoch_result[i] = BN_new();
			BN_set_word(epoch_result[i],
				uchar2ulong(message_buffer + offset, n_bytes_agg_bound));
			offset += n_bytes_agg_bound;
		}
	}
	~Epoch_Result_Msg()
	{
		for (int i = 0; i < d; ++i)
			BN_free(epoch_result[i]);
	}
};

class Ver_Round_1_Msg
{
public:
	int exclusive_V1_size;
	int batch;
	vector<int> pids;
	vector<unsigned char *> open_strs;

public:
	Ver_Round_1_Msg(int my_pid,
		int exclusive_V1_size,
		int batch,
		unsigned char *message_buffer)
		: exclusive_V1_size(exclusive_V1_size),
		  batch(batch)
	{
		pids.resize(exclusive_V1_size);
		open_strs.resize(batch*exclusive_V1_size);

		for (int i = 0; i < batch*exclusive_V1_size; ++i)
			open_strs[i] = new unsigned char[_ECC_POINT_SIZE*2];

		int offset = 0, pid;
		for (int i = 0; i < exclusive_V1_size; ++i)
		{
			offset += decodePid(pid, message_buffer + offset);
			if (pid == my_pid)		// Skip my message
			{
				offset += (_ECC_POINT_SIZE*2*batch);
				i--;
				continue;
			}

			pids[i] = pid;

			for (int j = 0; j < batch; ++j)
			{
				memcpy(open_strs[j + i*batch], message_buffer + offset,
					_ECC_POINT_SIZE*2);
				offset += (_ECC_POINT_SIZE*2);
			}
		}
	}
	~Ver_Round_1_Msg()
	{
		for (int i = 0; i < batch*exclusive_V1_size; ++i)
			delete[] open_strs[i];
	}
};

class Ver_Round_2_Msg
{
public:
	int dropped_size;
	vector<int> dropped_pids;
	vector<unsigned char *> recon_open_strs;

public:
	Ver_Round_2_Msg(int dropped_size,
		unsigned char *message_buffer)
		: dropped_size(dropped_size)
	{
		dropped_pids.resize(dropped_size);
		recon_open_strs.resize(dropped_size);

		int offset = 0;
		for (int i = 0; i < dropped_size; ++i)
		{
			offset += decodePid(dropped_pids[i], message_buffer + offset);

			recon_open_strs[i] = new unsigned char[_ECC_POINT_SIZE*2];
			memcpy(recon_open_strs[i], message_buffer + offset,
				_ECC_POINT_SIZE*2);
			offset += (_ECC_POINT_SIZE*2);
		}
	}
	~Ver_Round_2_Msg()
	{
		for (int i = 0; i < dropped_size; ++i)
			delete[] recon_open_strs[i];
	}
};

#endif

