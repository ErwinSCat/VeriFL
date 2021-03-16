#include "ServerContext.h"

/*
#include <iostream>
#include <iomanip>
using namespace std;

void _print_buffer(unsigned char *buffer, int length)
{
	cout << hex;
	for (int i = 0; i < length; ++i)
	{
		cout << setw(2) << setfill('0') << (int)buffer[i];
	}
	cout << dec << endl;
}
*/

ServerContext::ServerContext(int logR, int d, int t, int N, int batch)
	: logR(logR), d(d), t(t), N(N), batch(batch),
	  curr_epoch(0),
	  n_bytes_agg_bound(ceil((logR + _AGG_BOUND_SLACK_SIZE)/8.0)),
	  modB(((BN_ULONG)1 << (logR + _AGG_BOUND_SLACK_SIZE)) - 1),
	  mpk(N), epoch_result(d),
	  b_arr(N),
	  b_shares_size(N), msk_shares_size(N),
	  U2(N*batch), U3(N*batch),
	  U2_size(batch), U3_size(batch),
	  U4(N),
	  h_shares_size(N*batch), r_shares_size(N*batch)
{
	ctx = BN_CTX_new();
	for (int i = 0; i < N; ++i)
		mpk[i] = EC_POINT_new(mask.curve);

	b_shares_arr = new vector<SharedVal>[N];
	msk_shares_arr = new vector<SharedVal>[N];
	for (int i = 0; i < N; ++i)
	{
		b_shares_arr[i].resize(t);
		b_shares_size[i] = 0;
		msk_shares_arr[i].resize(t);
		msk_shares_size[i] = 0;
	}

	for (int i = 0; i < N; ++i)
		b_arr[i] = BN_new();

	for (int i = 0; i < N*batch; ++i)
	{
		U2[i] = false;
		U3[i] = false;
	}

	for (int i = 0; i < N; ++i)
		U4[i] = false;

	for (int i = 0; i < d; ++i)
		epoch_result[i] = 0;

	h_shares_arr = new vector<SharedVal>[N*batch];
	r_shares_arr = new vector<SharedVal>[N*batch];
	for (int i = 0; i < N*batch; ++i)
	{
		h_shares_arr[i].resize(t);
		h_shares_size[i] = 0;
		r_shares_arr[i].resize(t);
		r_shares_size[i] = 0;
	}
}

ServerContext::~ServerContext()
{
	for (int i = 0; i < N; ++i)
		BN_free(b_arr[i]);

	delete[] h_shares_arr;
	delete[] r_shares_arr;

	delete[] b_shares_arr;
	delete[] msk_shares_arr;

	for (int i = 0; i < N; ++i)
		EC_POINT_free(mpk[i]);

	BN_CTX_free(ctx);
}

void ServerContext::UpdateKeys(const MaskKey &maskKey)
{
	EC_POINT_copy(mpk[maskKey.my_pid - 1], maskKey.my_mpk);
}

void ServerContext::UpdateU2(const int pid)
{
	U2[curr_epoch + (pid - 1)*batch] = true;
	U2_size[curr_epoch]++;
}

void ServerContext::UpdateInput(const MaskedInput &maskedInput)
{
	U3[curr_epoch + (maskedInput.my_pid - 1)*batch] = true;
	U3_size[curr_epoch]++;

	for (int i = 0; i < d; ++i)
		epoch_result[i] += maskedInput.my_maskedInput[i];
}

void ServerContext::UpdateMaskShares(const MaskShares &maskShares)
{
	int pid;
	BN_copy(b_arr[maskShares.my_pid - 1], maskShares.my_b);
	U4[maskShares.my_pid - 1] = true;

	for (int i = 0; i < maskShares.exclusive_U3_size; ++i)
	{
		pid = maskShares.exclusive_U3_pids[i];
		if (b_shares_size[pid - 1] < t)
		{
			(b_shares_arr[pid - 1])[b_shares_size[pid - 1]]
				= maskShares.exclusive_U3_shares[i];
			b_shares_size[pid - 1]++;
		}
	}
	for (int i = 0; i < maskShares.dropped_size; ++i)
	{
		pid = maskShares.dropped_pids[i];
		if (msk_shares_size[pid - 1] < t)
		{
			(msk_shares_arr[pid - 1])[msk_shares_size[pid - 1]]
				= maskShares.dropped_shares[i];
			msk_shares_size[pid - 1]++;
		}
	}
}

int ServerContext::FinalResult(unsigned char *buffer)
{
	int buffer_offset = 0;

	/*
	 *	Cancel the pairwise-mask
	 */
	unsigned char mak[_AGREED_KEY_SIZE];
	BIGNUM *msk = BN_new();
	Cipher PRG(EVP_aes_128_ctr());

	int out_len;
	unsigned char output[_ULTRA_BUFFER_SIZE];
	unsigned char key[_SYM_KEY_SIZE];
	unsigned char iv[_IV_SIZE];
	BN_ULONG mask_entry;

	for (int i = 1; i <= N; ++i)
	{
		if ((U2[curr_epoch + (i - 1)*batch] == true) &&
			(U3[curr_epoch + (i - 1)*batch] == false))
		{
			assert( msk_shares_size[i - 1] == t );

			ss.Combine(msk, t, msk_shares_arr[i - 1]);
			BN_copy(mask.priv_key, msk);	// Set private key
			
			for (int j = 1; j <= N; ++j)
			{
				if (U3[curr_epoch + (j - 1)*batch] == true)
				{
					mask.Agree(mak, mpk[j - 1]);

					memcpy(key, mak, _SYM_KEY_SIZE);
					memcpy(iv, mak + _SYM_KEY_SIZE, _IV_SIZE);

					PRG.Encrypt(output, out_len, _prg_seed_plaintext, _ULTRA_BUFFER_SIZE, key, iv);

					for (int k = 0; k < d; ++k)
					{
						mask_entry = uchar2ulong(output + k*n_bytes_agg_bound, n_bytes_agg_bound);

						if (i > j)
							epoch_result[k] += (mask_entry)&modB;
						else if (i < j)
							epoch_result[k] -= (mask_entry)&modB;
					}
				}
			}
		}
	}
	BN_free(msk);

	/*
	 *	Cancel self-mask
	 */
	BIGNUM *b = BN_new();
	unsigned char temp[_AGREED_KEY_SIZE];
	for (int i = 1; i <= N; ++i)
	{
		if (U3[curr_epoch + (i - 1)*batch] == true)
		{
			assert( b_shares_size[i - 1] == t );

			if (U4[i - 1] == true)
				BN_copy(b, b_arr[i - 1]);
			else
				ss.Combine(b, t, b_shares_arr[i - 1]);

			BN_bn2binpad(b, temp, _AGREED_KEY_SIZE);
			memcpy(key, temp, _SYM_KEY_SIZE);
			memcpy(iv, temp, _IV_SIZE);

			PRG.Encrypt(output, out_len, _prg_seed_plaintext, _ULTRA_BUFFER_SIZE, key, iv);

			for (int j = 0; j < d; ++j)
			{
				mask_entry = uchar2ulong(output + j*n_bytes_agg_bound, n_bytes_agg_bound);

				epoch_result[j] -= (mask_entry)&modB;
			}
		}
	}
	BN_free(b);

	/*
	 *	Encode aggregated result
	 */
	for (int i = 0; i < d; ++i)
	{
		ulong2uchar(buffer + buffer_offset, (epoch_result[i]&modB), n_bytes_agg_bound);
		buffer_offset += n_bytes_agg_bound;
	}

	/*
	 *	Reset context
	 */
	for (int i = 0; i < d; ++i)
		epoch_result[i] = 0;
	for (int i = 0; i < N; ++i)
	{
		b_shares_size[i] = 0;
		msk_shares_size[i] = 0;
		U4[i] = false;
	}
	curr_epoch++;

	return buffer_offset;
}

void ServerContext::UpdateV1(const int pid)
{
	V1.insert(pid);
}

void ServerContext::UpdateDecomStrShares(const DecomStrShares &decomStrShares)
{
	int pid;
	int offset = 0;
	for (int epoch = 0; epoch < batch; ++epoch)
	{
		for (int j = 0; j < U3_size[epoch] - V1.size(); ++j)
		{
			pid = decomStrShares.dropped_pids[epoch + j + offset];
			if (h_shares_size[epoch + (pid - 1)*batch] < t)
			{
				(h_shares_arr[epoch + (pid - 1)*batch])[h_shares_size[epoch + (pid - 1)*batch]]
					= decomStrShares.dropped_h_shares[epoch + j + offset];
				h_shares_size[epoch + (pid - 1)*batch]++;
			}
			if (r_shares_size[epoch + (pid - 1)*batch] < t)
			{
				(r_shares_arr[epoch + (pid - 1)*batch])[r_shares_size[epoch + (pid - 1)*batch]]
					= decomStrShares.dropped_r_shares[epoch + j + offset];
				r_shares_size[epoch + (pid - 1)*batch]++;
			}
		}
		offset += (U3_size[epoch] - V1.size() - 1);
	}
}

int ServerContext::FinalDecomStr(unsigned char *buffer)
{
	int buffer_offset = 0;

	/*
	 *	Reconstruct decommitment strings of dropped clients
	 */
	BIGNUM *temp = BN_new();
	for (int epoch = 0; epoch < batch; ++epoch)
	{
		for (int pid = 1; pid <= N; ++pid)
		{
			if ((U3[epoch + (pid - 1)*batch] == true) &&
				(V1.find(pid) == V1.end()))
			{
				assert( (h_shares_size[epoch + (pid - 1)*batch] == t) &&
					(r_shares_size[epoch + (pid - 1)*batch] == t) );

				buffer_offset += encodePid(buffer + buffer_offset, pid);

				ss.Combine(temp, t, h_shares_arr[epoch + (pid - 1)*batch]);
				BN_bn2binpad(temp, buffer + buffer_offset, _ECC_POINT_SIZE);
				buffer_offset += _ECC_POINT_SIZE;

				ss.Combine(temp, t, r_shares_arr[epoch + (pid - 1)*batch]);
				BN_bn2binpad(temp, buffer + buffer_offset, _ECC_POINT_SIZE);
				buffer_offset += _ECC_POINT_SIZE;
			}
		}
	}
	BN_free(temp);

	return buffer_offset;
}