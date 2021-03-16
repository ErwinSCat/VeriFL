#include "Context.h"

#ifndef __ANDROID_PLATFORM_FLAG__

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

#include <sys/time.h>

#endif

Context::Context(int logR, int d, int t, int N, int pid, int batch)
	: logR(logR), d(d), t(t), N(N), pid(pid), batch(batch),
	  curr_epoch(0),
	  n_bytes_agg_bound(ceil((logR + _AGG_BOUND_SLACK_SIZE)/8.0)),
	  modB(((BN_ULONG)1 << (logR + _AGG_BOUND_SLACK_SIZE)) - 1),
	  cipher(EVP_aes_256_ofb()),
	  sym_key(N), mak(N),
	  my_vec(d), epoch_hash(batch), my_open_str(batch),
	  U2(N*batch), U3(N*batch),
	  exclusive_U2_size(batch), exclusive_U3_size(batch),
	  com_str(N*batch), Ctxt(N), open_str_share(N*batch),
	  alpha(batch), comb_result(d)
{
	// System check
	unsigned char ul_buffer[5];
	BN_ULONG test_ul = 17179869183;
	ulong2uchar(ul_buffer, test_ul, 5);
	BN_ULONG ver_ul = uchar2ulong(ul_buffer, 5);

	assert( ver_ul == 17179869183 );

	BN_ULONG test_a = 1, test_b = 17179869183;
	BN_ULONG test_c = test_a - test_b;
	BN_ULONG ver_a = test_c + 17179869183;

	assert( ver_a == 1);


	// Allocate memory
	ctx = BN_CTX_new();
	for (int i = 0; i < N; ++i)
	{
		sym_key[i] = new unsigned char[_AGREED_KEY_SIZE];
		mak[i] = new unsigned char[_AGREED_KEY_SIZE];
	}
	b = BN_new();
	for (int i = 0; i < batch; ++i)
		epoch_hash[i] = EC_POINT_new(hh.curve);
	for (int i = 0; i < batch; ++i)
		my_open_str[i] = new unsigned char[_ECC_POINT_SIZE*2];

	for (int i = 0; i < N*batch; ++i)
	{
		U2[i] = false;
		U3[i] = false;
	}
	for (int i = 0; i < N*batch; ++i)
		com_str[i] = new unsigned char[_COMMITMENT_SIZE];
	for (int i = 0; i < N; ++i)
		Ctxt[i] = new unsigned char[_SYM_CIPHERTEXT_SIZE];
	for (int i = 0; i < N*batch; ++i)
		open_str_share[i] = new unsigned char[_SHARE_FIELD_SIZE*2];

	for (int i = 0; i < batch; ++i)
		alpha[i] = BN_new();
	for (int i = 0; i < d; ++i)
		comb_result[i] = BN_new();
}

HomHash Context::hh(500000);

Context::~Context()
{
	for (int i = 0; i < d; ++i)
		BN_free(comb_result[i]);
	for (int i = 0; i < batch; ++i)
		BN_free(alpha[i]);

	for (int i = 0; i < N*batch; ++i)
		delete[] open_str_share[i];
	for (int i = 0; i < N; ++i)
		delete[] Ctxt[i];
	for (int i = 0; i < N*batch; ++i)
		delete[] com_str[i];

	for (int i = 0; i < batch; ++i)
		delete[] my_open_str[i];
	for (int i = 0; i < batch; ++i)
		EC_POINT_free(epoch_hash[i]);
	BN_free(b);
	for (int i = 0; i < N; ++i)
	{
		delete[] sym_key[i];
		delete[] mak[i];
	}
	BN_CTX_free(ctx);
}

int Context::AdvertiseKeys(unsigned char *buffer)
{
	enc.KeyGen();
	mask.KeyGen();

	BIGNUM *temp = BN_new();
	int buffer_offset = 0;
	buffer_offset += encodePid(buffer + buffer_offset, pid);

	EC_POINT_point2bn(enc.curve, enc.pub_key,
		POINT_CONVERSION_COMPRESSED, temp, ctx);
	BN_bn2binpad(temp, buffer + buffer_offset, _ECC_POINT_SIZE);
	buffer_offset += _ECC_POINT_SIZE;

	EC_POINT_point2bn(mask.curve, mask.pub_key,
		POINT_CONVERSION_COMPRESSED, temp, ctx);
	BN_bn2binpad(temp, buffer + buffer_offset, _ECC_POINT_SIZE);
	buffer_offset += _ECC_POINT_SIZE;

	BN_free(temp);
	return buffer_offset;
	// = _PID_BYTE_SIZE + _ECC_POINT_SIZE*2
}

int Context::ShareMetadata(unsigned char *buffer,
	const Round_1_Msg &round_1_msg)
{
	int buffer_offset = 0;
	buffer_offset += encodePid(buffer + buffer_offset, pid);

#ifndef __ANDROID_PLATFORM_FLAG__
	struct timeval start, end;
#endif
	
	/*
	 * 	Compute symmetric encryption key using ECDH and SHA384
	 *	   384 bits = 48 bytes = 32 bytes (key) + 16 bytes (iv)
	 */
	for (int i = 0; i < round_1_msg.exclusive_U1_size; ++i)
	{
		enc.Agree(sym_key[round_1_msg.pids[i] - 1], round_1_msg.pks[i]);
		mask.Agree(mak[round_1_msg.pids[i] - 1], round_1_msg.mpks[i]);
	}

#ifndef __ANDROID_PLATFORM_FLAG__
	gettimeofday(&start, NULL);
#endif

	/*
	 * 	Compute the linearly homomorphic hash of my vector
	 */
	hh.Hash(epoch_hash[curr_epoch], my_vec);

	BIGNUM *hash = BN_new();
	BIGNUM *rand = BN_new();

	EC_POINT_point2bn(hh.curve, epoch_hash[curr_epoch],
		POINT_CONVERSION_COMPRESSED, hash, ctx);
	BN_bn2binpad(hash, my_open_str[curr_epoch], _ECC_POINT_SIZE);

	/*
	 * 	Compute and store the commitment string in the first _COMMITMENT_SIZE bytes of buffer.
	 *
	 * 	NOTE: An opening string stored in my_open_str[curr_epoch] contains
	 *    in the first _ECC_POINT_SIZE bytes the hash and in the last _ECC_POINT_SIZE bytes
	 *    the randomness.
	 */
	com.Commit(buffer + buffer_offset, my_open_str[curr_epoch] + _ECC_POINT_SIZE,
		my_open_str[curr_epoch], _ECC_POINT_SIZE, false);
	buffer_offset += _COMMITMENT_SIZE;

	/*
	 *	Compute four kinds of shares
	 */
	vector<SharedVal> hash_shares(round_1_msg.exclusive_U1_size), 
		rand_shares(round_1_msg.exclusive_U1_size),
		b_shares(round_1_msg.exclusive_U1_size),
		msk_shares(round_1_msg.exclusive_U1_size);

	// Share my hash
	ss.Share(hash_shares, t, round_1_msg.pids, hash);

	// Share my randomness
	BN_bin2bn(my_open_str[curr_epoch] + _ECC_POINT_SIZE, _ECC_POINT_SIZE, rand);
	ss.Share(rand_shares, t, round_1_msg.pids, rand);

#ifndef __ANDROID_PLATFORM_FLAG__
	gettimeofday(&end, NULL);
	cout << "    [c++]: Wall-clock time of verification part in Context::ShareMetadata: "
		<< 1000*(end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)/1000 << " ms" << endl;
#endif

	// Share my seed for self-mask
	BN_rand_range(b, ss.p);
	ss.Share(b_shares, t, round_1_msg.pids, b);

	// Share my secret key for pairwise-mask
	ss.Share(msk_shares, t, round_1_msg.pids, mask.priv_key);

	/*
	 * 	Call symmetric encryption to encrypt shares
	 */
	unsigned char message[_SHARE_FIELD_SIZE*4];
	unsigned char ciphertext[_MAX_BUFFER_SIZE];
	unsigned char key[_SYM_KEY_SIZE];
	unsigned char iv[_IV_SIZE];
	int cipher_len;
	
	for (int i = 0; i < round_1_msg.exclusive_U1_size; ++i)
	{
		BN_bn2binpad(hash_shares[i].val, message                      , _SHARE_FIELD_SIZE);
		BN_bn2binpad(rand_shares[i].val, message + _SHARE_FIELD_SIZE  , _SHARE_FIELD_SIZE);
		BN_bn2binpad(b_shares[i].val   , message + _SHARE_FIELD_SIZE*2, _SHARE_FIELD_SIZE);
		BN_bn2binpad(msk_shares[i].val , message + _SHARE_FIELD_SIZE*3, _SHARE_FIELD_SIZE);

		memcpy(key, sym_key[round_1_msg.pids[i] - 1], _SYM_KEY_SIZE);
		memcpy(iv, sym_key[round_1_msg.pids[i] - 1] + _SYM_KEY_SIZE, _IV_SIZE);

		cipher.Encrypt(ciphertext, cipher_len,
			message, _SHARE_FIELD_SIZE*4, key, iv);
		buffer_offset += encodePid(buffer + buffer_offset, round_1_msg.pids[i]);

		memcpy(buffer + buffer_offset, ciphertext, _SYM_CIPHERTEXT_SIZE);
		buffer_offset += _SYM_CIPHERTEXT_SIZE;
	}

	/*
	 *	Cleanup memory
	 */
	BN_free(rand);
	BN_free(hash);

	return buffer_offset;	
	// = _PID_BYTE_SIZE + _COMMITMENT_SIZE
	//     + exclusive_U1_size*(_PID_BYTE_SIZE + _SYM_CIPHERTEXT_SIZE)
}

int Context::MaskedInputCollection(unsigned char *buffer,
	const Round_2_Msg &round_2_msg)
{
	int buffer_offset = 0;
	buffer_offset += encodePid(buffer + buffer_offset, pid);

	exclusive_U2_size[curr_epoch] = round_2_msg.exclusive_U2_size;

	/*
	 *	Store commitment strings and ciphertexts received in this epoch 
	 */
	for (int i = 0; i < round_2_msg.exclusive_U2_size; ++i)
	{
		U2[curr_epoch + (round_2_msg.pids[i] - 1)*batch] = true;

		memcpy(com_str[curr_epoch + (round_2_msg.pids[i] - 1)*batch],
			round_2_msg.commitment[i], _COMMITMENT_SIZE);

		memcpy(Ctxt[round_2_msg.pids[i] - 1],
			round_2_msg.ctxt[i], _SYM_CIPHERTEXT_SIZE);
	}

	/*
	 *	Add self-mask
	 */
	Cipher PRG(EVP_aes_128_ctr());
	int out_len;
	unsigned char *output = new unsigned char[_ULTRA_BUFFER_SIZE];
	unsigned char key[_SYM_KEY_SIZE];
	unsigned char iv[_IV_SIZE];
	BN_ULONG mask_entry;

	unsigned char temp[_AGREED_KEY_SIZE];
	BN_bn2binpad(b, temp, _AGREED_KEY_SIZE);
	memcpy(key, temp, _SYM_KEY_SIZE);
	memcpy(iv, temp, _IV_SIZE);

	PRG.Encrypt(output, out_len, _prg_seed_plaintext, _ULTRA_BUFFER_SIZE, key, iv);

	for (int i = 0; i < d; ++i)
	{
		mask_entry = uchar2ulong(output + i*n_bytes_agg_bound, n_bytes_agg_bound);

		my_vec[i] = (my_vec[i] + (mask_entry)&modB)&modB;
	}

	/*
	 *	Add pairwise-mask
	 */
	for (int i = 0; i < round_2_msg.exclusive_U2_size; ++i)
	{
		memcpy(key, mak[round_2_msg.pids[i] - 1], _SYM_KEY_SIZE);
		memcpy(iv, mak[round_2_msg.pids[i] - 1] + _SYM_KEY_SIZE, _IV_SIZE);

		PRG.Encrypt(output, out_len, _prg_seed_plaintext, _ULTRA_BUFFER_SIZE, key, iv);

		for (int j = 0; j < d; ++j)
		{
			mask_entry = uchar2ulong(output + j*n_bytes_agg_bound, n_bytes_agg_bound);

			if (pid > round_2_msg.pids[i])
				my_vec[j] = (my_vec[j] + (mask_entry)&modB)&modB;
			else if (pid < round_2_msg.pids[i])
				my_vec[j] = (my_vec[j] - (mask_entry)&modB)&modB;	// Warning: "-" may cause bug
		}
	}

	/*
	 *	Encode my masked input
	 */
	for (int i = 0; i < d; ++i)
	{
		ulong2uchar(buffer + buffer_offset, my_vec[i], n_bytes_agg_bound);
		buffer_offset += n_bytes_agg_bound;
	}

	delete[] output;
	return buffer_offset;
	// = _PID_BYTE_SIZE + d*n_bytes_agg_bound
	// = _PID_BYTE_SIZE + d*ceil((logR + _AGG_BOUND_SLACK_SIZE)/8.0)
}

int Context::Unmasking(unsigned char *buffer,
	const Round_3_Msg &round_3_msg)
{
	int buffer_offset = 0;
	buffer_offset += encodePid(buffer + buffer_offset, pid);

	exclusive_U3_size[curr_epoch] = round_3_msg.exclusive_U3_size;

	/*
	 *	Store the set U3 received in this epoch
	 */
	for (int i = 0; i < round_3_msg.exclusive_U3_size; ++i)
		U3[curr_epoch + (round_3_msg.pids[i] - 1)*batch] = true;

	/*
	 *	Decrypt ciphertexts received in the previous round
	 */
	const int share_item_len = _PID_BYTE_SIZE + _SHARE_FIELD_SIZE;
	unsigned char *b_shares
		= new unsigned char[round_3_msg.exclusive_U3_size*share_item_len];
	unsigned char *msk_shares
		= new unsigned char[(exclusive_U2_size[curr_epoch] - round_3_msg.exclusive_U3_size)*share_item_len];

	unsigned char message[_MAX_BUFFER_SIZE];
	unsigned char key[_SYM_KEY_SIZE];
	unsigned char iv[_IV_SIZE];
	int message_len;
	int b_shares_offset = 0, msk_shares_offset = 0;

	for (int other_pid = 1; other_pid <= N; ++other_pid)
	{
		if ((U2[curr_epoch + (other_pid - 1)*batch] == false) || 
			(other_pid == pid)) continue;

		// Decryption
		memcpy(key, sym_key[other_pid - 1], _SYM_KEY_SIZE);
		memcpy(iv, sym_key[other_pid - 1] + _SYM_KEY_SIZE, _IV_SIZE);

		cipher.Decrypt(message, message_len,
			Ctxt[other_pid - 1], _SYM_CIPHERTEXT_SIZE, key, iv);

		// For parties in U3[curr_epoch]
		// Retrieve my share of b and store shares of decrypted opening string
		if (U3[curr_epoch + (other_pid - 1)*batch] == true)
		{
			b_shares_offset += encodePid(b_shares + b_shares_offset, other_pid);
			memcpy(b_shares + b_shares_offset, message + _SHARE_FIELD_SIZE*2, _SHARE_FIELD_SIZE);
			b_shares_offset += _SHARE_FIELD_SIZE;

			memcpy(open_str_share[curr_epoch + (other_pid - 1)*batch], message, _SHARE_FIELD_SIZE*2);
		}
		// For parties in U2[curr_epoch] \ U3[curr_epoch]
		// Retrieve my share of msk
		else
		{
			msk_shares_offset += encodePid(msk_shares + msk_shares_offset, other_pid);
			memcpy(msk_shares + msk_shares_offset, message + _SHARE_FIELD_SIZE*3, _SHARE_FIELD_SIZE);
			msk_shares_offset += _SHARE_FIELD_SIZE;
		}
	}

	/*
	 *	Copy my secret b to output buffer
	 */
	BN_bn2binpad(b, buffer + buffer_offset, _SHARE_FIELD_SIZE);
	buffer_offset += _SHARE_FIELD_SIZE;

	/*
	 *	Copy shares to output buffer
	 */
	memcpy(buffer + buffer_offset, b_shares, b_shares_offset);
	buffer_offset += b_shares_offset;
	memcpy(buffer + buffer_offset, msk_shares, msk_shares_offset);
	buffer_offset += msk_shares_offset;

	/*
	 *	Cleanup memory
	 */
	delete[] msk_shares;
	delete[] b_shares;

	return buffer_offset;
	// = _PID_BYTE_SIZE + _SHARE_FIELD_SIZE + round_3_msg.exclusive_U3_size*(_PID_BYTE_SIZE + _SHARE_FIELD_SIZE)
	//     + (exclusive_U2_size[curr_epoch] - round_3_msg.exclusive_U3_size)*(_PID_BYTE_SIZE + _SHARE_FIELD_SIZE)
	// = _PID_BYTE_SIZE + _SHARE_FIELD_SIZE + exclusive_U2_size[curr_epoch]*(_PID_BYTE_SIZE + _SHARE_FIELD_SIZE)
}

void Context::ReceiveResult(const Epoch_Result_Msg &epoch_result_msg)
{
	/*
	 *	Compute random linear combination with aggregated result
	 *	  of this epoch
	 */
	BN_rand_range(alpha[curr_epoch], hh.q);
	BIGNUM *temp = BN_new();
	for (int i = 0; i < d; ++i)
	{
		BN_mod_mul(temp, alpha[curr_epoch], epoch_result_msg.epoch_result[i],
			hh.q, ctx);
		BN_mod_add(comb_result[i], comb_result[i], temp,
			hh.q, ctx);
	}
	BN_free(temp);

	/*
	 *	Here we can do anything with the aggregated result
	 */

	/*
	 * Go to next epoch
	 */
	curr_epoch++;
}

int Context::Decommitting(unsigned char *buffer)
{
	int buffer_offset = 0;
	buffer_offset += encodePid(buffer + buffer_offset, pid);

	for (int i = 0; i < batch; ++i)
	{
		memcpy(buffer + buffer_offset, my_open_str[i], _ECC_POINT_SIZE*2);
		buffer_offset += (_ECC_POINT_SIZE*2);
	}

	return buffer_offset;
	// = _PID_BYTE_SIZE + batch*(_ECC_POINT_SIZE*2)
}

int Context::DroppedDecommitting(unsigned char *buffer,
		const Ver_Round_1_Msg &ver_round_1_msg)
{
	int buffer_offset = 0;
	buffer_offset += encodePid(buffer + buffer_offset, pid);

	/*
	 *	Decommit part of commitments using opening strings
	 *    received in this round
	 */
	bool flag = true;

	for (int i = 0; i < ver_round_1_msg.exclusive_V1_size; ++i)
	{
		V1.insert(ver_round_1_msg.pids[i]);

		for (int j = 0; j < batch; ++j)
		{
			flag = flag && com.Decommit(com_str[j + (ver_round_1_msg.pids[i] - 1)*batch],
				ver_round_1_msg.open_strs[j + i*batch] + _ECC_POINT_SIZE,
				ver_round_1_msg.open_strs[j + i*batch],
				_ECC_POINT_SIZE);
		}
	}
	assert( flag == true );

	/*
	 *	Partially combine the hashes received in this round
	 */
	BIGNUM *temp = BN_new();
	EC_POINT *hash = EC_POINT_new(hh.curve);
	for (int i = 0; i < batch; ++i)
	{
		for (int j = 0; j < ver_round_1_msg.exclusive_V1_size; ++j)
		{
			BN_bin2bn(ver_round_1_msg.open_strs[i + j*batch], _ECC_POINT_SIZE, temp);
			EC_POINT_bn2point(hh.curve, temp, hash, ctx);

			// Explicitly call EC_POINT_ADD()
			EC_POINT_add(hh.curve, epoch_hash[i], epoch_hash[i], hash, ctx);
		}
	}

	/*
	 *	Encode shares of opening strings
	 */
	for (int i = 0; i < batch; ++i)
	{
		for (int other_pid = 1; other_pid <= N; ++other_pid)
		{
			if ((U3[i + (other_pid - 1)*batch] == false) ||
				(other_pid == pid)) continue;

			// This party is dropped
			if (V1.find(other_pid) == V1.end())
			{
				buffer_offset += encodePid(buffer + buffer_offset, other_pid);
				memcpy(buffer + buffer_offset,
					open_str_share[i + (other_pid - 1)*batch], _SHARE_FIELD_SIZE*2);
				buffer_offset += (_SHARE_FIELD_SIZE*2);
			}
		}
	}

	/*
	 *	Cleanup memory
	 */
	EC_POINT_free(hash);
	BN_free(temp);

	return buffer_offset;
	// = _PID_BYTE_SIZE
	//     + (exclusive_U3_size[0] - ver_round_1_msg.exclusive_V1_size)*(_PID_BYTE_SIZE + _ECC_POINT_SIZE*2)
	//     + ...
	//     + (exclusive_U3_size[batch - 1] - ver_round_1_msg.exclusive_V1_size)*(_PID_BYTE_SIZE + _ECC_POINT_SIZE*2)
}

bool Context::BatchChecking(const Ver_Round_2_Msg &ver_round_2_msg)
{
	bool flag = true;

	/*
	 *	Decommit remaining commitments
	 */
	int offset = 0;
	for (int i = 0; i < batch; ++i)
	{
		for (int j = 0; j < exclusive_U3_size[i] - V1.size(); ++j)
		{
			flag = flag && com.Decommit(com_str[i + (ver_round_2_msg.dropped_pids[i + j + offset] - 1)*batch],
				ver_round_2_msg.recon_open_strs[i + j + offset] + _ECC_POINT_SIZE,
				ver_round_2_msg.recon_open_strs[i + j + offset],
				_ECC_POINT_SIZE);
		}
		offset += (exclusive_U3_size[i] - V1.size() - 1);
	}
	assert( flag == true );

	/*
	 *	Combine hashes
	 */
	BIGNUM *temp = BN_new();
	EC_POINT *hash = EC_POINT_new(hh.curve);
	offset = 0;
	for (int i = 0; i < batch; ++i)
	{
		for (int j = 0; j < exclusive_U3_size[i] - V1.size(); ++j)
		{
			BN_bin2bn(ver_round_2_msg.recon_open_strs[i + j + offset], _ECC_POINT_SIZE, temp);
			EC_POINT_bn2point(hh.curve, temp, hash, ctx);

			// Explicitly call EC_POINT_ADD()
			EC_POINT_add(hh.curve, epoch_hash[i], epoch_hash[i], hash, ctx);
		}
		offset += (exclusive_U3_size[i] - V1.size() - 1);
	}

	EC_POINT *agg_hash = EC_POINT_new(hh.curve);
	EC_POINT *ver_agg_hash = EC_POINT_new(hh.curve);

	hh.Hash(agg_hash, comb_result);
	hh.Eval(ver_agg_hash, epoch_hash, alpha);
	flag = flag && (EC_POINT_cmp(hh.curve, agg_hash, ver_agg_hash, ctx) == 0);

	/*
	 *	Cleanup memory
	 */
	EC_POINT_free(ver_agg_hash);
	EC_POINT_free(agg_hash);
	EC_POINT_free(hash);
	BN_free(temp);

	return flag;
}


void Context::_rand_input()
{
	BN_ULONG mod = ((BN_ULONG)1 << logR) - 1;
	for (int i = 0; i < d; ++i)
		my_vec[i] = rand()&mod;
		//my_vec[i] = 1;
}

int Context::_compute_multiplied_input(unsigned char *buffer,
	int scalar)
{
	int buffer_offset = 0;
	BN_ULONG entry;

	for (int i = 0; i < d; ++i)
	{
		entry = (my_vec[i]*scalar)&modB;

		ulong2uchar(buffer + buffer_offset, entry, n_bytes_agg_bound);
		buffer_offset += n_bytes_agg_bound;
	}

	return buffer_offset;
}