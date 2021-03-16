#include "Commitment.h"

void Commitment::Commit(unsigned char *commitment,
	unsigned char *open_str,
	unsigned char *message,
	int message_len,
	bool isDecommit)
{
	unsigned char *buffer = new unsigned char[message_len];

	if (!isDecommit)
	{
		BIGNUM *rand = BN_new();
		BN_rand(rand, message_len*8,
			BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
		BN_bn2binpad(rand, open_str, message_len);
		BN_free(rand);
	}

	for (int i = 0; i < message_len; ++i)
		buffer[i] = message[i]^open_str[i];
	SHA256(buffer, message_len, commitment);

	delete[] buffer;
}

bool Commitment::Decommit(unsigned char *commitment,
	unsigned char *open_str,
	unsigned char *message,
	int message_len)
{
	unsigned char result[_COMMITMENT_SIZE];		// SHA-256 digest
	Commit(result, open_str, message, message_len, true);
	if (strncmp((char *)result, (char *)commitment, _COMMITMENT_SIZE) == 0)
		return true;
	else return false;
}

void _test_Commitment()
{
	Commitment com;

	unsigned char commitment[_COMMITMENT_SIZE];
	unsigned char open_str[_ECC_POINT_SIZE*2];

	BIGNUM *rand = BN_new();
	BN_rand(rand, _ECC_POINT_SIZE*8, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
	BN_bn2binpad(rand, open_str, _ECC_POINT_SIZE);
	BN_free(rand);

	com.Commit(commitment, open_str + _ECC_POINT_SIZE, open_str, _ECC_POINT_SIZE, false);
	bool flag;
	for (int i = 0; i < 1000; ++i)
		flag = com.Decommit(commitment, open_str + _ECC_POINT_SIZE, open_str, _ECC_POINT_SIZE);

	assert( flag == true );
}