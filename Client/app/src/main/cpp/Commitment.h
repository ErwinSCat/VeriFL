#ifndef _COMMITMENT_H
#define _COMMITMENT_H

#include "Config.h"

#include <openssl/rand.h>
#include <openssl/bn.h>
#include <openssl/sha.h>

#include <assert.h>
#include <string.h>

class Commitment
{
public:
	Commitment() {};
	~Commitment() {};

	// Commit a message and store the randomness
	// used in commitment in open_str
	// Note: assert len(open_str) = len(message)
	void Commit(unsigned char *commitment,
		unsigned char *open_str,
		unsigned char *message,
		int message_len,
		bool isDecommit);

	// Decommit a commitment
	// Note: assert len(open_str) = len(message)
	bool Decommit(unsigned char *commitment,
		unsigned char *open_str,
		unsigned char *message,
		int message_len);
};

void _test_Commitment();

#endif