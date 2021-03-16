#ifndef _CIPHER_H
#define _CIPHER_H

#include "Config.h"

#include <openssl/evp.h>

#include <assert.h>
#include <string.h>

class Cipher
{
private:
	EVP_CIPHER_CTX *cipher_ctx;

public:
	Cipher(const EVP_CIPHER *cipher_type);
	~Cipher();

	// Encryption routine
	void Encrypt(unsigned char *ciphertext, int &cipher_len,
		const unsigned char *message, int message_len,
		const unsigned char *sym_key, const unsigned char *iv);

	// Decryption routine
	bool Decrypt(unsigned char *message, int &message_len,
		const unsigned char *ciphertext, int cipher_len,
		const unsigned char *sym_key, const unsigned char *iv);

};

void _test_Cipher();

#endif