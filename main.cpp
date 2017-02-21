#include <iostream>
#include <fstream>

#include "mbedtls/sha512.h"
#include "mbedtls/aes.h"
#include "macros.h"

#define USE_SHA512 0

#define AES_CBC_BLOCK_SIZE 16
#define SHA512_LENGTH 64
#define IV_LENGTH 16
#define KEYBITS 128

void generate_random_string(unsigned char *iv, int len)
{
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	for (int i = 0; i < len; ++i) {
		iv[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}
}

void pkcs7_pad(unsigned char *buf, unsigned int *count)
{
	unsigned int padding = AES_CBC_BLOCK_SIZE - *count;
	for(unsigned int i = 1; i <= padding; i++) {
		buf[AES_CBC_BLOCK_SIZE - i] = padding;
	}
	// We pad to the block size
	*count = AES_CBC_BLOCK_SIZE;
}

unsigned int pkcs7_detect(unsigned char *buf)
{
	unsigned int count = AES_CBC_BLOCK_SIZE;
	unsigned char last = buf[AES_CBC_BLOCK_SIZE - 1];
	if(last < 16) {
		for(int i = AES_CBC_BLOCK_SIZE - last; i < AES_CBC_BLOCK_SIZE; i++) {
			if(buf[i] != last) {
				return count;
			}
		}
		count -= last;
	}
	return count;
}

void set_aes_key(mbedtls_aes_context *aes_ctx, unsigned char *key, bool encrypt)
{
	int result;
	if(encrypt) {
		result = mbedtls_aes_setkey_enc(aes_ctx, key, KEYBITS);
	} else {
		result = mbedtls_aes_setkey_dec(aes_ctx, key, KEYBITS);
	}
	if(result == MBEDTLS_ERR_AES_INVALID_KEY_LENGTH) {
		DIE(2, "Invalid input key length");
	}
}

bool compare_hashes(unsigned char *h1, unsigned char *h2, int len) {
	for(int i = 0; i < len; i++) {
		if(h1[i] != h2[i]) return false;
	}
	return true;
}

void post_decrypt(unsigned char *sha512, std::ifstream *src)
{
	unsigned char read_sha512[SHA512_LENGTH];
	src->read(reinterpret_cast<char *>(&read_sha512), SHA512_LENGTH);
	printf("Comparing encrypted hashes ... ");
	if(!compare_hashes(sha512, read_sha512, SHA512_LENGTH)) {
		printf("failed\n");
	} else {
		printf("OK\n");
	}
}


void hash_n_stuff(std::ifstream *src, std::ofstream *dst, unsigned char *key, bool encrypt, unsigned char *sha512)
{
	// Initialization vector, this should be random
	unsigned char iv[16];
	unsigned char buf[AES_CBC_BLOCK_SIZE];
	unsigned char outbuf[AES_CBC_BLOCK_SIZE];
	unsigned int bytes;

	// Get how long the input is
	src->seekg(0, std::ios_base::end);
	size_t in_length = src->tellg();
	src->seekg(0, std::ios_base::beg);

	mbedtls_sha512_context sha_ctx;
	mbedtls_aes_context aes_ctx;

	mbedtls_sha512_init(&sha_ctx);
	mbedtls_sha512_starts(&sha_ctx, USE_SHA512);

	mbedtls_aes_init(&aes_ctx);
	set_aes_key(&aes_ctx, key, encrypt);

	if(!encrypt) {
		// There are two 64bit long hashes at the end of the file and IV at the beginning
		in_length -= SHA512_LENGTH + IV_LENGTH;
		src->read(reinterpret_cast<char *>(iv), IV_LENGTH);
	} else {
		// Generate initial IV and write it into the file
		generate_random_string(iv, IV_LENGTH);
		dst->write(reinterpret_cast<char *>(iv), IV_LENGTH);
	}

	// While there's something to read
	for(size_t i = 0; i < in_length; i += AES_CBC_BLOCK_SIZE) {
		// Read one block
		src->read(reinterpret_cast<char *>(buf), AES_CBC_BLOCK_SIZE);
		bytes = src->gcount();

		// Hash the block
		if(encrypt) {
			// Add padding when encrypting
			pkcs7_pad(buf, &bytes);
		} else {
			// Hash the read blocks when decrypting
			mbedtls_sha512_update(&sha_ctx, buf, bytes);
		}

		// Encrypt the block and write it to the output stream
		mbedtls_aes_crypt_cbc(&aes_ctx, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, bytes, iv, buf, outbuf);

		// Detect padding when decrypting
		if(!encrypt && i + AES_CBC_BLOCK_SIZE >= in_length) bytes = pkcs7_detect(outbuf);

		// Write the encrypted/decrypted block to disk
		dst->write(reinterpret_cast<char *>(outbuf), bytes);

		// Hash the encrypted block
		if(encrypt) mbedtls_sha512_update(&sha_ctx, outbuf, bytes);
	}

	// Finish generating checksums
	mbedtls_sha512_finish(&sha_ctx, sha512);

	// Clean things up
	mbedtls_sha512_free(&sha_ctx);
	mbedtls_aes_free(&aes_ctx);

	if(encrypt) {
		// Write the hash if we're encrypting
		dst->write(reinterpret_cast<char*>(sha512), SHA512_LENGTH);
	} else {
		// Run post-decrypt checks
		post_decrypt(sha512, src);
	}
}

int main(int argc, char **argv)
{
	if(argc != 5) {
		DIE(1, "Wrong argument count, expected 4, got %d\n", argc - 1);
	}
	bool encrypt;
	encrypt = argv[1][0] == 'e' ? true : false;
	std::ifstream src;
	std::ofstream dst;
	src.open(argv[2]);
	dst.open(argv[3]);
	unsigned char sha512[SHA512_LENGTH];
	hash_n_stuff(&src, &dst, reinterpret_cast<unsigned char *>(argv[4]), encrypt, sha512);
	src.close();
	dst.close();
	return 0;
}
