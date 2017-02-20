#include <iostream>
#include <fstream>

#include "mbedtls/sha512.h"
#include "mbedtls/aes.h"
#include "macros.h"

#define USE_SHA512 0

#define AES_CBC_BLOCK_SIZE 16
#define CHUNK_SIZE 4096
#define SHA512_LENGTH 64
#define KEYBITS 128

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

void post_decrypt(unsigned char *enc_sha512, unsigned char *orig_sha512, std::ifstream *src)
{
	unsigned char read_orig_sha512[SHA512_LENGTH], read_enc_sha512[SHA512_LENGTH];
	src->read(reinterpret_cast<char *>(&read_orig_sha512), SHA512_LENGTH);
	src->read(reinterpret_cast<char *>(&read_enc_sha512), SHA512_LENGTH);
	printf("Comparing encrypted hashes ... ");
	if(!compare_hashes(enc_sha512, read_enc_sha512, SHA512_LENGTH)) {
		printf("failed\n");
	} else {
		printf("OK\n");
	}
	printf("Comparing decrypted hashes ... ");
	if(!compare_hashes(orig_sha512, read_orig_sha512, SHA512_LENGTH)) {
		printf("failed\n");
	} else {
		printf("OK\n");
	}
}


void hash_n_stuff(std::ifstream *src, std::ofstream *dst, unsigned char *key, bool encrypt, unsigned char *orig_sha512, unsigned char *enc_sha512)
{
	// Initialization vector, this should be random
	unsigned char iv[17] = "0123456789123456";
	unsigned char buf[AES_CBC_BLOCK_SIZE];
	unsigned char outbuf[AES_CBC_BLOCK_SIZE];
	unsigned int bytes;

	// Get how long the input is
	src->seekg(0, std::ios_base::end);
	size_t in_length = src->tellg();
	src->seekg(0, std::ios_base::beg);

	mbedtls_sha512_context orig_sha_ctx;
	mbedtls_sha512_context enc_sha_ctx;
	mbedtls_aes_context aes_ctx;

	mbedtls_sha512_init(&orig_sha_ctx);
	mbedtls_sha512_starts(&orig_sha_ctx, USE_SHA512);

	mbedtls_sha512_init(&enc_sha_ctx);
	mbedtls_sha512_starts(&enc_sha_ctx, USE_SHA512);

	mbedtls_aes_init(&aes_ctx);
	set_aes_key(&aes_ctx, key, encrypt);

	// If we're decrypting, there are two 64bit long hashes at the end of the file
	if(!encrypt) in_length -= 2*SHA512_LENGTH;

	// While there's something to read
	for(size_t i = 0; i < in_length; i += AES_CBC_BLOCK_SIZE) {
		// Read one block
		src->read(reinterpret_cast<char *>(buf), AES_CBC_BLOCK_SIZE);
		bytes = src->gcount();

		// Hash the block
		mbedtls_sha512_update(&orig_sha_ctx, buf, bytes);
		
		// Add padding when encrypting
		if(encrypt) pkcs7_pad(buf, &bytes);

		// Encrypt the block and write it to the output stream
		mbedtls_aes_crypt_cbc(&aes_ctx, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, bytes, iv, buf, outbuf);

		// Detect padding when decrypting
		if(!encrypt && i + AES_CBC_BLOCK_SIZE >= in_length) bytes = pkcs7_detect(outbuf);

		// Write the encrypted/decrypted block to disk
		dst->write(reinterpret_cast<char *>(outbuf), bytes);

		// Hash the encrypted block
		mbedtls_sha512_update(&enc_sha_ctx, outbuf, bytes);
	}

	// Finish generating checksums
	mbedtls_sha512_finish(&orig_sha_ctx, orig_sha512);
	mbedtls_sha512_finish(&enc_sha_ctx, enc_sha512);

	// Clean things up
	mbedtls_sha512_free(&orig_sha_ctx);
	mbedtls_sha512_free(&enc_sha_ctx);
	mbedtls_aes_free(&aes_ctx);

	if(!encrypt) {
		post_decrypt(orig_sha512, enc_sha512, src);
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
	unsigned char orig_sha512[SHA512_LENGTH], enc_sha512[SHA512_LENGTH];
	hash_n_stuff(&src, &dst, reinterpret_cast<unsigned char *>(argv[4]), encrypt, orig_sha512, enc_sha512);
	if(encrypt) {
		dst.write(reinterpret_cast<char*>(orig_sha512), SHA512_LENGTH);
		dst.write(reinterpret_cast<char*>(enc_sha512), SHA512_LENGTH);
	}
	src.close();
	dst.close();
	return 0;
}
