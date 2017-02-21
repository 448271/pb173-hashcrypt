#include <iostream>
#include <fstream>
#include <cstring>

#include "mbedtls/sha512.h"
#include "mbedtls/aes.h"
#include "macros.h"

#define USE_SHA512 0

#define AES_CBC_BLOCK_SIZE 16
#define SHA512_LENGTH 64
#define IV_LENGTH 16
#define KEYBITS 128
#define HEADER_SIZE (SHA512_LENGTH + IV_LENGTH + 3)

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

bool check_hashes(unsigned char *h1, unsigned char *h2, size_t length)
{
	for(size_t i = 0; i < length; i++) {
		if(h1[i] != h2[i]) return false;
	}
	return true;
}

void hash_n_stuff(std::ifstream *src, std::ofstream *dst, bool encrypt, unsigned char *key, unsigned char *sha512, unsigned char *iv, size_t length)
{
	unsigned char buf[AES_CBC_BLOCK_SIZE];
	unsigned char outbuf[AES_CBC_BLOCK_SIZE];
	unsigned int bytes;

	mbedtls_sha512_context sha_ctx;
	mbedtls_aes_context aes_ctx;

	mbedtls_sha512_init(&sha_ctx);
	mbedtls_sha512_starts(&sha_ctx, USE_SHA512);

	mbedtls_aes_init(&aes_ctx);
	set_aes_key(&aes_ctx, key, encrypt);
	size_t foo = src->tellg();

	// While there's something to read
	for(size_t i = 0; i < length; i += AES_CBC_BLOCK_SIZE) {
		// Read one block
		src->read(reinterpret_cast<char *>(buf), AES_CBC_BLOCK_SIZE);
		bytes = src->gcount();

		if(encrypt) {
			// Add padding when encrypting
			pkcs7_pad(buf, &bytes);
		}

		// Encrypt the block and write it to the output stream
		mbedtls_aes_crypt_cbc(&aes_ctx, encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT, bytes, iv, buf, outbuf);

		// Detect padding when decrypting
		if(!encrypt && i + AES_CBC_BLOCK_SIZE >= length) bytes = pkcs7_detect(outbuf);

		// Write the encrypted/decrypted block to disk
		dst->write(reinterpret_cast<char *>(outbuf), bytes);

		// Hash the block
		mbedtls_sha512_update(&sha_ctx, encrypt ? outbuf : buf, AES_CBC_BLOCK_SIZE);
	}

	// Finish generating checksums
	mbedtls_sha512_finish(&sha_ctx, sha512);

	// Clean things up
	mbedtls_sha512_free(&sha_ctx);
	mbedtls_aes_free(&aes_ctx);
}

size_t stream_length(std::fstream *stream)
{
	size_t pos = stream->tellg();
	stream->seekg(0, std::ios_base::end);
	size_t length = stream->tellg();
	stream->seekg(pos);
	return length;
}

void write_header(std::ofstream *out, unsigned char *sha512, unsigned char *iv)
{
	out->seekp(0, std::ios_base::beg);
	out->write("AES", 3);
	out->write(reinterpret_cast<char *>(iv), IV_LENGTH);
	out->write(reinterpret_cast<char *>(sha512), SHA512_LENGTH);
}

void read_header(std::ifstream *in, unsigned char *sha512, unsigned char *iv, size_t *length)
{
	char buf[3];
	in->read(buf, 3);
	if(std::strncmp(buf, "AES", 3) != 0) {
		DIE(5, "The encrpyted file misses the AES header.");
	}
	in->read(reinterpret_cast<char *>(iv), IV_LENGTH);
	if(in->gcount() != IV_LENGTH) {
		DIE(6, "The encrypted file does not contain the IV.");
	}
	in->read(reinterpret_cast<char *>(sha512), SHA512_LENGTH);
	if(in->gcount() != SHA512_LENGTH) {
		DIE(7, "The encrypted file does not contain the SHA512 hash.");
	}
	*length = stream_length((std::fstream *)in) - (HEADER_SIZE);
}

void perform(bool encrypt, char *src, char *dst, unsigned char *key)
{
	std::ifstream in;
	std::ofstream out;
	unsigned char sha512[SHA512_LENGTH], iv[IV_LENGTH], iv_backup[IV_LENGTH];
	size_t length;
	in.open(src);
	out.open(dst);

	if(encrypt) {
		length = stream_length((std::fstream *)&in);
		// Leave blank space for the header
		out.seekp(HEADER_SIZE);
		// Generate IV
		generate_random_string(iv, IV_LENGTH);
		memcpy(iv_backup, iv, IV_LENGTH*sizeof(unsigned char));
		// Encrypt the file
		hash_n_stuff(&in, &out, encrypt, key, sha512, iv, length);
		// Write the header
		write_header(&out, sha512, iv_backup);
	} else {
		unsigned char read_sha512[SHA512_LENGTH];
		read_header(&in, read_sha512, iv, &length);
		if(length % 16 != 0) {
			DIE(3, "The encrypted payload is of the wrong size.");
		}
		hash_n_stuff(&in, &out, encrypt, key, sha512, iv, length);
		if(!check_hashes(sha512, read_sha512, SHA512_LENGTH)) {
			DIE(4, "The hashes do not match.");
		}
	}
	in.close();
	out.close();
}

int main(int argc, char **argv)
{
	if(argc != 5) {
		DIE(1, "Wrong argument count, expected 4, got %d\n", argc - 1);
	}
	bool encrypt;
	encrypt = argv[1][0] == 'e' ? true : false;
	perform(encrypt, argv[2], argv[3], reinterpret_cast<unsigned char *>(argv[4]));
	return 0;
}
