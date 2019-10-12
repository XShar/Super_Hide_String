#pragma once
#include <stdint.h>
class xtea3
{
protected:
	friend void xtea3_decipher(unsigned int num_rounds, uint32_t *v, const uint32_t *k);
	friend void xtea3_encipher(unsigned int num_rounds, uint32_t *v, const uint32_t *k);
	friend void xtea3_data_crypt(uint8_t *inout, uint32_t len, bool encrypt, const uint32_t *key);
public:
	xtea3();
	~xtea3();
	uint8_t *data_crypt(const uint8_t *data, const uint32_t key[8], uint32_t size);
	uint8_t *data_decrypt(const uint8_t *data, const uint32_t key[8], uint32_t size);
	uint32_t get_decrypt_size(void);
	uint32_t get_crypt_size(void);
	void free_ptr(uint8_t *ptr);
};