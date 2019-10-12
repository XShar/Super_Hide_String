#include "xtea3.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <stdlib.h>

#define DEBUG_PRINT(m,...) //printf(m,__VA_ARGS__)
#define BLOCK_SIZE 16

static uint8_t *data_ptr = NULL;
static uint32_t size_crypt = 0;
static uint32_t size_decrypt_data = 0;

static inline uint32_t rol(uint32_t base, uint32_t shift) 
{
	uint32_t res;
	/* only 5 bits of shift are significant*/
	shift &= 0x1F;
	res = (base << shift) | (base >> (32 - shift));
	return res;
};

xtea3::xtea3()
{
}


xtea3::~xtea3()
{
}

void xtea3_encipher(unsigned int num_rounds, uint32_t *v, const uint32_t *k)
{
	unsigned int i;
	uint32_t a, b, c, d, sum = 0, t, delta = 0x9E3779B9;
	sum = 0;
	a = v[0] + k[0];
	b = v[1] + k[1];
	c = v[2] + k[2];
	d = v[3] + k[3];
	for (i = 0; i < num_rounds; i++) {
		a += (((b << 4) + rol(k[(sum % 4) + 4], b)) ^
			(d + sum) ^ ((b >> 5) + rol(k[sum % 4], b >> 27)));
		sum += delta;
		c += (((d << 4) + rol(k[((sum >> 11) % 4) + 4], d)) ^
			(b + sum) ^ ((d >> 5) + rol(k[(sum >> 11) % 4], d >> 27)));
		t = a; a = b; b = c; c = d; d = t;
	}
	v[0] = a ^ k[4];
	v[1] = b ^ k[5];
	v[2] = c ^ k[6];
	v[3] = d ^ k[7];
};

void xtea3_decipher(unsigned int num_rounds, uint32_t *v, const uint32_t *k)
{
	unsigned int i;
	uint32_t a, b, c, d, t, delta = 0x9E3779B9, sum = delta * num_rounds;
	d = v[3] ^ k[7];
	c = v[2] ^ k[6];
	b = v[1] ^ k[5];
	a = v[0] ^ k[4];
	for (i = 0; i < num_rounds; i++) {
		t = d; d = c; c = b; b = a; a = t;
		c -= (((d << 4) + rol(k[((sum >> 11) % 4) + 4], d)) ^
			(b + sum) ^ ((d >> 5) + rol(k[(sum >> 11) % 4], d >> 27)));
		sum -= delta;
		a -= (((b << 4) + rol(k[(sum % 4) + 4], b)) ^
			(d + sum) ^ ((b >> 5) + rol(k[sum % 4], b >> 27)));
	}
	v[3] = d - k[3];
	v[2] = c - k[2];
	v[1] = b - k[1];
	v[0] = a - k[0];
};

void xtea3_data_crypt(uint8_t *inout, uint32_t len, bool encrypt, const uint32_t *key)
{
	static unsigned char dataArray[BLOCK_SIZE];

	for (int i = 0; i < len / BLOCK_SIZE; i++)
	{
		memcpy(dataArray, inout, BLOCK_SIZE);

		if (encrypt)
			xtea3_encipher(48, (uint32_t*)dataArray, key);
		else
			xtea3_decipher(48, (uint32_t*)dataArray, key);

		memcpy(inout, dataArray, BLOCK_SIZE);
		inout = inout + BLOCK_SIZE;
	}

	if (len%BLOCK_SIZE != 0)
	{
		int mod = len % BLOCK_SIZE;
		int offset = (len / BLOCK_SIZE)*BLOCK_SIZE;
		uint32_t data[BLOCK_SIZE];
		memcpy(data, inout + offset, mod);
		if (encrypt)
			xtea3_encipher(32, (uint32_t*)data, key);
		else
			xtea3_decipher(32, (uint32_t*)data, key);
		memcpy(inout + offset, data, mod);
	}

}

uint8_t *xtea3::data_crypt(const uint8_t *data, const uint32_t key[8], uint32_t size)
{
	uint32_t size_crypt_tmp = size;

	DEBUG_PRINT("CRYPT: \n");
	DEBUG_PRINT("SIZE = %d \n",size);

	//Выровнить размер буфера до 16-ти (для этого алгоритма)
	while ((size_crypt_tmp % 16) != 0)
	{
		size_crypt_tmp++;
	}

	//Выделить память под выровненный буфер (Плюс восемь байт, что-бы был размер зашифрованных данных и размер оригинальных данных, всё это будет хранится в зашифрованных данных)
	data_ptr = NULL;
	data_ptr = (uint8_t*) malloc(size_crypt_tmp + 8);
	if (data_ptr == NULL)
	{
		DEBUG_PRINT("NO FREE MEM \n");
		return NULL;
	}

	//Положим в получившийся буфер размер криптованных данных и размер оригинала
	size_crypt = size_crypt_tmp + 8;
	size_decrypt_data = size;

	memcpy(data_ptr, (char*)&size_crypt, 4);
	memcpy(data_ptr + 4, (char*)&size_decrypt_data, 4);

	memcpy(data_ptr + 8, data, size);

	//Зашифруем данные
	xtea3_data_crypt(data_ptr + 8, size_crypt - 8, true, key);

	return data_ptr;
}
uint8_t *xtea3:: data_decrypt(const uint8_t *data, const uint32_t key[8], uint32_t size)
{
	//Получим размер криптованных данных и размер оригинала
	memcpy((char*)&size_crypt, data,  4);
	memcpy((char*)&size_decrypt_data, data + 4, 4);

	DEBUG_PRINT("DECRYPT: \n");
	DEBUG_PRINT("SIZE = %d \n", size);

	DEBUG_PRINT("size_crypt = %d \n", size_crypt);
	DEBUG_PRINT("size_decrypt_data = %d \n", size_decrypt_data);


	if (size_crypt <= size)
	{ 
	//Выделить память для расшифрованных данных
	data_ptr = NULL;
	data_ptr = (uint8_t*)malloc(size_crypt);
	if (data_ptr == NULL)
	{
		DEBUG_PRINT("NO FREE MEM \n");
		return NULL;
	}

	memcpy(data_ptr, data + 8, size_crypt - 8);

	//Расшифруем данные
	xtea3_data_crypt(data_ptr, size_crypt - 8, false, key);
	}
	else
	{
		DEBUG_PRINT("size_crypt > size \n");
		return NULL;
	}

	return data_ptr;
}

uint32_t xtea3::get_decrypt_size(void)
{
	return size_decrypt_data;
}

uint32_t xtea3::get_crypt_size(void)
{

	return size_crypt;
}

void xtea3::free_ptr(uint8_t *ptr)
{
	free(ptr);
}