#include "pch.h"
#include "xtea3.h"
#include <iostream>
#include <string.h>
#include <stdio.h>

#define PATH_FILE_OPEN "Putty.exe"
#define PATH_FILE_CRYPT "Putty_crypt.exe"
#define PATH_FILE_DECRYPT "Putty_orig.exe"
#define SIZE_FILE 50*1024*1024

static uint8_t buffer[SIZE_FILE];
static uint8_t tmp;

int main()
{
	/******************************************************************************************************
	Тест шифрование строки, суть теста:

	Формируется строка из 143 эллементов (string), далее шифруется.

	Выводится оригинальная строка, выводится шифрованная строка и выводится расшифрованная строка.

	*******************************************************************************************************/

	std::string str_tst = "Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! Hello World! \0\r";
	
	std::cout << "ORIG STR:\n\n";
	std::cout << str_tst.c_str() << "\n\nSIZE ORIG STR: " <<str_tst.length()<< " \n\n";

	//Создаем класс
	xtea3 *ptr_xtea_lib = new xtea3;

	//Создадим ключ
	uint32_t key[8] = {0x11, 0x55, 0xAA, 0x88, 0x12, 0x55, 0x77, 0x12};

	//Зашифруем данные и получим указатель на зашифрованные данные
	uint8_t *p_crypt_data = ptr_xtea_lib->data_crypt((uint8_t*)str_tst.c_str(), key, str_tst.length() + 1);
	if (p_crypt_data == NULL)
	{
		std::cout << "Error decrypt fdata \n";
		return (-1);
	}

	//Убедимся, что данные зашифровались, выведем зашифрованный массив
	std::cout << "CRYPT_STR: \n\n";
	std::cout << "CRYPT_STR SIZE = " << ptr_xtea_lib->get_crypt_size() << "\n\n";
	for (int i = 0; i < ptr_xtea_lib->get_crypt_size(); i++)
	{
		std::cout << p_crypt_data[i];
	}

	//Расшифруем данные и получим указатель на расшифрованные данные
	uint8_t *p_decrypt_data = ptr_xtea_lib->data_decrypt((uint8_t*)p_crypt_data, key, ptr_xtea_lib->get_crypt_size());
	if (p_decrypt_data == NULL)
	{
		std::cout << "Error decrypt fdata \n";
		return (-1);
	}

	//Очистим строку
	str_tst.clear();

	//Прировняем указатель на расшифрованные данные нашей строки
	str_tst = (char*)p_decrypt_data;

	std::cout << "\n\nDECRYPT_STR: \n\n";
	
		
	//Выведем строку

	std::cout << "SIZE DECRYPT STR: " << ptr_xtea_lib->get_decrypt_size() <<" \n\n";
	std::cout << "SIZE DECRYPT STRING: " << str_tst.length() << " \n\n";
	std::cout << str_tst.c_str() << " \n\n";

	/**********************************************************************************************************************
	Тест шифрования бинарного файла:
	В папке с программой лежит пример (Putty.exe), он шифруется в Putty_crypt.exe, далее расшифровывается в Putty_orig.exe.
	***********************************************************************************************************************/

	unsigned int count = 0;
	unsigned int size_file = 0;

	std::cout << "\n\n************* Start test crypt bin file *********************\n";

	//Открываем файлы
	
	//На чтение (можно только читать)
	FILE *hFileOpen = fopen(PATH_FILE_OPEN, "rb");
	
	//На запись/создание если нет
	FILE *hFileCrypt = fopen(PATH_FILE_CRYPT, "wb+");

	if ((hFileOpen == NULL) || (hFileCrypt == NULL))
	{
		std::cout << "Error open files \n";
		return (-1);
	}

	//Считываем файл, который нужно зашифровать в буфер

	while (!feof(hFileOpen))
	{
		tmp = getc(hFileOpen);
		if (size_file < SIZE_FILE) buffer[size_file] = tmp;
		else
		{
			printf("Error file size = %d Size file must be < %d \n", size_file, SIZE_FILE);
			return (-1);
		}
		size_file++;
	}

	fclose(hFileOpen);

	//Зашифруем буфер:
	p_crypt_data = ptr_xtea_lib->data_crypt((uint8_t*)buffer, key, size_file - 1);
	if (p_crypt_data == NULL)
	{
		std::cout << "Error crypt files \n";
		return (-1);
	}

	//Сохраним зашифрованные данные на диск:
	fwrite(p_crypt_data, 1, ptr_xtea_lib->get_crypt_size(), hFileCrypt);
	
	//Закроем файл
	fclose(hFileCrypt);

	//Открываем файл, куда поместим расшифрованные данные

	//На запись/создание если нет
	FILE *hFileDecrypt = fopen(PATH_FILE_DECRYPT, "wb+");

	if (hFileDecrypt == NULL)
	{
		std::cout << "Error open files \n";
		return (-1);
	}

	//Расшифруем данные
	p_decrypt_data = ptr_xtea_lib->data_decrypt((uint8_t*)p_crypt_data, key, ptr_xtea_lib->get_crypt_size());
	if (p_decrypt_data == NULL)
	{
		std::cout << "Error decrypt fdata \n";
		return (-1);
	}

	//Сохраним расшифрованные данные на диск:
	fwrite(p_decrypt_data, 1, ptr_xtea_lib ->get_decrypt_size(), hFileDecrypt);
	
	//Закроем файл
	fclose(hFileDecrypt);
	
	std::cout << "\n*************** End test crypt bin file ******************** \n\n\n";

	system("pause");
	return 0;
}