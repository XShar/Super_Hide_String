#include <iostream>

#include "hide_str.hpp"

//Примеры использования
int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	//ВАРИАНТ1:

	//Создаём класс с зашифрованной строкой
	HIDE_STR(hide_str, "Hide String1");
	//Получаем указатель на расшифрованную строку
	uint8_t *decrypt_string = hide_str.decrypt();
	MessageBoxA(0, (LPCSTR)decrypt_string, (LPCSTR)decrypt_string, MB_OK);
	//Освобождаем память
	hide_str.str_free(decrypt_string);

	//ВАРИАНТ2:
	//Более простой
	MessageBoxA(0, (LPCSTR)PRINT_HIDE_STR("Hide String2"), (LPCSTR)PRINT_HIDE_STR("Hide String2"), MB_OK);

	//Метка, что-бы было видно отличие в декомпиляторе
	MessageBoxA(0, "NO Hide String1", "NO Hide String2", MB_OK);
}
