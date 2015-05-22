// RSA_AES Test.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include "Crypto.h"
#include <vector>

int _tmain(int argc, _TCHAR* argv[])
{
	SecureCrypto CryptoEngine = SecureCrypto();

	std::string Msg = "Hello";

	//CryptoEngine.GenerateRSAKeys();
	CryptoEngine.ReadRSAKeys();

	//RSA SIGN EXAMPLE
	printf("\nBegginning RSA Sign Test\n");

	std::string HashMsg;
	CryptoEngine.RSASign(Msg,HashMsg,CryptoEngine.GetServerPrivateKey());

	std::string B64Hash;
	CryptoEngine.Base64Encrypt(HashMsg,B64Hash);
	printf("RSA B64 MSG HASH:\n\n%s \n", B64Hash);

	bool Authentic;
	if (CryptoEngine.RSAVerifySignature(HashMsg,Msg,CryptoEngine.GetServerPublicKey(), &Authentic) && Authentic)
		printf("\nMessage Is Authentic \n");
	else
		printf("\nMessage Is Not Authentic \n");

	printf("END RSA SIGN TEST\n");
	//AES EXAMPLE
	printf("\n\nBegginning AES Encryption Test\n");

	std::string EncMsg;
	std::string B64EncMsg;
	CryptoEngine.AESEncrypt(Msg, EncMsg);
	CryptoEngine.Base64Encrypt(EncMsg,B64EncMsg);
	printf("AES B64 Encrypted Message:\n%s\n", B64EncMsg.c_str());

	std::string DecodedB64EncMsg;
	CryptoEngine.Base64Decrypt(B64EncMsg,DecodedB64EncMsg);

	std::string DecMsg;
	CryptoEngine.AESDecrypt(DecodedB64EncMsg,DecMsg);
	printf("\nAES Decrypted Message:%s\n", DecMsg.c_str());
	printf("END AES ENCRYPTION TEST\n");

	printf("\n\nBegginning HASH TEST\n");
	std::string HashResult;
	CryptoEngine.SHA256("hello hashing", HashResult);
	printf("Hash Result:%s\n", HashResult.c_str());

	Sleep(50000);
	return 0;
}

