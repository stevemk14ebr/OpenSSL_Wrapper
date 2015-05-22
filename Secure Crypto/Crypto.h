#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/bio.h>
#include <openssl/applink.c>
#include <openssl/sha.h>
#include <memory>
#include <algorithm>

#pragma comment(lib,"libeay32MD.lib")
#define NotInit std::cout << "Not Initialized\n"
typedef std::shared_ptr<EVP_PKEY> SmartEVP_PKey;
typedef std::shared_ptr<BIO> SmartBIO;
typedef std::shared_ptr<EVP_MD_CTX> SmartEVP_MD_CTX;
typedef std::shared_ptr<EVP_CIPHER_CTX> Smart_EVP_CIPHER_CTX;
typedef std::shared_ptr<unsigned char> SmartUChar;

//Custom Deleters for Smart Wrappers
void SmartEVPDel(EVP_PKEY* key)
{
	std::cout << "Deleting EVP_PKEY \n";
	EVP_PKEY_free(key);
}
void SmartBIODel(BIO* bio)
{
	std::cout << "Deleting BIO \n";
	BIO_free_all(bio);
}
void SmartMD_CTXDel(EVP_MD_CTX* ctx)
{
	std::cout << "Deleting MD_CTX \n";
	EVP_MD_CTX_destroy(ctx);
}
void SmartCIPHER_CTXDel(EVP_CIPHER_CTX* ctx)
{
	std::cout << "Deleting CIPHER_CTX \n";
	EVP_CIPHER_CTX_free(ctx);
}
void SmartFreeUChar(void* p)
{
	std::cout << "Freeing UChar\n";
	free(p);
}

class SecureCrypto
{
public:
	SecureCrypto();
	~SecureCrypto();
	bool AESEncrypt(const unsigned char* Msg, size_t MsgLen, SmartUChar& EncMsg,size_t& MsgLenEnc);
	bool AESEncrypt(std::string Msg, std::string& EncMessage);
	bool AESEncrypt(std::string Msg, std::string& EncMessage,size_t &EncMsgLen);
	bool AESDecrypt(const unsigned char* EncMsg, size_t EncMsgLen, SmartUChar& Msg, size_t& MsgLen);
	bool AESDecrypt(std::string EncMsg, std::string& DecMsg);

	bool Base64Encrypt(const unsigned char* Msg, size_t length, SmartUChar& EncMsg);
	bool Base64Encrypt(std::string Msg, std::string& EncMsg);
	bool URLB64Encrypt(std::string Msg, std::string& EncMsg);

	bool Base64Decrypt(const unsigned char* EncMsg,SmartUChar& Msg,size_t& OutLen);
	bool Base64Decrypt(std::string EncMsg, std::string& DecMsg);
	bool URLB64Decrypt(std::string EncMsg, std::string& DecMsg);

	bool RSASign(const unsigned char* Msg, size_t MsgLen,SmartUChar& MsgHash, size_t& MsgLenEnc,SmartEVP_PKey PrivateKey);
	bool RSASign(std::string Msg, std::string& MsgHash, SmartEVP_PKey PrivateKey);
	bool RSAVerifySignature(const unsigned char* MsgHash, size_t MsgHashLen,const unsigned char* Msg, size_t MsgLen,SmartEVP_PKey PublicKey,bool* Authentic);
	bool RSAVerifySignature(std::string MsgHash, std::string OriginalMsg, SmartEVP_PKey PublicKey, bool* Authentic);

	bool SHA256(const std::string Data, std::string& HashResult);

	bool GenerateRSAKeys();
	bool ReadRSAKeys();
	std::string GetServerPrivateKeyTxt();
	std::string GetServerPublicKeyTxt();
	std::string GetClientPublicKeyTxt();
	std::string GetClientPrivateKeyTxt();
	SmartEVP_PKey GetServerPrivateKey();
	SmartEVP_PKey GetServerPublicKey();
	SmartEVP_PKey GetClientPublicKey();
	SmartEVP_PKey GetClientPrivateKey();
private:
	int RSA_KeyLen = 2048;//Size of Prime
	int RSA_PubExp = 65537; //Size of Public Exponent
	int AES_KeyLen = 256;
	int AES_Rounds = 6;
	
	SmartEVP_PKey m_ServerKeyPair;
	SmartEVP_PKey m_ClientKeyPair;

	SmartBIO m_ClientPublicBIO;
	SmartBIO m_ClientPrivateBIO;
	SmartBIO m_ServerPublicKeyBIO;
	SmartBIO m_ServerPrivateKeyBIO;

	SmartEVP_PKey m_ServerPrivateKey;
	SmartEVP_PKey m_ServerPublicKey;
	SmartEVP_PKey m_ClientPrivateKey;
	SmartEVP_PKey m_ClientPublicKey;

	SmartEVP_MD_CTX m_RSASignCtx;
	SmartEVP_MD_CTX m_RSAVerifyCtx;

	SmartEVP_MD_CTX m_HashCtx;

	Smart_EVP_CIPHER_CTX m_AESEncCtx;
	Smart_EVP_CIPHER_CTX m_AESDecCtx;

	unsigned char* m_AESKey;
	unsigned char* m_AESIV; //Initialization Vector
	bool m_InitializeOK;
	
	//Some Internal Helpers
	bool Initialize();
	size_t B64DecodeLen(const char* EncInput);
	std::string BioToString(BIO* bio);
	BIO* KeyToPubBio(EVP_PKEY* KeyPair);
	BIO* KeyToPrivBio(EVP_PKEY* KeyPair);
};
SecureCrypto::~SecureCrypto()
{
	free(m_AESKey);
	free(m_AESIV);
	ERR_free_strings();
	RAND_cleanup();
	EVP_cleanup();
}
bool SecureCrypto::Initialize()
{
	OpenSSL_add_all_digests();

	//Initialize Contexts and verify they're not null
	m_RSASignCtx=SmartEVP_MD_CTX(EVP_MD_CTX_create(),&SmartMD_CTXDel);
	m_RSAVerifyCtx = SmartEVP_MD_CTX(EVP_MD_CTX_create(), &SmartMD_CTXDel);

	m_AESEncCtx=Smart_EVP_CIPHER_CTX(EVP_CIPHER_CTX_new(),&SmartCIPHER_CTXDel);
	m_AESDecCtx = Smart_EVP_CIPHER_CTX(EVP_CIPHER_CTX_new(), &SmartCIPHER_CTXDel);

	m_HashCtx = SmartEVP_MD_CTX(EVP_MD_CTX_create(), &SmartMD_CTXDel);

	if (m_RSASignCtx == nullptr || m_AESEncCtx == nullptr || m_RSAVerifyCtx == nullptr || m_AESDecCtx == nullptr || m_HashCtx==nullptr)
		return false;
	
	EVP_MD_CTX_init(m_RSASignCtx.get());
	EVP_MD_CTX_init(m_RSAVerifyCtx.get());

	EVP_CIPHER_CTX_init(m_AESEncCtx.get());
	EVP_CIPHER_CTX_init(m_AESDecCtx.get());

	//Init AES
	m_AESKey = (unsigned char*)malloc(AES_KeyLen / 8);
	m_AESIV = (unsigned char*)malloc(AES_KeyLen / 8);
	if (m_AESKey == nullptr || m_AESIV == nullptr)
	{
		free(m_AESKey);
		free(m_AESIV);
		return false;
	}

	if (RAND_bytes(m_AESKey, AES_KeyLen / 8)==0 || RAND_bytes(m_AESIV,AES_KeyLen/8)==0)
		return false;

	return true;
}
SecureCrypto::SecureCrypto()
{
	m_InitializeOK=Initialize();

	m_ServerPrivateKeyBIO = SmartBIO(BIO_new(BIO_s_mem()),&SmartBIODel);
	m_ServerPublicKeyBIO = SmartBIO(BIO_new(BIO_s_mem()), &SmartBIODel);
	m_ClientPrivateBIO = SmartBIO(BIO_new(BIO_s_mem()), &SmartBIODel);
	m_ClientPublicBIO = SmartBIO(BIO_new(BIO_s_mem()), &SmartBIODel);
	printf("Initialized\n");
}

BIO* SecureCrypto::KeyToPubBio(EVP_PKEY* KeyPair)
{
	BIO* TempBio = BIO_new(BIO_s_mem());;
	PEM_write_bio_PUBKEY(TempBio, KeyPair);
	return TempBio;
}
BIO* SecureCrypto::KeyToPrivBio(EVP_PKEY* KeyPair)
{
	BIO* TempBio = BIO_new(BIO_s_mem());;
	PEM_write_bio_PKCS8PrivateKey(TempBio, KeyPair, NULL, NULL, 0, 0, NULL);
	return TempBio;
}

bool SecureCrypto::AESEncrypt(const unsigned char* Msg, size_t MsgLen,SmartUChar& EncMsg,size_t &MsgLenEnc)
{
	if (!m_InitializeOK)
	{
		NotInit;
		return false;
	}
	printf("Beginning Encryption\n");

	size_t BlockLen = 0;
	size_t EncMsgLen = 0;

	EncMsg = SmartUChar((unsigned char*)malloc(MsgLen + AES_BLOCK_SIZE),&SmartFreeUChar);
	if (EncMsg == nullptr)
		return false;

	if (!EVP_EncryptInit_ex(m_AESEncCtx.get(), EVP_aes_256_cbc(), NULL, m_AESKey, m_AESIV))
		return false;

	if (!EVP_EncryptUpdate(m_AESEncCtx.get(), EncMsg.get(), (int*)&BlockLen, (unsigned char*)Msg, MsgLen))
		return false;

	EncMsgLen += BlockLen;
	if (!EVP_EncryptFinal_ex(m_AESEncCtx.get(), EncMsg.get() + EncMsgLen, (int*)&BlockLen))
		return false;

	EVP_CIPHER_CTX_cleanup(m_AESEncCtx.get());
	MsgLenEnc = EncMsgLen + BlockLen;

	return true;
}
bool SecureCrypto::AESEncrypt(std::string Msg, std::string& EncMessage)
{
	SmartUChar EncryptedMsg=nullptr;
	size_t EncMsgLen = 0;
	bool Succes = AESEncrypt((const unsigned char*)Msg.c_str(), Msg.size() + 1, EncryptedMsg, EncMsgLen);
	EncMessage = std::string((char*)EncryptedMsg.get(),(char*) EncryptedMsg.get()+EncMsgLen);
	return Succes;
}
bool SecureCrypto::AESEncrypt(std::string Msg, std::string& EncMessage, size_t &EncMsgLen)
{
	SmartUChar EncryptedMsg=nullptr;
	bool Succes = AESEncrypt((const unsigned char*)Msg.c_str(), Msg.size() + 1, EncryptedMsg, EncMsgLen);
	EncMessage = std::string((char*)EncryptedMsg.get(), (char*)EncryptedMsg.get() + EncMsgLen);
	return Succes;
}

bool SecureCrypto::AESDecrypt(const unsigned char* EncMsg, size_t EncMsgLen, SmartUChar& Msg, size_t& MsgLen)
{
	if (!m_InitializeOK)
	{
		NotInit;
		return false;
	}
	size_t DecryptLen = 0;
	size_t BlockLen = 0;

	Msg = SmartUChar((unsigned char*)malloc(EncMsgLen), &SmartFreeUChar);
	if (Msg == nullptr)
		return false;

	if (!EVP_DecryptInit_ex(m_AESDecCtx.get(), EVP_aes_256_cbc(), nullptr, m_AESKey, m_AESIV))
		return false;

	if (!EVP_DecryptUpdate(m_AESDecCtx.get(), (unsigned char*)Msg.get(), (int*)&BlockLen, EncMsg, (int)EncMsgLen))
		return false;

	DecryptLen += BlockLen;
	if (!EVP_DecryptFinal_ex(m_AESDecCtx.get(), (unsigned char*)Msg.get() + DecryptLen, (int*)&BlockLen))
		return false;

	EVP_CIPHER_CTX_cleanup(m_AESDecCtx.get());
	MsgLen = DecryptLen += BlockLen;
	return true;
}
bool SecureCrypto::AESDecrypt(std::string EncMsg, std::string& DecMsg)
{
	SmartUChar TempDecMsg = nullptr;
	size_t DecMsgLen = 0;
	bool RetVal = AESDecrypt((const unsigned char*)EncMsg.c_str(), EncMsg.length(), TempDecMsg, DecMsgLen);

	//Null terminator not guaranteed
	DecMsg = std::string((char*)TempDecMsg.get(), (char*)TempDecMsg.get() + DecMsgLen);
	return RetVal;
}

bool SecureCrypto::Base64Encrypt(const unsigned char* Msg, size_t length,SmartUChar& EncMsg)
{
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, Msg, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);

	//Copy OpenSSL mem into our smart ptr, to free after return
	EncMsg = SmartUChar((unsigned char*)malloc(bufferPtr->length+1));
	memcpy(EncMsg.get(), bufferPtr->data, bufferPtr->length);
	EncMsg.get()[bufferPtr->length] = 0; //add null terminator

	BIO_free_all(b64);
	return true;
}
bool SecureCrypto::Base64Encrypt(std::string Msg, std::string& EncMsg)
{
	SmartUChar TempEncMsg = nullptr;
	bool RetVal=Base64Encrypt((const unsigned char*)Msg.c_str(), Msg.length(), TempEncMsg);

	//Null terminator is guaranteed
	EncMsg = std::string((char*)TempEncMsg.get());
	return RetVal;
}
bool SecureCrypto::URLB64Encrypt(std::string Msg, std::string& EncMsg)
{
	/*In url's the characters + / and = are treated as special control characters,
	therefore if you send a b64 encoded string along the web it will come out the other
	side mangled, so we first need to replace these characters with non used ones to
	avoid this mangling
	*/
	if (!Base64Encrypt(Msg, EncMsg))
	{
		EncMsg = " ";
		return false;
	}
	std::replace(EncMsg.begin(), EncMsg.end(), '+', '-');
	std::replace(EncMsg.begin(), EncMsg.end(), '/', '_');
	std::replace(EncMsg.begin(), EncMsg.end(), '=', '~');
	return true;
}

size_t SecureCrypto::B64DecodeLen(const char* EncInput) { //Calculates the length of a decoded string
	size_t len = strlen(EncInput),
		padding = 0;

	if (EncInput[len - 1] == '=' && EncInput[len - 2] == '=') //last two chars are =
		padding = 2;
	else if (EncInput[len - 1] == '=') //last char is =
		padding = 1;

	return (size_t)len*0.75 - padding;
}
bool SecureCrypto::Base64Decrypt(const unsigned char* EncMsg, SmartUChar& Msg, size_t& OutLen)
{
	BIO *bio, *b64;

	int decodeLen = B64DecodeLen((const char*)EncMsg);
	Msg = SmartUChar((unsigned char*)malloc(decodeLen), &SmartFreeUChar);

	bio = BIO_new_mem_buf((void*)EncMsg, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	OutLen= BIO_read(bio, Msg.get(), strlen((const char*)EncMsg));

	BIO_free_all(b64);
	return true;
}
bool SecureCrypto::Base64Decrypt(std::string EncMsg, std::string& DecMsg)
{
	SmartUChar TempDecMsg = nullptr;
	size_t DecMsgLen=0;
	bool RetVal = Base64Decrypt((const unsigned char*)EncMsg.c_str(), TempDecMsg, DecMsgLen);

	//Null terminator not guaranteed
	DecMsg = std::string((char*)TempDecMsg.get(), (char*)TempDecMsg.get() + DecMsgLen);
	return RetVal;
}
bool SecureCrypto::URLB64Decrypt(std::string EncMsg, std::string& DecMsg)
{
	//Modifies functions copy of EncMsg, no need to make a copy ourselves
	std::replace(EncMsg.begin(), EncMsg.end(), '-', '+');
	std::replace(EncMsg.begin(), EncMsg.end(), '_', '/');
	std::replace(EncMsg.begin(), EncMsg.end(), '~', '=');

	if (!Base64Decrypt(EncMsg, DecMsg))
	{
		DecMsg = " ";
		return false;
	}
	return true;
}

bool SecureCrypto::GenerateRSAKeys()
{
	//Generate RSA Keys
	EVP_PKEY_CTX* KeyCtx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if (KeyCtx == nullptr)
		return false;

	if (EVP_PKEY_keygen_init(KeyCtx) <= 0)
		return false;

	if (EVP_PKEY_CTX_set_rsa_keygen_bits(KeyCtx, RSA_KeyLen) <= 0)
		return false;

	EVP_PKEY* TempKey;
	EVP_PKEY* TempKey2;
	if (EVP_PKEY_keygen(KeyCtx, &TempKey) <= 0)
		return false;
	m_ServerKeyPair=SmartEVP_PKey(TempKey, &SmartEVPDel);

	if (EVP_PKEY_keygen(KeyCtx, &TempKey2) <= 0)
		return false;
	m_ClientKeyPair = SmartEVP_PKey(TempKey2, &SmartEVPDel);

	//Create Key File for later use
	FILE* ServPrivateKey = fopen("C:\\Users\\Steve\\Desktop\\Priv.pem", "w");
	FILE* ServPublicKey = fopen("C:\\Users\\Steve\\Desktop\\Pub.pem", "w");
	FILE* ClientPrivateKey = fopen("C:\\Users\\Steve\\Desktop\\ClientPriv.pem", "w");
	FILE* ClientPublicKey = fopen("C:\\Users\\Steve\\Desktop\\ClientPub.pem", "w");

	//Write Keys to File
	PEM_write_PKCS8PrivateKey(ServPrivateKey, m_ServerKeyPair.get(), NULL, NULL, 0, 0, NULL);
	PEM_write_PUBKEY(ServPublicKey, m_ServerKeyPair.get());
	PEM_write_PKCS8PrivateKey(ClientPrivateKey, m_ClientKeyPair.get(), NULL, NULL, 0, 0, NULL);
	PEM_write_PUBKEY(ClientPublicKey, m_ClientKeyPair.get());

	//Close File Handles
	fclose(ClientPublicKey);
	fclose(ClientPrivateKey);
	fclose(ServPublicKey);
	fclose(ServPrivateKey);
	
	//Write Keys to Bio for easy Display
	m_ServerPublicKeyBIO = SmartBIO(KeyToPubBio(m_ServerKeyPair.get()),&SmartBIODel);
	m_ServerPrivateKeyBIO = SmartBIO(KeyToPrivBio(m_ServerKeyPair.get()), &SmartBIODel);
	m_ClientPublicBIO = SmartBIO(KeyToPubBio(m_ClientKeyPair.get()), &SmartBIODel);
	m_ClientPrivateBIO = SmartBIO(KeyToPrivBio(m_ClientKeyPair.get()), &SmartBIODel);

	EVP_PKEY* TempServPriv;
	EVP_PKEY* TempServPub;
	EVP_PKEY* TempClientPriv;
	EVP_PKEY* TempClientPub;
	//Write Keys to EVP_PKEYS for actual internal encryption,BIO mem is wiped after read so we need a new copy
	PEM_read_bio_PrivateKey(KeyToPrivBio(m_ServerKeyPair.get()), &TempServPriv, NULL, NULL);
	PEM_read_bio_PUBKEY(KeyToPubBio(m_ServerKeyPair.get()), &TempServPub, NULL, NULL);
	PEM_read_bio_PrivateKey(KeyToPrivBio(m_ClientKeyPair.get()), &TempClientPriv, NULL, NULL);
	PEM_read_bio_PUBKEY(KeyToPubBio(m_ClientKeyPair.get()), &TempClientPub, NULL, NULL);

	//Assign Temporary Keys to SmartKeys for ease of use
	m_ServerPrivateKey = SmartEVP_PKey(TempServPriv, &SmartEVPDel);
	m_ServerPublicKey = SmartEVP_PKey(TempServPub, &SmartEVPDel);
	m_ClientPrivateKey = SmartEVP_PKey(TempClientPriv, &SmartEVPDel);
	m_ClientPublicKey = SmartEVP_PKey(TempClientPub, &SmartEVPDel);
	return true;
}
bool SecureCrypto::ReadRSAKeys()
{
	FILE* ServPrivateKey = fopen("C:\\Users\\Steve\\Desktop\\Priv.pem", "r");
	FILE* ServPublicKey = fopen("C:\\Users\\Steve\\Desktop\\Pub.pem", "r");
	FILE* ClientPrivateKey = fopen("C:\\Users\\Steve\\Desktop\\ClientPriv.pem", "r");
	FILE* ClientPublicKey = fopen("C:\\Users\\Steve\\Desktop\\ClientPub.pem", "r");
	
	m_ServerPrivateKey= SmartEVP_PKey(PEM_read_PrivateKey(ServPrivateKey, NULL, NULL, NULL),&SmartEVPDel);
	m_ServerPublicKey = SmartEVP_PKey(PEM_read_PUBKEY(ServPublicKey, NULL, NULL, NULL), &SmartEVPDel);
	m_ClientPrivateKey = SmartEVP_PKey(PEM_read_PrivateKey(ClientPrivateKey, NULL, NULL, NULL), &SmartEVPDel);
	m_ClientPublicKey = SmartEVP_PKey(PEM_read_PUBKEY(ClientPublicKey, NULL, NULL, NULL), &SmartEVPDel);

	m_ServerPublicKeyBIO = SmartBIO(KeyToPubBio(m_ServerPublicKey.get()),&SmartBIODel);
	m_ServerPrivateKeyBIO = SmartBIO(KeyToPrivBio(m_ServerPrivateKey.get()), &SmartBIODel);
	m_ClientPublicBIO = SmartBIO(KeyToPubBio(m_ClientPublicKey.get()), &SmartBIODel);
	m_ClientPrivateBIO = SmartBIO(KeyToPrivBio(m_ClientPrivateKey.get()), &SmartBIODel);

	return true;
}

std::string SecureCrypto::BioToString(BIO* bio)
{
	size_t BuffSize = BIO_ctrl_pending(bio);
	void* Buffer = malloc(BuffSize);
	if (BIO_read(bio, Buffer, BuffSize) < 0)
		return "Error Reading BIO";
	return std::string((const char*)Buffer, BuffSize);
}

std::string SecureCrypto::GetServerPrivateKeyTxt()
{
	return BioToString(m_ServerPrivateKeyBIO.get());
}
std::string SecureCrypto::GetServerPublicKeyTxt()
{
	return BioToString(m_ServerPublicKeyBIO.get());
}
std::string SecureCrypto::GetClientPrivateKeyTxt()
{
	return BioToString(m_ClientPrivateBIO.get());
}
std::string SecureCrypto::GetClientPublicKeyTxt()
{
	return BioToString(m_ClientPublicBIO.get());
}

SmartEVP_PKey SecureCrypto::GetServerPrivateKey()
{
	return m_ServerPrivateKey;
}
SmartEVP_PKey SecureCrypto::GetServerPublicKey()
{
	return m_ServerPublicKey;
}
SmartEVP_PKey SecureCrypto::GetClientPrivateKey()
{
	return m_ClientPrivateKey;
}
SmartEVP_PKey SecureCrypto::GetClientPublicKey()
{
	return m_ClientPublicKey;
}

bool SecureCrypto::RSASign(const unsigned char* Msg, size_t MsgLen,SmartUChar& MsgHash, size_t& MsgHashLen,SmartEVP_PKey PrivateKey)
{
	if (EVP_DigestSignInit(m_RSASignCtx.get(),NULL, EVP_sha512(), NULL,PrivateKey.get()) <= 0)
	{
		printf("Failed Init\n");
		return false;
	}
	
	if (EVP_DigestSignUpdate(m_RSASignCtx.get(), Msg, MsgLen) <= 0)
	{
		printf("Failed Update\n");
		return false;
	}
	
	if (EVP_DigestSignFinal(m_RSASignCtx.get(), NULL,&MsgHashLen) <=0)
	{
		printf("Failed Final Sign\n");
		return false;
	}

	MsgHash = SmartUChar((unsigned char*)malloc(MsgHashLen), &SmartFreeUChar);
	if (EVP_DigestSignFinal(m_RSASignCtx.get(), MsgHash.get(), &MsgHashLen) <= 0)
	{
		printf("Failed Final Sign 1\n");
		return false;
	}
	EVP_MD_CTX_cleanup(m_RSASignCtx.get());
	return true;
}
bool SecureCrypto::RSASign(std::string Msg, std::string& MsgHash, SmartEVP_PKey PrivateKey)
{
	SmartUChar TempMsgHash;
	size_t MsgHashLen = 0;
	bool RetVal= RSASign((const unsigned char*)Msg.c_str(), Msg.length(), TempMsgHash, MsgHashLen, PrivateKey);
	MsgHash = std::string((char*)TempMsgHash.get(), (char*)TempMsgHash.get() + MsgHashLen);
	return RetVal;
}
bool SecureCrypto::RSAVerifySignature(const unsigned char* MsgHash, size_t MsgHashLen,const unsigned char* Msg, size_t MsgLen,SmartEVP_PKey PublicKey,bool* Authentic)
{
	if (EVP_DigestVerifyInit(m_RSAVerifyCtx.get(),NULL, EVP_sha512(),NULL,PublicKey.get()) <= 0)
	{
		printf("Failed Verify Init\n");
		return false;
	}

	if (EVP_DigestVerifyUpdate(m_RSAVerifyCtx.get(), Msg, MsgLen) <= 0)
	{
		printf("Failed Verify \n");
		return false;
	}

	int AuthStatus = EVP_DigestVerifyFinal(m_RSAVerifyCtx.get(), (unsigned char*)MsgHash, MsgHashLen);
	
	if (AuthStatus)
	{
		//Message Authentic
		*Authentic = true;
		EVP_MD_CTX_cleanup(m_RSAVerifyCtx.get());
		return true;
	} else if(!AuthStatus){
		//Message Not Authentic
		*Authentic = false;
		EVP_MD_CTX_cleanup(m_RSAVerifyCtx.get());
		return true; //Message Not Authentic but function still succeeded
	} else{
		printf("Error Verifying RSA\n");
		*Authentic = false;
		EVP_MD_CTX_cleanup(m_RSAVerifyCtx.get());
		return false;
	}
}
bool SecureCrypto::RSAVerifySignature(std::string MsgHash, std::string OriginalMsg, SmartEVP_PKey PublicKey, bool* Authentic)
{
	return RSAVerifySignature((const unsigned char*)MsgHash.c_str(), MsgHash.length(), (const unsigned char*) OriginalMsg.c_str(), OriginalMsg.length(), PublicKey, Authentic);
}

bool SecureCrypto::SHA256(const std::string Data, std::string& HashResult)
{
	const EVP_MD* HashType = EVP_get_digestbyname("SHA256");
	unsigned char HashResultBuf[EVP_MAX_MD_SIZE];

	if (EVP_DigestInit(m_HashCtx.get(), HashType) <= 0)
	{
		printf("Failed init\n");
		return false;
	}

	if (EVP_DigestUpdate(m_HashCtx.get(), Data.c_str(), Data.length()) <= 0)
	{
		printf("Failed Update\n");
		return false;
	}

	unsigned int len;
	if (EVP_DigestFinal_ex(m_HashCtx.get(), HashResultBuf, &len) <= 0)
	{
		printf("Failed Final\n");
		return false;
	}
	EVP_MD_CTX_cleanup(m_HashCtx.get());
	HashResult = std::string(HashResultBuf, HashResultBuf + len);
	return true;
}
