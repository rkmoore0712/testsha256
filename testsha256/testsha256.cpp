// testsha256.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <afxwin.h>

#include "cryptpp/cryptlib.h"
#include "cryptpp/sha.h"
#include "cryptpp/hex.h"
#include "cryptpp/files.h"
#include <iostream>
#include <fstream>


#include<ncrypt.h>

using std::ostream;
using std::cout;
using std::endl;

#include <string>
using std::string;

#include <array>
using std::array;

#include <cryptpp/files.h>
#include <cryptpp/modes.h>
#include <cryptpp/osrng.h>
#include <cryptpp/aes.h>

#include <cryptpp/files.h>
using CryptoPP::FileSink;
using CryptoPP::FileSource;

#include <cryptpp/hex.h>
using CryptoPP::HexEncoder;

#include <cryptpp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;

#include <cryptpp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptpp/integer.h>
using CryptoPP::Integer;

#include <cryptpp/pubkey.h>
using CryptoPP::PublicKey;
using CryptoPP::PrivateKey;

#include <cryptpp/eccrypto.h>
using CryptoPP::ECP;    // Prime field
using CryptoPP::EC2N;   // Binary field
using CryptoPP::ECIES;
using CryptoPP::ECPPoint;
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::DL_GroupPrecomputation;
using CryptoPP::DL_FixedBasePrecomputation;

#include <cryptpp/pubkey.h>
using CryptoPP::DL_PrivateKey_EC;
using CryptoPP::DL_PublicKey_EC;

#include <cryptpp/asn.h>
#include <cryptpp/oids.h>
namespace ASN1 = CryptoPP::ASN1;

#include <cryptpp/cryptlib.h>
using CryptoPP::PK_Encryptor;
using CryptoPP::PK_Decryptor;
using CryptoPP::g_nullNameValuePairs;



void aes_cbc_run();

void PrintPrivateKey(const DL_PrivateKey_EC<ECP>& key, ostream& out = cout);
void PrintPublicKey(const DL_PublicKey_EC<ECP>& key, ostream& out = cout);

void SavePrivateKey(const PrivateKey& key, const string& file = "ecies.private.key");
void SavePublicKey(const PublicKey& key, const string& file = "ecies.public.key");

void LoadPrivateKey(PrivateKey& key, const string& file = "ecies.private.key");
void LoadPublicKey(PublicKey& key, const string& file = "ecies.public.key");

static const string message("Now is the time for all good men to come to the aide of their country.");



using aes_key_t = std::array<CryptoPP::byte, CryptoPP::AES::DEFAULT_KEYLENGTH>;
using aes_iv_t = std::array<CryptoPP::byte, CryptoPP::AES::BLOCKSIZE>;

void encrypt(const aes_key_t &key, const aes_iv_t &iv,
	const std::string &filename_in, const std::string &filename_out) {
	CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption cipher{};
	cipher.SetKeyWithIV(key.data(), key.size(), iv.data());

	std::ifstream in{ filename_in, std::ios::binary };
	std::ofstream out{ filename_out, std::ios::binary };

	CryptoPP::FileSource{ in, /*pumpAll=*/true,
						 new CryptoPP::StreamTransformationFilter{
							 cipher, new CryptoPP::FileSink{out}} };
}

void decrypt(const aes_key_t &key, const aes_iv_t &iv,
	const std::string &filename_in, const std::string &filename_out) {
	CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption cipher{};
	cipher.SetKeyWithIV(key.data(), key.size(), iv.data());

	std::ifstream in{ filename_in, std::ios::binary };
	std::ofstream out{ filename_out, std::ios::binary };

	CryptoPP::FileSource{ in, /*pumpAll=*/true,
						 new CryptoPP::StreamTransformationFilter{
							 cipher, new CryptoPP::FileSink{out}} };
}


void cryptoppAES()
{

		std::cout << CryptoPP::AES::BLOCKSIZE << std::endl;

		CryptoPP::AutoSeededRandomPool rng{};

		// Generate a random key
		aes_key_t key{};
		rng.GenerateBlock(key.data(), key.size());

		// Generate a random IV
		aes_iv_t iv{};
		rng.GenerateBlock(iv.data(), iv.size());

		// encrypt
		encrypt(key, iv, "ecies.private.key", "abc_encrypted");

		// decrypt
		decrypt(key, iv, "abc_encrypted", "ecies.private_decrypted.key");

		
}


void PtrVoid()
{
}

void UseNCrypt()
{
	SECURITY_STATUS sSS;
	// get handle to stroage provider - windows key store
	NCRYPT_PROV_HANDLE hNCP;
	HRESULT hResult = NCryptOpenStorageProvider(&hNCP, MS_KEY_STORAGE_PROVIDER, 0);
	if (hResult == S_OK)
	{
		// maybe use NCryptSetProperty
		// 
		// create a key
		NCRYPT_KEY_HANDLE hNKH;
		hResult = NCryptCreatePersistedKey(hNCP, &hNKH, BCRYPT_ECDH_P384_ALGORITHM, L"DC_USER_KEY", 0, 0);
		if (hResult == ERROR_SUCCESS)
		{
			sSS = NCryptFinalizeKey(hNKH, 0);
			if (sSS == ERROR_SUCCESS)
			{
				OutputDebugString(L"Finalized");


				PBYTE pbOutput = nullptr;
				pbOutput = new BYTE[256];
				DWORD dwOutput = 256;
				DWORD dwResult;
				
				// export?
//				NCRYPT_KEY_HANDLE hNKHExport;
				
				sSS = NCryptExportKey(hNKH, hNKH, BCRYPT_ECCPUBLIC_BLOB, 0, pbOutput, dwOutput, &dwResult, 0);
				if (sSS == ERROR_SUCCESS)
				{
					
				}

//				NCryptKeyName **ncKeyName;
	//			NCryptKeyName **pncKeyName = ncKeyName;
	//			PVOID pVoid();
//				sSS = NCryptEnumKeys(hNCP, 0, &ncKeyName, PtrVoid(), 0);
				
				
				sSS = NCryptOpenKey(hNCP, &hNKH, L"DC_USER_KEY", 0, 0);
				if (sSS == ERROR_SUCCESS)
				{
					OutputDebugString(L"OpenKey");
					sSS = NCryptDeleteKey(hNKH, 0);
					if (sSS == ERROR_SUCCESS)
					{
						OutputDebugString(L"Deleted");
					}
					else
						OutputDebugString(L"NOT Deleted");
				}
				else
				{
					OutputDebugString(L"NOT OpenKey");

				}
				if (nullptr != pbOutput)
					delete(pbOutput);



			}
			else
				OutputDebugString(L"NOT Finalized");

		}
		else
		{
			sSS = NCryptOpenKey(hNCP, &hNKH, L"DC_USER_KEY", 0, 0);
			if (sSS == ERROR_SUCCESS)
			{
				OutputDebugString(L"OpenKey");
				sSS = NCryptDeleteKey(hNKH, 0);
				if (sSS == ERROR_SUCCESS)
				{
					OutputDebugString(L"Deleted");
				}
				else
					OutputDebugString(L"NOT Deleted");
			}
			else
			{
				OutputDebugString(L"NOT OpenKey");

			}

		}
	}
	//else
		//ERROR

}


void SavePrivateKey(const PrivateKey& key, const string& file)
{
	FileSink sink(file.c_str());
	key.Save(sink);
}

void SavePublicKey(const PublicKey& key, const string& file)
{
	FileSink sink(file.c_str());
	key.Save(sink);
}

void LoadPrivateKey(PrivateKey& key, const string& file)
{
	FileSource source(file.c_str(), true);
	key.Load(source);
}

void LoadPublicKey(PublicKey& key, const string& file)
{
	FileSource source(file.c_str(), true);
	key.Load(source);
}

void PrintPrivateKey(const DL_PrivateKey_EC<ECP>& key, ostream& out)
{
	// Group parameters
	const DL_GroupParameters_EC<ECP>& params = key.GetGroupParameters();
	// Base precomputation (for public key calculation from private key)
	const DL_FixedBasePrecomputation<ECPPoint>& bpc = params.GetBasePrecomputation();
	// Public Key (just do the exponentiation)
	const ECPPoint point = bpc.Exponentiate(params.GetGroupPrecomputation(), key.GetPrivateExponent());

	out << "Modulus: " << std::hex << params.GetCurve().GetField().GetModulus() << endl;
	out << "Cofactor: " << std::hex << params.GetCofactor() << endl;

	out << "Coefficients" << endl;
	out << "  A: " << std::hex << params.GetCurve().GetA() << endl;
	out << "  B: " << std::hex << params.GetCurve().GetB() << endl;

	out << "Base Point" << endl;
	out << "  x: " << std::hex << params.GetSubgroupGenerator().x << endl;
	out << "  y: " << std::hex << params.GetSubgroupGenerator().y << endl;

	out << "Public Point" << endl;
	out << "  x: " << std::hex << point.x << endl;
	out << "  y: " << std::hex << point.y << endl;

	out << "Private Exponent (multiplicand): " << endl;
	out << "  " << std::hex << key.GetPrivateExponent() << endl;
}

void PrintPublicKey(const DL_PublicKey_EC<ECP>& key, ostream& out)
{
	// Group parameters
	const DL_GroupParameters_EC<ECP>& params = key.GetGroupParameters();
	// Public key
	const ECPPoint& point = key.GetPublicElement();

	out << "Modulus: " << std::hex << params.GetCurve().GetField().GetModulus() << endl;
	out << "Cofactor: " << std::hex << params.GetCofactor() << endl;

	out << "Coefficients" << endl;
	out << "  A: " << std::hex << params.GetCurve().GetA() << endl;
	out << "  B: " << std::hex << params.GetCurve().GetB() << endl;

	out << "Base Point" << endl;
	out << "  x: " << std::hex << params.GetSubgroupGenerator().x << endl;
	out << "  y: " << std::hex << params.GetSubgroupGenerator().y << endl;

	out << "Public Point" << endl;
	out << "  x: " << std::hex << point.x << endl;
	out << "  y: " << std::hex << point.y << endl;
}


int main(int argc, char* argv[])
{
    using namespace CryptoPP;

	//UseNCrypt();
	//
//	cryptoppAES();

	aes_cbc_run();
	
	return 0;
	
	
    SHA256 hash;
    std::cout << "Name: " << hash.AlgorithmName() << std::endl;
    std::cout << "Digest size: " << hash.DigestSize() << std::endl;
    std::cout << "Block size: " << hash.BlockSize() << std::endl;
    
    HexEncoder encoder(new FileSink(std::cout));

//    std::string msg = "Yoda said, Do or do not. There is no try.";
    std::string msg = "DC01tester";
    std::string digest;


    hash.Update((const byte*)msg.data(), msg.size());
    digest.resize(hash.DigestSize());
    hash.Final((byte*)&digest[0]);


    std::cout << "Message: " << msg << std::endl;

    std::cout << "Digest: " << std::endl;
    StringSource(digest, true, new Redirector(encoder));
    std::cout << std::endl;
	std::cout << std::endl;


    std::string msg2 = "Yoda said, Do or do not. There is no try.";
	std::cout << "Message2: Update hash: " << msg2 << std::endl;
	hash.Update((const byte*)msg2.data(), msg2.size());
	digest.resize(hash.DigestSize());
	hash.Final((byte*)&digest[0]);
	std::cout << "Digest after update " << std::endl;
    StringSource(digest, true, new Redirector(encoder));
    std::cout << std::endl;

    bool verified = hash.Verify((const byte*)digest.data());

    if (verified == true)
    {
        std::cout << "Verified hash over message: " << msg << std::endl;
        std::cout << "Verified hash over message2: " << msg2 << std::endl;
    }
    else
    {
        std::cout << "Failed to verify hash over message: " << msg << std::endl;
        std::cout << "Failed to verify hash over message2: " << msg2 << std::endl;
    }



		AutoSeededRandomPool prng;

		/////////////////////////////////////////////////
		// Part one - generate keys

		ECIES<ECP>::Decryptor d0(prng, ASN1::secp256r1());
		PrintPrivateKey(d0.GetKey());

		ECIES<ECP>::Encryptor e0(d0);
		PrintPublicKey(e0.GetKey());

		/////////////////////////////////////////////////
		// Part two - save keys
		//   Get* returns a const reference

		SavePrivateKey(d0.GetPrivateKey());
		SavePublicKey(e0.GetPublicKey());

		/////////////////////////////////////////////////
		// Part three - load keys
		//   Access* returns a non-const reference

		ECIES<ECP>::Decryptor d1;
		LoadPrivateKey(d1.AccessPrivateKey());
		d1.GetPrivateKey().ThrowIfInvalid(prng, 3);

		ECIES<ECP>::Encryptor e1;
		LoadPublicKey(e1.AccessPublicKey());
		e1.GetPublicKey().ThrowIfInvalid(prng, 3);

		/////////////////////////////////////////////////
		// Part four - encrypt/decrypt with e0/d1

		string em0; // encrypted message
		StringSource ss1(message, true, new PK_EncryptorFilter(prng, e0, new StringSink(em0)));
		string dm0; // decrypted message
		StringSource ss2(em0, true, new PK_DecryptorFilter(prng, d1, new StringSink(dm0)));

		cout << dm0 << endl;

		/////////////////////////////////////////////////
		// Part five - encrypt/decrypt with e1/d0

		string em1; // encrypted message
		StringSource ss3(message, true, new PK_EncryptorFilter(prng, e1, new StringSink(em1)));
		string dm1; // decrypted message
		StringSource ss4(em1, true, new PK_DecryptorFilter(prng, d0, new StringSink(dm1)));

		cout << dm1 << endl;


    return 0;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
