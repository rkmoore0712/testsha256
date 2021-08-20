
#include <afxwin.h>

#include <iostream>
#include <ostream>
#include <fstream>

using std::ostream;
using std::ofstream;
using std::ifstream;
using std::ios;
using std::cout;
using std::endl;
using std::cerr;


#include <string>
using std::string;

#include "cryptpp/cryptlib.h"
#include "cryptpp/sha.h"
#include "cryptpp/hex.h"
#include "cryptpp/files.h"
#include "cryptpp/modes.h"
using CryptoPP::CBC_Mode;

#include "cryptpp/aes.h"
using CryptoPP::AES;

#include <cryptpp/hex.h>
using CryptoPP::HexEncoder;


#include <cryptpp/base32.h>
using CryptoPP::Base32HexEncoder;

#include <cryptpp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptpp/filters.h>
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::PK_EncryptorFilter;
using CryptoPP::PK_DecryptorFilter;
using CryptoPP::StreamTransformationFilter;

#include <cryptpp/secblock.h>
using CryptoPP::SecByteBlock;

void aes_cbc_run()
{

	AutoSeededRandomPool prng;

	SecByteBlock key(AES::DEFAULT_KEYLENGTH);
	prng.GenerateBlock(key, key.size());

	byte iv[AES::BLOCKSIZE];
	byte ivRead[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	string plain = "CBC Mode Test";
	string cipher, encoded, recovered, ivstr;

	/*********************************\
	\*********************************/

	try
	{
		cout << "plain text: " << plain << endl;
		cout << "iv: " << iv << endl;

		CBC_Mode< AES >::Encryption e;
		e.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter adds padding
		//  as required. ECB and CBC Mode must be padded
		//  to the block size of the cipher.
		StringSource ss(plain, true,
			new StreamTransformationFilter(e,
				new StringSink(cipher)
			) // StreamTransformationFilter      
		); // StringSource
	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}

	/*********************************\
	\*********************************/

	// Pretty print cipher text
	StringSource ss(cipher, true,
		new HexEncoder(
			new StringSink(encoded)
		) // HexEncoder
	); // StringSource
	cout << "cipher text: " << encoded << endl;

	// Pretty print iv text


	
	StringSource ssIV(iv, sizeof(iv), true,
		new HexEncoder(
			new StringSink(ivstr)
		) // Base32HexEncoder
	); // StringSource

	
	cout <<"iv text: " << ivstr << endl;

	

	byte bData[] = { 0xfd, 0x43, 0xff, 0x31, 0x41, 0x21, 0x14, 0x00 };
	string sData;
	cout << "sData text: " <<  endl;

	
	StringSource ssD(bData, sizeof(bData), true,
		new HexEncoder(
			new StringSink(sData)
		) // Base32HexEncoder
	); // StringSource

	cout << sData << endl;
	/*********************************\
	\*********************************/

	try
	{
		CBC_Mode< AES >::Decryption d;
		d.SetKeyWithIV(key, key.size(), iv);

		// The StreamTransformationFilter removes
		//  padding as required.
		StringSource ss(cipher, true,
			new StreamTransformationFilter(d,
				new StringSink(recovered)
			) // StreamTransformationFilter
		); // StringSource

		cout << "recovered text: " << recovered << endl;


		// next test, save to file, reload and confirm key value

		ofstream wf("iv.txt", ios::out | ios::binary);
		wf.write((char*)iv, sizeof(iv));
		wf.close();

		memset(ivRead, 0, sizeof(ivRead));
		
		ifstream rf("iv.txt", ios::in | ios::binary);
		rf.read((char*)&ivRead, sizeof(ivRead));
		rf.close();


		cout << "iv text read raw: " << ivRead << endl;

		ivstr.clear();
		StringSource ssIVR(ivRead, sizeof(ivRead), true,
			new HexEncoder(
				new StringSink(ivstr)
			) // Base32HexEncoder
		); // StringSource


		cout << "iv text read: " << ivstr << endl;

	}
	catch (const CryptoPP::Exception& e)
	{
		cerr << e.what() << endl;
		exit(1);
	}
}