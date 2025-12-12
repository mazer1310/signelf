/**********************************************************************************
 * Implementation of the libsign functions declared in libsign.h
 *
 * Copyright (C) 2004 Joe Fox All rights reserved.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *********************************************************************************/

/*
 * Libsign is used to verify signatures in binary files. It expects a section in
 * the binary to be called ".lsesig". That section should contain an RSA signature
 * of the SHA1 hash of the .text and .data sections of the binary.
 */

#include <iostream>
#include <iomanip>
#include <iterator>

#include "readelf.h"
#include "signelf.h"

#ifdef OPENSSL_MODERN
struct EVP_MD_CTX_Wrapper
{
public:
	EVP_MD_CTX_Wrapper() : ctx(nullptr) {}
	~EVP_MD_CTX_Wrapper() { if (ctx) EVP_MD_CTX_free(ctx); }
	EVP_MD_CTX* ctx;
};

struct EVP_PKEY_CTX_Wrapper
{
public:
	EVP_PKEY_CTX_Wrapper() : ctx(nullptr) {}
	~EVP_PKEY_CTX_Wrapper() { if (ctx) EVP_PKEY_CTX_free(ctx); }
	EVP_PKEY_CTX* ctx;
};
#endif

namespace signelf
{
#ifdef OPENSSL_MODERN
	const EVP_MD* Get_EVP_MD(const char* pAlgorithmName)
	{
		if (strcmp(pAlgorithmName, "sha256") == 0 || strcmp(pAlgorithmName, "SHA256") == 0
			 || strcmp(pAlgorithmName, "sha2") == 0 || strcmp(pAlgorithmName, "SHA2") == 0) 
		{ //if sha2 is specified, just use sha256
			return EVP_sha256();
		}
		else if (strcmp(pAlgorithmName, "sha512") == 0 || strcmp(pAlgorithmName, "SHA512") == 0) 
		{
			return EVP_sha512();
		}
		else if (strcmp(pAlgorithmName, "sha1") == 0 || strcmp(pAlgorithmName, "SHA1") == 0) 
		{
			return EVP_sha1();
		}
		else if (strcmp(pAlgorithmName, "sha224") == 0 || strcmp(pAlgorithmName, "SHA224") == 0) 
		{
			return EVP_sha224();
		}
		else if (strcmp(pAlgorithmName, "sha384") == 0 || strcmp(pAlgorithmName, "SHA384") == 0) 
		{
			return EVP_sha512();
		}
		
		return nullptr;
	}
#endif

	UCharArray hashLib(const char *szBinFile)
	{
		// create a buffer for the hash
		UCharArray arRetval;

		// create a hash context
	#ifdef OPENSSL_MODERN
		EVP_MD_CTX_Wrapper shaWrapper;
		shaWrapper.ctx = EVP_MD_CTX_new(); 
		EVP_MD_CTX* sha = shaWrapper.ctx;
		const EVP_MD* hashalg = Get_EVP_MD("sha256");
		EVP_DigestInit_ex(sha, hashalg, nullptr);
	#else
		SHA_CTX shactx;
		SHA_CTX* sha = &shactx;
		SHA1_Init(sha);
	#endif

		readelf::CReadElf elf(szBinFile);
		// get the hash for the data section
		hashSection(&elf, ".data", sha);
		// get the hash for the text section
		hashSection(&elf, ".text", sha);
		// get the hash for the rodata section
		hashSection(&elf, ".rodata", sha);
		// get the hash for the init section
		hashSection(&elf, ".init", sha);
		// get the hash for the fini section
		hashSection(&elf, ".fini", sha);
		// get the hash for the ctors section
		hashSection(&elf, ".ctors", sha);
		// get the hash for the dtors section
		hashSection(&elf, ".dtors", sha);
		// get the hash for the dynamic section
		hashSection(&elf, ".dynamic", sha);
		// get the hash for the dynsym section
		hashSection(&elf, ".dynsym", sha);
		// get the hash for the dynstr section
		hashSection(&elf, ".dynstr", sha);

		// size the buffer large enough
	#ifdef OPENSSL_MODERN
		unsigned int mdsize = EVP_MD_CTX_size(sha);
	#else
		unsigned int mdsize = SHA_DIGEST_LENGTH;
	#endif
		arRetval.resize(mdsize);

		// resolve the hash
	#ifdef OPENSSL_MODERN
		EVP_DigestFinal_ex(sha, arRetval.data(), &mdsize);
	#else
		SHA1_Final(arRetval.data(), sha);
	#endif

		return arRetval;
	}

#ifdef OPENSSL_MODERN
	void hashSection(readelf::CReadElf *pElf, const char *szSectionName, EVP_MD_CTX *pSHA)
#else
	void hashSection(readelf::CReadElf *pElf, const char *szSectionName, SHA_CTX *pSHA)
#endif
	{
		// pick up the given section and generate a hash of the thing
		readelf::UCharArray section = pElf->getSection(szSectionName);
		if (!section.empty())
		{
			// hash them
#ifdef OPENSSL_MODERN
			EVP_DigestUpdate(pSHA, section.data(), section.size());
#else
			SHA1_Update(pSHA, section.data(), section.size());
#endif
		}
	}

	UCharArray signHash(const unsigned char *szHashBuf, unsigned int nHashSize, unsigned char *szKeyBuf, unsigned int nKeySize)
	{
		UCharArray arRetval;
#ifdef OPENSSL_MODERN
		// read the private key from our buffer
		EVP_PKEY *pKey = nullptr;
		BIO *pBio = BIO_new_mem_buf(szKeyBuf, nKeySize);
		// if we could wrap it
		if (pBio)
		{
			// Read the key from the bio
			d2i_PrivateKey_bio(pBio, &pKey);
		}

		if (pKey)
		{
			EVP_PKEY_CTX_Wrapper ctxWrapper;
			ctxWrapper.ctx = EVP_PKEY_CTX_new(pKey, nullptr);
			EVP_PKEY_sign_init(ctxWrapper.ctx);
			EVP_PKEY_CTX_set_rsa_padding(ctxWrapper.ctx, RSA_PKCS1_PADDING);
			const EVP_MD* hashalg = Get_EVP_MD("sha256");
			EVP_PKEY_CTX_set_signature_md(ctxWrapper.ctx, hashalg);

			//calculate signature length
			size_t siglen = 0;
			EVP_PKEY_sign(ctxWrapper.ctx, NULL, &siglen, szHashBuf, nHashSize);

			arRetval.resize(siglen);
			EVP_PKEY_sign(ctxWrapper.ctx, arRetval.data(), &siglen, szHashBuf, nHashSize);
		}
#else
		RSA *pKey = NULL;

		// wrap the keybuf in a bio
		BIO *pBio = NULL;
		pBio = BIO_new_mem_buf(szKeyBuf, nKeySize);

		// if we could wrap it
		if(pBio)
		{
			// Read the key from it
			d2i_RSAPrivateKey_bio(pBio, &pKey);
		}

		// if we could read the key
		if(pKey)
		{
			unsigned int nSigLen;
			arRetval.resize(RSA_size(pKey));

			// sign the hash and save it to arRetval
			RSA_sign(NID_sha1, szHashBuf, nHashSize, &arRetval[0], &nSigLen, pKey);
		}
#endif
		return arRetval;
	}

	bool verifyLib(unsigned char *szKeyBuf, unsigned int nKeySize, const char *szBinFile)
	{
		bool bResult = false;
#ifdef OPENSSL_MODERN
		// read the private key from our buffer
		EVP_PKEY *pKey = nullptr;
		BIO *pBio = BIO_new_mem_buf(szKeyBuf, nKeySize);
		// if we could wrap it
		if (pBio)
		{
			// Read the key from the bio
			pKey = d2i_PUBKEY_bio(pBio, &pKey);
		}

		if (pKey)
		{
			// get the signature from the binfile
			readelf::CReadElf elf(szBinFile);
			readelf::UCharArray szSig = elf.getSection(".lsesig");

			// if we could get the section
			if (!szSig.empty())
			{
				// calculate the hash of the binary
				UCharArray szHash = hashLib(szBinFile);

				// verify the signature
				EVP_PKEY_CTX_wrapper ctxWrapper;
				ctxWrapper.ctx = EVP_PKEY_CTX_new(pKey, nullptr);
				EVP_PKEY_verify_init(ctxWrapper.ctx);
				EVP_PKEY_CTX_set_rsa_padding(ctxWrapper.ctx, RSA_PKCS1_PADDING);
				const EVP_MD* hashalg = Get_EVP_MD("sha256");
				EVP_PKEY_CTX_set_signature_md(ctxWrapper.ctx, hashalg); 
				bResult = (1 == EVP_PKEY_verify(ctxWrapper.ctx, szSig.data(), szSig.size(), szHash.data(), szHash.size()));
			}
		}
#else
		RSA *pKey = NULL;
		BIO *pBio;
		// load up the key
		pBio = BIO_new_mem_buf(szKeyBuf, nKeySize);
		if(pBio)
		{
			//		Load the key
			d2i_RSA_PUBKEY_bio(pBio, &pKey);
			BIO_free(pBio);
		}

		// if we could load the key
		if(pKey)
		{
			// get the signature from the binfile:w
			readelf::CReadElf elf(szBinFile);
			readelf::UCharArray szSig = elf.getSection(".lsesig");

			// if we could get the section
			if(!szSig.empty())
			{
				// pick up the hash of the binary
				UCharArray szHash = hashLib(szBinFile);

				// verify the signature
				bResult = (0 != RSA_verify(NID_sha1, &szHash[0], szHash.size(), &szSig[0], szSig.size(), pKey));
				RSA_free(pKey);
			}
		}
#endif
		return bResult;
	}

	void hexPrint(const char *szName, const char *szBuf, const unsigned int nLength)
	{
		std::cout << "hash " << szName << " (" << nLength << ") ---\n" << std::endl;
		for(unsigned int i=0 ; i < nLength ; ++i)
		{
			std::cout << std::hex << std::setw(2) << std::setfill('0') << szBuf[i];
		}
		std::cout << "\n---" << std::endl;
	}

}
