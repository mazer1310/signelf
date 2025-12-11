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

	UCharArray hashLib(const char *szBinFile, char* errMsg, unsigned int errMsgSize)
	{
		// create a buffer for the hash
		UCharArray arRetval;

		// create a hash context
	#ifdef OPENSSL_MODERN
		EVP_MD_CTX_Wrapper shaWrapper;
		shaWrapper.ctx = EVP_MD_CTX_new(); 
		if (!shaWrapper.ctx)
		{
			if (errMsg)
				snprintf(errMsg, errMsgSize, "Error: EVP_MD_CTX_new failed\n");
			return arRetval;
		}
		EVP_MD_CTX* sha = shaWrapper.ctx;
		const EVP_MD* hashalg = Get_EVP_MD("sha256");
		if (EVP_DigestInit_ex(sha, hashalg, nullptr) != 1)
		{
			if (errMsg)
				snprintf(errMsg, errMsgSize, "Error: EVP_DigestInit failed\n");
			return arRetval;
		}
	#else
		SHA_CTX shactx;
		SHA_CTX* sha = &shactx;
		SHA1_Init(sha);
	#endif

		readelf::CReadElf elf(szBinFile);
		// get the hash for the data section
		if (!hashSection(&elf, ".data", sha, errMsg, errMsgSize))
			return arRetval;
		// get the hash for the text section
		if (!hashSection(&elf, ".text", sha, errMsg, errMsgSize))
			return arRetval;
		// get the hash for the rodata section
		if (!hashSection(&elf, ".rodata", sha, errMsg, errMsgSize))
			return arRetval;
		// get the hash for the init section
		if (!hashSection(&elf, ".init", sha, errMsg, errMsgSize))
			return arRetval;
		// get the hash for the fini section
		if (!hashSection(&elf, ".fini", sha, errMsg, errMsgSize))
			return arRetval;
		// get the hash for the ctors section
		if (!hashSection(&elf, ".ctors", sha, errMsg, errMsgSize))
			return arRetval;
		// get the hash for the dtors section
		if (!hashSection(&elf, ".dtors", sha, errMsg, errMsgSize))
			return arRetval;
		// get the hash for the dynamic section
		if (!hashSection(&elf, ".dynamic", sha, errMsg, errMsgSize))
			return arRetval;
		// get the hash for the dynsym section
		if (!hashSection(&elf, ".dynsym", sha, errMsg, errMsgSize))
			return arRetval;
		// get the hash for the dynstr section
		if (!hashSection(&elf, ".dynstr", sha, errMsg, errMsgSize))
			return arRetval;

		// size the buffer large enough
	#ifdef OPENSSL_MODERN
		unsigned int mdsize = EVP_MD_CTX_size(sha);
	#else
		unsigned int mdsize = SHA_DIGEST_LENGTH;
	#endif
		arRetval.resize(mdsize);

		// resolve the hash
	#ifdef OPENSSL_MODERN
		if (EVP_DigestFinal_ex(sha, arRetval.data(), &mdsize) != 1)
		{
			if (errMsg)
				snprintf(errMsg, errMsgSize, "Error: EVP_DigestFinal_ex failed\n");
		}
	#else
		SHA1_Final(arRetval.data(), sha);
	#endif

		return arRetval;
	}

#ifdef OPENSSL_MODERN
	bool hashSection(readelf::CReadElf *pElf, const char *szSectionName, EVP_MD_CTX *pSHA, char* errMsg, unsigned int errMsgSize)
#else
	bool hashSection(readelf::CReadElf *pElf, const char *szSectionName, SHA_CTX *pSHA, char* errMsg, unsigned int errMsgSize)
#endif
	{
		// pick up the given section and generate a hash of the thing
		readelf::UCharArray section = pElf->getSection(szSectionName);
		if (!section.empty())
		{
			// hash them
#ifdef OPENSSL_MODERN
			if (EVP_DigestUpdate(pSHA, section.data(), section.size()) != 1)
			{
				if (errMsg)
					snprintf(errMsg, errMsgSize, "Error: EVP_DigestUpdate failed for section %hs\n", szSectionName);
				return false;
			}
#else
			SHA1_Update(pSHA, section.data(), section.size());
#endif
		}
		return true;
	}

	UCharArray signHash(const unsigned char *szHashBuf, unsigned int nHashSize, unsigned char *szKeyBuf, unsigned int nKeySize, char* errMsg, unsigned int errMsgSize)
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
		else
		{
			if (errMsg)
				snprintf(errMsg, errMsgSize, "Error: BIO_new_mem_buf failed to allocate bio\n");
			return arRetval;
		}

		if (pKey)
		{
			EVP_PKEY_CTX_Wrapper ctxWrapper;
			ctxWrapper.ctx = EVP_PKEY_CTX_new(pKey, nullptr);
			if (!ctxWrapper.ctx)
			{
				if (errMsg)
					snprintf(errMsg, errMsgSize, "Error: EVP_PKEY_CTX_new failed to create context\n");
				return arRetval;
			}
			
			if (EVP_PKEY_sign_init(ctxWrapper.ctx) != 1)
			{
				if (errMsg)
					snprintf("Error: EVP_PKEY_CTX_new failed\n");
				return arRetval;
			}

			if (EVP_PKEY_CTX_set_rsa_padding(ctxWrapper.ctx, RSA_PKCS1_PADDING) != 1)
			{
				if (errMsg)
					snprintf(errMsg, errMsgSize, "Error: EVP_PKEY_CTX_set_rsa_padding failed\n");
				return arRetval;
			}
			
			const EVP_MD* hashalg = Get_EVP_MD("sha256");
			if (EVP_PKEY_CTX_set_signature_md(ctxWrapper.ctx, hashalg) != 1)
			{
				if (errMsg)
					snprintf(errMsg, errMsgSize, "Error: EVP_PKEY_CTX_set_signature_md failed\n");
				return arRetval;
			}

			//calculate signature length
			size_t siglen = 0;
			if (EVP_PKEY_sign(ctxWrapper.ctx, NULL, &siglen, szHashBuf, nHashSize) != 1)
			{
				if (errMsg)
					snprintf(errMsg, errMsgSize, "Error: EVP_PKEY_sign failed while calculating signature length\n");
				return arRetval;
			}

			arRetval.resize(siglen);
			if (EVP_PKEY_sign(ctxWrapper.ctx, arRetval.data(), &siglen, szHashBuf, nHashSize) != 1)
			{
				if (errMsg)
					snprintf(errMsg, errMsgSize, "Error: EVP_PKEY_sign failed while signing hash\n");
				return arRetval;
			}
		}
		else if (errMsg)
			snprintf(errMsg, errMsgSize, "Error: d2i_PrivateKey_bio failed to read private key\n");
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

	bool verifyLib(unsigned char *szKeyBuf, unsigned int nKeySize, const char *szBinFile, char* errMsg, unsigned int errMsgSize)
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
		else
		{
			if (errMsg)
				snprintf(errMsg, errMsgSize, "Error: BIO_new_mem_buf failed to allocate bio\n");
			return false;
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
				if (!ctxWrapper.ctx)
				{
					if (errMsg)
						snprintf(errMsg, errMsgSize, "Error: EVP_PKEY_CTX_new failed\n");
					return false;
				}
				if (EVP_PKEY_verify_init(ctxWrapper.ctx) != 1)
				{
					if (errMsg)
						snprintf(errMsg, errMsgSize, "Error: EVP_PKEY_verify_init failed\n");
					return false;
				}
				if (EVP_PKEY_CTX_set_rsa_padding(ctxWrapper.ctx, RSA_PKCS1_PADDING) != 1)
				{
					if (errMsg)
						snprintf(errMsg, errMsgSize, "Error: EVP_PKEY_CTX_set_rsa_padding failed\n");
					return false;
				}
				const EVP_MD* hashalg = Get_EVP_MD("sha256");
				if (EVP_PKEY_CTX_set_signature_md(ctxWrapper.ctx, hashalg) != 1)
				{
					if (errMsg)
						snprintf(errMsg, errMsgSize, "Error: EVP_PKEY_CTX_set_signature_md failed\n");
					return false;
				}
				bResult = (1 == EVP_PKEY_verify(ctxWrapper.ctx, szSig.data(), szSig.size(), szHash.data(), szHash.size()))
			}
		}
		else if (errMsg)
			snprintf(errMsg, errMsgSize, "Error: d2i_PUBKEY_bio failed to read public key\n");
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
