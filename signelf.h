/**********************************************************************************
 * Header file for the libsign namespace.
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

#ifndef __LibSign_h__
#define __LibSign_h__

#include <vector>

#include <openssl/opensslv.h>
#if OPENSSL_VERSION_MAJOR >= 3
#	define OPENSSL_MODERN
#	include <openssl/evp.h>
#	include <openssl/rsa.h>
#else
#	include <openssl/err.h>
#	include <openssl/sha.h>
#endif
#include <openssl/x509.h>


#include "readelf.h"

namespace signelf
{
	typedef std::vector<unsigned char> UCharArray;

#ifdef OPENSSL_MODERN
	// hash a given section in the pBfd and add it to pSha
	void hashSection(readelf::CReadElf *pElf, const char *szSectionName, EVP_MD_CTX *pSha);
#else
	// hash a given section in the pBfd and add it to pSha
	void hashSection(readelf::CReadElf *pElf, const char *szSectionName, SHA_CTX *pSha);
#endif
	
	enum HashAlg 
	{
		HashAlg_sha1
		, HashAlg_sha224
		, HashAlg_sha256  //default
		, HashAlg_sha384
		, HashAlg_sha512
	};
	//supported: all lowercase or all uppercase matching the entries above:
	//e.g. "sha256" or "SHA256", "sha1" or "SHA1", etc.
	//for older versions of openssl (before 3.0), only sha1 is supported, and the various pHashAlg parameters are ignored
	//openssl 3.0 and above default to "sha256"
	HashAlg getHashAlg(const char* szHashAlgName);

	// generate a hash of the .text and .data sections of the binary with the specified hash algorithm
	UCharArray hashLib(const char *szBinFile, HashAlg pHashAlg = HashAlg_256);

	// sign a given hash with the key stored in szKeyBuf and the specified hash algorithm
	UCharArray signHash(const unsigned char *szHashBuf, unsigned int nHashSize, unsigned char *szKeyBuf, unsigned int nKeySize, HashAlg pHashAlg = HashAlg_256);

	// verify a libs signature (assumed to be stored in .lsesig section of szBinFile) with the key given in szKeyBuf and the specified hash algorithm
	bool verifyLib(unsigned char *szKeyBuf, unsigned int nKeySize, const char *szBinFile, HashAlg pHashAlg = HashAlg_256);

	// helper function, useful for debugging
	void hexPrint(const char *szName, const char *szBuf, const unsigned int nLength);
}

#endif
