/**
 * vim: set ts=4 :
 * =============================================================================
 * SourceMod Sample Extension
 * Copyright (C) 2004-2008 AlliedModders LLC.  All rights reserved.
 * =============================================================================
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License, version 3.0, as published by the
 * Free Software Foundation.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * As a special exception, AlliedModders LLC gives you permission to link the
 * code of this program (as well as its derivative works) to "Half-Life 2," the
 * "Source Engine," the "SourcePawn JIT," and any Game MODs that run on software
 * by the Valve Corporation.  You must obey the GNU General Public License in
 * all respects for all other code used.  Additionally, AlliedModders LLC grants
 * this exception to all derivative works.  AlliedModders LLC defines further
 * exceptions, found in LICENSE.txt (as of this writing, version JULY-31-2007),
 * or <http://www.sourcemod.net/license.php>.
 *
 * Version: $Id$
 */

#include "extension.h"

/**
 * @file extension.cpp
 * @brief Implement extension code here.
 */

SourceSig g_SourceSig;		/**< Global singleton for extension's main interface */

SMEXT_LINK(&g_SourceSig);

void SourceSig::SDK_OnAllLoaded()
{
	g_pShareSys->AddNatives(myself, sourcesig_natives);
}

// Calculates SHA256 of given file
int calc_sha256(char* path, char output[65])
{
	FILE* file = fopen(path, "rb");
	if(!file) return -1;

	unsigned char hash[SHA256_DIGEST_LENGTH];
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	const int bufSize = 32768;
	char* buffer = (char*)malloc(bufSize);
	int bytesRead = 0;
	if(!buffer) return -1;
	while((bytesRead = fread(buffer, 1, bufSize, file)))
	{
		SHA256_Update(&sha256, buffer, bytesRead);
	}
	SHA256_Final(hash, &sha256);

	sha256_hash_string(hash, output);
	fclose(file);
	free(buffer);
	return 0;
}

// Internal helper to convert result to readable string
void sha256_hash_string(unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65])
{
	int i = 0;

	for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
	{
		sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
	}

	outputBuffer[64] = 0;
}

cell_t RSAUtilVerify(IPluginContext *pContext, const cell_t *params)
{
	char *data;
	size_t len;
	char *pubKey, *inFile, *inSig;

	// Output buffer
	pContext->LocalToString(params[1], &data);
	// Buffer max size
	len = params[2];
	// Public key file path
	pContext->LocalToString(params[3], &pubKey);
	// Input data file path
	pContext->LocalToString(params[4], &inFile);
	// Input signature file path (encrypted)
	pContext->LocalToString(params[5], &inSig);

	// SHA256 hash result of inFile
	unsigned char hash[65];

	return 0;
}

cell_t DgstSHA256(IPluginContext *pContext, const cell_t *params)
{
	return 0;
}

const sp_nativeinfo_t sourcesig_natives[] = 
{
	{"SourceSig_Verify",			RSAUtilVerify},
	{"SourceSig_GetSHA256",			DgstSHA256},
	{NULL,							NULL},
};
