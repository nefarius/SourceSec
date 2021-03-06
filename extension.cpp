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

SourceSec g_sourcesec;		/**< Global singleton for extension's main interface */

SMEXT_LINK(&g_sourcesec);

void SourceSec::SDK_OnAllLoaded()
{
	g_pShareSys->AddNatives(myself, sourcesec_natives);
	plsys->AddPluginsListener(&g_sourcesec);
}

void SourceSec::OnPluginCreated( IPlugin *plugin )
{
	// Get plugin absolute path
	char inFile[PLATFORM_MAX_PATH];
	smutils->BuildPath(Path_SM, inFile, PLATFORM_MAX_PATH,
		"plugins/%s", plugin->GetFilename());

	smutils->LogMessage(myself, 
		"Plugin load requested: %s", 
		plugin->GetFilename());

	// Get plugin signature path (plugin.smx.sig)
	char sigFile[PLATFORM_MAX_PATH];
	smutils->BuildPath(Path_SM, sigFile, PLATFORM_MAX_PATH,
		"plugins/%s.sig", plugin->GetFilename());
	smutils->LogMessage(myself, 
		"Searching for signature file: %s", sigFile);

	// Get authors public key
	char pubKey[PLATFORM_MAX_PATH];
	smutils->BuildPath(Path_SM, pubKey, PLATFORM_MAX_PATH,
		"data/rsa/%s.pub", plugin->GetPublicInfo()->author);
	smutils->LogMessage(myself, 
		"Searching for public key file: %s", pubKey);

	int ret = rsautl_verify(pubKey, inFile, sigFile);

	switch (ret)
	{
	case SourceSec_ValidationOk:
		smutils->LogMessage(myself, 
			"Plugin %s passed validation",
			plugin->GetFilename());
		break;
	case SourceSec_ValidationFail:
		smutils->LogMessage(myself, 
			"Plugin %s didn't pass the integrity check",
			plugin->GetFilename());
		plugin->SetPauseState(true);
		break;
	case SourceSec_PubKeyNotFound:
		smutils->LogMessage(myself, 
			"Public key %s couldn't be opened",
			pubKey);
		break;
	case SourceSec_SigNotFound:
		smutils->LogMessage(myself, 
			"Signature file %s couldn't be opened",
			sigFile);
		break;
	case SourceSec_SigTooBig:
		smutils->LogMessage(myself, 
			"Signature file %s exceeded maximum allowed size",
			sigFile);
		break;
	case SourceSec_SigIncomplete:
		smutils->LogMessage(myself, 
			"Signature file %s wasn't loaded completely",
			sigFile);
		break;
	}
}

// http://stackoverflow.com/questions/7853156/calculate-sha256-of-a-file-using-openssl-libcrypto-in-c
// Calculates SHA256 of given file
int calc_sha256(const char* path, unsigned char hash[SHA256_DIGEST_LENGTH])
{
	FILE* file = fopen(path, "rb");
	if(!file) return -1;

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

int rsautl_verify(const char *pubKey, const char *inFile, const char *inSig)
{
	int ret = SourceSec_PubKeyNotFound;

	FILE *fpPubKey = fopen(pubKey, "rt");
	if(!fpPubKey)
		return ret;

	// Set file as public key source (must be in PEM format)
	RSA *rsa_pub = PEM_read_RSA_PUBKEY(fpPubKey, NULL, NULL, NULL);

	// Try to open signature file
	FILE *fpSigFile = fopen(inSig, "rb");
	if(!fpSigFile)
	{
		fclose(fpPubKey);
		return SourceSec_SigNotFound;
	}

	// Calculate hash of input file
	unsigned char hash[SHA256_DIGEST_LENGTH];
	calc_sha256(inFile, hash);

	// Get size of signature file
	fseek(fpSigFile, 0L, SEEK_END);
	size_t lenSig = ftell(fpSigFile);
	fseek(fpSigFile, 0L, SEEK_SET);

	// Signature size is suspiciously high, cancel process
	if(lenSig > 1024)
	{
		fclose(fpPubKey);
		fclose(fpSigFile);
		return SourceSec_SigTooBig;
	}

	// Read content into memory
	unsigned char *signature = (unsigned char*)malloc(lenSig);
	size_t rv = fread(signature, sizeof(unsigned char), lenSig, fpSigFile);

	// Check if full content was loaded
	if(rv != lenSig)
	{
		fclose(fpPubKey);
		fclose(fpSigFile);
		return SourceSec_SigIncomplete;
	}

	// Verify signature integrity
	ret = RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, 
		(const unsigned char*)signature, lenSig, rsa_pub);

	// Free resources
	fclose(fpPubKey);
	fclose(fpSigFile);
	free(signature);

	return ret;
}

cell_t sm_rsautl_verify(IPluginContext *pContext, const cell_t *params)
{
	char *pubKey, *inFile, *sigFile;
	int ret = -1;
	char pubKeyPath[PLATFORM_MAX_PATH];
	char inFilePath[PLATFORM_MAX_PATH];
	char sigFilePath[PLATFORM_MAX_PATH];

	// Public key file path
	pContext->LocalToString(params[1], &pubKey);
	// Input hash
	pContext->LocalToString(params[2], &inFile);
	// Input signature file path (encrypted)
	pContext->LocalToString(params[3], &sigFile);

	smutils->BuildPath(Path_Game, pubKeyPath, PLATFORM_MAX_PATH, pubKey);
	smutils->BuildPath(Path_Game, inFilePath, PLATFORM_MAX_PATH, inFile);
	smutils->BuildPath(Path_Game, sigFilePath, PLATFORM_MAX_PATH, sigFile);

	return rsautl_verify(pubKeyPath, inFilePath, sigFilePath);
}

cell_t dgst_sha256(IPluginContext *pContext, const cell_t *params)
{
	char *path;
	char buffer[PLATFORM_MAX_PATH];

	// Get input file to calculate
	pContext->LocalToString(params[3], &path);

	unsigned char hash[SHA256_DIGEST_LENGTH];
	char output[65];
	// Open file and calculate hash
	smutils->BuildPath(Path_Game, buffer, PLATFORM_MAX_PATH, path);
	if(calc_sha256(buffer, hash) == -1)
		return -1;

	// Convert digest into human readable hex string
	sha256_hash_string(hash, output);

	// Set return buffer
	pContext->StringToLocalUTF8(params[1], params[2], output, NULL);

	return 0;
}

const sp_nativeinfo_t sourcesec_natives[] = 
{
	{"SourceSec_Verify",			sm_rsautl_verify},
	{"SourceSec_GetSHA256",			dgst_sha256},
	{NULL,							NULL},
};
