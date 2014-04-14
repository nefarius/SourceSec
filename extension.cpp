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

cell_t RSAUtilVerify(IPluginContext *pContext, const cell_t *params)
{
	char *data, *pubKey, *inFile;
	size_t len;

	// Output buffer
	pContext->LocalToString(params[1], &data);
	// Buffer max size
	len = params[2];
	// Public key file path
	pContext->LocalToString(params[3], &pubKey);
	// Input data file path
	pContext->LocalToString(params[4], &inFile);



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
