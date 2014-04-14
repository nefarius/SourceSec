#if defined _sourcesig_included
	#endinput
#endif

#define _sourcesig_included

native SourceSec_Verify(const String:publicKeyFile[], const String:sourceFile[], const String:signatureFile[]);

native SourceSec_GetSHA256(String:output[], size, const String:file[]);

/**
 * Do not edit below this line!
 */
public Extension:__ext_sourcesig = 
{
	name = "SOURCESIG",
	file = "sourcesig.ext",
#if defined AUTOLOAD_EXTENSIONS
	autoload = 1,
#else
	autoload = 0,
#endif
#if defined REQUIRE_EXTENSIONS
	required = 1,
#else
	required = 0,
#endif
};
