/**
 * privly/version.c
 */

#include "privly/version.h"


int PRIVLY_EXPORT privly_VersionMajor()
{
	/* $$version major$$ */
    static const int version_major = 0;
	return version_major;
}

int PRIVLY_EXPORT privly_VersionMinor()
{
	// $$version minor$$
    static const int version_minor = 1;
	return version_minor;
}

int PRIVLY_EXPORT privly_VersionRev()
{
	// $$version rev$$
    static const int version_rev = 1;
	return version_rev;
}
