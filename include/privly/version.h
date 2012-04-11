/**
 * privly/version.h
 */

#ifndef PRIVLY_VERSION_H_
#define PRIVLY_VERSION_H_

#include "privly/compiler.h"

#ifdef __cplusplus
extern "C" {
#endif


int PRIVLY_EXPORT privly_VersionMajor();
int PRIVLY_EXPORT privly_VersionMinor();
int PRIVLY_EXPORT privly_VersionRev();


#ifdef __cplusplus
}
#endif

#endif /* PRIVLY_VERSION_H_ */
