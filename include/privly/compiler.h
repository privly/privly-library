/**
 * compiler.h
 *
 * Compiler detection macros. Also defines PRIVLY_EXPORT.
 */

#ifndef PRIVLY_COMPILER_H_
#define PRIVLY_COMPILER_H_

#include "privly/platform.h"

/* Compilers */
#define PRIVLY_COMPILER_MSVC 	1
#define PRIVLY_COMPILER_GCC		2

#if defined( _MSC_VER )
#	define PRIVLY_COMPILER PRIVLY_COMPILER_MSVC
#elif defined( __GNUC__ )
#	define PRIVLY_COMPILER PRIVLY_COMPILER_GCC
#endif

#if PRIVLY_PLATFORM == PRIVLY_PLATFORM_MSW32
#	if defined( PRIVLY_STATIC_BUILD )
#		define PRIVLY_EXPORT /*nothing*/
#	else
#		if defined( PRIVLY_NONCLIENT_BUILD )
#			define PRIVLY_EXPORT __declspec( dllexport )
#		elif defined( __MINGW32__ )
#			define PRIVLY_EXPORT /*nothing*/
#		else
#			define PRIVLY_EXPORT __declspec( dllimport )
#		endif
#	endif
#else
#	define PRIVLY_EXPORT /*nothing*/
#endif


#endif /* PRIVLY_COMPILER_H_ */
