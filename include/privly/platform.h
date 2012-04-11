/**
 * platform.h
 *
 * Platform detection macros.
 */

#ifndef PRIVLY_PLATFORM_H_
#define PRIVLY_PLATFORM_H_


#define PRIVLY_PLATFORM_MSW32	1
#define PRIVLY_PLATFORM_LINUX	2
#define PRIVLY_PLATFORM_OSX		3

#if defined( WIN32 ) || defined( _WIN32 )
#	define PRIVLY_PLATFORM PRIVLY_PLATFORM_MSW32
#elif defined( __APPLE_CC__ )
#	define PRIVLY_PLATFORM PRIVLY_PLATFORM_OSX
#else
#	define PRIVLY_PLATFORM PRIVLY_PLATFORM_LINUX
#endif


#endif /* PRIVLY_PLATFORM_H_ */
