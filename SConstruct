# ----------------------------------------------------------------------------
# Top-level SCons script for privly client library.
#
# TODO:
#	[2012/04/23:jhostetler] This is only tested on Windows with MSVC 9.
#
# History:
#	[2012/04/23:jhostetler] Created by translating the original Makefile.
# ----------------------------------------------------------------------------

import os
import SCons

# Trick from: http://www.scons.org/wiki/ImportingEnvironmentSettings
# We're essentially dumping the external environment into SCons, but for fields
# like PATH, we're appending rather than overwriting.
#
# Needed because Scons can't find cl.exe on my Windows machine without "help"
def ENV_update( tgt_ENV, src_ENV ):
    for K in src_ENV.keys():
        if K in tgt_ENV.keys() and K in [ 'PATH', 'LD_LIBRARY_PATH',
                                          'LIB', 'LIBPATH', 'INCLUDE' ]:
            tgt_ENV[K] = SCons.Util.AppendPath(tgt_ENV[K], src_ENV[K])
        else:
            tgt_ENV[K] = src_ENV[K]

# ----------------------------------------------------------------------------

env = Environment()
ENV_update(env["ENV"], os.environ)
env.SetDefault( PRIVLY_CRYPTO_BACKEND = "nss" )
env.SetDefault( PRIVLY_DEBUG = False )

# ----------------------------------------------------------------------------
# Options
# ----------------------------------------------------------------------------

# build with `scons --debug-build` for debug.
AddOption( "--debug-build", dest="debug_build", action="store_true", default=False,
		   help="Enable debug build" )
		   
# ----------------------------------------------------------------------------

if GetOption( "debug_build" ):
	env["PRIVLY_DEBUG"] = True

platform = ARGUMENTS.get( "OS", Platform() )

build_dir = "#build"
inc_dir = "#include"
sandbox_dir = "#sandbox"
src_dir = "#src"
lib_dir = "#lib"
dist_dir = "#dist"

# NSS
nss_root = "C:/lib/mozilla/dist"

# MSVC
msvc_root = "C:/programs/msvc9/VC"

# Windows SDK
windows_sdk_root = "C:/lib/windows_sdk/v6.0A"

# Includes
include_path = [
	inc_dir,
	nss_root + "/public",
	nss_root + "/WINNT6.1_OPT.OBJ/include",
	msvc_root + "/include",
	windows_sdk_root + "/Include"
]
env.Append( CPPPATH = include_path )

libpath = [
	lib_dir,
	msvc_root + "/lib",
	nss_root + "/WINNT6.1_OPT.OBJ/lib",
	windows_sdk_root + "/Lib"
]
env.Append( LIBPATH = libpath )

libs = [
	"nss3.lib",
	"libplc4.lib",
	"libnspr4.lib"
]
env.Append( LIBS = libs )

Export( "env" )

# ----------------------------------------------------------------------------
# Build steps
# ----------------------------------------------------------------------------

obj_list = env.SConscript( "#src/obj.scons", variant_dir="build", duplicate=False )
env.Replace( PRIVLY_OBJECT_LIST = obj_list )
libs = env.SConscript( "#lib/lib.scons", duplicate=False )
# env.Replace( PRIVLY_LIBRARY_LIST = libs )
# env.SConscript( "#dist/dist.scons", duplicate=False )
