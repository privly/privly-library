# ----------------------------------------------------------------------------
# Makefile for the privly-client library.
#
# TODO:
#	[2012/04/09:jhostetler] We need a cross-platform build system. This
#		Makefile only works on Windows+Cygwin.
#
# History:
#	[2012/01/21:jhostetler] Created by copying Makefile from 'bwlogger'
# ----------------------------------------------------------------------------

# ----------------------------------------------------------------------------
# Paths
# ----------------------------------------------------------------------------

VERSION_MAJOR = 0
VERSION_MINOR = 1
# Gets the current SVN revision.
# VERSION_REV = $(shell svn info -R | grep "^Revision" | sort -n -r | head -n1 | awk -F": " '{print $$2}')

PROJECT_ROOT = $(shell pwd)

OBJ_DIR = $(PROJECT_ROOT)/obj
INC_DIR = $(PROJECT_ROOT)/include
SANDBOX_DIR = $(PROJECT_ROOT)/sandbox
SRC_DIR = $(PROJECT_ROOT)/src
LIB_DIR = $(PROJECT_ROOT)/lib

# NSS
NSS_ROOT = /cygdrive/c/lib/mozilla/dist

# MSVC
MSVC_ROOT = /cygdrive/c/programs/msvc9/VC

# Windows SDK
WINDOWS_SDK_ROOT = /cygdrive/c/lib/windows_sdk/v6.0A

# ----------------------------------------------------------------------------
# Dependencies
# ----------------------------------------------------------------------------

# Includes
INCLUDE_PATH_LIST = \
	$(INC_DIR) \
	$(NSS_ROOT)/public \
	$(NSS_ROOT)/WINNT6.1_OPT.OBJ/include \
	$(MSVC_ROOT)/include \
	$(WINDOWS_SDK_ROOT)/Include

# Libs
LIB_PATH_LIST = \
	$(LIB_DIR) \
	$(MSVC_ROOT)/lib \
	$(NSS_ROOT)/WINNT6.1_OPT.OBJ/lib \
	$(WINDOWS_SDK_ROOT)/Lib

LIBS_COMMON = \
	nss3.lib \
	libplc4.lib \
	libnspr4.lib
LIBS_DEBUG =
LIBS_RELEASE = 

# ----------------------------------------------------------------------------
# Build tools
# ----------------------------------------------------------------------------

CP = cp
MV = mv
RM = rm
CC = cl.exe -TC
CXX = cl.exe -TP
LD = link.exe

# This voodoo gets us a quoted Windows format path for each entry in a list
PosixPathsToWindowsPaths = $(foreach p,$(1),"$(shell cygpath -ma $(p))")

# ----------------------------------------------------------------------------
# Command line flags
# ----------------------------------------------------------------------------

# NSS library says we want the following flags:
# -c -O2 -MD -W3 -nologo -D_X86_ -GT -DWINNT -DXP_PC -UDEBUG -U_DEBUG -DNDEBUG -DWIN32 -D_WINDOWS 

OBJ_EXTENSION = .obj

# __WIN3__ is a non-standard Windows platform identification macro that 
# libraries occasionally depend on.
CPPFLAGS_COMMON = -DWIN32 -D_WINDOWS -D__WIN32__ -DWINNT -DXP_PC

CPPFLAGS_DEBUG = 

# _SCL_SECURE_NO_WARNINGS : disable compiler warnings for using standard
#	library functions that "rely on the caller to ensure the arguments are
#	correct" (as though that's unusual!)
CPPFLAGS_RELEASE = -UDEBUG -U_DEBUG -DNDEBUG -D_SCL_SECURE_NO_WARNINGS

# Common cxx flags:
#	-W4		Warning level 4/4
#	-nologo	Suppress startup banner
#	-GT		Consult NSS manual
CCFLAGS_COMMON = -W4 -nologo -GT

# Debug-specific flags:
#	-Od		No optimizations
#	-MDd	C runtime library
CCFLAGS_DEBUG = -Od -MDd

# Release-specific flags:
#	-O2		Speed optimizations
#	-MD		C runtime library
CCFLAGS_RELEASE = -O2 -MD

# Linker flags:
#	-nologo	Suppress startup banner
LDFLAGS_COMMON = -nologo
LDFLAGS_DEBUG = 
LDFLAGS_RELEASE = 

# Flags to specify output file
CC_OUTPUT_FILE_FLAG = -Fo
LD_OUTPUT_FILE_FLAG = -OUT:

# Special commands to generate library
LD_GENERATE_RELEASE_LIB = -DLL
LD_GENERATE_DEBUG_LIB = -DLL

# Prefix for link search paths: '-L' for gcc, '-LIBPATH:' for MSVC
LIBRARY_PATH_LINKER_PREFIX = -LIBPATH:

# Prefix for link libraries: '-l' for gcc, nothing for MSVC
LIBRARY_LINKER_PREFIX =

# ----------------------------------------------------------------------------
# Configuration-specific option lists
# ----------------------------------------------------------------------------

POSIX_INCLUDE_PATH_LIST = $(INCLUDE_PATH_LIST)
WINDOWS_INCLUDE_PATH_LIST = $(call PosixPathsToWindowsPaths,$(INCLUDE_PATH_LIST))
INCLUDE_PATHS = $(addprefix -I,$(WINDOWS_INCLUDE_PATH_LIST))
POSIX_INCLUDE_PATHS = $(addprefix -I,$(POSIX_INCLUDE_PATH_LIST))

LIB_PATH_LIST := $(call PosixPathsToWindowsPaths,$(LIB_PATH_LIST))
LIB_PATHS = $(addprefix $(LIBRARY_PATH_LINKER_PREFIX),$(LIB_PATH_LIST))

ifeq ($(TARGET), debug)
	LIBS = $(LIBS_COMMON) $(LIBS_DEBUG)
	CPPFLAGS = $(CPPFLAGS_COMMON) $(CPPFLAGS_DEBUG)
	CCFLAGS = $(CCFLAGS_COMMON) $(CCFLAGS_DEBUG)
	LDFLAGS = $(LDFLAGS_COMMON) $(LDFLAGS_DEBUG)
	LD_GENERATE_LIBRARY = $(LD_GENERATE_DEBUG_LIB)
	EXPORT_LIB_SUFFIX = -d.dll
	IMPORT_LIB_SUFFIX = -d.lib
else
	LIBS = $(LIBS_COMMON) $(LIBS_RELEASE)
	CPPFLAGS = $(CPPFLAGS_COMMON) $(CPPFLAGS_RELEASE)
	CCFLAGS = $(CCFLAGS_COMMON) $(CCFLAGS_RELEASE)
	LDFLAGS = $(LDFLAGS_COMMON) $(LDFLAGS_RELEASE)
	LD_GENERATE_LIBRARY = $(LD_GENERATE_RELEASE_LIB)
	EXPORT_LIB_SUFFIX = .dll
	IMPORT_LIB_SUFFIX = .lib
endif

LIBS := $(addprefix $(LIBRARY_LINKER_PREFIX),$(LIBS))

LIB_HEADERS = $(addprefix $(INC_DIR)/privly/,ccrypto.h compiler.h platform.h version.h)
LIB_SRCS = $(addprefix privly/, \
	nss_crypto.c \
	version.c )
	
# Objects
LIB_OBJECTS = $(LIB_SRCS:.c=$(OBJ_EXTENSION))


# ----------------------------------------------------------------------------
# Stuff to build
# ----------------------------------------------------------------------------

lib: $(LIB_DIR)/privly-client.dll

sandbox: lib $(SANDBOX_DIR)/sandbox.exe
	
$(LIB_DIR)/privly-client.dll: $(addprefix $(OBJ_DIR)/,$(LIB_OBJECTS))
	@echo
	@echo Building $(@F)
	@echo
	# rm -f $@
	$(LD) $(LD_GENERATE_LIBRARY) $(LD_OUTPUT_FILE_FLAG)`cygpath -m $@` `cygpath -m $^` $(LIB_PATHS) $(LIBS) $(LDFLAGS)

$(SANDBOX_DIR)/sandbox.exe: $(SANDBOX_DIR)/sandbox.cpp
	cp $(LIB_DIR)/privly-client.dll $(SANDBOX_DIR)/privly-client.dll
	@echo
	@echo Building 'sandbox.exe'
	@echo
	# rm -f $@
	$(CXX) -nologo $(CCFLAGS) $(INCLUDE_PATHS) -Fe`cygpath -m $@` `cygpath -m $^` -link $(LIB_PATHS) privly-client.lib $(LIBS) $(LDFLAGS)
	
# Generic compile step
$(OBJ_DIR)/%$(OBJ_EXTENSION): $(SRC_DIR)/%.c
	@echo
	@echo Building $(@F)
	@echo
	@rm -f $@
	$(CC) $(CPPFLAGS) -DPRIVLY_NONCLIENT_BUILD $(CCFLAGS) -c $(INCLUDE_PATHS) $(CC_OUTPUT_FILE_FLAG)`cygpath -m $@` `cygpath -m $<`	
