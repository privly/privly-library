#
# This is a translation of 'vsvars32.bat' to a Bash script
# Its purpose is to configure the build environment to suit
# the MSVC compiler (cl.exe)
#
# Given how the compiler expects to get include path names
# (i.e. Windows format, double-quoted), you may need to tweak
# this file. That should be your starting point for weird compiler
# errors.
#

export VSINSTALLDIR=`cygpath -ua "C:\programs\msvc9"`
export FrameworkDir=`cygpath -ua "C:\WINDOWS\Microsoft.NET\Framework"`
export FrameworkVersion=v2.0.50727
export Framework35Version=v3.5

#if [ -n $WindowsSdkDir ]; then
#	export PATH="$WindowsSdkDir/bin:$PATH"
#	export INCLUDE="$WindowsSdkDir/include:$INCLUDE"
#	export LIB="$WindowsSdkDir/lib:$LIB"
#fi

export DevEnvDir=/cygdrive/c/programs/msvc9/Common7/IDE

export PATH=`cygpath -up "C:\programs\msvc9\VC\bin;C:\programs\msvc9\Common7\IDE;C:\programs\msvc9\Common7\Tools;C:\programs\msvc9\VC\VCPackages;C:\WINDOWS\Microsoft.NET\Framework\v3.5;C:\WINDOWS\Microsoft.NET\Framework\v2.0.50727;"`$PATH
export INCLUDE=`cygpath -up "C:\programs\msvc9\VC\include;$INCLUDE"`
export LIB=`cygpath -up "C:\programs\msvc9\VC\lib;$LIB"`
export LIBPATH=`cygpath -up "C:\WINDOWS\Microsoft.NET\Framework\v3.5;C:\WINDOWS\Microsoft.NET\Framework\v2.0.50727;C:\programs\msvc9\VC\lib;$LIBPATH"`

export MSVC_BUILD_ENVIRONMENT_CONFIGURED="true"
