# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html

# Sets the minimum version of CMake required to build the native library.

cmake_minimum_required(VERSION 3.4.1)

# Set directories for OPENSSL
include_directories(${CMAKE_SOURCE_DIR}/include)
link_directories(${CMAKE_SOURCE_DIR}/lib/openssl/${ANDROID_ABI})

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.

add_library( # Sets the name of the library.
             native-client

             # Sets the library as a shared library.
             SHARED

             # Provides a relative path to your source file(s).
             Utils.cpp
             HomHash.cpp
             Commitment.cpp
             SecretShare.cpp
             KeyAgreement.cpp
             Cipher.cpp
             Context.cpp
             com_va_client_NativeClient.cpp )

find_library( # Sets the name of the path variable.
              log-lib
              # Specifies the name of the NDK library that
              # you want CMake to locate.
              log )

target_link_libraries( # Specifies the target library.
                       native-client
                       # Links the target library to the log library
                       # included in the NDK.
                       ${log-lib}
                       libcrypto.a )