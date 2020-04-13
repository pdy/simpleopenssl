# Usage
Library is header only, so just copy [simpleopenssl.h](https://raw.githubusercontent.com/severalgh/simpleopenssl/master/include/simpleopenssl/simpleopenssl.h) to your build tree. It requires C++11 or higher and openssl version 1.1.0 or higher being already setup in your environment.

# Features
* Simple API - **no fancy abstractions**, no templates, just simple set of functions which get the job done.
* All heap allocated OpenSSL **types encapsulated with unique pointers** with stateless deleters.
* No custom processing added over OpenSSL - **if you got error, it came from OpenSSL**. Even IO is done by OpenSSL itself.
* Clear, unified error handling **without exceptions**.
