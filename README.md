# Usage
Library is header only, so just copy [simpleopenssl.h](https://raw.githubusercontent.com/severalgh/simpleopenssl/master/include/simpleopenssl/simpleopenssl.h) to your build tree. It requires C++11 or higher and openssl version 1.1.0 or higher being already setup in your environment.

# Features
* Simple API - no fancy abstractions, no templates, just simple set of functions which get the job done.
* All heap allocated openssl types encapsulated with unique pointer with stateless deleter.
* No processing added over openssl that may fail - if you got error, it came from openssl.
* Clear, unified error handling WITHOUT EXCEPTIONS.
