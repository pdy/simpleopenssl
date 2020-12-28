# Features
* Simple API - **no fancy abstractions**, no templates in interface, just simple set of functions.
* No custom processing added over OpenSSL - **if you got error, it came from OpenSSL**. Even IO is done by OpenSSL itself.
* Clear, unified error handling **without exceptions**.
* All heap allocated OpenSSL **types encapsulated with unique pointers** with stateless deleters.

# Usage
1. Copy [simpleopenssl.h](https://raw.githubusercontent.com/severalgh/simpleopenssl/master/include/simpleopenssl/simpleopenssl.h) to your build tree.
2. Add ```#define SO_IMPLEMENTATION``` in exacly one place just before the include to specify where implementation should be placed for the linker:

    ```
    #define SO_IMPLEMENTATION
    #include "simpleopenssl.h"
    ```
    
3. Use plain ```#include "simpleopenssl.h"``` in every other place.
 
# Dependencies
* OpenSSL version 1.1.0 or higher.
* C++11 or higher
* STL

