# Features
* Simple API - **no fancy abstractions**, no templates in interface, just simple set of functions.
* No custom processing added over OpenSSL - **if you got error, it came from OpenSSL**. Even IO is done by OpenSSL itself.
* Clear, unified error handling **without exceptions**.
* All heap allocated OpenSSL **types encapsulated with unique pointers** with stateless deleters.

# Examples
Check [examples](https://raw.githubusercontent.com/severalgh/simpleopenssl/master/examples) folder for sample applications.

* Hash file using sha256
```cpp
using namespace so;

if(const auto hash = hash::fileSHA256(filePath))
{
    LOG_DBG << "File " << filePath << " hash: " << binToHexStr(hash.value);
}
else
{
    LOG_ERR << hash.msg();
}

```
* Generate RSA key and convert it to PEM format
```cpp
using namespace so;

auto key = rsa::create(rsa::KeyBits::_3072_)
if(!key)
{
    LOG_ERR << key.msg();
    return;
}

const auto pemKey = rsa::convertPrivKeyToPem(*key.value);
if(!pemKey)
{
    LOG_ERR <<  pemKey.msg();
    return;
}

LOG_INF << "New key pem: " << pemKey.value;
```
* Check certificate validity period
```cpp
using namespace so;
std::string timetPrettyString(std::time_t time);

so::X509_uptr cert = so::make_unique(SSL_get_peer_certificate(ssl));
if(!cert)
    return;
  
const auto validity = x509::getValidity(*cert);
if(!validity)
{
    LOG_ERR << "Getting validity failed: " << validity.msg();
    return;
}

LOG_INF << "Cert not before: " << timetPrettyString(validity.value.notBefore);
LOG_INF << "Cert not after: " << timetPrettyString(validity.value.notAfter);

// ...............................

std::string timetPrettyString(std::time_t time)
{
  std::tm *ptm = std::gmtime(&time);

  char buffer[32];
  std::strftime(buffer, 32, "%a, %d.%m.%Y %H:%M:%S", ptm);

  return buffer;
}
```

# Usage
1. Copy [simpleopenssl.h](https://raw.githubusercontent.com/severalgh/simpleopenssl/master/include/simpleopenssl/simpleopenssl.h) to your build tree.
2. Add ```#define SO_IMPLEMENTATION``` in exacly one place just before the include to specify where implementation should be placed for the linker:

    ```
    #define SO_IMPLEMENTATION
    #include "simpleopenssl.h"
    ```
    
3. Use plain ```#include "simpleopenssl.h"``` in every other place.
 
# Dependencies
* OpenSSL version 1.1.0 or higher
* C++11 or higher
* STL

