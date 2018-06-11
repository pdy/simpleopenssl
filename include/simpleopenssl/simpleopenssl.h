#ifndef SEVERALGH_SIMPLEOPENSSL_H_
#define SEVERALGH_SIMPLEOPENSSL_H_

/*
* Copyright (c) 2018 Pawel Drzycimski
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*
*/

// openssl
#include <openssl/asn1.h>
#include <openssl/ssl.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/bn.h>
#include <openssl/buffer.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/cmac.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <openssl/md4.h>

// std
#include <vector>
#include <memory>
#include <type_traits>
#include <algorithm>
#include <cstring>
#include <ctime>
#include <chrono>

namespace so {

using Bytes = std::vector<uint8_t>;

#define SO_API static inline
#define SO_LIB static

namespace detail {
  template<typename T>
  struct is_uptr : std::false_type {}; 

  template<typename T>
  class CustomDeleter
  {
  public:
    void operator()(T *p)
    {
      std::default_delete<T>{}(p);
    }
  };

  template<typename T, typename D = CustomDeleter<T>>
  using CustomDeleterUniquePtr = std::unique_ptr<T, D>;

} //namespace detail
  
#define CUSTOM_DELETER_UNIQUE_POINTER(Type, Deleter)\
namespace detail {                                  \
template<>                                          \
class CustomDeleter<Type>                           \
{                                                   \
public:                                             \
  void operator()(Type *ptr)                        \
  {                                                 \
    Deleter(ptr);                                   \
  }                                                 \
};                                                  \
}                                                   \
using Type ## _uptr = detail::CustomDeleterUniquePtr<Type>; \
namespace detail {                                          \
template<> struct is_uptr<detail::CustomDeleterUniquePtr<Type>> : std::true_type {};}

template<typename T, typename D = detail::CustomDeleter<T>>
SO_API auto make_unique(T *ptr) -> std::unique_ptr<T, D>
{
  return std::unique_ptr<T, D>(ptr);
}

CUSTOM_DELETER_UNIQUE_POINTER(ASN1_STRING, ASN1_STRING_free);
using ASN1_INTEGER_uptr         = ASN1_STRING_uptr;
using ASN1_ENUMERATED_uptr      = ASN1_STRING_uptr;
using ASN1_BIT_STRING_uptr      = ASN1_STRING_uptr;
using ASN1_OCTET_STRING_uptr    = ASN1_STRING_uptr;
using ASN1_PRINTABLESTRING_uptr = ASN1_STRING_uptr;
using ASN1_T61STRING_uptr       = ASN1_STRING_uptr;
using ASN1_IA5STRING_uptr       = ASN1_STRING_uptr;
using ASN1_GENERALSTRING_uptr   = ASN1_STRING_uptr;
using ASN1_UNIVERSALSTRING_uptr = ASN1_STRING_uptr;
using ASN1_BMPSTRING_uptr       = ASN1_STRING_uptr;
using ASN1_UTCTIME_uptr         = ASN1_STRING_uptr;
using ASN1_TIME_uptr            = ASN1_STRING_uptr;
using ASN1_GENERALIZEDTIME_uptr = ASN1_STRING_uptr;
using ASN1_VISIBLESTRING_uptr   = ASN1_STRING_uptr;
using ASN1_UTF8STRING_uptr      = ASN1_STRING_uptr;

CUSTOM_DELETER_UNIQUE_POINTER(BIGNUM, BN_free);
CUSTOM_DELETER_UNIQUE_POINTER(BN_CTX, BN_CTX_free);
CUSTOM_DELETER_UNIQUE_POINTER(BIO, BIO_free_all);
CUSTOM_DELETER_UNIQUE_POINTER(EC_GROUP, EC_GROUP_free);
CUSTOM_DELETER_UNIQUE_POINTER(EC_KEY, EC_KEY_free);
CUSTOM_DELETER_UNIQUE_POINTER(EC_POINT, EC_POINT_free);
CUSTOM_DELETER_UNIQUE_POINTER(ECDSA_SIG, ECDSA_SIG_free);
CUSTOM_DELETER_UNIQUE_POINTER(EVP_CIPHER_CTX, EVP_CIPHER_CTX_free);
CUSTOM_DELETER_UNIQUE_POINTER(EVP_MD_CTX, EVP_MD_CTX_free);
CUSTOM_DELETER_UNIQUE_POINTER(EVP_PKEY, EVP_PKEY_free);
CUSTOM_DELETER_UNIQUE_POINTER(RSA, RSA_free);
CUSTOM_DELETER_UNIQUE_POINTER(X509, X509_free);
CUSTOM_DELETER_UNIQUE_POINTER(X509_CRL, X509_CRL_free);
CUSTOM_DELETER_UNIQUE_POINTER(X509_NAME, X509_NAME_free);
CUSTOM_DELETER_UNIQUE_POINTER(X509_NAME_ENTRY, X509_NAME_ENTRY_free);

namespace detail {

template<typename T, typename TSelf, typename Tag>
class AddValueRef {};

template<typename T, typename TSelf>
class AddValueRef<T, TSelf, std::false_type>
{
public:
  const T& operator*() const { return value(); }
  const T& value() const { return static_cast<const TSelf*>(this)->m_value; }
};

template<typename T, typename TSelf>
class AddValueRef<T, TSelf, std::true_type>
{};

SO_LIB std::string errCodeToString(unsigned long errCode);
} //namespace detail

template<typename T>
class Expected : public detail::AddValueRef<T, Expected<T>, typename detail::is_uptr<T>::type>
{
public: 
  template
  < 
    typename T_ = T,
    typename = typename std::enable_if<std::is_default_constructible<T_>::value>::type
  >
  explicit Expected(unsigned long opensslErrorCode)
    : m_value {}, m_opensslErrCode{opensslErrorCode} {}  

  explicit Expected(unsigned long opensslErrorCode, T &&value)
    : m_value {std::move(value)}, m_opensslErrCode{opensslErrorCode} {}
     
  operator bool() const noexcept
  {
    return hasValue(); 
  }
 
  T&& moveValue()
  {
    return std::move(m_value);
  }

  unsigned long errorCode() const
  {
    return m_opensslErrCode;
  }

  bool hasValue() const noexcept
  { 
    return 0 == m_opensslErrCode;
  }

  bool hasError() const noexcept
  {
    return 0 != m_opensslErrCode;
  }

  std::string msg() const
  {
    if(0 == m_opensslErrCode) return "OK";
    return detail::errCodeToString(m_opensslErrCode); 
  }

private:
  friend detail::AddValueRef<T, Expected<T>, typename detail::is_uptr<T>::type>;

  T m_value;
  const unsigned long m_opensslErrCode;
};

template<>
class Expected<void>
{
public:
  explicit Expected(unsigned long opensslErrorCode)
    : m_opensslErrCode{opensslErrorCode} {}
 
  operator bool() const noexcept
  {
    return 0 == m_opensslErrCode;
  }

  bool hasError() const noexcept
  {
    return 0 != m_opensslErrCode;
  }

  std::string msg() const
  {
    if(0 == m_opensslErrCode) return "OK";
    return detail::errCodeToString(m_opensslErrCode); 
  }

private:
  const unsigned long m_opensslErrCode;
};

SO_API void init();
SO_API void cleanUp();

namespace asn1 {
  SO_API Expected<ASN1_INTEGER_uptr> encodeInteger(const Bytes &bt);
  SO_API Expected<ASN1_OCTET_STRING_uptr> encodeOctet(const Bytes &bt); 
  SO_API Expected<std::time_t> timeToStdTime(const ASN1_TIME &asn1Time);
  SO_API Expected<ASN1_TIME_uptr> stdTimeToTime(std::time_t time);
} // namepsace asn1

namespace bignum {
  SO_API Expected<Bytes> bnToBytes(const BIGNUM &bn);
  SO_API Expected<BIGNUM_uptr> bytesToBn(const Bytes &bt);
  SO_API Expected<size_t> size(const BIGNUM &bn);
}

namespace ecdsa {
  enum class Curve : int
  {
    secp112r1 = NID_secp112r1,
    secp112r2 = NID_secp112r2,
    secp128r1 = NID_secp128r1,
    secp160k1 = NID_secp160k1,
    secp160r1 = NID_secp160r1,
    secp160r2 = NID_secp160r2,
    secp192k1 = NID_secp192k1,
    secp224k1 = NID_secp224k1,
    secp224r1 = NID_secp224r1,
    secp256k1 = NID_secp256k1,
    secp384r1 = NID_secp384r1,
    secp521r1 = NID_secp521r1, 
    sect113r1 = NID_sect113r1,
    sect113r2 = NID_sect113r2,
    sect131r1 = NID_sect131r1,
    sect131r2 = NID_sect131r2,
    sect163k1 = NID_sect163k1,
    sect163r1 = NID_sect163r1,
    sect163r2 = NID_sect163r2,
    sect193r1 = NID_sect193r1,
    sect193r2 = NID_sect193r2,
    sect233k1 = NID_sect233k1,
    sect233r1 = NID_sect233r1,
    sect239k1 = NID_sect239k1,
    sect283k1 = NID_sect283k1,
    sect283r1 = NID_sect283r1,
    sect409k1 = NID_sect409k1,
    sect571k1 = NID_sect571k1,
    sect571r1 = NID_sect571r1
  };

  struct Signature
  {
    Bytes r;
    Bytes s;
  };

  SO_API Expected<bool> checkKey(const EC_KEY &ecKey);
  SO_API Expected<EC_KEY_uptr> copyKey(const EC_KEY &ecKey);
  SO_API Expected<Curve> curveOf(const EC_KEY &key);
  SO_API Expected<Bytes> der(const Signature &signature);
  SO_API Expected<EC_KEY_uptr> extractPublic(const EC_KEY &key);
  SO_API Expected<EVP_PKEY_uptr> keyToEvp(const EC_KEY &key);
  SO_API Expected<EC_KEY_uptr> generateKey(Curve curve);
  SO_API Expected<EC_KEY_uptr> pemToPrivateKey(const std::string &pemPriv);
  SO_API Expected<EC_KEY_uptr> pemToPublicKey(const std::string &pemPub);
  SO_API Expected<Bytes> signSha1(const Bytes &message, EC_KEY &key);
  SO_API Expected<Bytes> signSha224(const Bytes &message, EC_KEY &key);
  SO_API Expected<Bytes> signSha256(const Bytes &message, EC_KEY &key);
  SO_API Expected<Bytes> signSha384(const Bytes &message, EC_KEY &key);
  SO_API Expected<Bytes> signSha512(const Bytes &message, EC_KEY &key);
  SO_API Expected<bool> verifySha1Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey);
  SO_API Expected<bool> verifySha224Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey);
  SO_API Expected<bool> verifySha256Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey);
  SO_API Expected<bool> verifySha384Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey);
  SO_API Expected<bool> verifySha512Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey);
} // namespace ecdsa

namespace evp {
  SO_API Expected<EVP_PKEY_uptr> pemToPrivateKey(const std::string &pemPriv);
  SO_API Expected<EVP_PKEY_uptr> pemToPublicKey(const std::string &pemPub);
  SO_API Expected<Bytes> signSha1(const Bytes &message, EVP_PKEY &privateKey);
  SO_API Expected<Bytes> signSha224(const Bytes &msg, EVP_PKEY &privKey);
  SO_API Expected<Bytes> signSha256(const Bytes &msg, EVP_PKEY &privKey);
  SO_API Expected<Bytes> signSha384(const Bytes &msg, EVP_PKEY &privKey);
  SO_API Expected<Bytes> signSha512(const Bytes &msg, EVP_PKEY &privKey);
  SO_API Expected<bool> verifySha1Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey);
  SO_API Expected<bool> verifySha224Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey);
  SO_API Expected<bool> verifySha256Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey);
  SO_API Expected<bool> verifySha384Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey);
  SO_API Expected<bool> verifySha512Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey);
} // namepsace evp

namespace hash {
  SO_API Expected<Bytes> md4(const Bytes &data);
  SO_API Expected<Bytes> md5(const Bytes &data);
  SO_API Expected<Bytes> sha1(const Bytes &data);
  SO_API Expected<Bytes> sha224(const Bytes &data);
  SO_API Expected<Bytes> sha256(const Bytes &data);
  SO_API Expected<Bytes> sha384(const Bytes &data);
  SO_API Expected<Bytes> sha512(const Bytes &data);
} // namespace hash

namespace rand {
  SO_API Expected<Bytes> bytes(unsigned short numOfBytes);
} //namespace rand

namespace x509 {
  
  struct Info
  {
    std::string commonName;
    std::string countryName;
    std::string localityName;
    std::string organizationName;
    std::string stateOrProvinceName;

    inline bool operator ==(const Info &other) const;
    inline bool operator !=(const Info &other) const;
  };

  struct Validity
  {
    std::time_t notAfter;
    std::time_t notBefore;
    
    inline bool operator ==(const Validity &other) const;
    inline bool operator !=(const Validity &other) const; 
  };

  SO_API Expected<ecdsa::Signature> ecdsaSignature(const X509 &cert);
  SO_API Expected<size_t> extensionsCount(const X509 &cert);
  SO_API Expected<Info> issuer(const X509 &cert);
  SO_API Expected<std::string> issuerString(const X509 &cert);
  SO_API Expected<bool> isCa(X509 &cert);
  SO_API Expected<bool> isSelfSigned(X509 &cert);
  SO_API Expected<X509_uptr> pemToX509(const std::string &pemCert);
  SO_API Expected<EVP_PKEY_uptr> pubKey(X509 &cert);
  SO_API Expected<Bytes> serialNumber(X509 &cert);
  SO_API Expected<size_t> signSha1(X509 &cert, EVP_PKEY &pkey);
  SO_API Expected<size_t> signSha256(X509 &cert, EVP_PKEY &pkey);
  SO_API Expected<size_t> signSha384(X509 &cert, EVP_PKEY &pkey);
  SO_API Expected<Bytes> signature(const X509 &cert);
  SO_API Expected<Info> subject(const X509 &cert);
  SO_API Expected<std::string> subjectString(const X509 &cert);
  SO_API Expected<Validity> validity(const X509 &cert);
  SO_API Expected<bool> verifySignature(X509 &cert, EVP_PKEY &pkey);
  SO_API Expected<long> version(const X509 &cert);

  SO_API Expected<void> setIssuer(X509 &cert, const X509 &rootCert);
  SO_API Expected<void> setIssuer(X509 &cert, const Info &commonInfo);
  SO_API Expected<void> setPubKey(X509 &cert, EVP_PKEY &pkey);
  SO_API Expected<void> setSerial(X509 &cert, const Bytes &bytes);
  SO_API Expected<void> setSubject(X509 &cert, const Info &commonInfo);
  SO_API Expected<void> setValidity(X509 &cert, const Validity &validity);
  SO_API Expected<void> setVersion(X509 &cert, long version);
} // namespace x509


/////////////////////////////////////////////////////////////////////////////////
//
//                Implementation
//
/////////////////////////////////////////////////////////////////////////////////

namespace detail {
  SO_LIB std::string errCodeToString(unsigned long errCode)
  {
    constexpr size_t SIZE = 1024;
    char buff[SIZE];
    std::memset(buff, 0x00, SIZE);
    ERR_error_string_n(errCode, buff, SIZE);
    return std::string(buff);
  }

  template<typename T>
  struct uptr_underlying_type
  {
    using type = typename std::remove_pointer<decltype(std::declval<T>().get())>::type;
  };

  template<typename T>
  SO_LIB Expected<T> err(T &&val)
  {
    return Expected<T>(ERR_get_error(), std::move(val));
  }
 
  template
  <
    typename T,
    typename = typename std::enable_if<!detail::is_uptr<T>::value>::type
  >
  SO_LIB Expected<T> err()
  {
    return detail::err<T>({});
  }

  template
  <
    typename T,
    typename T_ = T, // TODO: T_ is placeholder to avoid of 'reassining default template param' error, I should use some smarter solution
    typename = typename std::enable_if<detail::is_uptr<T>::value>::type
  >
  SO_LIB Expected<T> err()
  {
    auto tmp = make_unique<typename uptr_underlying_type<T>::type>(nullptr);
    return detail::err(std::move(tmp));
  }

  template<typename T>
  SO_LIB Expected<T> err(unsigned long errCode)
  { 
    return Expected<T>(errCode);
  }

  SO_LIB Expected<void> err()
  {
    return Expected<void>(ERR_get_error());
  }

  SO_LIB Expected<void> err(unsigned long errCode)
  {
    return Expected<void>(errCode);
  }

  template<typename T>
  SO_LIB Expected<T> ok(T &&val)
  {
    return Expected<T>(0, std::move(val));
  }

  SO_LIB Expected<void> ok()
  {
    return Expected<void>(0);
  }

  SO_LIB Expected<Bytes> evpSign(const Bytes &message, const EVP_MD *evpMd,  EVP_PKEY &privateKey)
  {
    auto mdCtx = make_unique(EVP_MD_CTX_new());
    if(!mdCtx) return detail::err<Bytes>();
    
    const int initStatus = EVP_DigestSignInit(mdCtx.get(), nullptr, evpMd, nullptr, &privateKey);
    if(1 != initStatus) return detail::err<Bytes>();
    
    const int updateStatus = EVP_DigestSignUpdate(mdCtx.get(), message.data(), message.size());
    if(1 != updateStatus) return detail::err<Bytes>();
    
    size_t sigLen = 0;
    int signStatus = EVP_DigestSignFinal(mdCtx.get(), nullptr, &sigLen);
    if(1 != signStatus) return detail::err<Bytes>();
 
    Bytes tmp(sigLen);
    signStatus = EVP_DigestSignFinal(mdCtx.get(), tmp.data(), &sigLen);
    if(1 != signStatus) return detail::err<Bytes>();
        
    Bytes signature(tmp.begin(), std::next(tmp.begin(), static_cast<long>(sigLen))); 
    return detail::ok(std::move(signature));
  }

  SO_LIB Expected<bool> evpVerify(const Bytes &sig, const Bytes &msg, const EVP_MD *evpMd, EVP_PKEY &pubKey)
  {
    auto ctx = make_unique(EVP_MD_CTX_new());
    if (!ctx) return detail::err(false);

    if (1 != EVP_DigestVerifyInit(ctx.get(), nullptr, evpMd, nullptr, &pubKey))
      return detail::err(false);
    
    if(1 != EVP_DigestVerifyUpdate(ctx.get(), msg.data(), msg.size()))
      return detail::err(false); 
   
    const int result = EVP_DigestVerifyFinal(ctx.get(), sig.data(), sig.size());
    return result == 1 ? detail::ok(true) : result == 0 ? detail::ok(false) : detail::err<bool>();
  }
  
  SO_LIB Expected<std::string> nameEntry2String(X509_NAME &name, int nid)
  {
    // X509_NAME_get_text_by_NID() is considered legacy and with limitations, we'll
    // use more safe option
    // all returned pointers here are internal openssl
    // pointers so they must not be freed
    const int entriesCount = X509_NAME_entry_count(&name);
    if(entriesCount < 0) return detail::err<std::string>();
    if(entriesCount == 0) return detail::ok<std::string>("");

    const int position = X509_NAME_get_index_by_NID(&name, nid, -1);
    // if position == -2 then nid is invalid
    if(position == -2) return detail::err<std::string>();
    // item not found, it's not lib error, user should decide if value that is not there
    // is an error or not
    if(position == -1) return detail::ok<std::string>("");
    
    const X509_NAME_ENTRY *entry = X509_NAME_get_entry(&name, position);
    // previously we found correct index, if we got nullptr here it
    // means sth went wrong
    if(!entry) return detail::err<std::string>();
    
    // internal pointer
    const ASN1_STRING *asn1 = X509_NAME_ENTRY_get_data(entry);
    const int asn1EstimatedStrLen = ASN1_STRING_length(asn1);
    if(asn1EstimatedStrLen <= 0) return detail::ok<std::string>("");

    const auto freeOpenssl = [](unsigned char *ptr) { OPENSSL_free(ptr); };
    unsigned char *ptr; // we need to call OPENSSL_free on this
    const int len = ASN1_STRING_to_UTF8(&ptr, asn1);
    std::unique_ptr<unsigned char[], decltype(freeOpenssl)> strBuff(ptr, freeOpenssl);

    std::string ret;
    ret.reserve(static_cast<size_t>(len));
    std::transform(strBuff.get(), strBuff.get() + len, std::back_inserter(ret), [](unsigned char chr){ return static_cast<char>(chr); });

    return detail::ok(std::move(ret)); 
  }

  SO_LIB Expected<std::string> nameToString(const X509_NAME &name, unsigned long flags = XN_FLAG_RFC2253)
  {
    auto bio = make_unique(BIO_new(BIO_s_mem()));
    if(0 > X509_NAME_print_ex(bio.get(), &name, 0, flags))
      return detail::err<std::string>();

    char *dataStart;
    const long nameLength = BIO_get_mem_data(bio.get(), &dataStart);
    if(nameLength < 0) return detail::err<std::string>();
    
    return detail::ok(std::string(dataStart, static_cast<size_t>(nameLength)));
  }

  SO_LIB Expected<x509::Info> commonInfo(X509_NAME &name)
  {
    const auto error = [](unsigned long errCode){ return detail::err<x509::Info>(errCode); }; 
    const auto commonName = nameEntry2String(name, NID_commonName);
    if(!commonName) return error(commonName.errorCode());
    const auto countryName = nameEntry2String(name, NID_countryName);
    if(!countryName) return error(countryName.errorCode());
    const auto organizationName = nameEntry2String(name, NID_organizationName);
    if(!organizationName) return error(organizationName.errorCode());
    const auto localityName = nameEntry2String(name, NID_localityName);
    if(!localityName) return error(localityName.errorCode());
    const auto stateOrProvinceName = nameEntry2String(name, NID_stateOrProvinceName);
    if(!stateOrProvinceName) return error(stateOrProvinceName.errorCode());

    return detail::ok<x509::Info>({ 
        *commonName,
        *countryName,
        *localityName,
        *organizationName,
        *stateOrProvinceName
    });
  }

  SO_LIB Expected<X509_NAME_uptr> info2X509Name(const x509::Info &info)
  {
    auto name = make_unique(X509_NAME_new()); 

    const auto err = []{ return detail::err<X509_NAME_uptr>(); };
    const auto append = [](X509_NAME *nm, int nid, const std::string &val) {
      return val.empty() || X509_NAME_add_entry_by_NID(nm, nid, MBSTRING_ASC, reinterpret_cast<const unsigned char*>(val.c_str()), -1, -1, 0);
    };

    if(!name) return err();
    if(!append(name.get(), NID_commonName, info.commonName)) return err();
    if(!append(name.get(), NID_countryName, info.countryName)) return err();
    if(!append(name.get(), NID_localityName, info.localityName)) return err();
    if(!append(name.get(), NID_organizationName, info.organizationName)) return err();
    if(!append(name.get(), NID_stateOrProvinceName, info.stateOrProvinceName)) return err();

    return detail::ok(std::move(name));
  }

  SO_LIB Expected<size_t> signCert(X509 &cert, EVP_PKEY &key, const EVP_MD *md)
  {
    const int sigLen = X509_sign(&cert, &key, md);
    if(sigLen == 0) return detail::err<size_t>();
    return detail::ok(static_cast<size_t>(sigLen));
  }

  SO_LIB Expected<Bytes> ecdsaSign(const Bytes &dg, EC_KEY &key)
  {
    const int sigLen = ECDSA_size(&key);
    if(0 >= sigLen) return detail::err<Bytes>();

    Bytes tmpSig(static_cast<size_t>(sigLen));
    unsigned int finalSigLen = 0;
    if(1 != ECDSA_sign(0,
          dg.data(),
          static_cast<int>(dg.size()),
          tmpSig.data(),
          &finalSigLen,
          &key))
    {
      return detail::err<Bytes>();
    }

    Bytes signature(tmpSig.begin(), std::next(tmpSig.begin(), finalSigLen));
    return detail::ok(std::move(signature));
  }

  SO_LIB Expected<bool> ecdsaVerifySignature(const Bytes &signature, const Bytes &dg, EC_KEY &publicKey)
  {
    if(1 != ECDSA_verify(0,
          dg.data(),
          static_cast<int>(dg.size()),
          signature.data(),
          static_cast<int>(signature.size()),
          &publicKey))
    {
      return detail::err<bool>();
    }

    return detail::ok(true);
  }

} //namespace detail

SO_API void init()
{
  // Since openssl v.1.1.0 we no longer need to set
  // locking callback for multithreaded support

  OpenSSL_add_all_algorithms();

  // more descriptive error messages
  ERR_load_crypto_strings();
  ERR_load_BIO_strings();
}

SO_API void cleanUp()
{
  ERR_free_strings();
}

namespace asn1 {
  SO_API Expected<ASN1_INTEGER_uptr> encodeInteger(const Bytes &bt)
  {
    auto maybeBn = bignum::bytesToBn(bt);
    if(!maybeBn) return detail::err<ASN1_INTEGER_uptr>(); 
    auto bn = maybeBn.moveValue();
    auto integer = make_unique(BN_to_ASN1_INTEGER(bn.get(), nullptr));
    if(!integer) return detail::err<ASN1_INTEGER_uptr>();
    return detail::ok(std::move(integer)); 
  }

  //SO_API Expected<ASN1_INTEGER_uptr> encodeInteger(uint64_t num);
  
  SO_API Expected<ASN1_OCTET_STRING_uptr> encodeOctet(const Bytes &bt)
  {
    auto ret = make_unique(ASN1_OCTET_STRING_new());
    if(!ret) return detail::err<ASN1_OCTET_STRING_uptr>();
    if(1 != ASN1_OCTET_STRING_set(ret.get(), bt.data(), static_cast<int>(bt.size())))
      return detail::err<ASN1_OCTET_STRING_uptr>();

    return detail::ok(std::move(ret));
  }

  SO_API Expected<ASN1_TIME_uptr> stdTimeToTime(std::time_t time)
  {
    auto ret = make_unique(ASN1_TIME_set(nullptr, time));
    if(!ret) return detail::err<ASN1_TIME_uptr>();
    return detail::ok(std::move(ret));
  }

  SO_API Expected<std::time_t> timeToStdTime(const ASN1_TIME &asn1Time)
  {
    // TODO: If we're extremly unlucky, we can be off by whole second.
    // Despite tests didn't fail once, I should consider just straight string parsing here.
    static_assert(sizeof(std::time_t) >= sizeof(int64_t), "std::time_t size too small, the dates may overflow");
    static constexpr int64_t SECONDS_IN_A_DAY = 24 * 60 * 60;
    using sysClock = std::chrono::system_clock;

    int pday, psec;
    if(1 != ASN1_TIME_diff(&pday, &psec, nullptr, &asn1Time)) return detail::err<std::time_t>(); 
    return detail::ok(sysClock::to_time_t(sysClock::now()) + pday * SECONDS_IN_A_DAY + psec);
  } 
} // namespace asn1

namespace bignum {
  SO_API Expected<Bytes> bnToBytes(const BIGNUM &bn)
  {
    const auto sz = size(bn);
    if(!sz) return detail::err<Bytes>(sz.errorCode());
    Bytes ret(*sz);
    BN_bn2bin(&bn, ret.data());
    return detail::ok(std::move(ret));
  }

  SO_API Expected<BIGNUM_uptr> bytesToBn(const Bytes &bt)
  {
    auto ret = make_unique(BN_bin2bn(bt.data(), static_cast<int>(bt.size()), nullptr));
    if(!ret) return detail::err<BIGNUM_uptr>();
    return detail::ok(std::move(ret));
  }

  SO_API Expected<size_t> size(const BIGNUM &bn)
  {
    const int bnlen = BN_num_bytes(&bn);
    if(bnlen < 0) return detail::err<size_t>();
    return detail::ok(static_cast<size_t>(bnlen));
  }
}// namespace bignum

namespace ecdsa {
  SO_API Expected<bool> checkKey(const EC_KEY &ecKey)
  {
    if(1 != EC_KEY_check_key(&ecKey)) return detail::err(false);
    return detail::ok(true);
  }
  
  SO_API Expected<EC_KEY_uptr> copyKey(const EC_KEY &ecKey)
  {
    auto copy = make_unique(EC_KEY_dup(&ecKey));
    if(!copy) return detail::err<EC_KEY_uptr>();
    return detail::ok(std::move(copy));
  }

  SO_API Expected<Curve> curveOf(const EC_KEY &key)
  {
    const EC_GROUP* group = EC_KEY_get0_group(&key);
    if(!group) return detail::err<Curve>();
    const int nid = EC_GROUP_get_curve_name(group);
    if(0 == nid) return detail::err<Curve>();
    return detail::ok(static_cast<Curve>(nid)); 
  }

  SO_API Expected<Bytes> der(const Signature &signature)
  {
    auto maybeR = bignum::bytesToBn(signature.r);
    if(!maybeR) return detail::err<Bytes>(maybeR.errorCode());
    auto maybeS = bignum::bytesToBn(signature.s);
    if(!maybeS) return detail::err<Bytes>(maybeS.errorCode());

    auto r = maybeR.moveValue();
    auto s = maybeS.moveValue();
    auto sig = make_unique(ECDSA_SIG_new()); 
    if(!sig) return detail::err<Bytes>();
    if(1 != ECDSA_SIG_set0(sig.get(), r.release(), s.release()))
      return detail::err<Bytes>();

    const int derLen = i2d_ECDSA_SIG(sig.get(), nullptr); 
    if(0 == derLen) return detail::err<Bytes>();
    
    Bytes ret;
    ret.reserve(static_cast<size_t>(derLen));
    auto *derIt = ret.data();
    if(!i2d_ECDSA_SIG(sig.get(), &derIt)) return detail::err<Bytes>();
    return detail::ok(std::move(ret));
  }

  SO_API Expected<EC_KEY_uptr> extractPublic(const EC_KEY &key)
  {
    auto ret = make_unique(EC_KEY_new());
    if(!ret) return detail::err<EC_KEY_uptr>();
    const EC_GROUP *group = EC_KEY_get0_group(&key);
    if(1 != EC_KEY_set_group(ret.get(), group)) return detail::err<EC_KEY_uptr>();

    const EC_POINT* pubPoint = EC_KEY_get0_public_key(&key);
    if(1 != EC_KEY_set_public_key(ret.get(), pubPoint)) return detail::err<EC_KEY_uptr>();
    return detail::ok(std::move(ret));
  }

  SO_API Expected<EVP_PKEY_uptr> keyToEvp(const EC_KEY &ecKey)
  {
    // I can keep const in arguments by doing this copy
    auto copy = make_unique(EC_KEY_dup(&ecKey));
    if(!copy) return detail::err<EVP_PKEY_uptr>();

    EVP_PKEY_uptr evpKey = make_unique(EVP_PKEY_new());
    if (!evpKey) return detail::err<EVP_PKEY_uptr>();

    if (1 != EVP_PKEY_set1_EC_KEY(evpKey.get(), copy.get()))
        return detail::err<EVP_PKEY_uptr>();
    
    return detail::ok(std::move(evpKey));
  }


  SO_API Expected<EC_KEY_uptr> pemToPublicKey(const std::string &pemPub)
  {
    auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPub.c_str()), static_cast<int>(pemPub.size())));
    if(!bio) return detail::err<EC_KEY_uptr>();
    EC_KEY *rawKey = PEM_read_bio_EC_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    if(!rawKey) return detail::err<EC_KEY_uptr>(); 
    return detail::ok(make_unique(rawKey));
  }

  SO_API Expected<EC_KEY_uptr> pemToPrivateKey(const std::string &pemPriv)
  {
    auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPriv.c_str()), static_cast<int>(pemPriv.size())));
    if(!bio) return detail::err<EC_KEY_uptr>();
    EC_KEY *rawKey = PEM_read_bio_ECPrivateKey(bio.get(), nullptr, nullptr, nullptr);
    if(!rawKey) return detail::err<EC_KEY_uptr>();
    return detail::ok(make_unique(rawKey));
  }

  SO_API Expected<EC_KEY_uptr> generateKey(Curve curve)
  {
    const int nidCurve = static_cast<int>(curve);
    auto key = make_unique(EC_KEY_new_by_curve_name(nidCurve));
    if(!key) return detail::err<EC_KEY_uptr>();
    if(!EC_KEY_generate_key(key.get())) return detail::err<EC_KEY_uptr>();
    return detail::ok(std::move(key));
  }

  SO_API Expected<Bytes> signSha1(const Bytes &message, EC_KEY &key)
  {
    const auto digest = hash::sha1(message);
    if(!digest) return detail::err<Bytes>(digest.errorCode());
    return detail::ecdsaSign(*digest, key);
  }

  SO_API Expected<Bytes> signSha224(const Bytes &message, EC_KEY &key)
  {
    const auto digest = hash::sha224(message);
    if(!digest) return detail::err<Bytes>(digest.errorCode());
    return detail::ecdsaSign(*digest, key);
  }

  SO_API Expected<Bytes> signSha256(const Bytes &message, EC_KEY &key)
  {
    const auto digest = hash::sha256(message);
    if(!digest) return detail::err<Bytes>(digest.errorCode());
    return detail::ecdsaSign(*digest, key);
  }

  SO_API Expected<Bytes> signSha384(const Bytes &message, EC_KEY &key)
  {
    const auto digest = hash::sha384(message);
    if(!digest) return detail::err<Bytes>(digest.errorCode());
    return detail::ecdsaSign(*digest, key);
  }
  
  SO_API Expected<Bytes> signSha512(const Bytes &message, EC_KEY &key)
  {
    const auto digest = hash::sha512(message);
    if(!digest) return detail::err<Bytes>(digest.errorCode());
    return detail::ecdsaSign(*digest, key);
  }

  SO_API Expected<bool> verifySha1Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey)
  {
    const auto digest = hash::sha1(message);
    if(!digest) return detail::err<bool>(digest.errorCode());
    return detail::ecdsaVerifySignature(signature, *digest, publicKey);
  }

  SO_API Expected<bool> verifySha224Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey)
  {
    const auto digest = hash::sha224(message);
    if(!digest) return detail::err<bool>(digest.errorCode());
    return detail::ecdsaVerifySignature(signature, *digest, publicKey);
  }

  SO_API Expected<bool> verifySha256Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey)
  {
    const auto digest = hash::sha256(message);
    if(!digest) return detail::err<bool>(digest.errorCode());
    return detail::ecdsaVerifySignature(signature, *digest, publicKey);
  }

  SO_API Expected<bool> verifySha384Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey)
  {
    const auto digest = hash::sha384(message);
    if(!digest) return detail::err<bool>(digest.errorCode());
    return detail::ecdsaVerifySignature(signature, *digest, publicKey);
  }

  SO_API Expected<bool> verifySha512Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey)
  {
    const auto digest = hash::sha512(message);
    if(!digest) return detail::err<bool>(digest.errorCode());
    return detail::ecdsaVerifySignature(signature, *digest, publicKey);
  }
} //namespace ecdsa

namespace evp {
  SO_API Expected<EVP_PKEY_uptr> pemToPublicKey(const std::string &pemPub)
  {
    auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPub.c_str()), static_cast<int>(pemPub.size())));
    if(!bio) return detail::err<EVP_PKEY_uptr>(); 
    EVP_PKEY *rawKey = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    if(!rawKey) return detail::err<EVP_PKEY_uptr>();
    return detail::ok(make_unique(rawKey));
  }

  SO_API Expected<EVP_PKEY_uptr> pemToPrivateKey(const std::string &pemPriv)
  {
    auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPriv.c_str()), static_cast<int>(pemPriv.size())));
    if(!bio) return detail::err<EVP_PKEY_uptr>(); 
    EVP_PKEY *rawKey = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    if(!rawKey) return detail::err<EVP_PKEY_uptr>();
    return detail::ok(make_unique(rawKey));
  }

  SO_API Expected<Bytes> signSha1(const Bytes &message, EVP_PKEY &privateKey)
  { 
    return detail::evpSign(message, EVP_sha1(), privateKey);
  }

  SO_API Expected<Bytes> signSha224(const Bytes &message, EVP_PKEY &privateKey)
  { 
    return detail::evpSign(message, EVP_sha224(), privateKey);
  }

  SO_API Expected<Bytes> signSha256(const Bytes &message, EVP_PKEY &privateKey)
  { 
    return detail::evpSign(message, EVP_sha256(), privateKey);
  }

  SO_API Expected<Bytes> signSha384(const Bytes &message, EVP_PKEY &privateKey)
  { 
    return detail::evpSign(message, EVP_sha384(), privateKey);
  }

  SO_API Expected<Bytes> signSha512(const Bytes &message, EVP_PKEY &privateKey)
  { 
    return detail::evpSign(message, EVP_sha512(), privateKey);
  }

  SO_API Expected<bool> verifySha1Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey)
  {
    return detail::evpVerify(signature, message, EVP_sha1(), pubKey); 
  }

  SO_API Expected<bool> verifySha224Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey)
  {
    return detail::evpVerify(signature, message, EVP_sha224(), pubKey); 
  }

  SO_API Expected<bool> verifySha256Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey)
  {
    return detail::evpVerify(signature, message, EVP_sha256(), pubKey); 
  }

  SO_API Expected<bool> verifySha384Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey)
  {
    return detail::evpVerify(signature, message, EVP_sha384(), pubKey); 
  }

  SO_API Expected<bool> verifySha512Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey)
  {
    return detail::evpVerify(signature, message, EVP_sha512(), pubKey); 
  }
} //namespace evp

namespace hash {
  SO_API Expected<Bytes> md4(const Bytes &data)
  {
    Bytes hash(MD4_DIGEST_LENGTH);
    MD4_CTX ctx;
    if(1 != MD4_Init(&ctx)) return detail::err<Bytes>();
    if(1 != MD4_Update(&ctx, data.data(), data.size())) return detail::err<Bytes>();
    if(1 != MD4_Final(hash.data(), &ctx)) return detail::err<Bytes>();
    return detail::ok(std::move(hash));
  }

  SO_API Expected<Bytes> md5(const Bytes &data)
  {
    Bytes hash(MD5_DIGEST_LENGTH);
    MD5_CTX ctx;
    if(1 != MD5_Init(&ctx)) return detail::err<Bytes>();
    if(1 != MD5_Update(&ctx, data.data(), data.size())) return detail::err<Bytes>();
    if(1 != MD5_Final(hash.data(), &ctx)) return detail::err<Bytes>();
    return detail::ok(std::move(hash));
  }

  SO_API Expected<Bytes> sha1(const Bytes &data)
  {
    Bytes hash(SHA_DIGEST_LENGTH);
    SHA_CTX ctx;
    if(1 != SHA1_Init(&ctx)) return detail::err<Bytes>();
    if(1 != SHA1_Update(&ctx, data.data(), data.size())) return detail::err<Bytes>();
    if(1 != SHA1_Final(hash.data(), &ctx)) return detail::err<Bytes>();
    return detail::ok(std::move(hash));
  }
  
  SO_API Expected<Bytes> sha224(const Bytes &data)
  {
    Bytes hash(SHA224_DIGEST_LENGTH);
    SHA256_CTX ctx;
    if(1 != SHA224_Init(&ctx)) return detail::err<Bytes>();
    if(1 != SHA224_Update(&ctx, data.data(), data.size())) return detail::err<Bytes>();
    if(1 != SHA224_Final(hash.data(), &ctx)) return detail::err<Bytes>();
    return detail::ok(std::move(hash));
  }

  SO_API Expected<Bytes> sha256(const Bytes &data)
  {
    Bytes hash(SHA256_DIGEST_LENGTH);
    SHA256_CTX ctx;
    if(1 != SHA256_Init(&ctx)) return detail::err<Bytes>();
    if(1 != SHA256_Update(&ctx, data.data(), data.size())) return detail::err<Bytes>();
    if(1 != SHA256_Final(hash.data(), &ctx)) return detail::err<Bytes>();
    return detail::ok(std::move(hash));
  }

  SO_API Expected<Bytes> sha384(const Bytes &data)
  {
    Bytes hash(SHA384_DIGEST_LENGTH);
    SHA512_CTX ctx;
    if(1 != SHA384_Init(&ctx)) return detail::err<Bytes>();
    if(1 != SHA384_Update(&ctx, data.data(), data.size())) return detail::err<Bytes>();
    if(1 != SHA384_Final(hash.data(), &ctx)) return detail::err<Bytes>();
    return detail::ok(std::move(hash));
  }

  SO_API Expected<Bytes> sha512(const Bytes &data)
  {
    Bytes hash(SHA512_DIGEST_LENGTH);
    SHA512_CTX ctx;
    if(1 != SHA512_Init(&ctx)) return detail::err<Bytes>();
    if(1 != SHA512_Update(&ctx, data.data(), data.size())) return detail::err<Bytes>();
    if(1 != SHA512_Final(hash.data(), &ctx)) return detail::err<Bytes>();
    return detail::ok(std::move(hash));
  }
} // namespace hash

namespace rand {
  SO_API Expected<Bytes> bytes(unsigned short numOfBytes)
  {
    Bytes ret(static_cast<size_t>(numOfBytes));
    if(1 != RAND_bytes(ret.data(), static_cast<int>(numOfBytes)))
      return detail::err<Bytes>();

    return detail::ok(std::move(ret));
  }
} // namespace rand

namespace x509 {
  inline bool Info::operator ==(const Info &other) const
  {
    return std::tie( commonName, countryName, organizationName, localityName, stateOrProvinceName) ==
      std::tie(other.commonName, other.countryName, other.organizationName, other.localityName, other.stateOrProvinceName); 
  }

  inline bool Info::operator !=(const Info &other) const
  {
    return !(*this == other);
  }
 
  inline bool Validity::operator==(const Validity &other) const
  {
    return std::tie(notBefore, notAfter) == std::tie(other.notBefore, other.notAfter);
  }
  
  inline bool Validity::operator!=(const Validity &other) const
  {
    return !(*this == other);
  }

  SO_API Expected<Info> issuer(const X509 &cert)
  {
    // this is internal ptr and must not be freed
    X509_NAME *issuer = X509_get_issuer_name(&cert);
    if(!issuer) return detail::err<Info>();
    return detail::commonInfo(*issuer); 
  }
  
  SO_API Expected<std::string> issuerString(const X509 &cert)
  {
    // this is internal ptr and must not be freed
    const X509_NAME *issuer = X509_get_issuer_name(&cert);
    if(!issuer) return detail::err<std::string>();
    return detail::nameToString(*issuer);
  }

  SO_API Expected<bool> isCa(X509 &cert)
  {
    if(0 == X509_check_ca(&cert)){
      const auto lastErr = ERR_get_error();
      if(0 == lastErr) return detail::ok(false);
      return detail::err<bool>(lastErr);
    }
    return detail::ok(true);
  }

  SO_API Expected<bool> isSelfSigned(X509 &cert)
  {
    if(X509_V_OK == X509_check_issued(&cert, &cert))
      return detail::ok(true);
    
    const auto lastErr = ERR_get_error();
    if(0 == lastErr) return detail::ok(false);
    return detail::err<bool>(lastErr);
  }

  SO_API Expected<X509_uptr> pemToX509(const std::string &pemCert)
  {
    BIO_uptr bio = make_unique(BIO_new(BIO_s_mem()));

    if(0 >= BIO_write(bio.get(), pemCert.c_str(), static_cast<int>(pemCert.length())))
      return detail::err<X509_uptr>(); 

    auto ret = make_unique(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if(!ret) return detail::err<X509_uptr>();
    return detail::ok(std::move(ret));
  }

  SO_API Expected<EVP_PKEY_uptr> pubKey(X509 &cert)
  { 
    auto pkey = make_unique(X509_get_pubkey(&cert));
    if(!pkey) return detail::err<EVP_PKEY_uptr>();
    return detail::ok(std::move(pkey));
  }

  SO_API Expected<Bytes> serialNumber(X509 &cert)
  {
    // both internal pointers, must not be freed
    const ASN1_INTEGER *serialNumber = X509_get_serialNumber(&cert);
    if(!serialNumber) return detail::err<Bytes>();
    const BIGNUM *bn = ASN1_INTEGER_to_BN(serialNumber, nullptr);
    if(!bn) return detail::err<Bytes>();
    return bignum::bnToBytes(*bn);
  }

  SO_API Expected<size_t> signSha1(X509 &cert, EVP_PKEY &pkey)
  {
    return detail::signCert(cert, pkey, EVP_sha256());  
  }

  SO_API Expected<size_t> signSha256(X509 &cert, EVP_PKEY &key)
  {
    return detail::signCert(cert, key, EVP_sha256());  
  }

  SO_API Expected<size_t> signSha384(X509 &cert, EVP_PKEY &pkey)
  {
    return detail::signCert(cert, pkey, EVP_sha384());  
  }

  SO_API Expected<Bytes> signature(const X509 &cert)
  {
    // both internal pointers and must not be freed
    const ASN1_BIT_STRING *psig = nullptr;
    const X509_ALGOR *palg = nullptr;
    X509_get0_signature(&psig, &palg, &cert);
    if(!palg || !psig) return detail::err<Bytes>();

    Bytes rawDerSequence;
    rawDerSequence.reserve(static_cast<size_t>(psig->length));
    std::memcpy(rawDerSequence.data(), psig->data, static_cast<size_t>(psig->length));

    return detail::ok(std::move(rawDerSequence));
  }
  
  SO_API Expected<ecdsa::Signature> ecdsaSignature(const X509 &cert)
  {
    // both internal pointers and must not be freed
    const ASN1_BIT_STRING *psig = nullptr;
    const X509_ALGOR *palg = nullptr;
    X509_get0_signature(&psig, &palg, &cert);
    if(!palg || !psig) return detail::err<ecdsa::Signature>();

    const unsigned char *it = psig->data;
    const auto sig = make_unique(d2i_ECDSA_SIG(nullptr, &it, static_cast<long>(psig->length)));
    if(!sig) return detail::err<ecdsa::Signature>();

    // internal pointers
    const BIGNUM *r,*s;
    ECDSA_SIG_get0(sig.get(), &r, &s);
    return detail::ok(ecdsa::Signature{ *bignum::bnToBytes(*r), *bignum::bnToBytes(*s) });
  }

  SO_API Expected<size_t> extensionsCount(const X509 &cert)
  {
    const int extsCount = X509_get_ext_count(&cert);
    if(extsCount < 0) return detail::err<size_t>(); 
    return detail::ok(static_cast<size_t>(extsCount));
  }

  SO_API Expected<Info> subject(const X509 &cert)
  {
    // this is internal ptr and must not be freed
    X509_NAME *subject = X509_get_subject_name(&cert);
    if(!subject) return detail::err<Info>();
    return detail::commonInfo(*subject); 
  }

  SO_API Expected<std::string> subjectString(const X509 &cert)
  {
    // this is internal ptr and must not be freed
    const X509_NAME *subject = X509_get_subject_name(&cert);
    if(!subject) return detail::err<std::string>();
    return detail::nameToString(*subject);
  }

  SO_API Expected<Validity> validity(const X509 &cert)
  {
    const auto notAfter = X509_get0_notAfter(&cert);
    if(!notAfter) return detail::err<Validity>();
    const auto notBefore = X509_get0_notBefore(&cert);
    if(!notBefore) return detail::err<Validity>();
    auto notBeforeTime = asn1::timeToStdTime(*notBefore);
    if(!notBeforeTime) return detail::err<Validity>(notBeforeTime.errorCode());
    auto notAfterTime = asn1::timeToStdTime(*notAfter);
    if(!notAfterTime) return detail::err<Validity>(notAfterTime.errorCode());
    return detail::ok(Validity{*notAfterTime, *notBeforeTime});
  }

  SO_API Expected<bool> verifySignature(X509 &cert, EVP_PKEY &pkey)
  {
    const int result = X509_verify(&cert, &pkey);
    return result == 1 ? detail::ok(true) : result == 0 ? detail::ok(false) : detail::err(false);
  }

  SO_API Expected<long> version(const X509 &cert)
  {
    // TODO: I kept returning Expected<> to keep API
    // consistent, but I could just return long here....I don't know...
    // Version is zero indexed, thus +1
    return detail::ok(X509_get_version(&cert) + 1);
  }

  SO_API Expected<void> setIssuer(X509 &cert, const X509 &rootCert)
  {
    X509_NAME *issuer = X509_get_subject_name(&rootCert);
    if(!issuer) return detail::err();
    if(1 != X509_set_issuer_name(&cert, issuer)) return detail::err();
    return detail::ok();
  }

  SO_API Expected<void> setIssuer(X509 &cert, const Info &info)
  {
    auto maybeIssuer = detail::info2X509Name(info);
    if(!maybeIssuer) return detail::err();
    auto issuer = maybeIssuer.moveValue();
    if(1 != X509_set_issuer_name(&cert, issuer.get())) return detail::err(); 
    return detail::ok();
  }

  SO_API Expected<void> setPubKey(X509 &cert, EVP_PKEY &pkey)
  {
    if(1 != X509_set_pubkey(&cert, &pkey)) return detail::err();
    return detail::ok();
  }
 
  SO_API Expected<void> setSerial(X509 &cert, const Bytes &bytes)
  {
    auto maybeInt = asn1::encodeInteger(bytes);
    if(!maybeInt) return detail::err(maybeInt.errorCode());
    auto integer = maybeInt.moveValue();
    if(1 != X509_set_serialNumber(&cert, integer.get()))
      return detail::err();

    return detail::ok();
  }

  SO_API Expected<void> setSubject(X509 &cert, const Info &info)
  {
    auto maybeSubject = detail::info2X509Name(info); 
    if(!maybeSubject) return detail::err();
    auto subject = maybeSubject.moveValue();
    if(1 != X509_set_subject_name(&cert, subject.get())) return detail::err();
    return detail::ok();
  }

  SO_API Expected<void> setValidity(X509 &cert, const Validity &validity)
  {
    ASN1_TIME_uptr notAfterTime = make_unique(ASN1_TIME_set(nullptr, validity.notAfter));
    if(!notAfterTime) return detail::err();
    ASN1_TIME_uptr notBeforeTime = make_unique(ASN1_TIME_set(nullptr, validity.notBefore));
    if(!notBeforeTime) return detail::err();
    if(1 != X509_set1_notBefore(&cert, notBeforeTime.get())) return detail::err();
    if(1 != X509_set1_notAfter(&cert, notAfterTime.get())) return detail::err();
    return detail::ok();
  }

  SO_API Expected<void> setVersion(X509 &cert, long version)
  {
    --version;
    if(1 != X509_set_version(&cert, version)) return detail::err();
    return detail::ok();
  }
} // namespace x509

} // namepsace so

#endif
