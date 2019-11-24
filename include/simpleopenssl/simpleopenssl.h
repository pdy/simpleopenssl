#ifndef PDY_SIMPLEOPENSSL_H_
#define PDY_SIMPLEOPENSSL_H_

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
#include <tuple>

namespace so {

using Bytes = std::vector<uint8_t>;

#define SO_API static inline
#define SO_PRV static

namespace internal {
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

} //namespace internal
  
#define CUSTOM_DELETER_UNIQUE_POINTER(Type, Deleter)\
namespace internal {                                  \
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
using Type ## _uptr = internal::CustomDeleterUniquePtr<Type>; \
namespace internal {                                          \
template<> struct is_uptr<internal::CustomDeleterUniquePtr<Type>> : std::true_type {};}

template<typename T, typename D = internal::CustomDeleter<T>>
SO_API auto make_unique(T *ptr) -> std::unique_ptr<T, D>
{
  return std::unique_ptr<T, D>(ptr);
}


CUSTOM_DELETER_UNIQUE_POINTER(ASN1_OBJECT, ASN1_OBJECT_free);
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
CUSTOM_DELETER_UNIQUE_POINTER(X509_EXTENSION, X509_EXTENSION_free);
CUSTOM_DELETER_UNIQUE_POINTER(X509_NAME, X509_NAME_free);
CUSTOM_DELETER_UNIQUE_POINTER(X509_NAME_ENTRY, X509_NAME_ENTRY_free);

namespace internal {

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

template<typename ID>
struct X509Extension
{
  ID id;
  bool critical;
  std::string name;
  std::string oidNumerical;
  Bytes data;

  bool operator==(const X509Extension<ID> &other) const
  {
    return std::tie(id, critical, name, oidNumerical, data)
        == std::tie(other.id, other.critical, other.name, other.oidNumerical, other.data);
  }

  bool operator!=(const X509Extension<ID> &other) const
  {
    return !(*this == other);
  }
};


SO_PRV std::string errCodeToString(unsigned long errCode);

} //namespace internal

template<typename T>
class Expected : public internal::AddValueRef<T, Expected<T>, typename internal::is_uptr<T>::type>
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
     
  explicit operator bool() const noexcept
  {
    return hasValue(); 
  }
 
  T&& moveValue()
  {
    return std::move(m_value);
  }

  unsigned long errorCode() const noexcept
  {
    return m_opensslErrCode;
  }

  bool hasValue() const noexcept
  { 
    return !hasError(); 
  }

  bool hasError() const noexcept
  {
    return 0 != m_opensslErrCode;
  }

  std::string msg() const
  {
    if(0 == m_opensslErrCode)
      return "OK";

    return internal::errCodeToString(m_opensslErrCode); 
  }

private:
  friend internal::AddValueRef<T, Expected<T>, typename internal::is_uptr<T>::type>;

  T m_value;
  unsigned long m_opensslErrCode;
};

template<>
class Expected<void>
{
public:
  explicit Expected(unsigned long opensslErrorCode)
    : m_opensslErrCode{opensslErrorCode} {}
 
  explicit operator bool() const noexcept
  {
    return !hasError();
  }

  bool hasError() const noexcept
  {
    return 0 != m_opensslErrCode;
  }

  unsigned long errorCode() const noexcept
  {
    return m_opensslErrCode;
  }

  std::string msg() const
  {
    if(0 == m_opensslErrCode)
      return "OK";

    return internal::errCodeToString(m_opensslErrCode); 
  }

private:
  unsigned long m_opensslErrCode;
};


/////////////////////////////////////////////////////////////////////////////////
//
//                           MAIN API 
//
/////////////////////////////////////////////////////////////////////////////////


SO_API void init();
SO_API void cleanUp();

namespace asn1 {
  enum class Form : int
  {
    NAME = 0,
    NUMERICAL = 1
  };

  SO_API Expected<std::string> convertObjToStr(const ASN1_OBJECT &obj, Form form = Form::NAME);
  SO_API Expected<ASN1_TIME_uptr> convertToAsn1Time(std::time_t time);
  SO_API Expected<std::time_t> convertToStdTime(const ASN1_TIME &asn1Time);

  SO_API Expected<ASN1_INTEGER_uptr> encodeInteger(const Bytes &bt);
  SO_API Expected<ASN1_OBJECT_uptr> encodeObject(const std::string &nameOrNumerical);
  SO_API Expected<ASN1_OCTET_STRING_uptr> encodeOctet(const Bytes &bt);
  SO_API Expected<ASN1_OCTET_STRING_uptr> encodeOctet(const std::string &str); 
} // namepsace asn1

namespace bignum { 
  SO_API Expected<BIGNUM_uptr> convertToBignum(const Bytes &bt);
  SO_API Expected<Bytes> convertToBytes(const BIGNUM &bn);
  
  SO_API Expected<size_t> getByteLen(const BIGNUM &bn);
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
    
    inline bool operator ==(const Signature &other) const;
    inline bool operator !=(const Signature &other) const; 
  };

  SO_API Expected<EC_KEY_uptr> convertPemToPrivKey(const std::string &pemPriv);
  SO_API Expected<EC_KEY_uptr> convertPemToPubKey(const std::string &pemPub); 
  SO_API Expected<Bytes> convertToDer(const Signature &signature); 
  SO_API Expected<EVP_PKEY_uptr> convertToEvp(const EC_KEY &key);
  SO_API Expected<Signature> convertToSignature(const Bytes &derSigBytes);

  SO_API Expected<bool> checkKey(const EC_KEY &ecKey);
  SO_API Expected<EC_KEY_uptr> copyKey(const EC_KEY &ecKey);
  SO_API Expected<EC_KEY_uptr> generateKey(Curve curve);
  SO_API Expected<Curve> getCurve(const EC_KEY &key);
  SO_API Expected<EC_KEY_uptr> getPublic(const EC_KEY &key);
 
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
  SO_API Expected<EVP_PKEY_uptr> convertPemToPrivKey(const std::string &pemPriv);
  SO_API Expected<EVP_PKEY_uptr> convertPemToPubKey(const std::string &pemPub);
  
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
  SO_API Expected<Bytes> md4(const std::string &str);
  SO_API Expected<Bytes> md5(const Bytes &data);
  SO_API Expected<Bytes> md5(const std::string &str);
  SO_API Expected<Bytes> sha1(const Bytes &data);
  SO_API Expected<Bytes> sha1(const std::string &str);
  SO_API Expected<Bytes> sha224(const Bytes &data);
  SO_API Expected<Bytes> sha224(const std::string &str);
  SO_API Expected<Bytes> sha256(const Bytes &data);
  SO_API Expected<Bytes> sha256(const std::string &str);
  SO_API Expected<Bytes> sha384(const Bytes &data);
  SO_API Expected<Bytes> sha384(const std::string &str);
  SO_API Expected<Bytes> sha512(const Bytes &data);
  SO_API Expected<Bytes> sha512(const std::string &str);

  SO_API Expected<Bytes> fileMD4(const std::string &path);
  SO_API Expected<Bytes> fileMD5(const std::string &path);
  SO_API Expected<Bytes> fileSHA1(const std::string &path);
  SO_API Expected<Bytes> fileSHA224(const std::string &path);
  SO_API Expected<Bytes> fileSHA256(const std::string &path);
  SO_API Expected<Bytes> fileSHA384(const std::string &path);
  SO_API Expected<Bytes> fileSHA512(const std::string &path);
} // namespace hash

namespace rand {
  SO_API Expected<Bytes> bytes(unsigned short numOfBytes);
} //namespace rand

namespace rsa { 
  // OPENSSL_RSA_MAX_MODULUS_BITS 16384
  enum class KeyBits : int
  {
    _1024_ = 1024,
    _2048_ = 2048,
    _3072_ = 3072,
    _4096_ = 4096,
    _5120_ = 5120,
    _6144_ = 6144,
    _7168_ = 7168
  };

  enum class Exponent : unsigned long
  {
    _3_ = RSA_3,
    _17_ = 0x11L,
    _65537_ = RSA_F4
  };

  SO_API Expected<RSA_uptr> convertPemToPrivKey(const std::string &pemPriv);
  SO_API Expected<RSA_uptr> convertPemToPubKey(const std::string &pemPub);
  SO_API Expected<std::string> convertPrivKeyToPem(RSA &rsa);
  //SO_API Expected<std::string> convertPubKeyToPem(RSA &rsa);
  SO_API Expected<EVP_PKEY_uptr> convertToEvp(RSA &rsa);
  SO_API Expected<bool> checkKey(RSA &rsa);
 
  SO_API Expected<RSA_uptr> generateKey(KeyBits keySize, Exponent exponent = Exponent::_65537_);
  SO_API Expected<KeyBits> getKeyBits(const RSA &rsa);
  SO_API Expected<RSA_uptr> getPublic(RSA &rsa);

  SO_API Expected<Bytes> signSha1(const Bytes &message, RSA &privateKey);
  SO_API Expected<Bytes> signSha224(const Bytes &msg, RSA &privKey);
  SO_API Expected<Bytes> signSha256(const Bytes &msg, RSA &privKey);
  SO_API Expected<Bytes> signSha384(const Bytes &msg, RSA &privKey);
  SO_API Expected<Bytes> signSha512(const Bytes &msg, RSA &privKey);
  
  SO_API Expected<bool> verifySha1Signature(const Bytes &signature, const Bytes &message, RSA &pubKey);
  SO_API Expected<bool> verifySha224Signature(const Bytes &signature, const Bytes &message, RSA &pubKey);
  SO_API Expected<bool> verifySha256Signature(const Bytes &signature, const Bytes &message, RSA &pubKey);
  SO_API Expected<bool> verifySha384Signature(const Bytes &signature, const Bytes &message, RSA &pubKey);
  SO_API Expected<bool> verifySha512Signature(const Bytes &signature, const Bytes &message, RSA &pubKey);
} // namespace rsa

namespace x509 {
   
  enum class CertExtensionId : int
  {
    // as of https://www.openssl.org/docs/man1.1.0/crypto/X509_REVOKED_add1_ext_i2d.html
    
    UNDEF                       = NID_undef,
    BASIC_CONSTRAINTS           = NID_basic_constraints,
    KEY_USAGE                   = NID_key_usage,
    EXT_KEY_USAGE               = NID_ext_key_usage,
    SUBJECT_KEY_IDENTIFIER      = NID_subject_key_identifier,
    AUTHORITY_KEY_IDENTIFIER    = NID_authority_key_identifier,
    PRIVATE_KEY_USAGE_PERIOD    = NID_private_key_usage_period,
    SUBJECT_ALT_NAME            = NID_subject_alt_name,
    ISSUER_ALT_NAME             = NID_issuer_alt_name,
    INFO_ACCESS                 = NID_info_access,
    SINFO_ACCESS                = NID_sinfo_access,
    NAME_CONSTRAINTS            = NID_name_constraints,
    CERTIFICATE_POLICIES        = NID_certificate_policies,
    POLICY_MAPPINGS             = NID_policy_mappings,
    POLICY_CONSTRAINTS          = NID_policy_constraints,
    INHIBIT_ANY_POLICY          = NID_inhibit_any_policy,
    TLS_FEATURE                 = NID_tlsfeature,
    
    NETSCAPE_CERT_TYPE          = NID_netscape_cert_type,
    NETSCAPE_BASE_URL           = NID_netscape_base_url,
    NETSCAPE_REVOCATION_URL     = NID_netscape_revocation_url,
    NETSCAPE_CA_REVOCATION_URL  = NID_netscape_ca_revocation_url,
    NETSCAPE_RENEWAL_URL        = NID_netscape_renewal_url,
    NETSCAPE_CA_POLICY_URL      = NID_netscape_ca_policy_url,
    NETSCAPE_SSL_SERVER_NAME    = NID_netscape_ssl_server_name,
    NETSCAPE_COMMENT            = NID_netscape_comment,
    
    STRONG_EXTRANET_ID          = NID_sxnet,
    PROXY_CERTIFICATE_INFO      = NID_proxyCertInfo
  };
 
  using CertExtension = internal::X509Extension<CertExtensionId>;

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

  enum class Version : long
  {
    // Version is zero indexed, thus this light enum
    // to not bring confusion.
    v1 = 0,
    v2 = 1,
    v3 = 2
  };

  SO_API Expected<X509_uptr> convertPemToX509(const std::string &pemCert); 

  SO_API Expected<ecdsa::Signature> getEcdsaSignature(const X509 &cert);
  SO_API Expected<CertExtension> getExtension(const X509 &cert, CertExtensionId getExtensionId);
  SO_API Expected<CertExtension> getExtension(const X509 &cert, const std::string &oidNumerical);
  SO_API Expected<std::vector<CertExtension>> getExtensions(const X509 &cert);
  SO_API Expected<size_t> getExtensionsCount(const X509 &cert);
  SO_API Expected<Info> getIssuer(const X509 &cert);
  SO_API Expected<std::string> getIssuerString(const X509 &cert); 
  SO_API Expected<EVP_PKEY_uptr> getPubKey(X509 &cert);
  SO_API Expected<Bytes> getSerialNumber(X509 &cert);
  SO_API Expected<Bytes> getSignature(const X509 &cert);
  SO_API Expected<Info> getSubject(const X509 &cert);
  SO_API Expected<std::string> getSubjectString(const X509 &cert);
  SO_API Expected<Validity> getValidity(const X509 &cert);
  SO_API Expected<Version> getVersion(const X509 &cert);
  
  SO_API Expected<bool> isCa(X509 &cert);
  SO_API Expected<bool> isSelfSigned(X509 &cert);

  SO_API Expected<void> setCustomExtension(X509 &cert, const std::string &oidNumerical, ASN1_OCTET_STRING &octet, bool critical = false);
  SO_API Expected<void> setExtension(X509 &cert, CertExtensionId id, ASN1_OCTET_STRING &octet, bool critical = false);
  SO_API Expected<void> setExtension(X509 &cert, const CertExtension &extension); 
  SO_API Expected<void> setIssuer(X509 &cert, const X509 &rootCert);
  SO_API Expected<void> setIssuer(X509 &cert, const Info &commonInfo);
  SO_API Expected<void> setPubKey(X509 &cert, EVP_PKEY &pkey);
  SO_API Expected<void> setSerial(X509 &cert, const Bytes &bytes);
  SO_API Expected<void> setSubject(X509 &cert, const Info &commonInfo);
  SO_API Expected<void> setValidity(X509 &cert, const Validity &validity);
  SO_API Expected<void> setVersion(X509 &cert, Version version);
  
  SO_API Expected<size_t> signSha1(X509 &cert, EVP_PKEY &pkey);
  SO_API Expected<size_t> signSha256(X509 &cert, EVP_PKEY &pkey);
  SO_API Expected<size_t> signSha384(X509 &cert, EVP_PKEY &pkey); 
  SO_API Expected<size_t> signSha512(X509 &cert, EVP_PKEY &pkey);  
  
  SO_API Expected<bool> verifySignature(X509 &cert, EVP_PKEY &pkey);
 
} // namespace x509


/////////////////////////////////////////////////////////////////////////////////
//
//                Implementation
//
/////////////////////////////////////////////////////////////////////////////////

namespace internal {
  SO_PRV std::string errCodeToString(unsigned long errCode)
  {
    static constexpr size_t SIZE = 1024;
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
  SO_PRV Expected<T> err(T &&val)
  {
    return Expected<T>(ERR_get_error(), std::move(val));
  }
 
  template
  <
    typename T,
    typename = typename std::enable_if<!internal::is_uptr<T>::value>::type
  >
  SO_PRV Expected<T> err()
  {
    return internal::err<T>({});
  }

  template
  <
    typename T,
    typename T_ = T, // TODO: T_ is placeholder to avoid of 'reassining default template param' error, I should use some smarter solution
    typename = typename std::enable_if<internal::is_uptr<T>::value>::type
  >
  SO_PRV Expected<T> err()
  {
    auto tmp = make_unique<typename uptr_underlying_type<T>::type>(nullptr);
    return internal::err(std::move(tmp));
  }

  template<typename T>
  SO_PRV Expected<T> err(unsigned long errCode)
  { 
    return Expected<T>(errCode);
  }

  template<typename T>
  SO_PRV Expected<T> ok(T &&val)
  {
    return Expected<T>(0, std::move(val));
  }

  SO_PRV Expected<void> err()
  {
    return Expected<void>(ERR_get_error());
  }

  SO_PRV Expected<void> err(unsigned long errCode)
  {
    return Expected<void>(errCode);
  }

  SO_PRV Expected<void> ok()
  {
    return Expected<void>(0);
  }
 
  SO_PRV Expected<std::string> nameEntry2String(X509_NAME &name, int nid)
  {
    // X509_NAME_get_text_by_NID() is considered legacy and with limitations, we'll
    // use more safe option
    // all returned pointers here are internal openssl
    // pointers so they must not be freed
    const int entriesCount = X509_NAME_entry_count(&name);
    if(entriesCount < 0)
      return internal::err<std::string>();

    if(entriesCount == 0)
      return internal::ok<std::string>("");

    const int position = X509_NAME_get_index_by_NID(&name, nid, -1);
    // if position == -2 then nid is invalid
    if(position == -2)
      return internal::err<std::string>();

    // item not found, it's not lib error, user should decide if value that is not there
    // is an error or not
    if(position == -1)
      return internal::ok<std::string>("");
    
    const X509_NAME_ENTRY *entry = X509_NAME_get_entry(&name, position);
    // previously we found correct index, if we got nullptr here it
    // means sth went wrong
    if(!entry)
      return internal::err<std::string>();
    
    // internal pointer
    const ASN1_STRING *asn1 = X509_NAME_ENTRY_get_data(entry);
    const int asn1EstimatedStrLen = ASN1_STRING_length(asn1);
    if(asn1EstimatedStrLen <= 0)
      return internal::ok<std::string>("");

    const auto freeOpenssl = [](unsigned char *ptr) { OPENSSL_free(ptr); };
    unsigned char *ptr; // we need to call OPENSSL_free on this
    const int len = ASN1_STRING_to_UTF8(&ptr, asn1);
    std::unique_ptr<unsigned char[], decltype(freeOpenssl)> strBuff(ptr, freeOpenssl);

    std::string ret;
    ret.reserve(static_cast<size_t>(len));
    std::transform(strBuff.get(), strBuff.get() + len, std::back_inserter(ret), [](unsigned char chr){ return static_cast<char>(chr); });

    return internal::ok(std::move(ret)); 
  }

  SO_PRV Expected<std::string> nameToString(const X509_NAME &name, unsigned long flags = XN_FLAG_RFC2253)
  {
    auto bio = make_unique(BIO_new(BIO_s_mem()));
    if(0 > X509_NAME_print_ex(bio.get(), &name, 0, flags))
      return internal::err<std::string>();

    char *dataStart;
    const long nameLength = BIO_get_mem_data(bio.get(), &dataStart);
    if(nameLength < 0)
      return internal::err<std::string>();
 
    return internal::ok(std::string(dataStart, static_cast<size_t>(nameLength)));
  }

  SO_PRV Expected<x509::Info> commonInfo(X509_NAME &name)
  {
    const auto error = [](unsigned long errCode){ return internal::err<x509::Info>(errCode); }; 
    const auto commonName = nameEntry2String(name, NID_commonName);
    if(!commonName)
      return error(commonName.errorCode());

    const auto countryName = nameEntry2String(name, NID_countryName);
    if(!countryName)
      return error(countryName.errorCode());

    const auto organizationName = nameEntry2String(name, NID_organizationName);
    if(!organizationName)
      return error(organizationName.errorCode());

    const auto localityName = nameEntry2String(name, NID_localityName);
    if(!localityName)
      return error(localityName.errorCode());

    const auto stateOrProvinceName = nameEntry2String(name, NID_stateOrProvinceName);
    if(!stateOrProvinceName)
      return error(stateOrProvinceName.errorCode());

    return internal::ok<x509::Info>({ 
        *commonName,
        *countryName,
        *localityName,
        *organizationName,
        *stateOrProvinceName
    });
  }

  SO_PRV Expected<X509_NAME_uptr> infoToX509Name(const x509::Info &info)
  {
    auto name = make_unique(X509_NAME_new()); 

    const auto err = []{ return internal::err<X509_NAME_uptr>(); };
    const auto append = [](X509_NAME *nm, int nid, const std::string &val) {
      return val.empty() || X509_NAME_add_entry_by_NID(nm, nid, MBSTRING_ASC, reinterpret_cast<const unsigned char*>(val.c_str()), -1, -1, 0);
    };

    if(!name)
      return err();

    if(!append(name.get(), NID_commonName, info.commonName))
      return err();

    if(!append(name.get(), NID_countryName, info.countryName))
      return err();

    if(!append(name.get(), NID_localityName, info.localityName))
      return err();

    if(!append(name.get(), NID_organizationName, info.organizationName))
      return err();

    if(!append(name.get(), NID_stateOrProvinceName, info.stateOrProvinceName))
      return err();

    return internal::ok(std::move(name));
  }

  SO_PRV Expected<size_t> signCert(X509 &cert, EVP_PKEY &key, const EVP_MD *md)
  {
    const int sigLen = X509_sign(&cert, &key, md);
    if(0 >= sigLen)
      return internal::err<size_t>();

    return internal::ok(static_cast<size_t>(sigLen));
  }

  SO_PRV Expected<Bytes> ecdsaSign(const Bytes &dg, EC_KEY &key)
  {
    const int sigLen = ECDSA_size(&key);
    if(0 >= sigLen)
      return internal::err<Bytes>();

    Bytes tmpSig(static_cast<size_t>(sigLen));
    unsigned int finalSigLen = 0;
    if(1 != ECDSA_sign(0,
          dg.data(),
          static_cast<int>(dg.size()),
          tmpSig.data(),
          &finalSigLen,
          &key))
    {
      return internal::err<Bytes>();
    }

    if(finalSigLen == static_cast<unsigned>(sigLen))
      return internal::ok(std::move(tmpSig));

    Bytes signature(tmpSig.begin(), std::next(tmpSig.begin(), finalSigLen));
    return internal::ok(std::move(signature));
  }

  SO_PRV Expected<bool> ecdsaVerify(const Bytes &signature, const Bytes &dg, EC_KEY &publicKey)
  {
    if(1 != ECDSA_verify(0,
          dg.data(),
          static_cast<int>(dg.size()),
          signature.data(),
          static_cast<int>(signature.size()),
          &publicKey))
    {
      return internal::err(false);
    }

    return internal::ok(true);
  }
  
  SO_PRV Expected<Bytes> evpSign(const Bytes &message, const EVP_MD *evpMd,  EVP_PKEY &privateKey)
  {
    auto mdCtx = make_unique(EVP_MD_CTX_new());
    if(!mdCtx)
      return internal::err<Bytes>();
    
    const int initStatus = EVP_DigestSignInit(mdCtx.get(), nullptr, evpMd, nullptr, &privateKey);
    if(1 != initStatus)
      return internal::err<Bytes>();

    
    const int updateStatus = EVP_DigestSignUpdate(mdCtx.get(), message.data(), message.size());
    if(1 != updateStatus)
      return internal::err<Bytes>();
    
    size_t sigLen = 0;
    int signStatus = EVP_DigestSignFinal(mdCtx.get(), nullptr, &sigLen);
    if(1 != signStatus)
      return internal::err<Bytes>();
 
    Bytes tmp(sigLen);
    signStatus = EVP_DigestSignFinal(mdCtx.get(), tmp.data(), &sigLen);
    if(1 != signStatus)
      return internal::err<Bytes>();
        
    Bytes signature(tmp.begin(), std::next(tmp.begin(), static_cast<long>(sigLen))); 
    return internal::ok(std::move(signature));
  }

  SO_PRV Expected<bool> evpVerify(const Bytes &sig, const Bytes &msg, const EVP_MD *evpMd, EVP_PKEY &pubKey)
  {
    auto ctx = make_unique(EVP_MD_CTX_new());
    if (!ctx)
      return internal::err(false);

    if (1 != EVP_DigestVerifyInit(ctx.get(), nullptr, evpMd, nullptr, &pubKey))
      return internal::err(false);
    
    if(1 != EVP_DigestVerifyUpdate(ctx.get(), msg.data(), msg.size()))
      return internal::err(false); 
   
    const int result = EVP_DigestVerifyFinal(ctx.get(), sig.data(), sig.size());
    return result == 1 ? internal::ok(true) : result == 0 ? internal::ok(false) : internal::err<bool>();
  }

  SO_PRV Expected<Bytes> rsaSign(int digestNid, const Bytes &digest, RSA &privKey)
  {
    if(1 != RSA_check_key_ex(&privKey, nullptr))
      return internal::err<Bytes>();
       
    const int sz = RSA_size(&privKey);
    if(0 > sz)
      return internal::err<Bytes>();

    Bytes firstSignature(static_cast<size_t>(sz));
    unsigned finalSigLen = 0;
    if(1 != RSA_sign(digestNid,
          digest.data(),
          static_cast<unsigned>(digest.size()),
          firstSignature.data(),
          &finalSigLen,
          &privKey))
    {
      return internal::err<Bytes>();
    }

    if(finalSigLen == static_cast<unsigned>(sz))
      return internal::ok(std::move(firstSignature));

    Bytes finalSig(firstSignature.begin(), std::next(firstSignature.begin(), finalSigLen));
    return internal::ok(std::move(finalSig));
  }

  SO_PRV Expected<bool> rsaVerify(int hashNid, const Bytes &signature, const Bytes &digest, RSA &pubKey)
  {
    if(1 != RSA_verify(hashNid,
          digest.data(),
          static_cast<unsigned int>(digest.size()),
          signature.data(),
          static_cast<unsigned int>(signature.size()),
          &pubKey))
    {
      return internal::err(false);
    }
    
    return internal::ok(true);
  }

  template<typename ID>
  SO_PRV Expected<internal::X509Extension<ID>> getExtension(X509_EXTENSION &ex)
  {
    using RetType = internal::X509Extension<ID>;
    const ASN1_OBJECT *asn1Obj = X509_EXTENSION_get_object(&ex);
    const int nid = OBJ_obj2nid(asn1Obj);
    const int critical = X509_EXTENSION_get_critical(&ex);
    const auto oidStr = asn1::convertObjToStr(*asn1Obj, asn1::Form::NUMERICAL);
    if(!oidStr)
      return internal::err<RetType>(oidStr.errorCode());

    if(nid == NID_undef)
    {  
      const auto val = X509_EXTENSION_get_data(&ex);

      Bytes data;
      data.reserve(static_cast<size_t>(val->length));
      std::copy_n(val->data, val->length, std::back_inserter(data));

      return internal::ok(RetType {
            static_cast<ID>(nid),
            static_cast<bool>(critical),
            "",
            std::move(*oidStr),
            std::move(data)
      });
    }

    
    auto bio = make_unique(BIO_new(BIO_s_mem()));
    if(!X509V3_EXT_print(bio.get(), &ex, 0, 0))
    {// revocation getExtensions, not yet fully working
      const auto val = X509_EXTENSION_get_data(&ex);

      Bytes data;
      data.reserve(static_cast<size_t>(val->length));
      std::copy_n(val->data, val->length, std::back_inserter(data));

      return internal::ok(RetType{
        static_cast<ID>(nid),
        static_cast<bool>(critical),
        std::string(OBJ_nid2ln(nid)),
        std::move(*oidStr),
        std::move(data)
      });
    }
    
    BUF_MEM *bptr; // will be freed when bio will be closed
    BIO_get_mem_ptr(bio.get(), &bptr);

    Bytes data;
    data.reserve(static_cast<size_t>(bptr->length));
    std::copy_n(bptr->data, bptr->length, std::back_inserter(data));

    return internal::ok(RetType{
        static_cast<ID>(nid),
        static_cast<bool>(critical),
        std::string(OBJ_nid2ln(nid)),
        std::move(*oidStr),
        std::move(data)
      });
  }

  template<typename CTX, typename DATA, typename INIT, typename UPDATE, typename FINAL>
  SO_PRV Expected<Bytes> doHash(const DATA &data, unsigned long digestLen, INIT init, UPDATE update, FINAL final)
  {
    Bytes hash(digestLen);
    CTX ctx;
    if(1 != init(&ctx))
      return internal::err<Bytes>();

    if(1 != update(&ctx, data.data(), data.size()))
      return internal::err<Bytes>();

    if(1 != final(hash.data(), &ctx))
      return internal::err<Bytes>(); 

    return internal::ok(std::move(hash));
  }

  SO_PRV Expected<Bytes> doHashFile(const std::string &path, const EVP_MD *evpMd)
  {    
    auto bioRaw = BIO_new_file(path.c_str(), "rb");
    if(!bioRaw)
      return internal::err<Bytes>();

    // mdtmp will be freed with bio
    BIO *mdtmp = BIO_new(BIO_f_md());
    if(!mdtmp)
      return internal::err<Bytes>();

    // WTF OpenSSL?
    // Every EVP_<digest>() function returns const pointer, but
    // BIO_set_md which supposed to consume this pointer takes.... non const!
    // WTF OpenSSL?
    BIO_set_md(mdtmp, const_cast<EVP_MD*>(evpMd));
    auto bio = make_unique(BIO_push(mdtmp, bioRaw));
    if(!bio)
      return internal::err<Bytes>();

    {
      char buf[1024];
      int rdlen;
      do {
        char *bufFirstPos = buf;
        rdlen = BIO_read(bio.get(), bufFirstPos, sizeof(buf));
      } while (rdlen > 0);
    }


    uint8_t mdbuf[EVP_MAX_MD_SIZE];
    const int mdlen = BIO_gets(mdtmp, reinterpret_cast<char*>(mdbuf), EVP_MAX_MD_SIZE);

    Bytes ret(std::begin(mdbuf), std::next(std::begin(mdbuf), mdlen));
    return internal::ok<Bytes>(std::move(ret));
  }

} //namespace internal

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
  SO_API Expected<std::string> convertObjToStr(const ASN1_OBJECT &obj, Form form)
  {
    // according to documentation, size of 80 should be more than enough
    static constexpr size_t size = 1024;
    char extname[size];
    std::memset(extname, 0x00, size);
    const int charsWritten = OBJ_obj2txt(extname, size, &obj, static_cast<int>(form));
    if(0 > charsWritten)
      return internal::err<std::string>();

    if(0 == charsWritten)
      return internal::ok(std::string{});

    return internal::ok(std::string(extname));
  }

  SO_API Expected<ASN1_TIME_uptr> convertToAsn1Time(std::time_t time)
  {
    auto ret = make_unique(ASN1_TIME_set(nullptr, time));
    if(!ret)
      return internal::err<ASN1_TIME_uptr>();

    return internal::ok(std::move(ret));
  }

  SO_API Expected<std::time_t> convertToStdTime(const ASN1_TIME &asn1Time)
  {
    // TODO:
    // If we're extremly unlucky, we can be off by one second.
    // Despite tests didn't fail once, I should consider just straight string parsing here.
    static_assert(sizeof(std::time_t) >= sizeof(int64_t), "std::time_t size too small, the dates may overflow");
    static constexpr int64_t SECONDS_IN_A_DAY = 24 * 60 * 60;
    using sysClock = std::chrono::system_clock;

    int pday, psec;
    if(1 != ASN1_TIME_diff(&pday, &psec, nullptr, &asn1Time))
      return internal::err<std::time_t>(); 

    return internal::ok(sysClock::to_time_t(sysClock::now()) + pday * SECONDS_IN_A_DAY + psec);
  }
  
  SO_API Expected<ASN1_INTEGER_uptr> encodeInteger(const Bytes &bt)
  {
    auto maybeBn = bignum::convertToBignum(bt);
    if(!maybeBn)
      return internal::err<ASN1_INTEGER_uptr>(); 

    auto bn = maybeBn.moveValue();
    auto integer = make_unique(BN_to_ASN1_INTEGER(bn.get(), nullptr));
    if(!integer)
      return internal::err<ASN1_INTEGER_uptr>();

    return internal::ok(std::move(integer)); 
  }
 
  SO_API Expected<ASN1_OBJECT_uptr> encodeObject(const std::string &nameOrNumerical)
  {
    auto ret = make_unique(OBJ_txt2obj(nameOrNumerical.c_str(), 0));
    if(!ret)
      return internal::err<ASN1_OBJECT_uptr>();

    return internal::ok(std::move(ret));
  }

  SO_API Expected<ASN1_OCTET_STRING_uptr> encodeOctet(const Bytes &bt)
  {
    auto ret = make_unique(ASN1_OCTET_STRING_new());
    if(!ret)
      return internal::err<ASN1_OCTET_STRING_uptr>();

    if(1 != ASN1_OCTET_STRING_set(ret.get(), bt.data(), static_cast<int>(bt.size())))
      return internal::err<ASN1_OCTET_STRING_uptr>();

    return internal::ok(std::move(ret));
  }
  
  SO_API Expected<ASN1_OCTET_STRING_uptr> encodeOctet(const std::string &str)
  {
    Bytes bt;
    bt.reserve(str.size());
    std::transform(str.begin(), str.end(), std::back_inserter(bt),
        [](char chr){ return static_cast<uint8_t>(chr);
    });

    return encodeOctet(bt);
  } 
} // namespace asn1

namespace bignum {
  SO_API Expected<Bytes> convertToBytes(const BIGNUM &bn)
  {
    const auto sz = getByteLen(bn);
    if(!sz)
      return internal::err<Bytes>(sz.errorCode());

    Bytes ret(*sz);
    BN_bn2bin(&bn, ret.data());
    return internal::ok(std::move(ret));
  }

  SO_API Expected<BIGNUM_uptr> convertToBignum(const Bytes &bt)
  {
    auto ret = make_unique(BN_bin2bn(bt.data(), static_cast<int>(bt.size()), nullptr));
    if(!ret)
      return internal::err<BIGNUM_uptr>();

    return internal::ok(std::move(ret));
  }

  SO_API Expected<size_t> getByteLen(const BIGNUM &bn)
  {
    const int bnlen = BN_num_bytes(&bn);
    if(0 > bnlen)
      return internal::err<size_t>();

    return internal::ok(static_cast<size_t>(bnlen));
  }
}// namespace bignum

namespace ecdsa {
  inline bool Signature::operator ==(const Signature &other) const
  {
    return r.size() == other.r.size() &&
      s.size() == other.s.size() &&
      std::equal(r.begin(), r.end(), other.r.begin()) && 
      std::equal(s.begin(), s.end(), other.s.begin());

  }
  
  inline bool Signature::operator !=(const Signature &other) const
  {
    return !(*this == other);
  }

  SO_API Expected<bool> checkKey(const EC_KEY &ecKey)
  {
    if(1 != EC_KEY_check_key(&ecKey))
      return internal::err(false);

    return internal::ok(true);
  }
  
  SO_API Expected<EC_KEY_uptr> copyKey(const EC_KEY &ecKey)
  {
    auto copy = make_unique(EC_KEY_dup(&ecKey));
    if(!copy)
      return internal::err<EC_KEY_uptr>();

    return internal::ok(std::move(copy));
  }

  SO_API Expected<Curve> getCurve(const EC_KEY &key)
  {
    const EC_GROUP* group = EC_KEY_get0_group(&key);
    if(!group)
      return internal::err<Curve>();

    const int nid = EC_GROUP_get_curve_name(group);
    if(0 == nid)
      return internal::err<Curve>();

    return internal::ok(static_cast<Curve>(nid)); 
  }

  SO_API Expected<Bytes> convertToDer(const Signature &signature)
  {
    auto maybeR = bignum::convertToBignum(signature.r);
    if(!maybeR)
      return internal::err<Bytes>(maybeR.errorCode());

    auto maybeS = bignum::convertToBignum(signature.s);
    if(!maybeS)
      return internal::err<Bytes>(maybeS.errorCode());

    auto r = maybeR.moveValue();
    auto s = maybeS.moveValue();
    auto sig = make_unique(ECDSA_SIG_new()); 
    if(!sig)
      return internal::err<Bytes>();

    if(1 != ECDSA_SIG_set0(sig.get(), r.release(), s.release()))
      return internal::err<Bytes>();

    const int derLen = i2d_ECDSA_SIG(sig.get(), nullptr); 
    if(0 == derLen)
      return internal::err<Bytes>();
 
    Bytes ret(static_cast<size_t>(derLen));
    auto *derIt = ret.data();
    if(!i2d_ECDSA_SIG(sig.get(), &derIt))
      return internal::err<Bytes>();

    return internal::ok(std::move(ret));
  }

  SO_API Expected<Signature> convertToSignature(const Bytes &derSigBytes)
  {
    auto *derIt = derSigBytes.data();
    auto sig = make_unique(d2i_ECDSA_SIG(nullptr, &derIt, static_cast<long>(derSigBytes.size())));
    if(!sig)
      return internal::err<Signature>();

    const BIGNUM *r,*s;
    ECDSA_SIG_get0(sig.get(), &r, &s);

    auto maybeR = bignum::convertToBytes(*r);
    if(!maybeR)
      return internal::err<Signature>();

    auto maybeS = bignum::convertToBytes(*s);
    if(!maybeS)
      return internal::err<Signature>();
 
    return internal::ok(Signature{
      maybeR.moveValue(),
      maybeS.moveValue(),
    });
  }

  SO_API Expected<EC_KEY_uptr> getPublic(const EC_KEY &key)
  {
    auto ret = make_unique(EC_KEY_new());
    if(!ret)
      return internal::err<EC_KEY_uptr>();

    const EC_GROUP *group = EC_KEY_get0_group(&key);
    if(1 != EC_KEY_set_group(ret.get(), group))
      return internal::err<EC_KEY_uptr>();

    const EC_POINT* pubPoint = EC_KEY_get0_public_key(&key);
    if(1 != EC_KEY_set_public_key(ret.get(), pubPoint))
      return internal::err<EC_KEY_uptr>();

    return internal::ok(std::move(ret));
  }

  SO_API Expected<EVP_PKEY_uptr> convertToEvp(const EC_KEY &ecKey)
  {
    // I can keep const in arguments by doing this copy
    auto copy = make_unique(EC_KEY_dup(&ecKey));
    if(!copy)
      return internal::err<EVP_PKEY_uptr>();

    EVP_PKEY_uptr evpKey = make_unique(EVP_PKEY_new());
    if (!evpKey)
      return internal::err<EVP_PKEY_uptr>();

    if (1 != EVP_PKEY_set1_EC_KEY(evpKey.get(), copy.get()))
        return internal::err<EVP_PKEY_uptr>();
    
    return internal::ok(std::move(evpKey));
  }

  SO_API Expected<EC_KEY_uptr> convertPemToPubKey(const std::string &pemPub)
  {
    auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPub.c_str()), static_cast<int>(pemPub.size())));
    if(!bio)
      return internal::err<EC_KEY_uptr>();

    auto key = make_unique(PEM_read_bio_EC_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
    if(!key)
      return internal::err<EC_KEY_uptr>(); 

    return internal::ok(std::move(key));
  }

  SO_API Expected<EC_KEY_uptr> convertPemToPrivKey(const std::string &pemPriv)
  {
    auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPriv.c_str()), static_cast<int>(pemPriv.size())));
    if(!bio)
      return internal::err<EC_KEY_uptr>();

    auto key= make_unique(PEM_read_bio_ECPrivateKey(bio.get(), nullptr, nullptr, nullptr));
    if(!key)
      return internal::err<EC_KEY_uptr>();

    return internal::ok(std::move(key));
  }

  SO_API Expected<EC_KEY_uptr> generateKey(Curve curve)
  {
    const int nidCurve = static_cast<int>(curve);
    auto key = make_unique(EC_KEY_new_by_curve_name(nidCurve));
    if(!key)
      return internal::err<EC_KEY_uptr>();

    if(!EC_KEY_generate_key(key.get()))
      return internal::err<EC_KEY_uptr>();

    return internal::ok(std::move(key));
  }

  SO_API Expected<Bytes> signSha1(const Bytes &message, EC_KEY &key)
  {
    const auto digest = hash::sha1(message);
    if(!digest)
      return digest;

    return internal::ecdsaSign(*digest, key);
  }

  SO_API Expected<Bytes> signSha224(const Bytes &message, EC_KEY &key)
  {
    const auto digest = hash::sha224(message);
    if(!digest)
      return digest; 

    return internal::ecdsaSign(*digest, key);
  }

  SO_API Expected<Bytes> signSha256(const Bytes &message, EC_KEY &key)
  {
    const auto digest = hash::sha256(message);
    if(!digest)
      return digest; 

    return internal::ecdsaSign(*digest, key);
  }

  SO_API Expected<Bytes> signSha384(const Bytes &message, EC_KEY &key)
  {
    const auto digest = hash::sha384(message);
    if(!digest)
      return digest;

    return internal::ecdsaSign(*digest, key);
  }
  
  SO_API Expected<Bytes> signSha512(const Bytes &message, EC_KEY &key)
  {
    const auto digest = hash::sha512(message);
    if(!digest)
      return digest;

    return internal::ecdsaSign(*digest, key);
  }

  SO_API Expected<bool> verifySha1Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey)
  {
    const auto digest = hash::sha1(message);
    if(!digest)
      return internal::err<bool>(digest.errorCode());

    return internal::ecdsaVerify(signature, *digest, publicKey);
  }

  SO_API Expected<bool> verifySha224Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey)
  {
    const auto digest = hash::sha224(message);
    if(!digest)
      return internal::err<bool>(digest.errorCode());

    return internal::ecdsaVerify(signature, *digest, publicKey);
  }

  SO_API Expected<bool> verifySha256Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey)
  {
    const auto digest = hash::sha256(message);
    if(!digest)
      return internal::err<bool>(digest.errorCode());

    return internal::ecdsaVerify(signature, *digest, publicKey);
  }

  SO_API Expected<bool> verifySha384Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey)
  {
    const auto digest = hash::sha384(message);
    if(!digest)
      return internal::err<bool>(digest.errorCode());

    return internal::ecdsaVerify(signature, *digest, publicKey);
  }

  SO_API Expected<bool> verifySha512Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey)
  {
    const auto digest = hash::sha512(message);
    if(!digest)
      return internal::err<bool>(digest.errorCode());

    return internal::ecdsaVerify(signature, *digest, publicKey);
  }
} //namespace ecdsa

namespace evp {
  SO_API Expected<EVP_PKEY_uptr> convertPemToPubKey(const std::string &pemPub)
  {
    auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPub.c_str()), static_cast<int>(pemPub.size())));
    if(!bio)
      return internal::err<EVP_PKEY_uptr>(); 

    EVP_PKEY *rawKey = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    if(!rawKey)
      return internal::err<EVP_PKEY_uptr>();

    return internal::ok(make_unique(rawKey));
  }

  SO_API Expected<EVP_PKEY_uptr> convertPemToPrivKey(const std::string &pemPriv)
  {
    auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPriv.c_str()), static_cast<int>(pemPriv.size())));
    if(!bio)
      return internal::err<EVP_PKEY_uptr>(); 

    EVP_PKEY *rawKey = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    if(!rawKey)
      return internal::err<EVP_PKEY_uptr>();

    return internal::ok(make_unique(rawKey));
  }

  SO_API Expected<Bytes> signSha1(const Bytes &message, EVP_PKEY &privateKey)
  { 
    return internal::evpSign(message, EVP_sha1(), privateKey);
  }

  SO_API Expected<Bytes> signSha224(const Bytes &message, EVP_PKEY &privateKey)
  { 
    return internal::evpSign(message, EVP_sha224(), privateKey);
  }

  SO_API Expected<Bytes> signSha256(const Bytes &message, EVP_PKEY &privateKey)
  { 
    return internal::evpSign(message, EVP_sha256(), privateKey);
  }

  SO_API Expected<Bytes> signSha384(const Bytes &message, EVP_PKEY &privateKey)
  { 
    return internal::evpSign(message, EVP_sha384(), privateKey);
  }

  SO_API Expected<Bytes> signSha512(const Bytes &message, EVP_PKEY &privateKey)
  { 
    return internal::evpSign(message, EVP_sha512(), privateKey);
  }

  SO_API Expected<bool> verifySha1Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey)
  {
    return internal::evpVerify(signature, message, EVP_sha1(), pubKey); 
  }

  SO_API Expected<bool> verifySha224Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey)
  {
    return internal::evpVerify(signature, message, EVP_sha224(), pubKey); 
  }

  SO_API Expected<bool> verifySha256Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey)
  {
    return internal::evpVerify(signature, message, EVP_sha256(), pubKey); 
  }

  SO_API Expected<bool> verifySha384Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey)
  {
    return internal::evpVerify(signature, message, EVP_sha384(), pubKey); 
  }

  SO_API Expected<bool> verifySha512Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey)
  {
    return internal::evpVerify(signature, message, EVP_sha512(), pubKey); 
  }
} //namespace evp

namespace hash {
  SO_API Expected<Bytes> md4(const Bytes &data)
  {  
    return internal::doHash<MD4_CTX>(data, MD4_DIGEST_LENGTH, MD4_Init, MD4_Update, MD4_Final);
  }

  SO_API Expected<Bytes> md4(const std::string &data)
  {    
    return internal::doHash<MD4_CTX>(data, MD4_DIGEST_LENGTH, MD4_Init, MD4_Update, MD4_Final);
  }

  SO_API Expected<Bytes> md5(const Bytes &data)
  {
    return internal::doHash<MD5_CTX>(data, MD5_DIGEST_LENGTH, MD5_Init, MD5_Update, MD5_Final);
  }

  SO_API Expected<Bytes> md5(const std::string &data)
  {
    return internal::doHash<MD5_CTX>(data, MD5_DIGEST_LENGTH, MD5_Init, MD5_Update, MD5_Final);
  }

  SO_API Expected<Bytes> sha1(const Bytes &data)
  {    
    return internal::doHash<SHA_CTX>(data, SHA_DIGEST_LENGTH, SHA1_Init, SHA1_Update, SHA1_Final);
  }

  SO_API Expected<Bytes> sha1(const std::string &data)
  {    
    return internal::doHash<SHA_CTX>(data, SHA_DIGEST_LENGTH, SHA1_Init, SHA1_Update, SHA1_Final);
  }
  
  SO_API Expected<Bytes> sha224(const Bytes &data)
  {
    return internal::doHash<SHA256_CTX>(data, SHA224_DIGEST_LENGTH, SHA224_Init, SHA224_Update, SHA224_Final);
  }

  SO_API Expected<Bytes> sha224(const std::string &data)
  {
    return internal::doHash<SHA256_CTX>(data, SHA224_DIGEST_LENGTH, SHA224_Init, SHA224_Update, SHA224_Final);
  }

  SO_API Expected<Bytes> sha256(const Bytes &data)
  {
    return internal::doHash<SHA256_CTX>(data, SHA256_DIGEST_LENGTH, SHA256_Init, SHA256_Update, SHA256_Final);
  }

  SO_API Expected<Bytes> sha256(const std::string &data)
  {
    return internal::doHash<SHA256_CTX>(data, SHA256_DIGEST_LENGTH, SHA256_Init, SHA256_Update, SHA256_Final);
  }

  SO_API Expected<Bytes> sha384(const Bytes &data)
  {
    return internal::doHash<SHA512_CTX>(data, SHA384_DIGEST_LENGTH, SHA384_Init, SHA384_Update, SHA384_Final);
  }

  SO_API Expected<Bytes> sha384(const std::string &data)
  {
    return internal::doHash<SHA512_CTX>(data, SHA384_DIGEST_LENGTH, SHA384_Init, SHA384_Update, SHA384_Final);
  }

  SO_API Expected<Bytes> sha512(const Bytes &data)
  {
    return internal::doHash<SHA512_CTX>(data, SHA512_DIGEST_LENGTH, SHA512_Init, SHA512_Update, SHA512_Final);
  }

  SO_API Expected<Bytes> sha512(const std::string &data)
  {
    return internal::doHash<SHA512_CTX>(data, SHA512_DIGEST_LENGTH, SHA512_Init, SHA512_Update, SHA512_Final);
  }
  
  SO_API Expected<Bytes> fileMD4(const std::string &path)
  {
    return internal::doHashFile(path, EVP_md4());
  }
  
  SO_API Expected<Bytes> fileMD5(const std::string &path)
  {
    return internal::doHashFile(path, EVP_md5());
  }
  
  SO_API Expected<Bytes> fileSHA1(const std::string &path)
  {
    return internal::doHashFile(path, EVP_sha1());
  }

  SO_API Expected<Bytes> fileSHA224(const std::string &path)
  {
    return internal::doHashFile(path, EVP_sha224());
  }

  SO_API Expected<Bytes> fileSHA256(const std::string &path)
  {
    return internal::doHashFile(path, EVP_sha256());
  }

  SO_API Expected<Bytes> fileSHA384(const std::string &path)
  {
    return internal::doHashFile(path, EVP_sha384());
  }

  SO_API Expected<Bytes> fileSHA512(const std::string &path)
  {
    return internal::doHashFile(path, EVP_sha512());
  }
}// namespace hash

namespace rand {
  SO_API Expected<Bytes> bytes(unsigned short numOfBytes)
  {
    Bytes ret(static_cast<size_t>(numOfBytes));
    if(1 != RAND_bytes(ret.data(), static_cast<int>(numOfBytes)))
      return internal::err<Bytes>();

    return internal::ok(std::move(ret));
  }
} // namespace rand

namespace rsa {
  SO_API Expected<RSA_uptr> convertPemToPubKey(const std::string &pemPub)
  {
    auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPub.c_str()), static_cast<int>(pemPub.size())));
    if(!bio)
      return internal::err<RSA_uptr>();

    auto key = make_unique(PEM_read_bio_RSA_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
    if(!key)
      return internal::err<RSA_uptr>(); 

    return internal::ok(std::move(key));
  }

  SO_API Expected<RSA_uptr> convertPemToPrivKey(const std::string &pemPriv)
  {
    auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPriv.c_str()), static_cast<int>(pemPriv.size())));
    if(!bio)
      return internal::err<RSA_uptr>();

    auto key = make_unique(PEM_read_bio_RSAPrivateKey(bio.get(), nullptr, nullptr, nullptr));
    if(!key)
      return internal::err<RSA_uptr>();

    return internal::ok(std::move(key));
  }

  
  SO_API Expected<std::string> convertPrivKeyToPem(RSA &rsa)
  {
    
    const auto check = rsa::checkKey(rsa);
    if(!check)
      return internal::err<std::string>(check.errorCode());

    /*const auto freeOpenssl = [](unsigned char *ptr) { OPENSSL_free(ptr);};
    unsigned char *ptr = nullptr; // this needs to be freed with OPENSSL_free
    const int len = i2d_RSAPrivateKey(&rsa, &ptr);
    if (0 > len)
      return internal::err<std::string>();

    std::unique_ptr<unsigned char[], decltype(freeOpenssl)> buf(ptr, freeOpenssl);
    */
    
    auto bio = make_unique(BIO_new(BIO_s_mem()));
    if(!bio)
      return internal::err<std::string>();

    if(1 != PEM_write_bio_RSAPrivateKey(bio.get(), &rsa, nullptr, nullptr, 0, nullptr, nullptr))
      return internal::err<std::string>();

    const auto keyBits = rsa::getKeyBits(rsa);
    if(!keyBits)
      return internal::err<std::string>(keyBits.errorCode());
    
    const int readBufSize = static_cast<int>(*keyBits) * 2 + 1;
    std::unique_ptr<char[]> readBuf (new char[static_cast<unsigned long>(readBufSize)]);
    int charsRead = 0;
    std::string ret;
    ret.reserve(static_cast<size_t>(*keyBits));
    do {
      std::memset(readBuf.get(), 0x00, static_cast<size_t>(readBufSize));
      char *ptr = readBuf.get();
      charsRead = BIO_read(bio.get(), ptr, readBufSize - 1);
      if(charsRead)
        ret += readBuf.get();

    } while(charsRead > 0);
  
    return internal::ok(std::move(ret));
  }

  /*
  SO_API Expected<std::string> convertPubKeyToPem(RSA &rsa)
  {
  }
  */

  SO_API Expected<EVP_PKEY_uptr> convertToEvp(RSA &rsa)
  {
    EVP_PKEY_uptr evpKey = make_unique(EVP_PKEY_new());
    if (!evpKey)
      return internal::err<EVP_PKEY_uptr>();

    if (1 != EVP_PKEY_set1_RSA(evpKey.get(), &rsa))
        return internal::err<EVP_PKEY_uptr>();
    
    return internal::ok(std::move(evpKey));
  }

  SO_API Expected<bool> checkKey(RSA &rsa)
  {
    if(1 != RSA_check_key_ex(&rsa, nullptr))
      return internal::err(false);
    
    return internal::ok(true);
  }

  SO_API Expected<RSA_uptr> generateKey(KeyBits keySize, Exponent exponent)
  {
    auto bnE = make_unique(BN_new());
    if(1 != BN_set_word(bnE.get(), static_cast<unsigned long>(exponent)))
      return internal::err<RSA_uptr>();

    auto rsa = make_unique(RSA_new());
    if(1 != RSA_generate_key_ex(rsa.get(), static_cast<int>(keySize), bnE.get(), nullptr))
      return internal::err<RSA_uptr>();

    return internal::ok(std::move(rsa));
  }

  SO_API Expected<KeyBits> getKeyBits(const RSA &rsa)
  {
    // TODO:
    // I kept returning Expected<> to keep API consistent,
    // but I could just return rsa::KeySize here....I don't know...
    return internal::ok(static_cast<KeyBits>(RSA_bits(&rsa)));
  }

  SO_API Expected<RSA_uptr> getPublic(RSA &rsa)
  {
    auto bio = make_unique(BIO_new(BIO_s_mem())); 
    if(0 >= i2d_RSAPublicKey_bio(bio.get(), &rsa))
      return internal::err<RSA_uptr>();
 
    auto retRsa = make_unique(d2i_RSAPublicKey_bio(bio.get(), nullptr));
    if(!retRsa)
      return internal::err<RSA_uptr>();

    return internal::ok(std::move(retRsa));
  }
 
  SO_API Expected<Bytes> signSha1(const Bytes &msg, RSA &privKey)
  {
    const auto digest = hash::sha1(msg);
    if(!digest)
      return digest;

    return internal::rsaSign(NID_sha1, digest.value(), privKey); 
  }

  SO_API Expected<Bytes> signSha224(const Bytes &msg, RSA &privKey)
  {
    const auto digest = hash::sha224(msg);
    if(!digest)
      return digest;

    return internal::rsaSign(NID_sha224, digest.value(), privKey); 
  }

  SO_API Expected<Bytes> signSha256(const Bytes &msg, RSA &privKey)
  {
    const auto digest = hash::sha256(msg);
    if(!digest)
      return digest;

    return internal::rsaSign(NID_sha256, digest.value(), privKey); 
  }

  SO_API Expected<Bytes> signSha384(const Bytes &msg, RSA &privKey)
  {
    const auto digest = hash::sha384(msg);
    if(!digest)
      return digest;

    return internal::rsaSign(NID_sha384, digest.value(), privKey); 
  }
  
  SO_API Expected<Bytes> signSha512(const Bytes &msg, RSA &privKey)
  {
    const auto digest = hash::sha512(msg);
    if(!digest)
      return digest;

    return internal::rsaSign(NID_sha512, digest.value(), privKey); 
  }
  
  SO_API Expected<bool> verifySha1Signature(const Bytes &signature, const Bytes &message, RSA &pubKey)
  {
    const auto digest = hash::sha1(message);
    if(!digest)
      return internal::err<bool>(digest.errorCode());

    return internal::rsaVerify(NID_sha1, signature, digest.value(), pubKey); 
  }
  
  SO_API Expected<bool> verifySha224Signature(const Bytes &signature, const Bytes &message, RSA &pubKey)
  {
    const auto digest = hash::sha224(message);
    if(!digest)
      return internal::err<bool>(digest.errorCode());

    return internal::rsaVerify(NID_sha224, signature, digest.value(), pubKey); 
  }

  SO_API Expected<bool> verifySha256Signature(const Bytes &signature, const Bytes &message, RSA &pubKey)
  {
    const auto digest = hash::sha256(message);
    if(!digest)
      return internal::err<bool>(digest.errorCode());

    return internal::rsaVerify(NID_sha256, signature, digest.value(), pubKey); 
  }

  SO_API Expected<bool> verifySha384Signature(const Bytes &signature, const Bytes &message, RSA &pubKey)
  {
    const auto digest = hash::sha384(message);
    if(!digest)
      return internal::err<bool>(digest.errorCode());

    return internal::rsaVerify(NID_sha384, signature, digest.value(), pubKey); 
  }

  SO_API Expected<bool> verifySha512Signature(const Bytes &signature, const Bytes &message, RSA &pubKey)
  {
    const auto digest = hash::sha512(message);
    if(!digest)
      return internal::err<bool>(digest.errorCode());

    return internal::rsaVerify(NID_sha512, signature, digest.value(), pubKey); 
  }
} // namespace rsa

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

  SO_API Expected<Info> getIssuer(const X509 &cert)
  {
    // this is internal ptr and must not be freed
    X509_NAME *getIssuer = X509_get_issuer_name(&cert);
    if(!getIssuer)
      return internal::err<Info>();

    return internal::commonInfo(*getIssuer); 
  }
  
  SO_API Expected<std::string> getIssuerString(const X509 &cert)
  {
    // this is internal ptr and must not be freed
    const X509_NAME *getIssuer = X509_get_issuer_name(&cert);
    if(!getIssuer)
      return internal::err<std::string>();

    return internal::nameToString(*getIssuer);
  }

  SO_API Expected<bool> isCa(X509 &cert)
  {
    if(0 == X509_check_ca(&cert)){
      const auto lastErr = ERR_get_error();
      if(0 == lastErr)
        return internal::ok(false);

      return internal::err<bool>(lastErr);
    }
    return internal::ok(true);
  }

  SO_API Expected<bool> isSelfSigned(X509 &cert)
  {
    if(X509_V_OK == X509_check_issued(&cert, &cert))
      return internal::ok(true);
    
    const auto lastErr = ERR_get_error();
    if(0 == lastErr)
      return internal::ok(false);

    return internal::err<bool>(lastErr);
  }

  SO_API Expected<X509_uptr> convertPemToX509(const std::string &pemCert)
  {
    BIO_uptr bio = make_unique(BIO_new(BIO_s_mem()));

    if(0 >= BIO_write(bio.get(), pemCert.c_str(), static_cast<int>(pemCert.length())))
      return internal::err<X509_uptr>(); 

    auto ret = make_unique(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if(!ret)
      return internal::err<X509_uptr>();

    return internal::ok(std::move(ret));
  }

  SO_API Expected<EVP_PKEY_uptr> getPubKey(X509 &cert)
  { 
    auto pkey = make_unique(X509_get_pubkey(&cert));
    if(!pkey)
      return internal::err<EVP_PKEY_uptr>();

    return internal::ok(std::move(pkey));
  }

  SO_API Expected<Bytes> getSerialNumber(X509 &cert)
  {
    // both internal pointers, must not be freed
    const ASN1_INTEGER *serialNumber = X509_get_serialNumber(&cert);
    if(!serialNumber)
      return internal::err<Bytes>();

    const BIGNUM *bn = ASN1_INTEGER_to_BN(serialNumber, nullptr);
    if(!bn)
      return internal::err<Bytes>();

    return bignum::convertToBytes(*bn);
  }

  SO_API Expected<size_t> signSha1(X509 &cert, EVP_PKEY &pkey)
  {
    return internal::signCert(cert, pkey, EVP_sha256());  
  }

  SO_API Expected<size_t> signSha256(X509 &cert, EVP_PKEY &key)
  {
    return internal::signCert(cert, key, EVP_sha256());  
  }

  SO_API Expected<size_t> signSha384(X509 &cert, EVP_PKEY &pkey)
  {
    return internal::signCert(cert, pkey, EVP_sha384());  
  }

  SO_API Expected<size_t> signSha512(X509 &cert, EVP_PKEY &pkey)
  {
    return internal::signCert(cert, pkey, EVP_sha512());  
  }

  SO_API Expected<Bytes> getSignature(const X509 &cert)
  {
    // both internal pointers and must not be freed
    const ASN1_BIT_STRING *psig = nullptr;
    const X509_ALGOR *palg = nullptr;
    X509_get0_signature(&psig, &palg, &cert);
    if(!palg || !psig)
      return internal::err<Bytes>();

    Bytes rawDerSequence(static_cast<size_t>(psig->length));
    std::memcpy(rawDerSequence.data(), psig->data, static_cast<size_t>(psig->length));

    return internal::ok(std::move(rawDerSequence));
  }
  
  SO_API Expected<ecdsa::Signature> getEcdsaSignature(const X509 &cert)
  {
    // both internal pointers and must not be freed
    const ASN1_BIT_STRING *psig = nullptr;
    const X509_ALGOR *palg = nullptr;
    X509_get0_signature(&psig, &palg, &cert);
    if(!palg || !psig)
      return internal::err<ecdsa::Signature>();

    const unsigned char *it = psig->data;
    const auto sig = make_unique(d2i_ECDSA_SIG(nullptr, &it, static_cast<long>(psig->length)));
    if(!sig)
      return internal::err<ecdsa::Signature>();

    // internal pointers
    const BIGNUM *r,*s;
    ECDSA_SIG_get0(sig.get(), &r, &s);
    return internal::ok(ecdsa::Signature{ *bignum::convertToBytes(*r), *bignum::convertToBytes(*s) });
  }

  SO_API Expected<CertExtension> getExtension(const X509 &cert, CertExtensionId getExtensionId)
  {
    const int loc = X509_get_ext_by_NID(&cert, static_cast<int>(getExtensionId), -1);
    if(-1 == loc)
      return internal::err<CertExtension>();

    return internal::getExtension<CertExtensionId>(*X509_get_ext(&cert, loc));
  }

  SO_API Expected<CertExtension> getExtension(const X509 &cert, const std::string &oidNumerical)
  {
    auto maybeObj = asn1::encodeObject(oidNumerical);
    if(!maybeObj)
      return internal::err<CertExtension>(maybeObj.errorCode());

    auto obj = maybeObj.moveValue();
    const int loc = X509_get_ext_by_OBJ(&cert, obj.get(), -1);
    if(-1 == loc)
      return internal::err<CertExtension>();

    return internal::getExtension<CertExtensionId>(*X509_get_ext(&cert, loc));
  }

  SO_API Expected<std::vector<CertExtension>> getExtensions(const X509 &cert)
  {
    using RetType = std::vector<CertExtension>;
    const auto extsCount = getExtensionsCount(cert);
    if(!extsCount)
      return internal::err<RetType>(extsCount.errorCode());

    if(0 == *extsCount)
      return internal::ok(RetType{});

    RetType ret;
    ret.reserve(*extsCount); 
    for(int index = 0; index < static_cast<int>(*extsCount); ++index)
    {
      auto getExtension = internal::getExtension<CertExtensionId>(*X509_get_ext(&cert, index));
      if(!getExtension)
        return internal::err<RetType>(getExtension.errorCode());

      ret.push_back(getExtension.moveValue());
    }

    return internal::ok(std::move(ret));
  }

  SO_API Expected<size_t> getExtensionsCount(const X509 &cert)
  {
    const int extsCount = X509_get_ext_count(&cert);
    if(extsCount < 0)
      return internal::err<size_t>(); 

    return internal::ok(static_cast<size_t>(extsCount));
  }

  SO_API Expected<Info> getSubject(const X509 &cert)
  {
    // this is internal ptr and must not be freed
    X509_NAME *subject = X509_get_subject_name(&cert);
    if(!subject)
      return internal::err<Info>();

    return internal::commonInfo(*subject); 
  }

  SO_API Expected<std::string> getSubjectString(const X509 &cert)
  {
    // this is internal ptr and must not be freed
    const X509_NAME *subject = X509_get_subject_name(&cert);
    if(!subject)
      return internal::err<std::string>();

    return internal::nameToString(*subject);
  }

  SO_API Expected<Validity> getValidity(const X509 &cert)
  {
    const auto notAfter = X509_get0_notAfter(&cert);
    if(!notAfter)
      return internal::err<Validity>();

    const auto notBefore = X509_get0_notBefore(&cert);
    if(!notBefore)
      return internal::err<Validity>();

    auto notBeforeTime = asn1::convertToStdTime(*notBefore);
    if(!notBeforeTime)
      return internal::err<Validity>(notBeforeTime.errorCode());

    auto notAfterTime = asn1::convertToStdTime(*notAfter);
    if(!notAfterTime)
      return internal::err<Validity>(notAfterTime.errorCode());

    return internal::ok(Validity{*notAfterTime, *notBeforeTime});
  }

  SO_API Expected<bool> verifySignature(X509 &cert, EVP_PKEY &pkey)
  {
    const int result = X509_verify(&cert, &pkey);
    return result == 1 ? internal::ok(true) : result == 0 ? internal::ok(false) : internal::err(false);
  }

  SO_API Expected<Version> getVersion(const X509 &cert)
  {
    // TODO:
    // I kept returning Expected<> to keep API
    // consistent, but I could just return x509::Version here....I don't know...
    return internal::ok(static_cast<Version>(X509_get_version(&cert)));
  }

  SO_API Expected<void> setCustomExtension(X509 &cert, const std::string &oidNumerical, ASN1_OCTET_STRING &octet, bool critical)
  {
    auto maybeAsn1Oid = asn1::encodeObject(oidNumerical);
    if(!maybeAsn1Oid)
      return internal::err(maybeAsn1Oid.errorCode());

    auto extension = make_unique(X509_EXTENSION_new());
    if(!extension)
      return internal::err();

    if(1 != X509_EXTENSION_set_critical(extension.get(), static_cast<int>(critical)))
      return internal::err();

    auto asn1Oid = maybeAsn1Oid.moveValue();
    if(1 != X509_EXTENSION_set_object(extension.get(), asn1Oid.get()))
      return internal::err();

    if(1 != X509_EXTENSION_set_data(extension.get(), &octet))
      return internal::err();

    if(1 != X509_add_ext(&cert, extension.get(), -1))
      return internal::err();

    return internal::ok();

  }

  SO_API Expected<void> setExtension(X509 &cert, CertExtensionId id, ASN1_OCTET_STRING &octet, bool critical)
  {
    auto oid = make_unique(OBJ_nid2obj(static_cast<int>(id)));
    if(!oid)
      return internal::err();
 
    auto extension = make_unique(X509_EXTENSION_new());
    if(!extension)
      return internal::err();

    if(1 != X509_EXTENSION_set_critical(extension.get(), static_cast<int>(critical)))
      return internal::err();

    if(1 != X509_EXTENSION_set_object(extension.get(), oid.get()))
      return internal::err();

    if(1 != X509_EXTENSION_set_data(extension.get(), &octet))
      return internal::err();

    if(1 != X509_add_ext(&cert, extension.get(), -1))
      return internal::err();

    return internal::ok(); 
  }

  SO_API Expected<void> setExtension(X509 &cert, const CertExtension &extension)
  {
    auto maybeData = asn1::encodeOctet(extension.data);
    if(!maybeData)
      return internal::err(maybeData.errorCode());

    auto data = maybeData.moveValue();
    if(x509::CertExtensionId::UNDEF == extension.id)
      return setCustomExtension(cert, extension.oidNumerical, *data, extension.critical);

    return setExtension(cert, extension.id, *data, extension.critical);
  }

  SO_API Expected<void> setIssuer(X509 &cert, const X509 &rootCert)
  {
    X509_NAME *getIssuer = X509_get_subject_name(&rootCert);
    if(!getIssuer)
      return internal::err();

    if(1 != X509_set_issuer_name(&cert, getIssuer))
      return internal::err();

    return internal::ok();
  }

  SO_API Expected<void> setIssuer(X509 &cert, const Info &info)
  {
    auto maybeIssuer = internal::infoToX509Name(info);
    if(!maybeIssuer)
      return internal::err(maybeIssuer.errorCode());

    auto getIssuer = maybeIssuer.moveValue();
    if(1 != X509_set_issuer_name(&cert, getIssuer.get()))
      return internal::err(); 

    return internal::ok();
  }

  SO_API Expected<void> setPubKey(X509 &cert, EVP_PKEY &pkey)
  {
    if(1 != X509_set_pubkey(&cert, &pkey))
      return internal::err();

    return internal::ok();
  }
 
  SO_API Expected<void> setSerial(X509 &cert, const Bytes &bytes)
  {
    auto maybeInt = asn1::encodeInteger(bytes);
    if(!maybeInt)
      return internal::err(maybeInt.errorCode());

    auto integer = maybeInt.moveValue();
    if(1 != X509_set_serialNumber(&cert, integer.get()))
      return internal::err();

    return internal::ok();
  }

  SO_API Expected<void> setSubject(X509 &cert, const Info &info)
  {
    auto maybeSubject = internal::infoToX509Name(info); 
    if(!maybeSubject)
      return internal::err(maybeSubject.errorCode());

    auto subject = maybeSubject.moveValue();
    if(1 != X509_set_subject_name(&cert, subject.get()))
      return internal::err();

    return internal::ok();
  }

  SO_API Expected<void> setValidity(X509 &cert, const Validity &validity)
  {
    ASN1_TIME_uptr notAfterTime = make_unique(ASN1_TIME_set(nullptr, validity.notAfter));
    if(!notAfterTime)
      return internal::err();

    ASN1_TIME_uptr notBeforeTime = make_unique(ASN1_TIME_set(nullptr, validity.notBefore));
    if(!notBeforeTime)
      return internal::err();

    if(1 != X509_set1_notBefore(&cert, notBeforeTime.get()))
      return internal::err();

    if(1 != X509_set1_notAfter(&cert, notAfterTime.get()))
      return internal::err();

    return internal::ok();
  }

  SO_API Expected<void> setVersion(X509 &cert, Version version)
  {
    if(1 != X509_set_version(&cert, static_cast<long>(version)))
      return internal::err();
    
    return internal::ok();
  }
} // namespace x509

} // namepsace so

#endif
