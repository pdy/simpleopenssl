#ifndef PDY_SIMPLEOPENSSL_H_
#define PDY_SIMPLEOPENSSL_H_

/*
* Copyright (c) 2018 - 2020 Pawel Drzycimski
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
class Result : public internal::AddValueRef<T, Result<T>, typename internal::is_uptr<T>::type>
{
public: 
  template
  < 
    typename T_ = T,
    typename = typename std::enable_if<std::is_default_constructible<T_>::value>::type
  >
  explicit Result(unsigned long opensslErrorCode)
    : m_value {}, m_opensslErrCode{opensslErrorCode} {}  

  explicit Result(unsigned long opensslErrorCode, T &&value)
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
      return "ok";

    return internal::errCodeToString(m_opensslErrCode); 
  }

private:
  friend internal::AddValueRef<T, Result<T>, typename internal::is_uptr<T>::type>;

  T m_value;
  unsigned long m_opensslErrCode;
};

template<>
class Result<void>
{
public:
  explicit Result(unsigned long opensslErrorCode)
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
      return "ok";

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

  SO_API Result<std::string> convertObjToStr(const ASN1_OBJECT &obj, Form form = Form::NAME);
  SO_API Result<ASN1_TIME_uptr> convertToAsn1Time(std::time_t time);
  SO_API Result<std::time_t> convertToStdTime(const ASN1_TIME &asn1Time);

  SO_API Result<ASN1_INTEGER_uptr> encodeInteger(const Bytes &bt);
  SO_API Result<ASN1_OBJECT_uptr> encodeObject(const std::string &nameOrNumerical);
  SO_API Result<ASN1_OCTET_STRING_uptr> encodeOctet(const Bytes &bt);
  SO_API Result<ASN1_OCTET_STRING_uptr> encodeOctet(const std::string &str); 
} // namepsace asn1

namespace bignum { 
  SO_API Result<BIGNUM_uptr> convertToBignum(const Bytes &bt);
  SO_API Result<Bytes> convertToBytes(const BIGNUM &bn);
  
  SO_API Result<size_t> getByteLen(const BIGNUM &bn);
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

  SO_API Result<EC_KEY_uptr> convertPemToPrivKey(const std::string &pemPriv);
  SO_API Result<EC_KEY_uptr> convertPemToPubKey(const std::string &pemPub);
  SO_API Result<std::string> convertPrivKeyToPem(EC_KEY &ec);
  SO_API Result<std::string> convertPubKeyToPem(EC_KEY &ec);

  SO_API Result<EC_KEY_uptr> convertDerToPrivKey(const Bytes &der);
  SO_API Result<EC_KEY_uptr> convertDerToPubKey(const Bytes &der);
  SO_API Result<Bytes> convertPrivKeyToDer(EC_KEY &ec);
  SO_API Result<Bytes> convertPubKeyToDer(EC_KEY &ec);

  SO_API Result<Bytes> convertToDer(const Signature &signature); 
  SO_API Result<EVP_PKEY_uptr> convertToEvp(const EC_KEY &key);
  SO_API Result<Signature> convertToSignature(const Bytes &derSigBytes);

  SO_API Result<bool> checkKey(const EC_KEY &ecKey);
  SO_API Result<EC_KEY_uptr> copyKey(const EC_KEY &ecKey);
  SO_API Result<EC_KEY_uptr> generateKey(Curve curve);
  SO_API Result<Curve> getCurve(const EC_KEY &key);
  SO_API Result<EC_KEY_uptr> getPublic(const EC_KEY &key);
 
  SO_API Result<Bytes> signSha1(const Bytes &message, EC_KEY &key);
  SO_API Result<Bytes> signSha224(const Bytes &message, EC_KEY &key);
  SO_API Result<Bytes> signSha256(const Bytes &message, EC_KEY &key);
  SO_API Result<Bytes> signSha384(const Bytes &message, EC_KEY &key);
  SO_API Result<Bytes> signSha512(const Bytes &message, EC_KEY &key);
  
  SO_API Result<bool> verifySha1Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey);
  SO_API Result<bool> verifySha224Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey);
  SO_API Result<bool> verifySha256Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey);
  SO_API Result<bool> verifySha384Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey);
  SO_API Result<bool> verifySha512Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey);
} // namespace ecdsa

namespace evp {
  SO_API Result<EVP_PKEY_uptr> convertPemToPrivKey(const std::string &pemPriv);
  SO_API Result<EVP_PKEY_uptr> convertPemToPubKey(const std::string &pemPub);

  SO_API Result<EVP_PKEY_uptr> convertDerToPrivKey(const Bytes &der);
  SO_API Result<EVP_PKEY_uptr> convertDerToPubKey(const Bytes &der);
  SO_API Result<Bytes> convertPrivKeyToDer(EVP_PKEY &privKey);
  SO_API Result<Bytes> convertPubKeyToDer(EVP_PKEY &pubKey);

  SO_API Result<Bytes> signSha1(const Bytes &message, EVP_PKEY &privateKey);
  SO_API Result<Bytes> signSha224(const Bytes &msg, EVP_PKEY &privKey);
  SO_API Result<Bytes> signSha256(const Bytes &msg, EVP_PKEY &privKey);
  SO_API Result<Bytes> signSha384(const Bytes &msg, EVP_PKEY &privKey);
  SO_API Result<Bytes> signSha512(const Bytes &msg, EVP_PKEY &privKey);
  
  SO_API Result<bool> verifySha1Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey);
  SO_API Result<bool> verifySha224Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey);
  SO_API Result<bool> verifySha256Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey);
  SO_API Result<bool> verifySha384Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey);
  SO_API Result<bool> verifySha512Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey);
} // namepsace evp

namespace hash {
  SO_API Result<Bytes> md4(const Bytes &data);
  SO_API Result<Bytes> md4(const std::string &str);
  SO_API Result<Bytes> md5(const Bytes &data);
  SO_API Result<Bytes> md5(const std::string &str);
  SO_API Result<Bytes> sha1(const Bytes &data);
  SO_API Result<Bytes> sha1(const std::string &str);
  SO_API Result<Bytes> sha224(const Bytes &data);
  SO_API Result<Bytes> sha224(const std::string &str);
  SO_API Result<Bytes> sha256(const Bytes &data);
  SO_API Result<Bytes> sha256(const std::string &str);
  SO_API Result<Bytes> sha384(const Bytes &data);
  SO_API Result<Bytes> sha384(const std::string &str);
  SO_API Result<Bytes> sha512(const Bytes &data);
  SO_API Result<Bytes> sha512(const std::string &str);

  SO_API Result<Bytes> fileMD4(const std::string &path);
  SO_API Result<Bytes> fileMD5(const std::string &path);
  SO_API Result<Bytes> fileSHA1(const std::string &path);
  SO_API Result<Bytes> fileSHA224(const std::string &path);
  SO_API Result<Bytes> fileSHA256(const std::string &path);
  SO_API Result<Bytes> fileSHA384(const std::string &path);
  SO_API Result<Bytes> fileSHA512(const std::string &path);
} // namespace hash

namespace nid {
  class Nid
  {
  public:
    inline explicit Nid(int raw);
    inline Nid(const Nid &other);
    inline Nid(Nid&&) = default;

    inline Nid& operator=(const Nid &other);
    inline Nid& operator=(Nid&&) = default;

    inline bool operator==(const Nid &other) const;
    inline bool operator!=(const Nid &other) const;

    inline operator bool() const;
    inline int operator*() const;

    inline int getRaw() const;
    inline std::string getLongName() const;
    inline std::string getShortName() const;

  private:
    ASN1_OBJECT_uptr m_object {nullptr};
  };

  const auto AACONTROLS = Nid(NID_aaControls);
  const auto ACCOUNT = Nid(NID_account);
  const auto AC_AUDITENTITY = Nid(NID_ac_auditEntity);
  const auto AC_PROXYING = Nid(NID_ac_proxying);
  const auto AC_TARGETING = Nid(NID_ac_targeting);
  const auto AD_CA_ISSUERS = Nid(NID_ad_ca_issuers);
  const auto AD_DVCS = Nid(NID_ad_dvcs);
  const auto AD_OCSP = Nid(NID_ad_OCSP);
  const auto AD_TIMESTAMPING = Nid(NID_ad_timeStamping);
  const auto AES_128_CBC = Nid(NID_aes_128_cbc);
  const auto AES_128_CBC_HMAC_SHA1 = Nid(NID_aes_128_cbc_hmac_sha1);
  const auto AES_128_CCM = Nid(NID_aes_128_ccm);
  const auto AES_128_CFB1 = Nid(NID_aes_128_cfb1);
  const auto AES_128_CFB8 = Nid(NID_aes_128_cfb8);
  const auto AES_128_CFB128 = Nid(NID_aes_128_cfb128);
  const auto AES_128_CTR = Nid(NID_aes_128_ctr);
  const auto AES_128_ECB = Nid(NID_aes_128_ecb);
  const auto AES_128_GCM = Nid(NID_aes_128_gcm);
  const auto AES_128_OFB128 = Nid(NID_aes_128_ofb128);
  const auto AES_128_XTS = Nid(NID_aes_128_xts);
  const auto AES_192_CBC = Nid(NID_aes_192_cbc);
  const auto AES_192_CBC_HMAC_SHA1 = Nid(NID_aes_192_cbc_hmac_sha1);
  const auto AES_192_CCM = Nid(NID_aes_192_ccm);
  const auto AES_192_CFB1 = Nid(NID_aes_192_cfb1);
  const auto AES_192_CFB8 = Nid(NID_aes_192_cfb8);
  const auto AES_192_CFB128 = Nid(NID_aes_192_cfb128);
  const auto AES_192_CTR = Nid(NID_aes_192_ctr);
  const auto AES_192_ECB = Nid(NID_aes_192_ecb);
  const auto AES_192_GCM = Nid(NID_aes_192_gcm);
  const auto AES_192_OFB128 = Nid(NID_aes_192_ofb128);
  const auto AES_256_CBC = Nid(NID_aes_256_cbc);
  const auto AES_256_CBC_HMAC_SHA1 = Nid(NID_aes_256_cbc_hmac_sha1);
  const auto AES_256_CCM = Nid(NID_aes_256_ccm);
  const auto AES_256_CFB1 = Nid(NID_aes_256_cfb1);
  const auto AES_256_CFB8 = Nid(NID_aes_256_cfb8);
  const auto AES_256_CFB128 = Nid(NID_aes_256_cfb128);
  const auto AES_256_CTR = Nid(NID_aes_256_ctr);
  const auto AES_256_ECB = Nid(NID_aes_256_ecb);
  const auto AES_256_GCM = Nid(NID_aes_256_gcm);
  const auto AES_256_OFB128 = Nid(NID_aes_256_ofb128);
  const auto AES_256_XTS = Nid(NID_aes_256_xts);
  const auto ALGORITHM = Nid(NID_algorithm);
  const auto ANSI_X9_62 = Nid(NID_ansi_X9_62);
  const auto ANYEXTENDEDKEYUSAGE = Nid(NID_anyExtendedKeyUsage);
  const auto ANY_POLICY = Nid(NID_any_policy);
  const auto ARECORD = Nid(NID_aRecord);
  const auto ASSOCIATEDDOMAIN = Nid(NID_associatedDomain);
  const auto ASSOCIATEDNAME = Nid(NID_associatedName);
  const auto AUDIO = Nid(NID_audio);
  const auto AUTHORITYREVOCATIONLIST = Nid(NID_authorityRevocationList);
  const auto AUTHORITY_KEY_IDENTIFIER = Nid(NID_authority_key_identifier);
  const auto BASIC_CONSTRAINTS = Nid(NID_basic_constraints);
  const auto BF_CBC = Nid(NID_bf_cbc);
  const auto BF_CFB64 = Nid(NID_bf_cfb64);
  const auto BF_ECB = Nid(NID_bf_ecb);
  const auto BF_OFB64 = Nid(NID_bf_ofb64);
  const auto BIOMETRICINFO = Nid(NID_biometricInfo);
  const auto BUILDINGNAME = Nid(NID_buildingName);
  const auto BUSINESSCATEGORY = Nid(NID_businessCategory);
  const auto CACERTIFICATE = Nid(NID_cACertificate);
  const auto CAMELLIA_128_CBC = Nid(NID_camellia_128_cbc);
  const auto CAMELLIA_128_CFB1 = Nid(NID_camellia_128_cfb1);
  const auto CAMELLIA_128_CFB8 = Nid(NID_camellia_128_cfb8);
  const auto CAMELLIA_128_CFB128 = Nid(NID_camellia_128_cfb128);
  const auto CAMELLIA_128_ECB = Nid(NID_camellia_128_ecb);
  const auto CAMELLIA_128_OFB128 = Nid(NID_camellia_128_ofb128);
  const auto CAMELLIA_192_CBC = Nid(NID_camellia_192_cbc);
  const auto CAMELLIA_192_CFB1 = Nid(NID_camellia_192_cfb1);
  const auto CAMELLIA_192_CFB8 = Nid(NID_camellia_192_cfb8);
  const auto CAMELLIA_192_CFB128 = Nid(NID_camellia_192_cfb128);
  const auto CAMELLIA_192_ECB = Nid(NID_camellia_192_ecb);
  const auto CAMELLIA_192_OFB128 = Nid(NID_camellia_192_ofb128);
  const auto CAMELLIA_256_CBC = Nid(NID_camellia_256_cbc);
  const auto CAMELLIA_256_CFB1 = Nid(NID_camellia_256_cfb1);
  const auto CAMELLIA_256_CFB8 = Nid(NID_camellia_256_cfb8);
  const auto CAMELLIA_256_CFB128 = Nid(NID_camellia_256_cfb128);
  const auto CAMELLIA_256_ECB = Nid(NID_camellia_256_ecb);
  const auto CAMELLIA_256_OFB128 = Nid(NID_camellia_256_ofb128);
  const auto CAREPOSITORY = Nid(NID_caRepository);
  const auto CASEIGNOREIA5STRINGSYNTAX = Nid(NID_caseIgnoreIA5StringSyntax);
  const auto CAST5_CBC = Nid(NID_cast5_cbc);
  const auto CAST5_CFB64 = Nid(NID_cast5_cfb64);
  const auto CAST5_ECB = Nid(NID_cast5_ecb);
  const auto CAST5_OFB64 = Nid(NID_cast5_ofb64);
  const auto CCITT = Nid(NID_ccitt);
  const auto CERTBAG = Nid(NID_certBag);
  const auto CERTICOM_ARC = Nid(NID_certicom_arc);
  const auto CERTIFICATEREVOCATIONLIST = Nid(NID_certificateRevocationList);
  const auto CERTIFICATE_ISSUER = Nid(NID_certificate_issuer);
  const auto CERTIFICATE_POLICIES = Nid(NID_certificate_policies);
  const auto CLEARANCE = Nid(NID_clearance);
  const auto CLIENT_AUTH = Nid(NID_client_auth);
  const auto CMAC = Nid(NID_cmac);
  const auto CNAMERECORD = Nid(NID_cNAMERecord);
  const auto CODE_SIGN = Nid(NID_code_sign);
  const auto COMMONNAME = Nid(NID_commonName);
  const auto COUNTRYNAME = Nid(NID_countryName);
  const auto CRLBAG = Nid(NID_crlBag);
  const auto CRL_DISTRIBUTION_POINTS = Nid(NID_crl_distribution_points);
  const auto CRL_NUMBER = Nid(NID_crl_number);
  const auto CRL_REASON = Nid(NID_crl_reason);
  const auto CROSSCERTIFICATEPAIR = Nid(NID_crossCertificatePair);
  const auto CRYPTOCOM = Nid(NID_cryptocom);
  const auto CRYPTOPRO = Nid(NID_cryptopro);
  const auto DATA = Nid(NID_data);
  const auto DCOBJECT = Nid(NID_dcObject);
  const auto DELTAREVOCATIONLIST = Nid(NID_deltaRevocationList);
  const auto DELTA_CRL = Nid(NID_delta_crl);
  const auto DESCRIPTION = Nid(NID_description);
  const auto DESTINATIONINDICATOR = Nid(NID_destinationIndicator);
  const auto DESX_CBC = Nid(NID_desx_cbc);
  const auto DES_CBC = Nid(NID_des_cbc);
  const auto DES_CDMF = Nid(NID_des_cdmf);
  const auto DES_CFB1 = Nid(NID_des_cfb1);
  const auto DES_CFB8 = Nid(NID_des_cfb8);
  const auto DES_CFB64 = Nid(NID_des_cfb64);
  const auto DES_ECB = Nid(NID_des_ecb);
  const auto DES_EDE3_CBC = Nid(NID_des_ede3_cbc);
  const auto DES_EDE3_CFB1 = Nid(NID_des_ede3_cfb1);
  const auto DES_EDE3_CFB8 = Nid(NID_des_ede3_cfb8);
  const auto DES_EDE3_CFB64 = Nid(NID_des_ede3_cfb64);
  const auto DES_EDE3_ECB = Nid(NID_des_ede3_ecb);
  const auto DES_EDE3_OFB64 = Nid(NID_des_ede3_ofb64);
  const auto DES_EDE_CBC = Nid(NID_des_ede_cbc);
  const auto DES_EDE_CFB64 = Nid(NID_des_ede_cfb64);
  const auto DES_EDE_ECB = Nid(NID_des_ede_ecb);
  const auto DES_EDE_OFB64 = Nid(NID_des_ede_ofb64);
  const auto DES_OFB64 = Nid(NID_des_ofb64);
  const auto DHKEYAGREEMENT = Nid(NID_dhKeyAgreement);
  const auto DIRECTORY = Nid(NID_Directory);
  const auto DISTINGUISHEDNAME = Nid(NID_distinguishedName);
  const auto DITREDIRECT = Nid(NID_dITRedirect);
  const auto DMDNAME = Nid(NID_dmdName);
  const auto DNQUALIFIER = Nid(NID_dnQualifier);
  const auto DNSDOMAIN = Nid(NID_dNSDomain);
  const auto DOCUMENT = Nid(NID_document);
  const auto DOCUMENTAUTHOR = Nid(NID_documentAuthor);
  const auto DOCUMENTIDENTIFIER = Nid(NID_documentIdentifier);
  const auto DOCUMENTLOCATION = Nid(NID_documentLocation);
  const auto DOCUMENTPUBLISHER = Nid(NID_documentPublisher);
  const auto DOCUMENTSERIES = Nid(NID_documentSeries);
  const auto DOCUMENTTITLE = Nid(NID_documentTitle);
  const auto DOCUMENTVERSION = Nid(NID_documentVersion);
  const auto DOD = Nid(NID_dod);
  const auto DOMAIN = Nid(NID_Domain);
  const auto DOMAINCOMPONENT = Nid(NID_domainComponent);
  const auto DOMAINRELATEDOBJECT = Nid(NID_domainRelatedObject);
  const auto DSA = Nid(NID_dsa);
  const auto DSAQUALITY = Nid(NID_dSAQuality);
  const auto DSAWITHSHA = Nid(NID_dsaWithSHA);
  const auto DSAWITHSHA1 = Nid(NID_dsaWithSHA1);
  const auto DSAWITHSHA1_2 = Nid(NID_dsaWithSHA1_2);
  const auto DSA_2 = Nid(NID_dsa_2);
  const auto DSA_WITH_SHA224 = Nid(NID_dsa_with_SHA224);
  const auto DSA_WITH_SHA256 = Nid(NID_dsa_with_SHA256);
  const auto DVCS = Nid(NID_dvcs);
  const auto ECDSA_WITH_RECOMMENDED = Nid(NID_ecdsa_with_Recommended);
  const auto ECDSA_WITH_SHA1 = Nid(NID_ecdsa_with_SHA1);
  const auto ECDSA_WITH_SHA224 = Nid(NID_ecdsa_with_SHA224);
  const auto ECDSA_WITH_SHA256 = Nid(NID_ecdsa_with_SHA256);
  const auto ECDSA_WITH_SHA384 = Nid(NID_ecdsa_with_SHA384);
  const auto ECDSA_WITH_SHA512 = Nid(NID_ecdsa_with_SHA512);
  const auto ECDSA_WITH_SPECIFIED = Nid(NID_ecdsa_with_Specified);
  const auto EMAIL_PROTECT = Nid(NID_email_protect);
  const auto ENHANCEDSEARCHGUIDE = Nid(NID_enhancedSearchGuide);
  const auto ENTERPRISES = Nid(NID_Enterprises);
  const auto EXPERIMENTAL = Nid(NID_Experimental);
  const auto EXT_KEY_USAGE = Nid(NID_ext_key_usage);
  const auto EXT_REQ = Nid(NID_ext_req);
  const auto FACSIMILETELEPHONENUMBER = Nid(NID_facsimileTelephoneNumber);
  const auto FAVOURITEDRINK = Nid(NID_favouriteDrink);
  const auto FRESHEST_CRL = Nid(NID_freshest_crl);
  const auto FRIENDLYCOUNTRY = Nid(NID_friendlyCountry);
  const auto FRIENDLYCOUNTRYNAME = Nid(NID_friendlyCountryName);
  const auto FRIENDLYNAME = Nid(NID_friendlyName);
  const auto GENERATIONQUALIFIER = Nid(NID_generationQualifier);
  const auto GIVENNAME = Nid(NID_givenName);
  const auto GOST89_CNT = Nid(NID_gost89_cnt);
  const auto HMAC = Nid(NID_hmac);
  const auto HMACWITHMD5 = Nid(NID_hmacWithMD5);
  const auto HMACWITHSHA1 = Nid(NID_hmacWithSHA1);
  const auto HMACWITHSHA224 = Nid(NID_hmacWithSHA224);
  const auto HMACWITHSHA256 = Nid(NID_hmacWithSHA256);
  const auto HMACWITHSHA384 = Nid(NID_hmacWithSHA384);
  const auto HMACWITHSHA512 = Nid(NID_hmacWithSHA512);
  const auto HMAC_MD5 = Nid(NID_hmac_md5);
  const auto HMAC_SHA1 = Nid(NID_hmac_sha1);
  const auto HOLD_INSTRUCTION_CALL_ISSUER = Nid(NID_hold_instruction_call_issuer);
  const auto HOLD_INSTRUCTION_CODE = Nid(NID_hold_instruction_code);
  const auto HOLD_INSTRUCTION_NONE = Nid(NID_hold_instruction_none);
  const auto HOLD_INSTRUCTION_REJECT = Nid(NID_hold_instruction_reject);
  const auto HOMEPOSTALADDRESS = Nid(NID_homePostalAddress);
  const auto HOMETELEPHONENUMBER = Nid(NID_homeTelephoneNumber);
  const auto HOST = Nid(NID_host);
  const auto HOUSEIDENTIFIER = Nid(NID_houseIdentifier);
  const auto IA5STRINGSYNTAX = Nid(NID_iA5StringSyntax);
  const auto IANA = Nid(NID_iana);
  const auto IDEA_CBC = Nid(NID_idea_cbc);
  const auto IDEA_CFB64 = Nid(NID_idea_cfb64);
  const auto IDEA_ECB = Nid(NID_idea_ecb);
  const auto IDEA_OFB64 = Nid(NID_idea_ofb64);
  const auto IDENTIFIED_ORGANIZATION = Nid(NID_identified_organization);
  const auto ID_ACA = Nid(NID_id_aca);
  const auto ID_ACA_ACCESSIDENTITY = Nid(NID_id_aca_accessIdentity);
  const auto ID_ACA_AUTHENTICATIONINFO = Nid(NID_id_aca_authenticationInfo);
  const auto ID_ACA_CHARGINGIDENTITY = Nid(NID_id_aca_chargingIdentity);
  const auto ID_ACA_ENCATTRS = Nid(NID_id_aca_encAttrs);
  const auto ID_ACA_GROUP = Nid(NID_id_aca_group);
  const auto ID_ACA_ROLE = Nid(NID_id_aca_role);
  const auto ID_AD = Nid(NID_id_ad);
  const auto ID_AES128_WRAP = Nid(NID_id_aes128_wrap);
  const auto ID_AES128_WRAP_PAD = Nid(NID_id_aes128_wrap_pad);
  const auto ID_AES192_WRAP = Nid(NID_id_aes192_wrap);
  const auto ID_AES192_WRAP_PAD = Nid(NID_id_aes192_wrap_pad);
  const auto ID_AES256_WRAP = Nid(NID_id_aes256_wrap);
  const auto ID_AES256_WRAP_PAD = Nid(NID_id_aes256_wrap_pad);
  const auto ID_ALG = Nid(NID_id_alg);
  const auto ID_ALG_DES40 = Nid(NID_id_alg_des40);
  const auto ID_ALG_DH_POP = Nid(NID_id_alg_dh_pop);
  const auto ID_ALG_DH_SIG_HMAC_SHA1 = Nid(NID_id_alg_dh_sig_hmac_sha1);
  const auto ID_ALG_NOSIGNATURE = Nid(NID_id_alg_noSignature);
  const auto ID_ALG_PWRI_KEK = Nid(NID_id_alg_PWRI_KEK);
  const auto ID_CAMELLIA128_WRAP = Nid(NID_id_camellia128_wrap);
  const auto ID_CAMELLIA192_WRAP = Nid(NID_id_camellia192_wrap);
  const auto ID_CAMELLIA256_WRAP = Nid(NID_id_camellia256_wrap);
  const auto ID_CCT = Nid(NID_id_cct);
  const auto ID_CCT_CRS = Nid(NID_id_cct_crs);
  const auto ID_CCT_PKIDATA = Nid(NID_id_cct_PKIData);
  const auto ID_CCT_PKIRESPONSE = Nid(NID_id_cct_PKIResponse);
  const auto ID_CE = Nid(NID_id_ce);
  const auto ID_CMC = Nid(NID_id_cmc);
  const auto ID_CMC_ADDEXTENSIONS = Nid(NID_id_cmc_addExtensions);
  const auto ID_CMC_CONFIRMCERTACCEPTANCE = Nid(NID_id_cmc_confirmCertAcceptance);
  const auto ID_CMC_DATARETURN = Nid(NID_id_cmc_dataReturn);
  const auto ID_CMC_DECRYPTEDPOP = Nid(NID_id_cmc_decryptedPOP);
  const auto ID_CMC_ENCRYPTEDPOP = Nid(NID_id_cmc_encryptedPOP);
  const auto ID_CMC_GETCERT = Nid(NID_id_cmc_getCert);
  const auto ID_CMC_GETCRL = Nid(NID_id_cmc_getCRL);
  const auto ID_CMC_IDENTIFICATION = Nid(NID_id_cmc_identification);
  const auto ID_CMC_IDENTITYPROOF = Nid(NID_id_cmc_identityProof);
  const auto ID_CMC_LRAPOPWITNESS = Nid(NID_id_cmc_lraPOPWitness);
  const auto ID_CMC_POPLINKRANDOM = Nid(NID_id_cmc_popLinkRandom);
  const auto ID_CMC_POPLINKWITNESS = Nid(NID_id_cmc_popLinkWitness);
  const auto ID_CMC_QUERYPENDING = Nid(NID_id_cmc_queryPending);
  const auto ID_CMC_RECIPIENTNONCE = Nid(NID_id_cmc_recipientNonce);
  const auto ID_CMC_REGINFO = Nid(NID_id_cmc_regInfo);
  const auto ID_CMC_RESPONSEINFO = Nid(NID_id_cmc_responseInfo);
  const auto ID_CMC_REVOKEREQUEST = Nid(NID_id_cmc_revokeRequest);
  const auto ID_CMC_SENDERNONCE = Nid(NID_id_cmc_senderNonce);
  const auto ID_CMC_STATUSINFO = Nid(NID_id_cmc_statusInfo);
  const auto ID_CMC_TRANSACTIONID = Nid(NID_id_cmc_transactionId);
  const auto ID_CT_ASCIITEXTWITHCRLF = Nid(NID_id_ct_asciiTextWithCRLF);
  const auto ID_DHBASEDMAC = Nid(NID_id_DHBasedMac);
  const auto ID_GOST28147_89 = Nid(NID_id_Gost28147_89);
  const auto ID_GOST28147_89_CC = Nid(NID_id_Gost28147_89_cc);
  const auto ID_GOST28147_89_CRYPTOPRO_A_PARAMSET = Nid(NID_id_Gost28147_89_CryptoPro_A_ParamSet);
  const auto ID_GOST28147_89_CRYPTOPRO_B_PARAMSET = Nid(NID_id_Gost28147_89_CryptoPro_B_ParamSet);
  const auto ID_GOST28147_89_CRYPTOPRO_C_PARAMSET = Nid(NID_id_Gost28147_89_CryptoPro_C_ParamSet);
  const auto ID_GOST28147_89_CRYPTOPRO_D_PARAMSET = Nid(NID_id_Gost28147_89_CryptoPro_D_ParamSet);
  const auto ID_GOST28147_89_CRYPTOPRO_KEYMESHING = Nid(NID_id_Gost28147_89_CryptoPro_KeyMeshing);
  const auto ID_GOST28147_89_CRYPTOPRO_OSCAR_1_0_PARAMSET = Nid(NID_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet);
  const auto ID_GOST28147_89_CRYPTOPRO_OSCAR_1_1_PARAMSET = Nid(NID_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet);
  const auto ID_GOST28147_89_CRYPTOPRO_RIC_1_PARAMSET = Nid(NID_id_Gost28147_89_CryptoPro_RIC_1_ParamSet);
  const auto ID_GOST28147_89_MAC = Nid(NID_id_Gost28147_89_MAC);
  const auto ID_GOST28147_89_NONE_KEYMESHING = Nid(NID_id_Gost28147_89_None_KeyMeshing);
  const auto ID_GOST28147_89_TESTPARAMSET = Nid(NID_id_Gost28147_89_TestParamSet);
  const auto ID_GOSTR3410_94 = Nid(NID_id_GostR3410_94);
  const auto ID_GOSTR3410_2001 = Nid(NID_id_GostR3410_2001);
  const auto ID_GOSTR3410_2001DH = Nid(NID_id_GostR3410_2001DH);
  const auto ID_GOSTR3410_2001_CC = Nid(NID_id_GostR3410_2001_cc);
  const auto ID_GOSTR3410_2001_CRYPTOPRO_A_PARAMSET = Nid(NID_id_GostR3410_2001_CryptoPro_A_ParamSet);
  const auto ID_GOSTR3410_2001_CRYPTOPRO_B_PARAMSET = Nid(NID_id_GostR3410_2001_CryptoPro_B_ParamSet);
  const auto ID_GOSTR3410_2001_CRYPTOPRO_C_PARAMSET = Nid(NID_id_GostR3410_2001_CryptoPro_C_ParamSet);
  const auto ID_GOSTR3410_2001_CRYPTOPRO_XCHA_PARAMSET = Nid(NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet);
  const auto ID_GOSTR3410_2001_CRYPTOPRO_XCHB_PARAMSET = Nid(NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet);
  const auto ID_GOSTR3410_2001_PARAMSET_CC = Nid(NID_id_GostR3410_2001_ParamSet_cc);
  const auto ID_GOSTR3410_2001_TESTPARAMSET = Nid(NID_id_GostR3410_2001_TestParamSet);
  const auto ID_GOSTR3410_94DH = Nid(NID_id_GostR3410_94DH);
  const auto ID_GOSTR3410_94_A = Nid(NID_id_GostR3410_94_a);
  const auto ID_GOSTR3410_94_ABIS = Nid(NID_id_GostR3410_94_aBis);
  const auto ID_GOSTR3410_94_B = Nid(NID_id_GostR3410_94_b);
  const auto ID_GOSTR3410_94_BBIS = Nid(NID_id_GostR3410_94_bBis);
  const auto ID_GOSTR3410_94_CC = Nid(NID_id_GostR3410_94_cc);
  const auto ID_GOSTR3410_94_CRYPTOPRO_A_PARAMSET = Nid(NID_id_GostR3410_94_CryptoPro_A_ParamSet);
  const auto ID_GOSTR3410_94_CRYPTOPRO_B_PARAMSET = Nid(NID_id_GostR3410_94_CryptoPro_B_ParamSet);
  const auto ID_GOSTR3410_94_CRYPTOPRO_C_PARAMSET = Nid(NID_id_GostR3410_94_CryptoPro_C_ParamSet);
  const auto ID_GOSTR3410_94_CRYPTOPRO_D_PARAMSET = Nid(NID_id_GostR3410_94_CryptoPro_D_ParamSet);
  const auto ID_GOSTR3410_94_CRYPTOPRO_XCHA_PARAMSET = Nid(NID_id_GostR3410_94_CryptoPro_XchA_ParamSet);
  const auto ID_GOSTR3410_94_CRYPTOPRO_XCHB_PARAMSET = Nid(NID_id_GostR3410_94_CryptoPro_XchB_ParamSet);
  const auto ID_GOSTR3410_94_CRYPTOPRO_XCHC_PARAMSET = Nid(NID_id_GostR3410_94_CryptoPro_XchC_ParamSet);
  const auto ID_GOSTR3410_94_TESTPARAMSET = Nid(NID_id_GostR3410_94_TestParamSet);
  const auto ID_GOSTR3411_94 = Nid(NID_id_GostR3411_94);
  const auto ID_GOSTR3411_94_CRYPTOPROPARAMSET = Nid(NID_id_GostR3411_94_CryptoProParamSet);
  const auto ID_GOSTR3411_94_PRF = Nid(NID_id_GostR3411_94_prf);
  const auto ID_GOSTR3411_94_TESTPARAMSET = Nid(NID_id_GostR3411_94_TestParamSet);
  const auto ID_GOSTR3411_94_WITH_GOSTR3410_94 = Nid(NID_id_GostR3411_94_with_GostR3410_94);
  const auto ID_GOSTR3411_94_WITH_GOSTR3410_2001 = Nid(NID_id_GostR3411_94_with_GostR3410_2001);
  const auto ID_GOSTR3411_94_WITH_GOSTR3410_2001_CC = Nid(NID_id_GostR3411_94_with_GostR3410_2001_cc);
  const auto ID_GOSTR3411_94_WITH_GOSTR3410_94_CC = Nid(NID_id_GostR3411_94_with_GostR3410_94_cc);
  const auto ID_HEX_MULTIPART_MESSAGE = Nid(NID_id_hex_multipart_message);
  const auto ID_HEX_PARTIAL_MESSAGE = Nid(NID_id_hex_partial_message);
  const auto ID_HMACGOSTR3411_94 = Nid(NID_id_HMACGostR3411_94);
  const auto ID_IT = Nid(NID_id_it);
  const auto ID_IT_CAKEYUPDATEINFO = Nid(NID_id_it_caKeyUpdateInfo);
  const auto ID_IT_CAPROTENCCERT = Nid(NID_id_it_caProtEncCert);
  const auto ID_IT_CONFIRMWAITTIME = Nid(NID_id_it_confirmWaitTime);
  const auto ID_IT_CURRENTCRL = Nid(NID_id_it_currentCRL);
  const auto ID_IT_ENCKEYPAIRTYPES = Nid(NID_id_it_encKeyPairTypes);
  const auto ID_IT_IMPLICITCONFIRM = Nid(NID_id_it_implicitConfirm);
  const auto ID_IT_KEYPAIRPARAMREP = Nid(NID_id_it_keyPairParamRep);
  const auto ID_IT_KEYPAIRPARAMREQ = Nid(NID_id_it_keyPairParamRep);
  const auto ID_IT_ORIGPKIMESSAGE = Nid(NID_id_it_origPKIMessage);
  const auto ID_IT_PREFERREDSYMMALG = Nid(NID_id_it_preferredSymmAlg);
  const auto ID_IT_REVPASSPHRASE = Nid(NID_id_it_revPassphrase);
  const auto ID_IT_SIGNKEYPAIRTYPES = Nid(NID_id_it_signKeyPairTypes);
  const auto ID_IT_SUBSCRIPTIONREQUEST = Nid(NID_id_it_subscriptionRequest);
  const auto ID_IT_SUBSCRIPTIONRESPONSE = Nid(NID_id_it_subscriptionResponse);
  const auto ID_IT_SUPPLANGTAGS = Nid(NID_id_it_suppLangTags);
  const auto ID_IT_UNSUPPORTEDOIDS = Nid(NID_id_it_unsupportedOIDs);
  const auto ID_KP = Nid(NID_id_kp);
  const auto ID_MOD_ATTRIBUTE_CERT = Nid(NID_id_mod_attribute_cert);
  const auto ID_MOD_CMC = Nid(NID_id_mod_cmc);
  const auto ID_MOD_CMP = Nid(NID_id_mod_cmp);
  const auto ID_MOD_CMP2000 = Nid(NID_id_mod_cmp2000);
  const auto ID_MOD_CRMF = Nid(NID_id_mod_crmf);
  const auto ID_MOD_DVCS = Nid(NID_id_mod_dvcs);
  const auto ID_MOD_KEA_PROFILE_88 = Nid(NID_id_mod_kea_profile_88);
  const auto ID_MOD_KEA_PROFILE_93 = Nid(NID_id_mod_kea_profile_93);
  const auto ID_MOD_OCSP = Nid(NID_id_mod_ocsp);
  const auto ID_MOD_QUALIFIED_CERT_88 = Nid(NID_id_mod_qualified_cert_88);
  const auto ID_MOD_QUALIFIED_CERT_93 = Nid(NID_id_mod_qualified_cert_93);
  const auto ID_MOD_TIMESTAMP_PROTOCOL = Nid(NID_id_mod_timestamp_protocol);
  const auto ID_ON = Nid(NID_id_on);
  const auto ID_ON_PERMANENTIDENTIFIER = Nid(NID_id_on_permanentIdentifier);
  const auto ID_ON_PERSONALDATA = Nid(NID_id_on_personalData);
  const auto ID_PASSWORDBASEDMAC = Nid(NID_id_PasswordBasedMAC);
  const auto ID_PBKDF2 = Nid(NID_id_pbkdf2);
  const auto ID_PDA = Nid(NID_id_pda);
  const auto ID_PDA_COUNTRYOFCITIZENSHIP = Nid(NID_id_pda_countryOfCitizenship);
  const auto ID_PDA_COUNTRYOFRESIDENCE = Nid(NID_id_pda_countryOfResidence);
  const auto ID_PDA_DATEOFBIRTH = Nid(NID_id_pda_dateOfBirth);
  const auto ID_PDA_GENDER = Nid(NID_id_pda_gender);
  const auto ID_PDA_PLACEOFBIRTH = Nid(NID_id_pda_placeOfBirth);
  const auto ID_PE = Nid(NID_id_pe);
  const auto ID_PKIP = Nid(NID_id_pkip);
  const auto ID_PKIX = Nid(NID_id_pkix);
  const auto ID_PKIX1_EXPLICIT_88 = Nid(NID_id_pkix1_explicit_88);
  const auto ID_PKIX1_EXPLICIT_93 = Nid(NID_id_pkix1_explicit_93);
  const auto ID_PKIX1_IMPLICIT_88 = Nid(NID_id_pkix1_implicit_88);
  const auto ID_PKIX1_IMPLICIT_93 = Nid(NID_id_pkix1_implicit_93);
  const auto ID_PKIX_MOD = Nid(NID_id_pkix_mod);
  const auto ID_PKIX_OCSP_ACCEPTABLERESPONSES = Nid(NID_id_pkix_OCSP_acceptableResponses);
  const auto ID_PKIX_OCSP_ARCHIVECUTOFF = Nid(NID_id_pkix_OCSP_archiveCutoff);
  const auto ID_PKIX_OCSP_BASIC = Nid(NID_id_pkix_OCSP_basic);
  const auto ID_PKIX_OCSP_CRLID = Nid(NID_id_pkix_OCSP_CrlID);
  const auto ID_PKIX_OCSP_EXTENDEDSTATUS = Nid(NID_id_pkix_OCSP_extendedStatus);
  const auto ID_PKIX_OCSP_NOCHECK = Nid(NID_id_pkix_OCSP_noCheck);
  const auto ID_PKIX_OCSP_NONCE = Nid(NID_id_pkix_OCSP_Nonce);
  const auto ID_PKIX_OCSP_PATH = Nid(NID_id_pkix_OCSP_path);
  const auto ID_PKIX_OCSP_SERVICELOCATOR = Nid(NID_id_pkix_OCSP_serviceLocator);
  const auto ID_PKIX_OCSP_TRUSTROOT = Nid(NID_id_pkix_OCSP_trustRoot);
  const auto ID_PKIX_OCSP_VALID = Nid(NID_id_pkix_OCSP_valid);
  const auto ID_PPL = Nid(NID_id_ppl);
  const auto ID_PPL_ANYLANGUAGE = Nid(NID_id_ppl_anyLanguage);
  const auto ID_PPL_INHERITALL = Nid(NID_id_ppl_inheritAll);
  const auto ID_QCS = Nid(NID_id_qcs);
  const auto ID_QCS_PKIXQCSYNTAX_V1 = Nid(NID_id_qcs_pkixQCSyntax_v1);
  const auto ID_QT = Nid(NID_id_qt);
  const auto ID_QT_CPS = Nid(NID_id_qt_cps);
  const auto ID_QT_UNOTICE = Nid(NID_id_qt_unotice);
  const auto ID_REGCTRL = Nid(NID_id_regCtrl);
  const auto ID_REGCTRL_AUTHENTICATOR = Nid(NID_id_regCtrl_authenticator);
  const auto ID_REGCTRL_OLDCERTID = Nid(NID_id_regCtrl_oldCertID);
  const auto ID_REGCTRL_PKIARCHIVEOPTIONS = Nid(NID_id_regCtrl_pkiArchiveOptions);
  const auto ID_REGCTRL_PKIPUBLICATIONINFO = Nid(NID_id_regCtrl_pkiPublicationInfo);
  const auto ID_REGCTRL_PROTOCOLENCRKEY = Nid(NID_id_regCtrl_protocolEncrKey);
  const auto ID_REGCTRL_REGTOKEN = Nid(NID_id_regCtrl_regToken);
  const auto ID_REGINFO = Nid(NID_id_regInfo);
  const auto ID_REGINFO_CERTREQ = Nid(NID_id_regInfo_certReq);
  const auto ID_REGINFO_UTF8PAIRS = Nid(NID_id_regInfo_utf8Pairs);
  const auto ID_SET = Nid(NID_id_set);
  const auto ID_SMIME_AA = Nid(NID_id_smime_aa);
  const auto ID_SMIME_AA_CONTENTHINT = Nid(NID_id_smime_aa_contentHint);
  const auto ID_SMIME_AA_CONTENTIDENTIFIER = Nid(NID_id_smime_aa_contentIdentifier);
  const auto ID_SMIME_AA_CONTENTREFERENCE = Nid(NID_id_smime_aa_contentReference);
  const auto ID_SMIME_AA_DVCS_DVC = Nid(NID_id_smime_aa_dvcs_dvc);
  const auto ID_SMIME_AA_ENCAPCONTENTTYPE = Nid(NID_id_smime_aa_encapContentType);
  const auto ID_SMIME_AA_ENCRYPKEYPREF = Nid(NID_id_smime_aa_encrypKeyPref);
  const auto ID_SMIME_AA_EQUIVALENTLABELS = Nid(NID_id_smime_aa_equivalentLabels);
  const auto ID_SMIME_AA_ETS_ARCHIVETIMESTAMP = Nid(NID_id_smime_aa_ets_archiveTimeStamp);
  const auto ID_SMIME_AA_ETS_CERTCRLTIMESTAMP = Nid(NID_id_smime_aa_ets_certCRLTimestamp);
  const auto ID_SMIME_AA_ETS_CERTIFICATEREFS = Nid(NID_id_smime_aa_ets_CertificateRefs);
  const auto ID_SMIME_AA_ETS_CERTVALUES = Nid(NID_id_smime_aa_ets_certValues);
  const auto ID_SMIME_AA_ETS_COMMITMENTTYPE = Nid(NID_id_smime_aa_ets_commitmentType);
  const auto ID_SMIME_AA_ETS_CONTENTTIMESTAMP = Nid(NID_id_smime_aa_ets_contentTimestamp);
  const auto ID_SMIME_AA_ETS_ESCTIMESTAMP = Nid(NID_id_smime_aa_ets_escTimeStamp);
  const auto ID_SMIME_AA_ETS_OTHERSIGCERT = Nid(NID_id_smime_aa_ets_otherSigCert);
  const auto ID_SMIME_AA_ETS_REVOCATIONREFS = Nid(NID_id_smime_aa_ets_RevocationRefs);
  const auto ID_SMIME_AA_ETS_REVOCATIONVALUES = Nid(NID_id_smime_aa_ets_revocationValues);
  const auto ID_SMIME_AA_ETS_SIGNERATTR = Nid(NID_id_smime_aa_ets_signerAttr);
  const auto ID_SMIME_AA_ETS_SIGNERLOCATION = Nid(NID_id_smime_aa_ets_signerLocation);
  const auto ID_SMIME_AA_ETS_SIGPOLICYID = Nid(NID_id_smime_aa_ets_sigPolicyId);
  const auto ID_SMIME_AA_MACVALUE = Nid(NID_id_smime_aa_macValue);
  const auto ID_SMIME_AA_MLEXPANDHISTORY = Nid(NID_id_smime_aa_mlExpandHistory);
  const auto ID_SMIME_AA_MSGSIGDIGEST = Nid(NID_id_smime_aa_msgSigDigest);
  const auto ID_SMIME_AA_RECEIPTREQUEST = Nid(NID_id_smime_aa_receiptRequest);
  const auto ID_SMIME_AA_SECURITYLABEL = Nid(NID_id_smime_aa_securityLabel);
  const auto ID_SMIME_AA_SIGNATURETYPE = Nid(NID_id_smime_aa_signatureType);
  const auto ID_SMIME_AA_SIGNINGCERTIFICATE = Nid(NID_id_smime_aa_signingCertificate);
  const auto ID_SMIME_AA_SMIMEENCRYPTCERTS = Nid(NID_id_smime_aa_smimeEncryptCerts);
  const auto ID_SMIME_AA_TIMESTAMPTOKEN = Nid(NID_id_smime_aa_timeStampToken);
  const auto ID_SMIME_ALG = Nid(NID_id_smime_alg);
  const auto ID_SMIME_ALG_3DESWRAP = Nid(NID_id_smime_alg_3DESwrap);
  const auto ID_SMIME_ALG_CMS3DESWRAP = Nid(NID_id_smime_alg_CMS3DESwrap);
  const auto ID_SMIME_ALG_CMSRC2WRAP = Nid(NID_id_smime_alg_CMSRC2wrap);
  const auto ID_SMIME_ALG_ESDH = Nid(NID_id_smime_alg_ESDH);
  const auto ID_SMIME_ALG_ESDHWITH3DES = Nid(NID_id_smime_alg_ESDHwith3DES);
  const auto ID_SMIME_ALG_ESDHWITHRC2 = Nid(NID_id_smime_alg_ESDHwithRC2);
  const auto ID_SMIME_ALG_RC2WRAP = Nid(NID_id_smime_alg_RC2wrap);
  const auto ID_SMIME_CD = Nid(NID_id_smime_cd);
  const auto ID_SMIME_CD_LDAP = Nid(NID_id_smime_cd_ldap);
  const auto ID_SMIME_CT = Nid(NID_id_smime_ct);
  const auto ID_SMIME_CTI = Nid(NID_id_smime_cti);
  const auto ID_SMIME_CTI_ETS_PROOFOFAPPROVAL = Nid(NID_id_smime_cti_ets_proofOfApproval);
  const auto ID_SMIME_CTI_ETS_PROOFOFCREATION = Nid(NID_id_smime_cti_ets_proofOfCreation);
  const auto ID_SMIME_CTI_ETS_PROOFOFDELIVERY = Nid(NID_id_smime_cti_ets_proofOfDelivery);
  const auto ID_SMIME_CTI_ETS_PROOFOFORIGIN = Nid(NID_id_smime_cti_ets_proofOfOrigin);
  const auto ID_SMIME_CTI_ETS_PROOFOFRECEIPT = Nid(NID_id_smime_cti_ets_proofOfReceipt);
  const auto ID_SMIME_CTI_ETS_PROOFOFSENDER = Nid(NID_id_smime_cti_ets_proofOfSender);
  const auto ID_SMIME_CT_AUTHDATA = Nid(NID_id_smime_ct_authData);
  const auto ID_SMIME_CT_COMPRESSEDDATA = Nid(NID_id_smime_ct_compressedData);
  const auto ID_SMIME_CT_CONTENTINFO = Nid(NID_id_smime_ct_contentInfo);
  const auto ID_SMIME_CT_DVCSREQUESTDATA = Nid(NID_id_smime_ct_DVCSRequestData);
  const auto ID_SMIME_CT_DVCSRESPONSEDATA = Nid(NID_id_smime_ct_DVCSResponseData);
  const auto ID_SMIME_CT_PUBLISHCERT = Nid(NID_id_smime_ct_publishCert);
  const auto ID_SMIME_CT_RECEIPT = Nid(NID_id_smime_ct_receipt);
  const auto ID_SMIME_CT_TDTINFO = Nid(NID_id_smime_ct_TDTInfo);
  const auto ID_SMIME_CT_TSTINFO = Nid(NID_id_smime_ct_TSTInfo);
  const auto ID_SMIME_MOD = Nid(NID_id_smime_mod);
  const auto ID_SMIME_MOD_CMS = Nid(NID_id_smime_mod_cms);
  const auto ID_SMIME_MOD_ESS = Nid(NID_id_smime_mod_ess);
  const auto ID_SMIME_MOD_ETS_ESIGNATURE_88 = Nid(NID_id_smime_mod_ets_eSignature_88);
  const auto ID_SMIME_MOD_ETS_ESIGNATURE_97 = Nid(NID_id_smime_mod_ets_eSignature_97);
  const auto ID_SMIME_MOD_ETS_ESIGPOLICY_88 = Nid(NID_id_smime_mod_ets_eSigPolicy_88);
  const auto ID_SMIME_MOD_ETS_ESIGPOLICY_97 = Nid(NID_id_smime_mod_ets_eSigPolicy_97);
  const auto ID_SMIME_MOD_MSG_V3 = Nid(NID_id_smime_mod_msg_v3);
  const auto ID_SMIME_MOD_OID = Nid(NID_id_smime_mod_oid);
  const auto ID_SMIME_SPQ = Nid(NID_id_smime_spq);
  const auto ID_SMIME_SPQ_ETS_SQT_UNOTICE = Nid(NID_id_smime_spq_ets_sqt_unotice);
  const auto ID_SMIME_SPQ_ETS_SQT_URI = Nid(NID_id_smime_spq_ets_sqt_uri);
  const auto INDEPENDENT = Nid(NID_Independent);
  const auto INFO = Nid(NID_info);
  const auto INFO_ACCESS = Nid(NID_info_access);
  const auto INHIBIT_ANY_POLICY = Nid(NID_inhibit_any_policy);
  const auto INITIALS = Nid(NID_initials);
  const auto INTERNATIONALISDNNUMBER = Nid(NID_internationaliSDNNumber);
  const auto INTERNATIONAL_ORGANIZATIONS = Nid(NID_international_organizations);
  const auto INVALIDITY_DATE = Nid(NID_invalidity_date);
  const auto IPSEC3 = Nid(NID_ipsec3);
  const auto IPSEC4 = Nid(NID_ipsec4);
  const auto IPSECENDSYSTEM = Nid(NID_ipsecEndSystem);
  const auto IPSECTUNNEL = Nid(NID_ipsecTunnel);
  const auto IPSECUSER = Nid(NID_ipsecUser);
  const auto ISO = Nid(NID_iso);
  const auto ISO_US = Nid(NID_ISO_US);
  const auto ISSUER_ALT_NAME = Nid(NID_issuer_alt_name);
  const auto ISSUING_DISTRIBUTION_POINT = Nid(NID_issuing_distribution_point);
  const auto ITU_T = Nid(NID_itu_t);
  const auto JANETMAILBOX = Nid(NID_janetMailbox);
  const auto JOINT_ISO_CCITT = Nid(NID_joint_iso_ccitt);
  const auto JOINT_ISO_ITU_T = Nid(NID_joint_iso_itu_t);
  const auto KEYBAG = Nid(NID_keyBag);
  const auto KEY_USAGE = Nid(NID_key_usage);
  const auto KISA = Nid(NID_kisa);
  const auto LASTMODIFIEDBY = Nid(NID_lastModifiedBy);
  const auto LASTMODIFIEDTIME = Nid(NID_lastModifiedTime);
  const auto LOCALITYNAME = Nid(NID_localityName);
  const auto LOCALKEYID = Nid(NID_localKeyID);
  const auto LOCALKEYSET = Nid(NID_LocalKeySet);
  const auto MAIL = Nid(NID_Mail);
  const auto MAILPREFERENCEOPTION = Nid(NID_mailPreferenceOption);
  const auto MANAGEMENT = Nid(NID_Management);
  const auto MANAGER = Nid(NID_manager);
  const auto MD2 = Nid(NID_md2);
  const auto MD4 = Nid(NID_md4);
  const auto MD5 = Nid(NID_md5);
  const auto MD2WITHRSAENCRYPTION = Nid(NID_md2WithRSAEncryption);
  const auto MD4WITHRSAENCRYPTION = Nid(NID_md4WithRSAEncryption);
  const auto MD5WITHRSA = Nid(NID_md5WithRSA);
  const auto MD5WITHRSAENCRYPTION = Nid(NID_md5WithRSAEncryption);
  const auto MD5_SHA1 = Nid(NID_md5_sha1);
  const auto MDC2 = Nid(NID_mdc2);
  const auto MDC2WITHRSA = Nid(NID_mdc2WithRSA);
  const auto MEMBER = Nid(NID_member);
  const auto MEMBER_BODY = Nid(NID_member_body);
  const auto MGF1 = Nid(NID_mgf1);
  const auto MIME_MHS = Nid(NID_mime_mhs);
  const auto MIME_MHS_BODIES = Nid(NID_mime_mhs_bodies);
  const auto MIME_MHS_HEADINGS = Nid(NID_mime_mhs_headings);
  const auto MOBILETELEPHONENUMBER = Nid(NID_mobileTelephoneNumber);
  const auto MS_CODE_COM = Nid(NID_ms_code_com);
  const auto MS_CODE_IND = Nid(NID_ms_code_ind);
  const auto MS_CSP_NAME = Nid(NID_ms_csp_name);
  const auto MS_CTL_SIGN = Nid(NID_ms_ctl_sign);
  const auto MS_EFS = Nid(NID_ms_efs);
  const auto MS_EXT_REQ = Nid(NID_ms_ext_req);
  const auto MS_SGC = Nid(NID_ms_sgc);
  const auto MS_SMARTCARD_LOGIN = Nid(NID_ms_smartcard_login);
  const auto MS_UPN = Nid(NID_ms_upn);
  const auto MXRECORD = Nid(NID_mXRecord);
  const auto NAME = Nid(NID_name);
  const auto NAME_CONSTRAINTS = Nid(NID_name_constraints);
  const auto NETSCAPE = Nid(NID_netscape);
  const auto NETSCAPE_BASE_URL = Nid(NID_netscape_base_url);
  const auto NETSCAPE_CA_POLICY_URL = Nid(NID_netscape_ca_policy_url);
  const auto NETSCAPE_CA_REVOCATION_URL = Nid(NID_netscape_ca_revocation_url);
  const auto NETSCAPE_CERT_EXTENSION = Nid(NID_netscape_cert_extension);
  const auto NETSCAPE_CERT_SEQUENCE = Nid(NID_netscape_cert_sequence);
  const auto NETSCAPE_CERT_TYPE = Nid(NID_netscape_cert_type);
  const auto NETSCAPE_COMMENT = Nid(NID_netscape_comment);
  const auto NETSCAPE_DATA_TYPE = Nid(NID_netscape_data_type);
  const auto NETSCAPE_RENEWAL_URL = Nid(NID_netscape_renewal_url);
  const auto NETSCAPE_REVOCATION_URL = Nid(NID_netscape_revocation_url);
  const auto NETSCAPE_SSL_SERVER_NAME = Nid(NID_netscape_ssl_server_name);
  const auto NO_REV_AVAIL = Nid(NID_no_rev_avail);
  const auto NSRECORD = Nid(NID_nSRecord);
  const auto NS_SGC = Nid(NID_ns_sgc);
  const auto OCSP_SIGN = Nid(NID_OCSP_sign);
  const auto ORG = Nid(NID_org);
  const auto ORGANIZATIONALSTATUS = Nid(NID_organizationalStatus);
  const auto ORGANIZATIONALUNITNAME = Nid(NID_organizationalUnitName);
  const auto ORGANIZATIONNAME = Nid(NID_organizationName);
  const auto OTHERMAILBOX = Nid(NID_otherMailbox);
  const auto OWNER = Nid(NID_owner);
  const auto PAGERTELEPHONENUMBER = Nid(NID_pagerTelephoneNumber);
  const auto PBES2 = Nid(NID_pbes2);
  const auto PBEWITHMD2ANDDES_CBC = Nid(NID_pbeWithMD2AndDES_CBC);
  const auto PBEWITHMD2ANDRC2_CBC = Nid(NID_pbeWithMD2AndRC2_CBC);
  const auto PBEWITHMD5ANDCAST5_CBC = Nid(NID_pbeWithMD5AndCast5_CBC);
  const auto PBEWITHMD5ANDDES_CBC = Nid(NID_pbeWithMD5AndDES_CBC);
  const auto PBEWITHMD5ANDRC2_CBC = Nid(NID_pbeWithMD5AndRC2_CBC);
  const auto PBEWITHSHA1ANDDES_CBC = Nid(NID_pbeWithSHA1AndDES_CBC);
  const auto PBEWITHSHA1ANDRC2_CBC = Nid(NID_pbeWithSHA1AndRC2_CBC);
  const auto PBE_WITHSHA1AND128BITRC4 = Nid(NID_pbe_WithSHA1And128BitRC2_CBC);
  const auto PBE_WITHSHA1AND128BITRC2_CBC = Nid(NID_pbe_WithSHA1And128BitRC2_CBC);
  const auto PBE_WITHSHA1AND2_KEY_TRIPLEDES_CBC = Nid(NID_pbe_WithSHA1And2_Key_TripleDES_CBC);
  const auto PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC = Nid(NID_pbe_WithSHA1And3_Key_TripleDES_CBC);
  const auto PBE_WITHSHA1AND40BITRC4 = Nid(NID_pbe_WithSHA1And40BitRC4);
  const auto PBE_WITHSHA1AND40BITRC2_CBC = Nid(NID_pbe_WithSHA1And40BitRC2_CBC);
  const auto PBMAC1 = Nid(NID_pbmac1);
  const auto PERSONALSIGNATURE = Nid(NID_personalSignature);
  const auto PERSONALTITLE = Nid(NID_personalTitle);
  const auto PHOTO = Nid(NID_photo);
  const auto PHYSICALDELIVERYOFFICENAME = Nid(NID_physicalDeliveryOfficeName);
  const auto PILOT = Nid(NID_pilot);
  const auto PILOTATTRIBUTESYNTAX = Nid(NID_pilotAttributeSyntax);
  const auto PILOTATTRIBUTETYPE = Nid(NID_pilotAttributeType);
  const auto PILOTATTRIBUTETYPE27 = Nid(NID_pilotAttributeType27);
  const auto PILOTDSA = Nid(NID_pilotDSA);
  const auto PILOTGROUPS = Nid(NID_pilotGroups);
  const auto PILOTOBJECT = Nid(NID_pilotObject);
  const auto PILOTOBJECTCLASS = Nid(NID_pilotObjectClass);
  const auto PILOTORGANIZATION = Nid(NID_pilotOrganization);
  const auto PILOTPERSON = Nid(NID_pilotPerson);
  const auto PKCS = Nid(NID_pkcs);
  const auto PKCS1 = Nid(NID_pkcs1);
  const auto PKCS3 = Nid(NID_pkcs3);
  const auto PKCS5 = Nid(NID_pkcs5);
  const auto PKCS7 = Nid(NID_pkcs7);
  const auto PKCS9 = Nid(NID_pkcs9);
  const auto PKCS7_DATA = Nid(NID_pkcs7_data);
  const auto PKCS7_DIGEST = Nid(NID_pkcs7_digest);
  const auto PKCS7_ENCRYPTED = Nid(NID_pkcs7_encrypted);
  const auto PKCS7_ENVELOPED = Nid(NID_pkcs7_enveloped);
  const auto PKCS7_SIGNED = Nid(NID_pkcs7_signed);
  const auto PKCS7_SIGNEDANDENVELOPED = Nid(NID_pkcs7_signedAndEnveloped);
  const auto PKCS8SHROUDEDKEYBAG = Nid(NID_pkcs8ShroudedKeyBag);
  const auto PKCS9_CHALLENGEPASSWORD = Nid(NID_pkcs9_challengePassword);
  const auto PKCS9_CONTENTTYPE = Nid(NID_pkcs9_contentType);
  const auto PKCS9_COUNTERSIGNATURE = Nid(NID_pkcs9_countersignature);
  const auto PKCS9_EMAILADDRESS = Nid(NID_pkcs9_emailAddress);
  const auto PKCS9_EXTCERTATTRIBUTES = Nid(NID_pkcs9_extCertAttributes);
  const auto PKCS9_MESSAGEDIGEST = Nid(NID_pkcs9_messageDigest);
  const auto PKCS9_SIGNINGTIME = Nid(NID_pkcs9_signingTime);
  const auto PKCS9_UNSTRUCTUREDADDRESS = Nid(NID_pkcs9_unstructuredAddress);
  const auto PKCS9_UNSTRUCTUREDNAME = Nid(NID_pkcs9_unstructuredName);
  const auto POLICY_CONSTRAINTS = Nid(NID_policy_constraints);
  const auto POLICY_MAPPINGS = Nid(NID_policy_mappings);
  const auto POSTALADDRESS = Nid(NID_postalAddress);
  const auto POSTALCODE = Nid(NID_postalCode);
  const auto POSTOFFICEBOX = Nid(NID_postOfficeBox);
  const auto PREFERREDDELIVERYMETHOD = Nid(NID_preferredDeliveryMethod);
  const auto PRESENTATIONADDRESS = Nid(NID_presentationAddress);
  const auto PRIVATE = Nid(NID_Private);
  const auto PRIVATE_KEY_USAGE_PERIOD = Nid(NID_private_key_usage_period);
  const auto PROTOCOLINFORMATION = Nid(NID_protocolInformation);
  const auto PROXYCERTINFO = Nid(NID_proxyCertInfo);
  const auto PSEUDONYM = Nid(NID_pseudonym);
  const auto PSS = Nid(NID_pss);
  const auto QCSTATEMENTS = Nid(NID_qcStatements);
  const auto QUALITYLABELLEDDATA = Nid(NID_qualityLabelledData);
  const auto RC4 = Nid(NID_rc4);
  const auto RC2_40_CBC = Nid(NID_rc2_40_cbc);
  const auto RC2_64_CBC = Nid(NID_rc2_64_cbc);
  const auto RC2_CBC = Nid(NID_rc2_cbc);
  const auto RC2_CFB64 = Nid(NID_rc2_cfb64);
  const auto RC2_ECB = Nid(NID_rc2_ecb);
  const auto RC2_OFB64 = Nid(NID_rc2_ofb64);
  const auto RC4_40 = Nid(NID_rc4_40);
  const auto RC4_HMAC_MD5 = Nid(NID_rc4_hmac_md5);
  const auto RC5_CBC = Nid(NID_rc5_cbc);
  const auto RC5_CFB64 = Nid(NID_rc5_cfb64);
  const auto RC5_ECB = Nid(NID_rc5_ecb);
  const auto RC5_OFB64 = Nid(NID_rc5_ofb64);
  const auto REGISTEREDADDRESS = Nid(NID_registeredAddress);
  const auto RFC822LOCALPART = Nid(NID_rFC822localPart);
  const auto RFC822MAILBOX = Nid(NID_rfc822Mailbox);
  const auto RIPEMD160 = Nid(NID_ripemd160);
  const auto RIPEMD160WITHRSA = Nid(NID_ripemd160WithRSA);
  const auto ROLE = Nid(NID_role);
  const auto ROLEOCCUPANT = Nid(NID_roleOccupant);
  const auto ROOM = Nid(NID_room);
  const auto ROOMNUMBER = Nid(NID_roomNumber);
  const auto RSA = Nid(NID_rsa);
  const auto RSADSI = Nid(NID_rsadsi);
  const auto RSAENCRYPTION = Nid(NID_rsaEncryption);
  const auto RSAESOAEP = Nid(NID_rsaesOaep);
  const auto RSAOAEPENCRYPTIONSET = Nid(NID_rsaOAEPEncryptionSET);
  const auto RSASIGNATURE = Nid(NID_rsaSignature);
  const auto RSASSAPSS = Nid(NID_rsassaPss);
  const auto SAFECONTENTSBAG = Nid(NID_safeContentsBag);
  const auto SBGP_AUTONOMOUSSYSNUM = Nid(NID_sbgp_autonomousSysNum);
  const auto SBGP_IPADDRBLOCK = Nid(NID_sbgp_ipAddrBlock);
  const auto SBGP_ROUTERIDENTIFIER = Nid(NID_sbgp_routerIdentifier);
  const auto SDSICERTIFICATE = Nid(NID_sdsiCertificate);
  const auto SEARCHGUIDE = Nid(NID_searchGuide);
  const auto SECP112R1 = Nid(NID_secp112r1);
  const auto SECP112R2 = Nid(NID_secp112r2);
  const auto SECP128R1 = Nid(NID_secp128r1);
  const auto SECP128R2 = Nid(NID_secp128r2);
  const auto SECP160K1 = Nid(NID_secp160k1);
  const auto SECP160R1 = Nid(NID_secp160r1);
  const auto SECP160R2 = Nid(NID_secp160r2);
  const auto SECP192K1 = Nid(NID_secp192k1);
  const auto SECP224K1 = Nid(NID_secp224k1);
  const auto SECP224R1 = Nid(NID_secp224r1);
  const auto SECP256K1 = Nid(NID_secp256k1);
  const auto SECP384R1 = Nid(NID_secp384r1);
  const auto SECP521R1 = Nid(NID_secp521r1);
  const auto SECRETARY = Nid(NID_secretary);
  const auto SECRETBAG = Nid(NID_secretBag);
  const auto SECT113R1 = Nid(NID_sect113r1);
  const auto SECT113R2 = Nid(NID_sect113r2);
  const auto SECT131R1 = Nid(NID_sect131r1);
  const auto SECT131R2 = Nid(NID_sect131r2);
  const auto SECT163K1 = Nid(NID_sect163k1);
  const auto SECT163R1 = Nid(NID_sect163r1);
  const auto SECT163R2 = Nid(NID_sect163r2);
  const auto SECT193R1 = Nid(NID_sect193r1);
  const auto SECT193R2 = Nid(NID_sect193r2);
  const auto SECT233K1 = Nid(NID_sect233k1);
  const auto SECT233R1 = Nid(NID_sect233r1);
  const auto SECT239K1 = Nid(NID_sect239k1);
  const auto SECT283K1 = Nid(NID_sect283k1);
  const auto SECT283R1 = Nid(NID_sect283r1);
  const auto SECT409K1 = Nid(NID_sect409k1);
  const auto SECT409R1 = Nid(NID_sect409r1);
  const auto SECT571K1 = Nid(NID_sect571k1);
  const auto SECT571R1 = Nid(NID_sect571r1);
  const auto SECURITY = Nid(NID_Security);
  const auto SEEALSO = Nid(NID_seeAlso);
  const auto SEED_CBC = Nid(NID_seed_cbc);
  const auto SEED_CFB128 = Nid(NID_seed_cfb128);
  const auto SEED_ECB = Nid(NID_seed_ecb);
  const auto SEED_OFB128 = Nid(NID_seed_ofb128);
  const auto SELECTED_ATTRIBUTE_TYPES = Nid(NID_selected_attribute_types);
  const auto SERIALNUMBER = Nid(NID_serialNumber);
  const auto SERVER_AUTH = Nid(NID_server_auth);
  const auto SETATTR_CERT = Nid(NID_setAttr_Cert);
  const auto SETATTR_GENCRYPTGRM = Nid(NID_setAttr_GenCryptgrm);
  const auto SETATTR_ISSCAP = Nid(NID_setAttr_IssCap);
  const auto SETATTR_ISSCAP_CVM = Nid(NID_setAttr_IssCap_CVM);
  const auto SETATTR_ISSCAP_SIG = Nid(NID_setAttr_IssCap_Sig);
  const auto SETATTR_ISSCAP_T2 = Nid(NID_setAttr_IssCap_T2);
  const auto SETATTR_PGWYCAP = Nid(NID_setAttr_PGWYcap);
  const auto SETATTR_SECDEVSIG = Nid(NID_setAttr_SecDevSig);
  const auto SETATTR_T2CLEARTXT = Nid(NID_setAttr_T2cleartxt);
  const auto SETATTR_T2ENC = Nid(NID_setAttr_T2Enc);
  const auto SETATTR_TOKENTYPE = Nid(NID_setAttr_TokenType);
  const auto SETATTR_TOKEN_B0PRIME = Nid(NID_setAttr_Token_B0Prime);
  const auto SETATTR_TOKEN_EMV = Nid(NID_setAttr_Token_EMV);
  const auto SETATTR_TOKICCSIG = Nid(NID_setAttr_TokICCsig);
  const auto SETCEXT_CCERTREQUIRED = Nid(NID_setCext_cCertRequired);
  const auto SETCEXT_CERTTYPE = Nid(NID_setCext_certType);
  const auto SETCEXT_HASHEDROOT = Nid(NID_setCext_hashedRoot);
  const auto SETCEXT_ISSUERCAPABILITIES = Nid(NID_setCext_IssuerCapabilities);
  const auto SETCEXT_MERCHDATA = Nid(NID_setCext_merchData);
  const auto SETCEXT_PGWYCAPABILITIES = Nid(NID_setCext_PGWYcapabilities);
  const auto SETCEXT_SETEXT = Nid(NID_setCext_setExt);
  const auto SETCEXT_SETQUALF = Nid(NID_setCext_setQualf);
  const auto SETCEXT_TOKENIDENTIFIER = Nid(NID_setCext_TokenIdentifier);
  const auto SETCEXT_TOKENTYPE = Nid(NID_setCext_TokenType);
  const auto SETCEXT_TRACK2DATA = Nid(NID_setCext_Track2Data);
  const auto SETCEXT_TUNNELING = Nid(NID_setCext_tunneling);
  const auto SETCT_ACQCARDCODEMSG = Nid(NID_setct_AcqCardCodeMsg);
  const auto SETCT_ACQCARDCODEMSGTBE = Nid(NID_setct_AcqCardCodeMsgTBE);
  const auto SETCT_AUTHREQTBE = Nid(NID_setct_AuthReqTBE);
  const auto SETCT_AUTHREQTBS = Nid(NID_setct_AuthReqTBS);
  const auto SETCT_AUTHRESBAGGAGE = Nid(NID_setct_AuthResBaggage);
  const auto SETCT_AUTHRESTBE = Nid(NID_setct_AuthResTBE);
  const auto SETCT_AUTHRESTBEX = Nid(NID_setct_AuthResTBEX);
  const auto SETCT_AUTHRESTBS = Nid(NID_setct_AuthResTBS);
  const auto SETCT_AUTHRESTBSX = Nid(NID_setct_AuthResTBSX);
  const auto SETCT_AUTHREVREQBAGGAGE = Nid(NID_setct_AuthRevReqBaggage);
  const auto SETCT_AUTHREVREQTBE = Nid(NID_setct_AuthRevReqTBE);
  const auto SETCT_AUTHREVREQTBS = Nid(NID_setct_AuthRevReqTBS);
  const auto SETCT_AUTHREVRESBAGGAGE = Nid(NID_setct_AuthRevResBaggage);
  const auto SETCT_AUTHREVRESDATA = Nid(NID_setct_AuthRevResData);
  const auto SETCT_AUTHREVRESTBE = Nid(NID_setct_AuthRevResTBE);
  const auto SETCT_AUTHREVRESTBEB = Nid(NID_setct_AuthRevResTBEB);
  const auto SETCT_AUTHREVRESTBS = Nid(NID_setct_AuthRevResTBS);
  const auto SETCT_AUTHTOKENTBE = Nid(NID_setct_AuthTokenTBE);
  const auto SETCT_AUTHTOKENTBS = Nid(NID_setct_AuthTokenTBS);
  const auto SETCT_BATCHADMINREQDATA = Nid(NID_setct_BatchAdminReqData);
  const auto SETCT_BATCHADMINREQTBE = Nid(NID_setct_BatchAdminReqTBE);
  const auto SETCT_BATCHADMINRESDATA = Nid(NID_setct_BatchAdminResData);
  const auto SETCT_BATCHADMINRESTBE = Nid(NID_setct_BatchAdminResTBE);
  const auto SETCT_BCIDISTRIBUTIONTBS = Nid(NID_setct_BCIDistributionTBS);
  const auto SETCT_CAPREQTBE = Nid(NID_setct_CapReqTBE);
  const auto SETCT_CAPREQTBEX = Nid(NID_setct_CapReqTBEX);
  const auto SETCT_CAPREQTBS = Nid(NID_setct_CapReqTBS);
  const auto SETCT_CAPREQTBSX = Nid(NID_setct_CapReqTBSX);
  const auto SETCT_CAPRESDATA = Nid(NID_setct_CapResData);
  const auto SETCT_CAPRESTBE = Nid(NID_setct_CapResTBE);
  const auto SETCT_CAPREVREQTBE = Nid(NID_setct_CapRevReqTBE);
  const auto SETCT_CAPREVREQTBEX = Nid(NID_setct_CapRevReqTBEX);
  const auto SETCT_CAPREVREQTBS = Nid(NID_setct_CapRevReqTBS);
  const auto SETCT_CAPREVREQTBSX = Nid(NID_setct_CapRevReqTBSX);
  const auto SETCT_CAPREVRESDATA = Nid(NID_setct_CapRevResData);
  const auto SETCT_CAPREVRESTBE = Nid(NID_setct_CapRevResTBE);
  const auto SETCT_CAPTOKENDATA = Nid(NID_setct_CapTokenData);
  const auto SETCT_CAPTOKENSEQ = Nid(NID_setct_CapTokenSeq);
  const auto SETCT_CAPTOKENTBE = Nid(NID_setct_CapTokenTBE);
  const auto SETCT_CAPTOKENTBEX = Nid(NID_setct_CapTokenTBEX);
  const auto SETCT_CAPTOKENTBS = Nid(NID_setct_CapTokenTBS);
  const auto SETCT_CARDCINITRESTBS = Nid(NID_setct_CardCInitResTBS);
  const auto SETCT_CERTINQREQTBS = Nid(NID_setct_CertInqReqTBS);
  const auto SETCT_CERTREQDATA = Nid(NID_setct_CertReqData);
  const auto SETCT_CERTREQTBE = Nid(NID_setct_CertReqTBE);
  const auto SETCT_CERTREQTBEX = Nid(NID_setct_CertReqTBEX);
  const auto SETCT_CERTREQTBS = Nid(NID_setct_CertReqTBS);
  const auto SETCT_CERTRESDATA = Nid(NID_setct_CertResData);
  const auto SETCT_CERTRESTBE = Nid(NID_setct_CertResTBE);
  const auto SETCT_CREDREQTBE = Nid(NID_setct_CredReqTBE);
  const auto SETCT_CREDREQTBEX = Nid(NID_setct_CredReqTBEX);
  const auto SETCT_CREDREQTBS = Nid(NID_setct_CredReqTBS);
  const auto SETCT_CREDREQTBSX = Nid(NID_setct_CredReqTBSX);
  const auto SETCT_CREDRESDATA = Nid(NID_setct_CredResData);
  const auto SETCT_CREDRESTBE = Nid(NID_setct_CredResTBE);
  const auto SETCT_CREDREVREQTBE = Nid(NID_setct_CredRevReqTBE);
  const auto SETCT_CREDREVREQTBEX = Nid(NID_setct_CredRevReqTBEX);
  const auto SETCT_CREDREVREQTBS = Nid(NID_setct_CredRevReqTBE);
  const auto SETCT_CREDREVREQTBSX = Nid(NID_setct_CredRevReqTBSX);
  const auto SETCT_CREDREVRESDATA = Nid(NID_setct_CredRevResData);
  const auto SETCT_CREDREVRESTBE = Nid(NID_setct_CredRevResTBE);
  const auto SETCT_CRLNOTIFICATIONRESTBS = Nid(NID_setct_CRLNotificationResTBS);
  const auto SETCT_CRLNOTIFICATIONTBS = Nid(NID_setct_CRLNotificationTBS);
  const auto SETCT_ERRORTBS = Nid(NID_setct_ErrorTBS);
  const auto SETCT_HODINPUT = Nid(NID_setct_HODInput);
  const auto SETCT_MEAQCINITRESTBS = Nid(NID_setct_MeAqCInitResTBS);
  const auto SETCT_OIDATA = Nid(NID_setct_OIData);
  const auto SETCT_PANDATA = Nid(NID_setct_PANData);
  const auto SETCT_PANONLY = Nid(NID_setct_PANOnly);
  const auto SETCT_PANTOKEN = Nid(NID_setct_PANToken);
  const auto SETCT_PCERTREQDATA = Nid(NID_setct_PCertReqData);
  const auto SETCT_PCERTRESTBS = Nid(NID_setct_PCertResTBS);
  const auto SETCT_PI = Nid(NID_setct_PI);
  const auto SETCT_PIDATA = Nid(NID_setct_PIData);
  const auto SETCT_PIDATAUNSIGNED = Nid(NID_setct_PIDataUnsigned);
  const auto SETCT_PIDUALSIGNEDTBE = Nid(NID_setct_PIDualSignedTBE);
  const auto SETCT_PINITRESDATA = Nid(NID_setct_PInitResData);
  const auto SETCT_PIUNSIGNEDTBE = Nid(NID_setct_PIUnsignedTBE);
  const auto SETCT_PI_TBS = Nid(NID_setct_PI_TBS);
  const auto SETCT_PRESDATA = Nid(NID_setct_PResData);
  const auto SETCT_REGFORMREQTBE = Nid(NID_setct_RegFormReqTBE);
  const auto SETCT_REGFORMRESTBS = Nid(NID_setct_RegFormResTBS);
  const auto SETEXT_CV = Nid(NID_setext_cv);
  const auto SETEXT_GENCRYPT = Nid(NID_setext_genCrypt);
  const auto SETEXT_MIAUTH = Nid(NID_setext_miAuth);
  const auto SETEXT_PINANY = Nid(NID_setext_pinAny);
  const auto SETEXT_PINSECURE = Nid(NID_setext_pinSecure);
  const auto SETEXT_TRACK2 = Nid(NID_setext_track2);
  const auto SET_ADDPOLICY = Nid(NID_set_addPolicy);
  const auto SET_ATTR = Nid(NID_set_attr);
  const auto SET_BRAND = Nid(NID_set_brand);
  const auto SET_BRAND_AMERICANEXPRESS = Nid(NID_set_brand_AmericanExpress);
  const auto SET_BRAND_DINERS = Nid(NID_set_brand_Diners);
  const auto SET_BRAND_IATA_ATA = Nid(NID_set_brand_IATA_ATA);
  const auto SET_BRAND_JCB = Nid(NID_set_brand_JCB);
  const auto SET_BRAND_MASTERCARD = Nid(NID_set_brand_MasterCard);
  const auto SET_BRAND_NOVUS = Nid(NID_set_brand_Novus);
  const auto SET_BRAND_VISA = Nid(NID_set_brand_Visa);
  const auto SET_CERTEXT = Nid(NID_set_certExt);
  const auto SET_CTYPE = Nid(NID_set_ctype);
  const auto SET_MSGEXT = Nid(NID_set_msgExt);
  const auto SET_POLICY = Nid(NID_set_policy);
  const auto SET_POLICY_ROOT = Nid(NID_set_policy_root);
  const auto SET_ROOTKEYTHUMB = Nid(NID_set_rootKeyThumb);
  const auto SHA = Nid(NID_sha);
  const auto SHA1 = Nid(NID_sha1);
  const auto SHA224 = Nid(NID_sha224);
  const auto SHA256 = Nid(NID_sha256);
  const auto SHA384 = Nid(NID_sha384);
  const auto SHA512 = Nid(NID_sha512);
  const auto SHA1WITHRSA = Nid(NID_sha1WithRSA);
  const auto SHA1WITHRSAENCRYPTION = Nid(NID_sha1WithRSAEncryption);
  const auto SHA224WITHRSAENCRYPTION = Nid(NID_sha224WithRSAEncryption);
  const auto SHA256WITHRSAENCRYPTION = Nid(NID_sha256WithRSAEncryption);
  const auto SHA384WITHRSAENCRYPTION = Nid(NID_sha384WithRSAEncryption);
  const auto SHA512WITHRSAENCRYPTION = Nid(NID_sha512WithRSAEncryption);
  const auto SHAWITHRSAENCRYPTION = Nid(NID_shaWithRSAEncryption);
  const auto SIMPLESECURITYOBJECT = Nid(NID_simpleSecurityObject);
  const auto SINFO_ACCESS = Nid(NID_sinfo_access);
  const auto SINGLELEVELQUALITY = Nid(NID_singleLevelQuality);
  const auto SMIME = Nid(NID_SMIME);
  const auto SMIMECAPABILITIES = Nid(NID_SMIMECapabilities);
  const auto SNMPV2 = Nid(NID_SNMPv2);
  const auto SOARECORD = Nid(NID_sOARecord);
  const auto STATEORPROVINCENAME = Nid(NID_stateOrProvinceName);
  const auto STREETADDRESS = Nid(NID_streetAddress);
  const auto SUBJECT_ALT_NAME = Nid(NID_subject_alt_name);
  const auto SUBJECT_DIRECTORY_ATTRIBUTES = Nid(NID_subject_directory_attributes);
  const auto SUBJECT_KEY_IDENTIFIER = Nid(NID_subject_key_identifier);
  const auto SUBTREEMAXIMUMQUALITY = Nid(NID_subtreeMaximumQuality);
  const auto SUBTREEMINIMUMQUALITY = Nid(NID_subtreeMinimumQuality);
  const auto SUPPORTEDALGORITHMS = Nid(NID_supportedAlgorithms);
  const auto SUPPORTEDAPPLICATIONCONTEXT = Nid(NID_supportedApplicationContext);
  const auto SURNAME = Nid(NID_surname);
  const auto SXNET = Nid(NID_sxnet);
  const auto TARGET_INFORMATION = Nid(NID_target_information);
  const auto TELEPHONENUMBER = Nid(NID_telephoneNumber);
  const auto TELETEXTERMINALIDENTIFIER = Nid(NID_teletexTerminalIdentifier);
  const auto TELEXNUMBER = Nid(NID_telexNumber);
  const auto TEXTENCODEDORADDRESS = Nid(NID_textEncodedORAddress);
  const auto TEXTNOTICE = Nid(NID_textNotice);
  const auto TIME_STAMP = Nid(NID_time_stamp);
  const auto TITLE = Nid(NID_title);
  const auto UCL = Nid(NID_ucl);
  const auto UNDEF = Nid(NID_undef);
  const auto UNIQUEMEMBER = Nid(NID_uniqueMember);
  const auto USERCERTIFICATE = Nid(NID_userCertificate);
  const auto USERCLASS = Nid(NID_userClass);
  const auto USERID = Nid(NID_userId);
  const auto USERPASSWORD = Nid(NID_userPassword);
  const auto WAP = Nid(NID_wap);
  const auto WAP_WSG = Nid(NID_wap_wsg);
  const auto WAP_WSG_IDM_ECID_WTLS1 = Nid(NID_wap_wsg_idm_ecid_wtls1);
  const auto WAP_WSG_IDM_ECID_WTLS3 = Nid(NID_wap_wsg_idm_ecid_wtls3);
  const auto WAP_WSG_IDM_ECID_WTLS4 = Nid(NID_wap_wsg_idm_ecid_wtls4);
  const auto WAP_WSG_IDM_ECID_WTLS5 = Nid(NID_wap_wsg_idm_ecid_wtls5);
  const auto WAP_WSG_IDM_ECID_WTLS6 = Nid(NID_wap_wsg_idm_ecid_wtls6);
  const auto WAP_WSG_IDM_ECID_WTLS7 = Nid(NID_wap_wsg_idm_ecid_wtls7);
  const auto WAP_WSG_IDM_ECID_WTLS8 = Nid(NID_wap_wsg_idm_ecid_wtls8);
  const auto WAP_WSG_IDM_ECID_WTLS9 = Nid(NID_wap_wsg_idm_ecid_wtls9);
  const auto WAP_WSG_IDM_ECID_WTLS10 = Nid(NID_wap_wsg_idm_ecid_wtls10);
  const auto WAP_WSG_IDM_ECID_WTLS11 = Nid(NID_wap_wsg_idm_ecid_wtls11);
  const auto WAP_WSG_IDM_ECID_WTLS12 = Nid(NID_wap_wsg_idm_ecid_wtls12);
  const auto WHIRLPOOL = Nid(NID_whirlpool);
  const auto X500 = Nid(NID_X509);
  const auto X509 = Nid(NID_X509);
  const auto X121ADDRESS = Nid(NID_x121Address);
  const auto X500ALGORITHMS = Nid(NID_X500algorithms);
  const auto X500UNIQUEIDENTIFIER = Nid(NID_x500UniqueIdentifier);
  const auto X509CERTIFICATE = Nid(NID_x509Certificate);
  const auto X509CRL = Nid(NID_x509Crl);
  const auto X9CM = Nid(NID_X9cm);
  const auto X9_57 = Nid(NID_X9_57);
  const auto X9_62_C2ONB191V4 = Nid(NID_X9_62_c2onb191v4);
  const auto X9_62_C2ONB191V5 = Nid(NID_X9_62_c2onb191v5);
  const auto X9_62_C2ONB239V4 = Nid(NID_X9_62_c2onb239v4);
  const auto X9_62_C2ONB239V5 = Nid(NID_X9_62_c2onb239v5);
  const auto X9_62_C2PNB163V1 = Nid(NID_X9_62_c2pnb163v1);
  const auto X9_62_C2PNB163V2 = Nid(NID_X9_62_c2pnb163v3);
  const auto X9_62_C2PNB163V3 = Nid(NID_X9_62_c2pnb163v3);
  const auto X9_62_C2PNB176V1 = Nid(NID_X9_62_c2pnb176v1);
  const auto X9_62_C2PNB208W1 = Nid(NID_X9_62_c2pnb208w1);
  const auto X9_62_C2PNB272W1 = Nid(NID_X9_62_c2pnb272w1);
  const auto X9_62_C2PNB304W1 = Nid(NID_X9_62_c2pnb304w1);
  const auto X9_62_C2PNB368W1 = Nid(NID_X9_62_c2pnb368w1);
  const auto X9_62_C2TNB191V1 = Nid(NID_X9_62_c2tnb191v1);
  const auto X9_62_C2TNB191V2 = Nid(NID_X9_62_c2tnb191v2);
  const auto X9_62_C2TNB191V3 = Nid(NID_X9_62_c2tnb191v3);
  const auto X9_62_C2TNB239V1 = Nid(NID_X9_62_c2tnb239v1);
  const auto X9_62_C2TNB239V2 = Nid(NID_X9_62_c2tnb239v2);
  const auto X9_62_C2TNB239V3 = Nid(NID_X9_62_c2tnb239v3);
  const auto X9_62_C2TNB359V1 = Nid(NID_X9_62_c2tnb359v1);
  const auto X9_62_C2TNB431R1 = Nid(NID_X9_62_c2tnb431r1);
  const auto X9_62_CHARACTERISTIC_TWO_FIELD = Nid(NID_X9_62_characteristic_two_field);
  const auto X9_62_ID_CHARACTERISTIC_TWO_BASIS = Nid(NID_X9_62_id_characteristic_two_basis);
  const auto X9_62_ID_ECPUBLICKEY = Nid(NID_X9_62_id_ecPublicKey);
  const auto X9_62_ONBASIS = Nid(NID_X9_62_onBasis);
  const auto X9_62_PPBASIS = Nid(NID_X9_62_ppBasis);
  const auto X9_62_PRIME192V1 = Nid(NID_X9_62_prime192v1);
  const auto X9_62_PRIME192V2 = Nid(NID_X9_62_prime192v2);
  const auto X9_62_PRIME192V3 = Nid(NID_X9_62_prime192v3);
  const auto X9_62_PRIME239V1 = Nid(NID_X9_62_prime239v1);
  const auto X9_62_PRIME239V2 = Nid(NID_X9_62_prime239v2);
  const auto X9_62_PRIME239V3 = Nid(NID_X9_62_prime239v3);
  const auto X9_62_PRIME256V1 = Nid(NID_X9_62_prime256v1);
  const auto X9_62_PRIME_FIELD = Nid(NID_X9_62_prime_field);
  const auto X9_62_TPBASIS = Nid(NID_X9_62_tpBasis);
  const auto ZLIB_COMPRESSION = Nid(NID_zlib_compression);
} // namespace nid

namespace rand {
  SO_API Result<Bytes> bytes(unsigned short numOfBytes);
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

  SO_API Result<RSA_uptr> convertPemToPrivKey(const std::string &pemPriv);
  SO_API Result<RSA_uptr> convertPemToPubKey(const std::string &pemPub);
  SO_API Result<std::string> convertPrivKeyToPem(RSA &rsa);
  SO_API Result<std::string> convertPubKeyToPem(RSA &rsa);

  SO_API Result<RSA_uptr> convertDerToPrivKey(const Bytes &der);
  SO_API Result<RSA_uptr> convertDerToPubKey(const Bytes &der);
  SO_API Result<Bytes> convertPrivKeyToDer(RSA &rsa);
  SO_API Result<Bytes> convertPubKeyToDer(RSA &rsa);

  SO_API Result<EVP_PKEY_uptr> convertToEvp(RSA &rsa);
  SO_API Result<bool> checkKey(RSA &rsa);
 
  SO_API Result<RSA_uptr> generateKey(KeyBits keySize, Exponent exponent = Exponent::_65537_);
  SO_API Result<KeyBits> getKeyBits(RSA &rsa);
  SO_API Result<RSA_uptr> getPublic(RSA &rsa);

  SO_API Result<Bytes> signSha1(const Bytes &message, RSA &privateKey);
  SO_API Result<Bytes> signSha224(const Bytes &msg, RSA &privKey);
  SO_API Result<Bytes> signSha256(const Bytes &msg, RSA &privKey);
  SO_API Result<Bytes> signSha384(const Bytes &msg, RSA &privKey);
  SO_API Result<Bytes> signSha512(const Bytes &msg, RSA &privKey);
  
  SO_API Result<bool> verifySha1Signature(const Bytes &signature, const Bytes &message, RSA &pubKey);
  SO_API Result<bool> verifySha224Signature(const Bytes &signature, const Bytes &message, RSA &pubKey);
  SO_API Result<bool> verifySha256Signature(const Bytes &signature, const Bytes &message, RSA &pubKey);
  SO_API Result<bool> verifySha384Signature(const Bytes &signature, const Bytes &message, RSA &pubKey);
  SO_API Result<bool> verifySha512Signature(const Bytes &signature, const Bytes &message, RSA &pubKey);
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
    // Version is zero indexed, thus this enum
    // to not bring confusion.
    v1 = 0,
    v2 = 1,
    v3 = 2,
    vx = -1 
  };

  SO_API Result<X509_uptr> convertPemToX509(const std::string &pemCert);
  SO_API Result<X509_uptr> convertPemFileToX509(const std::string &pemFilePath);

  SO_API Result<ecdsa::Signature> getEcdsaSignature(const X509 &cert);
  SO_API Result<CertExtension> getExtension(const X509 &cert, CertExtensionId getExtensionId);
  SO_API Result<CertExtension> getExtension(const X509 &cert, const std::string &oidNumerical);
  SO_API Result<std::vector<CertExtension>> getExtensions(const X509 &cert);
  SO_API Result<size_t> getExtensionsCount(const X509 &cert);
  SO_API Result<Info> getIssuer(const X509 &cert);
  SO_API Result<std::string> getIssuerString(const X509 &cert); 
  SO_API Result<EVP_PKEY_uptr> getPubKey(X509 &cert);
  SO_API Result<Bytes> getSerialNumber(X509 &cert);
  SO_API Result<Bytes> getSignature(const X509 &cert);
  SO_API Result<Info> getSubject(const X509 &cert);
  SO_API Result<std::string> getSubjectString(const X509 &cert);
  SO_API Result<Validity> getValidity(const X509 &cert);
  SO_API std::tuple<Version,long> getVersion(const X509 &cert);
  
  SO_API bool isCa(X509 &cert);
  SO_API bool isSelfSigned(X509 &cert);

  SO_API Result<void> setCustomExtension(X509 &cert, const std::string &oidNumerical, ASN1_OCTET_STRING &octet, bool critical = false);
  SO_API Result<void> setExtension(X509 &cert, CertExtensionId id, ASN1_OCTET_STRING &octet, bool critical = false);
  SO_API Result<void> setExtension(X509 &cert, const CertExtension &extension); 
  SO_API Result<void> setIssuer(X509 &cert, const X509 &rootCert);
  SO_API Result<void> setIssuer(X509 &cert, const Info &commonInfo);
  SO_API Result<void> setPubKey(X509 &cert, EVP_PKEY &pkey);
  SO_API Result<void> setSerial(X509 &cert, const Bytes &bytes);
  SO_API Result<void> setSubject(X509 &cert, const Info &commonInfo);
  SO_API Result<void> setValidity(X509 &cert, const Validity &validity);
  SO_API Result<void> setVersion(X509 &cert, Version version);
  SO_API Result<void> setVersion(X509 &cert, long version);
  
  SO_API Result<size_t> signSha1(X509 &cert, EVP_PKEY &pkey);
  SO_API Result<size_t> signSha256(X509 &cert, EVP_PKEY &pkey);
  SO_API Result<size_t> signSha384(X509 &cert, EVP_PKEY &pkey); 
  SO_API Result<size_t> signSha512(X509 &cert, EVP_PKEY &pkey);  
  
  SO_API Result<bool> verifySignature(X509 &cert, EVP_PKEY &pkey);
 
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
  SO_PRV Result<T> err(T &&val)
  {
    return Result<T>(ERR_get_error(), std::move(val));
  }
 
  template
  <
    typename T,
    typename std::enable_if<!internal::is_uptr<T>::value, int>::type = 0
  >
  SO_PRV Result<T> err()
  {
    return internal::err<T>({});
  }

  template
  <
    typename T,
    typename std::enable_if<internal::is_uptr<T>::value, int>::type = 0
  >
  SO_PRV Result<T> err()
  {
    auto tmp = make_unique<typename uptr_underlying_type<T>::type>(nullptr);
    return internal::err(std::move(tmp));
  }

  template<typename T>
  SO_PRV Result<T> err(unsigned long errCode)
  { 
    return Result<T>(errCode);
  }

  template<typename T>
  SO_PRV Result<T> ok(T &&val)
  {
    return Result<T>(0, std::move(val));
  }

  SO_PRV Result<void> err()
  {
    return Result<void>(ERR_get_error());
  }

  SO_PRV Result<void> err(unsigned long errCode)
  {
    return Result<void>(errCode);
  }

  SO_PRV Result<void> ok()
  {
    return Result<void>(0);
  }
 
  SO_PRV Result<std::string> nameEntry2String(X509_NAME &name, int nid)
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

  SO_PRV Result<std::string> nameToString(const X509_NAME &name, unsigned long flags = XN_FLAG_RFC2253)
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

  SO_PRV Result<x509::Info> commonInfo(X509_NAME &name)
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

  SO_PRV Result<X509_NAME_uptr> infoToX509Name(const x509::Info &info)
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

  SO_PRV Result<size_t> signCert(X509 &cert, EVP_PKEY &key, const EVP_MD *md)
  {
    const int sigLen = X509_sign(&cert, &key, md);
    if(0 >= sigLen)
      return internal::err<size_t>();

    return internal::ok(static_cast<size_t>(sigLen));
  }

  SO_PRV Result<Bytes> ecdsaSign(const Bytes &dg, EC_KEY &key)
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

  SO_PRV Result<bool> ecdsaVerify(const Bytes &signature, const Bytes &dg, EC_KEY &publicKey)
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
  
  SO_PRV Result<Bytes> evpSign(const Bytes &message, const EVP_MD *evpMd,  EVP_PKEY &privateKey)
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

  SO_PRV Result<bool> evpVerify(const Bytes &sig, const Bytes &msg, const EVP_MD *evpMd, EVP_PKEY &pubKey)
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

  SO_PRV Result<Bytes> rsaSign(int digestNid, const Bytes &digest, RSA &privKey)
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

  SO_PRV Result<bool> rsaVerify(int hashNid, const Bytes &signature, const Bytes &digest, RSA &pubKey)
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
  SO_PRV Result<internal::X509Extension<ID>> getExtension(X509_EXTENSION &ex)
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
  SO_PRV Result<Bytes> doHash(const DATA &data, unsigned long digestLen, INIT init, UPDATE update, FINAL final)
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

  SO_PRV Result<Bytes> doHashFile(const std::string &path, const EVP_MD *evpMd)
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
      char buf[10240];
      int rdlen;
      do {
        char *bufFirstPos = buf;
        rdlen = BIO_read(bio.get(), bufFirstPos, sizeof(buf));
      } while (rdlen > 0);
    }


    uint8_t mdbuf[EVP_MAX_MD_SIZE];
    const int mdlen = BIO_gets(mdtmp, reinterpret_cast<char*>(mdbuf), EVP_MAX_MD_SIZE);

    return internal::ok(Bytes(std::begin(mdbuf), std::next(std::begin(mdbuf), mdlen)));
  }

  template<typename FUNC, typename ... Types>
  SO_PRV Result<std::string> convertToPem(FUNC writeToBio, Types ...args)
  {
    auto bio = make_unique(BIO_new(BIO_s_mem()));
    if(!bio)
      return internal::err<std::string>();

    if(1 != writeToBio(bio.get(), std::forward<Types>(args)...))
      return internal::err<std::string>();

    std::string ret;
    BUF_MEM *buf; // this will be freed with bio
    BIO_get_mem_ptr(bio.get(), &buf);
    ret.reserve(static_cast<size_t>(buf->length));
    ret.append(buf->data, static_cast<size_t>(buf->length));

    return internal::ok(std::move(ret));
  }
  
  template<typename Key, typename FUNC, typename ... Types>
  SO_PRV Result<Key> convertPemToKey(const std::string &pem, FUNC readBio, Types ...args)
  {
    auto bio = make_unique(BIO_new_mem_buf(pem.c_str(), static_cast<int>(pem.size())));
    if(!bio)
      return internal::err<Key>();

    auto key = make_unique(readBio(bio.get(), std::forward<Types>(args)...));
    if(!key)
      return internal::err<Key>();

    return internal::ok(std::move(key));
  }

  template<typename Key, typename FUNC>
  SO_PRV Result<Key> convertDerToKey(const Bytes &der, FUNC d2iFunction)
  {
    const uint8_t *ptr = der.data();
    auto ret = make_unique(d2iFunction(nullptr, &ptr, static_cast<long>(der.size())));
    if(!ret)
      return internal::err<Key>();

    return internal::ok(std::move(ret));
  }

  template<typename Key, typename FUNC>
  SO_PRV Result<Bytes> convertKeyToDer(Key &key, FUNC i2dFunction)
  {
    const auto freeOpenssl = [](uint8_t *ptr) { OPENSSL_free(ptr);};
    uint8_t *ptr = nullptr; // this needs to be freed with OPENSSL_free
    const int len = i2dFunction(&key, &ptr);
    if (0 > len)
      return internal::err<Bytes>();

    std::unique_ptr<uint8_t[], decltype(freeOpenssl)> buf(ptr, freeOpenssl);
    Bytes ret;
    ret.reserve(static_cast<size_t>(len));
    std::copy_n(buf.get(), len, std::back_inserter(ret));
    return internal::ok(std::move(ret));
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
  SO_API Result<std::string> convertObjToStr(const ASN1_OBJECT &obj, Form form)
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

  SO_API Result<ASN1_TIME_uptr> convertToAsn1Time(std::time_t time)
  {
    auto ret = make_unique(ASN1_TIME_set(nullptr, time));
    if(!ret)
      return internal::err<ASN1_TIME_uptr>();

    return internal::ok(std::move(ret));
  }

  SO_API Result<std::time_t> convertToStdTime(const ASN1_TIME &asn1Time)
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
  
  SO_API Result<ASN1_INTEGER_uptr> encodeInteger(const Bytes &bt)
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
 
  SO_API Result<ASN1_OBJECT_uptr> encodeObject(const std::string &nameOrNumerical)
  {
    auto ret = make_unique(OBJ_txt2obj(nameOrNumerical.c_str(), 0));
    if(!ret)
      return internal::err<ASN1_OBJECT_uptr>();

    return internal::ok(std::move(ret));
  }

  SO_API Result<ASN1_OCTET_STRING_uptr> encodeOctet(const Bytes &bt)
  {
    auto ret = make_unique(ASN1_OCTET_STRING_new());
    if(!ret)
      return internal::err<ASN1_OCTET_STRING_uptr>();

    if(1 != ASN1_OCTET_STRING_set(ret.get(), bt.data(), static_cast<int>(bt.size())))
      return internal::err<ASN1_OCTET_STRING_uptr>();

    return internal::ok(std::move(ret));
  }
  
  SO_API Result<ASN1_OCTET_STRING_uptr> encodeOctet(const std::string &str)
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
  SO_API Result<Bytes> convertToBytes(const BIGNUM &bn)
  {
    const auto sz = getByteLen(bn);
    if(!sz)
      return internal::err<Bytes>(sz.errorCode());

    Bytes ret(*sz);
    BN_bn2bin(&bn, ret.data());
    return internal::ok(std::move(ret));
  }

  SO_API Result<BIGNUM_uptr> convertToBignum(const Bytes &bt)
  {
    auto ret = make_unique(BN_bin2bn(bt.data(), static_cast<int>(bt.size()), nullptr));
    if(!ret)
      return internal::err<BIGNUM_uptr>();

    return internal::ok(std::move(ret));
  }

  SO_API Result<size_t> getByteLen(const BIGNUM &bn)
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

  SO_API Result<EC_KEY_uptr> convertPemToPubKey(const std::string &pemPub)
  {
    return internal::convertPemToKey<EC_KEY_uptr>(pemPub, PEM_read_bio_EC_PUBKEY, nullptr, nullptr, nullptr); 
  }

  SO_API Result<EC_KEY_uptr> convertPemToPrivKey(const std::string &pemPriv)
  {
    return internal::convertPemToKey<EC_KEY_uptr>(pemPriv, PEM_read_bio_ECPrivateKey, nullptr, nullptr, nullptr); 
  }
 
  SO_API Result<std::string> convertPrivKeyToPem(EC_KEY &ec)
  { 
    const auto check = ecdsa::checkKey(ec);
    if(!check)
      return internal::err<std::string>(check.errorCode());
  
    return internal::convertToPem(PEM_write_bio_ECPrivateKey, &ec, nullptr, nullptr, 0, nullptr, nullptr); 
  }
 
  SO_API Result<std::string> convertPubKeyToPem(EC_KEY &pubKey)
  {
    return internal::convertToPem(PEM_write_bio_EC_PUBKEY, &pubKey);
  }

  SO_API Result<EC_KEY_uptr> convertDerToPrivKey(const Bytes &der)
  {
    return internal::convertDerToKey<EC_KEY_uptr>(der, d2i_ECPrivateKey);
  }

  SO_API Result<EC_KEY_uptr> convertDerToPubKey(const Bytes &der)
  {
    return internal::convertDerToKey<EC_KEY_uptr>(der, d2i_EC_PUBKEY);
  }

  SO_API Result<Bytes> convertPrivKeyToDer(EC_KEY &ec)
  {
    const auto check = ecdsa::checkKey(ec);
    if(!check)
      return internal::err<Bytes>(check.errorCode());

    return internal::convertKeyToDer(ec, i2d_ECPrivateKey);
  }

  SO_API Result<Bytes> convertPubKeyToDer(EC_KEY &ec)
  {
    return internal::convertKeyToDer(ec, i2d_EC_PUBKEY);
  }

  SO_API Result<bool> checkKey(const EC_KEY &ecKey)
  {
    if(1 != EC_KEY_check_key(&ecKey))
      return internal::err(false);

    return internal::ok(true);
  }
  
  SO_API Result<EC_KEY_uptr> copyKey(const EC_KEY &ecKey)
  {
    auto copy = make_unique(EC_KEY_dup(&ecKey));
    if(!copy)
      return internal::err<EC_KEY_uptr>();

    return internal::ok(std::move(copy));
  }

  SO_API Result<Curve> getCurve(const EC_KEY &key)
  {
    const EC_GROUP* group = EC_KEY_get0_group(&key);
    if(!group)
      return internal::err<Curve>();

    const int nid = EC_GROUP_get_curve_name(group);
    if(0 == nid)
      return internal::err<Curve>();

    return internal::ok(static_cast<Curve>(nid)); 
  }

  SO_API Result<Bytes> convertToDer(const Signature &signature)
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

  SO_API Result<Signature> convertToSignature(const Bytes &derSigBytes)
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

  SO_API Result<EC_KEY_uptr> getPublic(const EC_KEY &key)
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

  SO_API Result<EVP_PKEY_uptr> convertToEvp(const EC_KEY &ecKey)
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

  SO_API Result<EC_KEY_uptr> generateKey(Curve curve)
  {
    const int nidCurve = static_cast<int>(curve);
    auto key = make_unique(EC_KEY_new_by_curve_name(nidCurve));
    if(!key)
      return internal::err<EC_KEY_uptr>();

    if(!EC_KEY_generate_key(key.get()))
      return internal::err<EC_KEY_uptr>();

    return internal::ok(std::move(key));
  }

  SO_API Result<Bytes> signSha1(const Bytes &message, EC_KEY &key)
  {
    const auto digest = hash::sha1(message);
    if(!digest)
      return digest;

    return internal::ecdsaSign(*digest, key);
  }

  SO_API Result<Bytes> signSha224(const Bytes &message, EC_KEY &key)
  {
    const auto digest = hash::sha224(message);
    if(!digest)
      return digest; 

    return internal::ecdsaSign(*digest, key);
  }

  SO_API Result<Bytes> signSha256(const Bytes &message, EC_KEY &key)
  {
    const auto digest = hash::sha256(message);
    if(!digest)
      return digest; 

    return internal::ecdsaSign(*digest, key);
  }

  SO_API Result<Bytes> signSha384(const Bytes &message, EC_KEY &key)
  {
    const auto digest = hash::sha384(message);
    if(!digest)
      return digest;

    return internal::ecdsaSign(*digest, key);
  }
  
  SO_API Result<Bytes> signSha512(const Bytes &message, EC_KEY &key)
  {
    const auto digest = hash::sha512(message);
    if(!digest)
      return digest;

    return internal::ecdsaSign(*digest, key);
  }

  SO_API Result<bool> verifySha1Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey)
  {
    const auto digest = hash::sha1(message);
    if(!digest)
      return internal::err<bool>(digest.errorCode());

    return internal::ecdsaVerify(signature, *digest, publicKey);
  }

  SO_API Result<bool> verifySha224Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey)
  {
    const auto digest = hash::sha224(message);
    if(!digest)
      return internal::err<bool>(digest.errorCode());

    return internal::ecdsaVerify(signature, *digest, publicKey);
  }

  SO_API Result<bool> verifySha256Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey)
  {
    const auto digest = hash::sha256(message);
    if(!digest)
      return internal::err<bool>(digest.errorCode());

    return internal::ecdsaVerify(signature, *digest, publicKey);
  }

  SO_API Result<bool> verifySha384Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey)
  {
    const auto digest = hash::sha384(message);
    if(!digest)
      return internal::err<bool>(digest.errorCode());

    return internal::ecdsaVerify(signature, *digest, publicKey);
  }

  SO_API Result<bool> verifySha512Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey)
  {
    const auto digest = hash::sha512(message);
    if(!digest)
      return internal::err<bool>(digest.errorCode());

    return internal::ecdsaVerify(signature, *digest, publicKey);
  }
} //namespace ecdsa

namespace evp {
  SO_API Result<EVP_PKEY_uptr> convertPemToPubKey(const std::string &pemPub)
  {
    return internal::convertPemToKey<EVP_PKEY_uptr>(pemPub, PEM_read_bio_PUBKEY, nullptr, nullptr, nullptr); 
  }

  SO_API Result<EVP_PKEY_uptr> convertPemToPrivKey(const std::string &pemPriv)
  {
    return internal::convertPemToKey<EVP_PKEY_uptr>(pemPriv, PEM_read_bio_PrivateKey, nullptr, nullptr, nullptr); 
  }

  SO_API Result<EVP_PKEY_uptr> convertDerToPrivKey(const Bytes &der)
  {
    return internal::convertDerToKey<EVP_PKEY_uptr>(der, d2i_AutoPrivateKey);
  }

  SO_API Result<EVP_PKEY_uptr> convertDerToPubKey(const Bytes &der)
  {
    return internal::convertDerToKey<EVP_PKEY_uptr>(der, d2i_PUBKEY);
  }

  SO_API Result<Bytes> convertPrivKeyToDer(EVP_PKEY &privKey)
  {
    return internal::convertKeyToDer(privKey, i2d_PrivateKey);
  }

  SO_API Result<Bytes> convertPubKeyToDer(EVP_PKEY &pkey)
  {
    return internal::convertKeyToDer(pkey, i2d_PUBKEY);
  }

  SO_API Result<Bytes> signSha1(const Bytes &message, EVP_PKEY &privateKey)
  { 
    return internal::evpSign(message, EVP_sha1(), privateKey);
  }

  SO_API Result<Bytes> signSha224(const Bytes &message, EVP_PKEY &privateKey)
  { 
    return internal::evpSign(message, EVP_sha224(), privateKey);
  }

  SO_API Result<Bytes> signSha256(const Bytes &message, EVP_PKEY &privateKey)
  { 
    return internal::evpSign(message, EVP_sha256(), privateKey);
  }

  SO_API Result<Bytes> signSha384(const Bytes &message, EVP_PKEY &privateKey)
  { 
    return internal::evpSign(message, EVP_sha384(), privateKey);
  }

  SO_API Result<Bytes> signSha512(const Bytes &message, EVP_PKEY &privateKey)
  { 
    return internal::evpSign(message, EVP_sha512(), privateKey);
  }

  SO_API Result<bool> verifySha1Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey)
  {
    return internal::evpVerify(signature, message, EVP_sha1(), pubKey); 
  }

  SO_API Result<bool> verifySha224Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey)
  {
    return internal::evpVerify(signature, message, EVP_sha224(), pubKey); 
  }

  SO_API Result<bool> verifySha256Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey)
  {
    return internal::evpVerify(signature, message, EVP_sha256(), pubKey); 
  }

  SO_API Result<bool> verifySha384Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey)
  {
    return internal::evpVerify(signature, message, EVP_sha384(), pubKey); 
  }

  SO_API Result<bool> verifySha512Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey)
  {
    return internal::evpVerify(signature, message, EVP_sha512(), pubKey); 
  }
} //namespace evp

namespace hash {
  SO_API Result<Bytes> md4(const Bytes &data)
  {  
    return internal::doHash<MD4_CTX>(data, MD4_DIGEST_LENGTH, MD4_Init, MD4_Update, MD4_Final);
  }

  SO_API Result<Bytes> md4(const std::string &data)
  {    
    return internal::doHash<MD4_CTX>(data, MD4_DIGEST_LENGTH, MD4_Init, MD4_Update, MD4_Final);
  }

  SO_API Result<Bytes> md5(const Bytes &data)
  {
    return internal::doHash<MD5_CTX>(data, MD5_DIGEST_LENGTH, MD5_Init, MD5_Update, MD5_Final);
  }

  SO_API Result<Bytes> md5(const std::string &data)
  {
    return internal::doHash<MD5_CTX>(data, MD5_DIGEST_LENGTH, MD5_Init, MD5_Update, MD5_Final);
  }

  SO_API Result<Bytes> sha1(const Bytes &data)
  {    
    return internal::doHash<SHA_CTX>(data, SHA_DIGEST_LENGTH, SHA1_Init, SHA1_Update, SHA1_Final);
  }

  SO_API Result<Bytes> sha1(const std::string &data)
  {    
    return internal::doHash<SHA_CTX>(data, SHA_DIGEST_LENGTH, SHA1_Init, SHA1_Update, SHA1_Final);
  }
  
  SO_API Result<Bytes> sha224(const Bytes &data)
  {
    return internal::doHash<SHA256_CTX>(data, SHA224_DIGEST_LENGTH, SHA224_Init, SHA224_Update, SHA224_Final);
  }

  SO_API Result<Bytes> sha224(const std::string &data)
  {
    return internal::doHash<SHA256_CTX>(data, SHA224_DIGEST_LENGTH, SHA224_Init, SHA224_Update, SHA224_Final);
  }

  SO_API Result<Bytes> sha256(const Bytes &data)
  {
    return internal::doHash<SHA256_CTX>(data, SHA256_DIGEST_LENGTH, SHA256_Init, SHA256_Update, SHA256_Final);
  }

  SO_API Result<Bytes> sha256(const std::string &data)
  {
    return internal::doHash<SHA256_CTX>(data, SHA256_DIGEST_LENGTH, SHA256_Init, SHA256_Update, SHA256_Final);
  }

  SO_API Result<Bytes> sha384(const Bytes &data)
  {
    return internal::doHash<SHA512_CTX>(data, SHA384_DIGEST_LENGTH, SHA384_Init, SHA384_Update, SHA384_Final);
  }

  SO_API Result<Bytes> sha384(const std::string &data)
  {
    return internal::doHash<SHA512_CTX>(data, SHA384_DIGEST_LENGTH, SHA384_Init, SHA384_Update, SHA384_Final);
  }

  SO_API Result<Bytes> sha512(const Bytes &data)
  {
    return internal::doHash<SHA512_CTX>(data, SHA512_DIGEST_LENGTH, SHA512_Init, SHA512_Update, SHA512_Final);
  }

  SO_API Result<Bytes> sha512(const std::string &data)
  {
    return internal::doHash<SHA512_CTX>(data, SHA512_DIGEST_LENGTH, SHA512_Init, SHA512_Update, SHA512_Final);
  }
  
  SO_API Result<Bytes> fileMD4(const std::string &path)
  {
    return internal::doHashFile(path, EVP_md4());
  }
  
  SO_API Result<Bytes> fileMD5(const std::string &path)
  {
    return internal::doHashFile(path, EVP_md5());
  }
  
  SO_API Result<Bytes> fileSHA1(const std::string &path)
  {
    return internal::doHashFile(path, EVP_sha1());
  }

  SO_API Result<Bytes> fileSHA224(const std::string &path)
  {
    return internal::doHashFile(path, EVP_sha224());
  }

  SO_API Result<Bytes> fileSHA256(const std::string &path)
  {
    return internal::doHashFile(path, EVP_sha256());
  }

  SO_API Result<Bytes> fileSHA384(const std::string &path)
  {
    return internal::doHashFile(path, EVP_sha384());
  }

  SO_API Result<Bytes> fileSHA512(const std::string &path)
  {
    return internal::doHashFile(path, EVP_sha512());
  }
}// namespace hash

namespace nid {
  Nid::Nid(int raw)
  {
    if(0 < raw && raw != NID_undef)
      m_object = make_unique(OBJ_nid2obj(raw));
  }

  Nid::Nid(const Nid &other)
  {
    if(!other.m_object)
      m_object.reset();
    else
      m_object = make_unique(OBJ_dup(other.m_object.get()));
  }

  Nid& Nid::operator=(const Nid &other)
  {
    if(!other.m_object)
      m_object.reset();
    else
      m_object = make_unique(OBJ_dup(other.m_object.get()));

    return *this;
  }

  bool Nid::operator==(const Nid &other) const
  {
    return 0 == OBJ_cmp(m_object.get(), other.m_object.get());
  }

  bool Nid::operator!=(const Nid &other) const
  {
    return !(*this == other);
  }

  Nid::operator bool() const
  {
    return m_object != nullptr;
  }

  int Nid::operator*() const
  {
    return getRaw(); 
  }

  int Nid::getRaw() const
  {
    if(!m_object)
      return NID_undef;

    return OBJ_obj2nid(m_object.get());
  }

  std::string Nid::getLongName() const
  {
    return OBJ_nid2ln(getRaw());
  }

  std::string Nid::getShortName() const
  {
    return OBJ_nid2sn(getRaw());
  }

} // namespace nid

namespace rand {
  SO_API Result<Bytes> bytes(unsigned short numOfBytes)
  {
    Bytes ret(static_cast<size_t>(numOfBytes));
    if(1 != RAND_bytes(ret.data(), static_cast<int>(numOfBytes)))
      return internal::err<Bytes>();

    return internal::ok(std::move(ret));
  }
} // namespace rand

namespace rsa {
  SO_API Result<RSA_uptr> convertPemToPubKey(const std::string &pemPub)
  {
    return internal::convertPemToKey<RSA_uptr>(pemPub, PEM_read_bio_RSA_PUBKEY, nullptr, nullptr, nullptr); 
  }

  SO_API Result<RSA_uptr> convertPemToPrivKey(const std::string &pemPriv)
  {
    return internal::convertPemToKey<RSA_uptr>(pemPriv, PEM_read_bio_RSAPrivateKey, nullptr, nullptr, nullptr); 
  }
 
  SO_API Result<std::string> convertPrivKeyToPem(RSA &rsa)
  { 
    const auto check = rsa::checkKey(rsa);
    if(!check)
      return internal::err<std::string>(check.errorCode());
  
    return internal::convertToPem(PEM_write_bio_RSAPrivateKey, &rsa, nullptr, nullptr, 0, nullptr, nullptr); 
  }
 
  SO_API Result<std::string> convertPubKeyToPem(RSA &pubKey)
  {
    return internal::convertToPem(PEM_write_bio_RSA_PUBKEY, &pubKey);
  }
 
  SO_API Result<RSA_uptr> convertDerToPrivKey(const Bytes &der)
  {
    return internal::convertDerToKey<RSA_uptr>(der, d2i_RSAPrivateKey);
  }

  SO_API Result<RSA_uptr> convertDerToPubKey(const Bytes &der)
  {
    return internal::convertDerToKey<RSA_uptr>(der, d2i_RSA_PUBKEY);
  }

  SO_API Result<Bytes> convertPrivKeyToDer(RSA &rsa)
  {
    const auto check = rsa::checkKey(rsa);
    if(!check)
      return internal::err<Bytes>(check.errorCode());

    return internal::convertKeyToDer(rsa, i2d_RSAPrivateKey);
  }

  SO_API Result<Bytes> convertPubKeyToDer(RSA &rsa)
  {
    return internal::convertKeyToDer(rsa, i2d_RSA_PUBKEY);
  }

  SO_API Result<EVP_PKEY_uptr> convertToEvp(RSA &rsa)
  {
    EVP_PKEY_uptr evpKey = make_unique(EVP_PKEY_new());
    if (!evpKey)
      return internal::err<EVP_PKEY_uptr>();

    if (1 != EVP_PKEY_set1_RSA(evpKey.get(), &rsa))
        return internal::err<EVP_PKEY_uptr>();
    
    return internal::ok(std::move(evpKey));
  }

  SO_API Result<bool> checkKey(RSA &rsa)
  {
    if(1 != RSA_check_key_ex(&rsa, nullptr))
      return internal::err(false);
    
    return internal::ok(true);
  }

  SO_API Result<RSA_uptr> generateKey(KeyBits keySize, Exponent exponent)
  {
    auto bnE = make_unique(BN_new());
    if(1 != BN_set_word(bnE.get(), static_cast<unsigned long>(exponent)))
      return internal::err<RSA_uptr>();

    auto rsa = make_unique(RSA_new());
    if(1 != RSA_generate_key_ex(rsa.get(), static_cast<int>(keySize), bnE.get(), nullptr))
      return internal::err<RSA_uptr>();

    return internal::ok(std::move(rsa));
  }

  SO_API Result<KeyBits> getKeyBits(RSA &rsa)
  {
    // We need rsa->n to be not null to call RSA_size or we will have segfault.
    // Since rsa->n is public modulus we can check its validity by trying to
    // get public key.
    const auto pub = rsa::getPublic(rsa);
    if(!pub)
      return internal::err<KeyBits>(pub.errorCode());

    return internal::ok(static_cast<KeyBits>(RSA_bits(&rsa)));
  }

  SO_API Result<RSA_uptr> getPublic(RSA &rsa)
  {
    auto bio = make_unique(BIO_new(BIO_s_mem())); 
    if(0 >= i2d_RSAPublicKey_bio(bio.get(), &rsa))
      return internal::err<RSA_uptr>();
 
    auto retRsa = make_unique(d2i_RSAPublicKey_bio(bio.get(), nullptr));
    if(!retRsa)
      return internal::err<RSA_uptr>();

    return internal::ok(std::move(retRsa));
  }
 
  SO_API Result<Bytes> signSha1(const Bytes &msg, RSA &privKey)
  {
    const auto digest = hash::sha1(msg);
    if(!digest)
      return digest;

    return internal::rsaSign(NID_sha1, digest.value(), privKey); 
  }

  SO_API Result<Bytes> signSha224(const Bytes &msg, RSA &privKey)
  {
    const auto digest = hash::sha224(msg);
    if(!digest)
      return digest;

    return internal::rsaSign(NID_sha224, digest.value(), privKey); 
  }

  SO_API Result<Bytes> signSha256(const Bytes &msg, RSA &privKey)
  {
    const auto digest = hash::sha256(msg);
    if(!digest)
      return digest;

    return internal::rsaSign(NID_sha256, digest.value(), privKey); 
  }

  SO_API Result<Bytes> signSha384(const Bytes &msg, RSA &privKey)
  {
    const auto digest = hash::sha384(msg);
    if(!digest)
      return digest;

    return internal::rsaSign(NID_sha384, digest.value(), privKey); 
  }
  
  SO_API Result<Bytes> signSha512(const Bytes &msg, RSA &privKey)
  {
    const auto digest = hash::sha512(msg);
    if(!digest)
      return digest;

    return internal::rsaSign(NID_sha512, digest.value(), privKey); 
  }
  
  SO_API Result<bool> verifySha1Signature(const Bytes &signature, const Bytes &message, RSA &pubKey)
  {
    const auto digest = hash::sha1(message);
    if(!digest)
      return internal::err<bool>(digest.errorCode());

    return internal::rsaVerify(NID_sha1, signature, digest.value(), pubKey); 
  }
  
  SO_API Result<bool> verifySha224Signature(const Bytes &signature, const Bytes &message, RSA &pubKey)
  {
    const auto digest = hash::sha224(message);
    if(!digest)
      return internal::err<bool>(digest.errorCode());

    return internal::rsaVerify(NID_sha224, signature, digest.value(), pubKey); 
  }

  SO_API Result<bool> verifySha256Signature(const Bytes &signature, const Bytes &message, RSA &pubKey)
  {
    const auto digest = hash::sha256(message);
    if(!digest)
      return internal::err<bool>(digest.errorCode());

    return internal::rsaVerify(NID_sha256, signature, digest.value(), pubKey); 
  }

  SO_API Result<bool> verifySha384Signature(const Bytes &signature, const Bytes &message, RSA &pubKey)
  {
    const auto digest = hash::sha384(message);
    if(!digest)
      return internal::err<bool>(digest.errorCode());

    return internal::rsaVerify(NID_sha384, signature, digest.value(), pubKey); 
  }

  SO_API Result<bool> verifySha512Signature(const Bytes &signature, const Bytes &message, RSA &pubKey)
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

  SO_API Result<Info> getIssuer(const X509 &cert)
  {
    // this is internal ptr and must not be freed
    X509_NAME *getIssuer = X509_get_issuer_name(&cert);
    if(!getIssuer)
      return internal::err<Info>();

    return internal::commonInfo(*getIssuer); 
  }
  
  SO_API Result<std::string> getIssuerString(const X509 &cert)
  {
    // this is internal ptr and must not be freed
    const X509_NAME *getIssuer = X509_get_issuer_name(&cert);
    if(!getIssuer)
      return internal::err<std::string>();

    return internal::nameToString(*getIssuer);
  }

  SO_API bool isCa(X509 &cert)
  {
    // TODO:
    // I shold wrap somehow positive cases:
    // https://www.openssl.org/docs/man1.1.0/man3/X509_check_ca.html
    if(0 == X509_check_ca(&cert)){
      return false;
    }
    return true;
  }

  SO_API bool isSelfSigned(X509 &cert)
  {
    // TODO:
    // I should wrap somehow and return X509_V_ERR* macros
    if(X509_V_OK == X509_check_issued(&cert, &cert))
      return true;
    
    return false;
  }

  SO_API Result<X509_uptr> convertPemToX509(const std::string &pemCert)
  {
    BIO_uptr bio = make_unique(BIO_new(BIO_s_mem()));

    if(0 >= BIO_write(bio.get(), pemCert.c_str(), static_cast<int>(pemCert.length())))
      return internal::err<X509_uptr>(); 

    auto ret = make_unique(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if(!ret)
      return internal::err<X509_uptr>();

    return internal::ok(std::move(ret));
  }

  SO_API Result<X509_uptr> convertPemFileToX509(const std::string &pemFilePath)
  {
    BIO_uptr bio = make_unique(BIO_new(BIO_s_file()));

    // I'd rather do copy here than drop const in argument or use
    // const_cast in BIO_read_filename
    std::vector<char> fn;
    fn.reserve(pemFilePath.size() + 1);
    std::copy_n(pemFilePath.begin(), pemFilePath.size(), std::back_inserter(fn));
    fn.push_back('\0');

    if(0 >= BIO_read_filename(bio.get(), fn.data()))
      return internal::err<X509_uptr>(); 

    auto ret = make_unique(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if(!ret)
      return internal::err<X509_uptr>();

    return internal::ok(std::move(ret));
  }

  SO_API Result<EVP_PKEY_uptr> getPubKey(X509 &cert)
  { 
    auto pkey = make_unique(X509_get_pubkey(&cert));
    if(!pkey)
      return internal::err<EVP_PKEY_uptr>();

    return internal::ok(std::move(pkey));
  }

  SO_API Result<Bytes> getSerialNumber(X509 &cert)
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

  SO_API Result<size_t> signSha1(X509 &cert, EVP_PKEY &pkey)
  {
    return internal::signCert(cert, pkey, EVP_sha256());  
  }

  SO_API Result<size_t> signSha256(X509 &cert, EVP_PKEY &key)
  {
    return internal::signCert(cert, key, EVP_sha256());  
  }

  SO_API Result<size_t> signSha384(X509 &cert, EVP_PKEY &pkey)
  {
    return internal::signCert(cert, pkey, EVP_sha384());  
  }

  SO_API Result<size_t> signSha512(X509 &cert, EVP_PKEY &pkey)
  {
    return internal::signCert(cert, pkey, EVP_sha512());  
  }

  SO_API Result<Bytes> getSignature(const X509 &cert)
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
  
  SO_API Result<ecdsa::Signature> getEcdsaSignature(const X509 &cert)
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

  SO_API Result<CertExtension> getExtension(const X509 &cert, CertExtensionId getExtensionId)
  {
    const int loc = X509_get_ext_by_NID(&cert, static_cast<int>(getExtensionId), -1);
    if(-1 == loc)
      return internal::err<CertExtension>();

    return internal::getExtension<CertExtensionId>(*X509_get_ext(&cert, loc));
  }

  SO_API Result<CertExtension> getExtension(const X509 &cert, const std::string &oidNumerical)
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

  SO_API Result<std::vector<CertExtension>> getExtensions(const X509 &cert)
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

  SO_API Result<size_t> getExtensionsCount(const X509 &cert)
  {
    const int extsCount = X509_get_ext_count(&cert);
    if(extsCount < 0)
      return internal::err<size_t>(); 

    return internal::ok(static_cast<size_t>(extsCount));
  }

  SO_API Result<Info> getSubject(const X509 &cert)
  {
    // this is internal ptr and must not be freed
    X509_NAME *subject = X509_get_subject_name(&cert);
    if(!subject)
      return internal::err<Info>();

    return internal::commonInfo(*subject); 
  }

  SO_API Result<std::string> getSubjectString(const X509 &cert)
  {
    // this is internal ptr and must not be freed
    const X509_NAME *subject = X509_get_subject_name(&cert);
    if(!subject)
      return internal::err<std::string>();

    return internal::nameToString(*subject);
  }

  SO_API Result<Validity> getValidity(const X509 &cert)
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

  SO_API Result<bool> verifySignature(X509 &cert, EVP_PKEY &pkey)
  {
    const int result = X509_verify(&cert, &pkey);
    return result == 1 ? internal::ok(true) : result == 0 ? internal::ok(false) : internal::err(false);
  }

  SO_API std::tuple<Version,long> getVersion(const X509 &cert)
  {
    const long version = X509_get_version(&cert);
    if(3 <= version || -1 >= version)
      return std::make_tuple(Version::vx, version);

    return std::make_tuple(static_cast<Version>(version), version);
  }

  SO_API Result<void> setCustomExtension(X509 &cert, const std::string &oidNumerical, ASN1_OCTET_STRING &octet, bool critical)
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

  SO_API Result<void> setExtension(X509 &cert, CertExtensionId id, ASN1_OCTET_STRING &octet, bool critical)
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

  SO_API Result<void> setExtension(X509 &cert, const CertExtension &extension)
  {
    auto maybeData = asn1::encodeOctet(extension.data);
    if(!maybeData)
      return internal::err(maybeData.errorCode());

    auto data = maybeData.moveValue();
    if(x509::CertExtensionId::UNDEF == extension.id)
      return setCustomExtension(cert, extension.oidNumerical, *data, extension.critical);

    return setExtension(cert, extension.id, *data, extension.critical);
  }

  SO_API Result<void> setIssuer(X509 &cert, const X509 &rootCert)
  {
    X509_NAME *getIssuer = X509_get_subject_name(&rootCert);
    if(!getIssuer)
      return internal::err();

    if(1 != X509_set_issuer_name(&cert, getIssuer))
      return internal::err();

    return internal::ok();
  }

  SO_API Result<void> setIssuer(X509 &cert, const Info &info)
  {
    auto maybeIssuer = internal::infoToX509Name(info);
    if(!maybeIssuer)
      return internal::err(maybeIssuer.errorCode());

    auto getIssuer = maybeIssuer.moveValue();
    if(1 != X509_set_issuer_name(&cert, getIssuer.get()))
      return internal::err(); 

    return internal::ok();
  }

  SO_API Result<void> setPubKey(X509 &cert, EVP_PKEY &pkey)
  {
    if(1 != X509_set_pubkey(&cert, &pkey))
      return internal::err();

    return internal::ok();
  }
 
  SO_API Result<void> setSerial(X509 &cert, const Bytes &bytes)
  {
    auto maybeInt = asn1::encodeInteger(bytes);
    if(!maybeInt)
      return internal::err(maybeInt.errorCode());

    auto integer = maybeInt.moveValue();
    if(1 != X509_set_serialNumber(&cert, integer.get()))
      return internal::err();

    return internal::ok();
  }

  SO_API Result<void> setSubject(X509 &cert, const Info &info)
  {
    auto maybeSubject = internal::infoToX509Name(info); 
    if(!maybeSubject)
      return internal::err(maybeSubject.errorCode());

    auto subject = maybeSubject.moveValue();
    if(1 != X509_set_subject_name(&cert, subject.get()))
      return internal::err();

    return internal::ok();
  }

  SO_API Result<void> setValidity(X509 &cert, const Validity &validity)
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

  SO_API Result<void> setVersion(X509 &cert, Version version)
  {
    if(1 != X509_set_version(&cert, static_cast<long>(version)))
      return internal::err();
    
    return internal::ok();
  }

  SO_API Result<void> setVersion(X509 &cert, long version)
  {
    if(1 != X509_set_version(&cert, version))
      return internal::err();
    
    return internal::ok();
  }
} // namespace x509

} // namepsace so

#endif
