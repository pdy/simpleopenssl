#ifndef PDY_SIMPLEOPENSSL_H_
#define PDY_SIMPLEOPENSSL_H_

/*
*  MIT License
*  
*  Copyright (c) 2018 Pawel Drzycimski
*  
*  Permission is hereby granted, free of charge, to any person obtaining a copy
*  of this software and associated documentation files (the "Software"), to deal
*  in the Software without restriction, including without limitation the rights
*  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
*  copies of the Software, and to permit persons to whom the Software is
*  furnished to do so, subject to the following conditions:
*  
*  The above copyright notice and this permission notice shall be included in all
*  copies or substantial portions of the Software.
*  
*  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
*  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
*  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
*  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
*  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
*  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
*  SOFTWARE.
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
#include <sstream>
#include <iterator>

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
  
#define CUSTOM_DELETER_UPTR(Type, Deleter)\
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


CUSTOM_DELETER_UPTR(ASN1_OBJECT, ASN1_OBJECT_free);
CUSTOM_DELETER_UPTR(ASN1_STRING, ASN1_STRING_free);
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

CUSTOM_DELETER_UPTR(BIGNUM, BN_free);
CUSTOM_DELETER_UPTR(BN_CTX, BN_CTX_free);
CUSTOM_DELETER_UPTR(BIO, BIO_free_all);
CUSTOM_DELETER_UPTR(EC_GROUP, EC_GROUP_free);
CUSTOM_DELETER_UPTR(EC_KEY, EC_KEY_free);
CUSTOM_DELETER_UPTR(EC_POINT, EC_POINT_free);
CUSTOM_DELETER_UPTR(ECDSA_SIG, ECDSA_SIG_free);
CUSTOM_DELETER_UPTR(EVP_CIPHER_CTX, EVP_CIPHER_CTX_free);
CUSTOM_DELETER_UPTR(EVP_MD_CTX, EVP_MD_CTX_free);
CUSTOM_DELETER_UPTR(EVP_PKEY, EVP_PKEY_free);
CUSTOM_DELETER_UPTR(RSA, RSA_free);
CUSTOM_DELETER_UPTR(X509, X509_free);
CUSTOM_DELETER_UPTR(X509_CRL, X509_CRL_free);
CUSTOM_DELETER_UPTR(X509_EXTENSION, X509_EXTENSION_free);
CUSTOM_DELETER_UPTR(X509_NAME, X509_NAME_free);
CUSTOM_DELETER_UPTR(X509_NAME_ENTRY, X509_NAME_ENTRY_free);

#undef CUSTOM_DELETER_UPTR

namespace internal {

  /*
template<typename T, typename TSelf, typename Tag>
class AddValueRef {};

template<typename T, typename TSelf>
class AddValueRef<T, TSelf, std::false_type>
{
public:
  const T& operator*() const { return value; }
  const T* operator->() const { return &(value); }
  const T& value const { return static_cast<const TSelf*>(this)->value; }
};

template<typename T, typename TSelf>
class AddValueRef<T, TSelf, std::true_type>
{};
*/

static constexpr int OSSL_NO_ERR_CODE = 0;

template<typename ID>
struct X509Extension;

struct X509Name
{
  // as of https://tools.ietf.org/html/rfc2459
  std::string commonName;
  std::string surname;
  std::string countryName;
  std::string localityName;
  std::string stateOrProvinceName;
  std::string organizationName;
  std::string organizationalUnitName;
  std::string title;
  std::string name;
  std::string givenName;
  std::string initials;
  std::string generationQualifier;
  std::string dnQualifier;

  inline bool operator ==(const X509Name &other) const; 
  inline bool operator !=(const X509Name &other) const;
};

} //namespace internal

template<typename T>
struct Result 
{
  T value;
  unsigned long opensslErrCode;

  explicit inline operator bool() const noexcept;
  inline T&& moveValue();
  inline bool hasValue() const noexcept;
  inline bool hasError() const noexcept; 
  inline std::string msg() const;
 
};

template<>
struct Result<void>
{ 
  unsigned long opensslErrCode;
  
  explicit inline operator bool() const noexcept;
  inline bool hasError() const noexcept;
  inline std::string msg() const; 
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
  SO_API Result<std::string> convertToISO8601(const ASN1_TIME &asnTime);

  SO_API Result<ASN1_INTEGER_uptr> encodeInteger(const Bytes &bt);
  SO_API Result<ASN1_OBJECT_uptr> encodeObject(const std::string &nameOrNumerical);
  SO_API Result<ASN1_OCTET_STRING_uptr> encodeOctet(const Bytes &bt);
  SO_API Result<ASN1_OCTET_STRING_uptr> encodeOctet(const std::string &str); 
} // namepsace asn1

namespace bignum {
  SO_API BIGNUM_uptr create();

  SO_API Result<BIGNUM_uptr> convertToBignum(const Bytes &bt);
  SO_API Result<Bytes> convertToBytes(const BIGNUM &bn);
  
  SO_API Result<size_t> getByteLen(const BIGNUM &bn);
}

namespace bytes {
  SO_API std::string toString(const Bytes &bt);
  SO_API std::string toString(const Bytes &bt, const Bytes::const_iterator &start);
  SO_API Bytes fromString(const std::string &str);
} // namespace bytes

namespace ecdsa {
  enum class Curve : int
  {
    SECP112R1 = NID_secp112r1,
    SECP112R2 = NID_secp112r2,
    SECP128R1 = NID_secp128r1,
    SECP128R2 = NID_secp128r2,
    SECP160K1 = NID_secp160k1,
    SECP160R1 = NID_secp160r1,
    SECP160R2 = NID_secp160r2,
    SECP192K1 = NID_secp192k1,
    SECP224K1 = NID_secp224k1,
    SECP224R1 = NID_secp224r1,
    SECP256K1 = NID_secp256k1,
    SECP384R1 = NID_secp384r1,
    SECP521R1 = NID_secp521r1,
    SECT113R1 = NID_sect113r1,
    SECT113R2 = NID_sect113r2,
    SECT131R1 = NID_sect131r1,
    SECT131R2 = NID_sect131r2,
    SECT163K1 = NID_sect163k1,
    SECT163R1 = NID_sect163r1,
    SECT163R2 = NID_sect163r2,
    SECT193R1 = NID_sect193r1,
    SECT193R2 = NID_sect193r2,
    SECT233K1 = NID_sect233k1,
    SECT233R1 = NID_sect233r1,
    SECT239K1 = NID_sect239k1,
    SECT283K1 = NID_sect283k1,
    SECT283R1 = NID_sect283r1,
    SECT409K1 = NID_sect409k1,
    SECT409R1 = NID_sect409r1,
    SECT571K1 = NID_sect571k1,
    SECT571R1 = NID_sect571r1
  };

  struct Signature
  {
    Bytes r;
    Bytes s;
    
    inline bool operator ==(const Signature &other) const
    {
      return r.size() == other.r.size() &&
        s.size() == other.s.size() &&
        std::equal(r.begin(), r.end(), other.r.begin()) && 
        std::equal(s.begin(), s.end(), other.s.begin());
    }
  
    inline bool operator !=(const Signature &other) const
    {
      return !(*this == other);
    }
  };


  SO_API EC_KEY_uptr create();
  SO_API Result<EC_KEY_uptr> create(Curve curve);

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
  SO_API Result<std::string> convertCurveToString(Curve curve);

  SO_API Result<bool> checkKey(const EC_KEY &ecKey);
  SO_API Result<EC_KEY_uptr> copyKey(const EC_KEY &ecKey);
  SO_API Result<Curve> getCurve(const EC_KEY &key);
  SO_API Result<EC_KEY_uptr> getPublic(const EC_KEY &key);
  SO_API Result<size_t> getKeySize(const EC_KEY &key);
 
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
  enum class KeyType
  {
    NONE  = EVP_PKEY_NONE,
    EC    = EVP_PKEY_EC,
    RSA   = EVP_PKEY_RSA,
    DSA   = EVP_PKEY_DSA,
    DH    = EVP_PKEY_DH
  };

  SO_API EVP_PKEY_uptr create();

  SO_API Result<void> assign(EVP_PKEY &evp, RSA &rsa);
  SO_API Result<void> assign(EVP_PKEY &evp, EC_KEY &ec);

  SO_API Result<EVP_PKEY_uptr> convertPemToPrivKey(const std::string &pemPriv);
  SO_API Result<EVP_PKEY_uptr> convertPemToPubKey(const std::string &pemPub);
  SO_API Result<EVP_PKEY_uptr> convertDerToPrivKey(const Bytes &der);
  SO_API Result<EVP_PKEY_uptr> convertDerToPubKey(const Bytes &der);
  SO_API Result<Bytes> convertPrivKeyToDer(EVP_PKEY &privKey);
  SO_API Result<Bytes> convertPubKeyToDer(EVP_PKEY &pubKey);
  SO_API std::string convertPubkeyTypeToString(KeyType pubKeyType);
  SO_API Result<EC_KEY_uptr> convertToEcdsa(EVP_PKEY &key);
  SO_API Result<RSA_uptr> convertToRsa(EVP_PKEY &key);

  SO_API KeyType getKeyType(const EVP_PKEY &pubkey);

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

  // Generated with devtools/opensslnids
  enum class Nid : int
  {
    UNDEF = NID_undef,
    ITU_T = NID_itu_t,
    CCITT = NID_ccitt,
    ISO = NID_iso,
    JOINT_ISO_ITU_T = NID_joint_iso_itu_t,
    JOINT_ISO_CCITT = NID_joint_iso_ccitt,
    MEMBER_BODY = NID_member_body,
    IDENTIFIED_ORGANIZATION = NID_identified_organization,
    HMAC_MD5 = NID_hmac_md5,
    HMAC_SHA1 = NID_hmac_sha1,
    CERTICOM_ARC = NID_certicom_arc,
    INTERNATIONAL_ORGANIZATIONS = NID_international_organizations,
    WAP = NID_wap,
    WAP_WSG = NID_wap_wsg,
    SELECTED_ATTRIBUTE_TYPES = NID_selected_attribute_types,
    CLEARANCE = NID_clearance,
    ISO_US = NID_ISO_US,
    X9_57 = NID_X9_57,
    X9CM = NID_X9cm,
    DSA = NID_dsa,
    DSAWITHSHA1 = NID_dsaWithSHA1,
    ANSI_X9_62 = NID_ansi_X9_62,
    X9_62_PRIME_FIELD = NID_X9_62_prime_field,
    X9_62_CHARACTERISTIC_TWO_FIELD = NID_X9_62_characteristic_two_field,
    X9_62_ID_CHARACTERISTIC_TWO_BASIS = NID_X9_62_id_characteristic_two_basis,
    X9_62_ONBASIS = NID_X9_62_onBasis,
    X9_62_TPBASIS = NID_X9_62_tpBasis,
    X9_62_PPBASIS = NID_X9_62_ppBasis,
    X9_62_ID_ECPUBLICKEY = NID_X9_62_id_ecPublicKey,
    X9_62_C2PNB163V1 = NID_X9_62_c2pnb163v1,
    X9_62_C2PNB163V2 = NID_X9_62_c2pnb163v2,
    X9_62_C2PNB163V3 = NID_X9_62_c2pnb163v3,
    X9_62_C2PNB176V1 = NID_X9_62_c2pnb176v1,
    X9_62_C2TNB191V1 = NID_X9_62_c2tnb191v1,
    X9_62_C2TNB191V2 = NID_X9_62_c2tnb191v2,
    X9_62_C2TNB191V3 = NID_X9_62_c2tnb191v3,
    X9_62_C2ONB191V4 = NID_X9_62_c2onb191v4,
    X9_62_C2ONB191V5 = NID_X9_62_c2onb191v5,
    X9_62_C2PNB208W1 = NID_X9_62_c2pnb208w1,
    X9_62_C2TNB239V1 = NID_X9_62_c2tnb239v1,
    X9_62_C2TNB239V2 = NID_X9_62_c2tnb239v2,
    X9_62_C2TNB239V3 = NID_X9_62_c2tnb239v3,
    X9_62_C2ONB239V4 = NID_X9_62_c2onb239v4,
    X9_62_C2ONB239V5 = NID_X9_62_c2onb239v5,
    X9_62_C2PNB272W1 = NID_X9_62_c2pnb272w1,
    X9_62_C2PNB304W1 = NID_X9_62_c2pnb304w1,
    X9_62_C2TNB359V1 = NID_X9_62_c2tnb359v1,
    X9_62_C2PNB368W1 = NID_X9_62_c2pnb368w1,
    X9_62_C2TNB431R1 = NID_X9_62_c2tnb431r1,
    X9_62_PRIME192V1 = NID_X9_62_prime192v1,
    X9_62_PRIME192V2 = NID_X9_62_prime192v2,
    X9_62_PRIME192V3 = NID_X9_62_prime192v3,
    X9_62_PRIME239V1 = NID_X9_62_prime239v1,
    X9_62_PRIME239V2 = NID_X9_62_prime239v2,
    X9_62_PRIME239V3 = NID_X9_62_prime239v3,
    X9_62_PRIME256V1 = NID_X9_62_prime256v1,
    ECDSA_WITH_SHA1 = NID_ecdsa_with_SHA1,
    ECDSA_WITH_RECOMMENDED = NID_ecdsa_with_Recommended,
    ECDSA_WITH_SPECIFIED = NID_ecdsa_with_Specified,
    ECDSA_WITH_SHA224 = NID_ecdsa_with_SHA224,
    ECDSA_WITH_SHA256 = NID_ecdsa_with_SHA256,
    ECDSA_WITH_SHA384 = NID_ecdsa_with_SHA384,
    ECDSA_WITH_SHA512 = NID_ecdsa_with_SHA512,
    SECP112R1 = NID_secp112r1,
    SECP112R2 = NID_secp112r2,
    SECP128R1 = NID_secp128r1,
    SECP128R2 = NID_secp128r2,
    SECP160K1 = NID_secp160k1,
    SECP160R1 = NID_secp160r1,
    SECP160R2 = NID_secp160r2,
    SECP192K1 = NID_secp192k1,
    SECP224K1 = NID_secp224k1,
    SECP224R1 = NID_secp224r1,
    SECP256K1 = NID_secp256k1,
    SECP384R1 = NID_secp384r1,
    SECP521R1 = NID_secp521r1,
    SECT113R1 = NID_sect113r1,
    SECT113R2 = NID_sect113r2,
    SECT131R1 = NID_sect131r1,
    SECT131R2 = NID_sect131r2,
    SECT163K1 = NID_sect163k1,
    SECT163R1 = NID_sect163r1,
    SECT163R2 = NID_sect163r2,
    SECT193R1 = NID_sect193r1,
    SECT193R2 = NID_sect193r2,
    SECT233K1 = NID_sect233k1,
    SECT233R1 = NID_sect233r1,
    SECT239K1 = NID_sect239k1,
    SECT283K1 = NID_sect283k1,
    SECT283R1 = NID_sect283r1,
    SECT409K1 = NID_sect409k1,
    SECT409R1 = NID_sect409r1,
    SECT571K1 = NID_sect571k1,
    SECT571R1 = NID_sect571r1,
    WAP_WSG_IDM_ECID_WTLS1 = NID_wap_wsg_idm_ecid_wtls1,
    WAP_WSG_IDM_ECID_WTLS3 = NID_wap_wsg_idm_ecid_wtls3,
    WAP_WSG_IDM_ECID_WTLS4 = NID_wap_wsg_idm_ecid_wtls4,
    WAP_WSG_IDM_ECID_WTLS5 = NID_wap_wsg_idm_ecid_wtls5,
    WAP_WSG_IDM_ECID_WTLS6 = NID_wap_wsg_idm_ecid_wtls6,
    WAP_WSG_IDM_ECID_WTLS7 = NID_wap_wsg_idm_ecid_wtls7,
    WAP_WSG_IDM_ECID_WTLS8 = NID_wap_wsg_idm_ecid_wtls8,
    WAP_WSG_IDM_ECID_WTLS9 = NID_wap_wsg_idm_ecid_wtls9,
    WAP_WSG_IDM_ECID_WTLS10 = NID_wap_wsg_idm_ecid_wtls10,
    WAP_WSG_IDM_ECID_WTLS11 = NID_wap_wsg_idm_ecid_wtls11,
    WAP_WSG_IDM_ECID_WTLS12 = NID_wap_wsg_idm_ecid_wtls12,
    CAST5_CBC = NID_cast5_cbc,
    CAST5_ECB = NID_cast5_ecb,
    CAST5_CFB64 = NID_cast5_cfb64,
    CAST5_OFB64 = NID_cast5_ofb64,
    PBEWITHMD5ANDCAST5_CBC = NID_pbeWithMD5AndCast5_CBC,
    ID_PASSWORDBASEDMAC = NID_id_PasswordBasedMAC,
    ID_DHBASEDMAC = NID_id_DHBasedMac,
    RSADSI = NID_rsadsi,
    PKCS = NID_pkcs,
    PKCS1 = NID_pkcs1,
    RSAENCRYPTION = NID_rsaEncryption,
    MD2WITHRSAENCRYPTION = NID_md2WithRSAEncryption,
    MD4WITHRSAENCRYPTION = NID_md4WithRSAEncryption,
    MD5WITHRSAENCRYPTION = NID_md5WithRSAEncryption,
    SHA1WITHRSAENCRYPTION = NID_sha1WithRSAEncryption,
    RSAESOAEP = NID_rsaesOaep,
    MGF1 = NID_mgf1,
    PSPECIFIED = NID_pSpecified,
    RSASSAPSS = NID_rsassaPss,
    SHA256WITHRSAENCRYPTION = NID_sha256WithRSAEncryption,
    SHA384WITHRSAENCRYPTION = NID_sha384WithRSAEncryption,
    SHA512WITHRSAENCRYPTION = NID_sha512WithRSAEncryption,
    SHA224WITHRSAENCRYPTION = NID_sha224WithRSAEncryption,
    PKCS3 = NID_pkcs3,
    DHKEYAGREEMENT = NID_dhKeyAgreement,
    PKCS5 = NID_pkcs5,
    PBEWITHMD2ANDDES_CBC = NID_pbeWithMD2AndDES_CBC,
    PBEWITHMD5ANDDES_CBC = NID_pbeWithMD5AndDES_CBC,
    PBEWITHMD2ANDRC2_CBC = NID_pbeWithMD2AndRC2_CBC,
    PBEWITHMD5ANDRC2_CBC = NID_pbeWithMD5AndRC2_CBC,
    PBEWITHSHA1ANDDES_CBC = NID_pbeWithSHA1AndDES_CBC,
    PBEWITHSHA1ANDRC2_CBC = NID_pbeWithSHA1AndRC2_CBC,
    ID_PBKDF2 = NID_id_pbkdf2,
    PBES2 = NID_pbes2,
    PBMAC1 = NID_pbmac1,
    PKCS7 = NID_pkcs7,
    PKCS7_DATA = NID_pkcs7_data,
    PKCS7_SIGNED = NID_pkcs7_signed,
    PKCS7_ENVELOPED = NID_pkcs7_enveloped,
    PKCS7_SIGNEDANDENVELOPED = NID_pkcs7_signedAndEnveloped,
    PKCS7_DIGEST = NID_pkcs7_digest,
    PKCS7_ENCRYPTED = NID_pkcs7_encrypted,
    PKCS9 = NID_pkcs9,
    PKCS9_EMAILADDRESS = NID_pkcs9_emailAddress,
    PKCS9_UNSTRUCTUREDNAME = NID_pkcs9_unstructuredName,
    PKCS9_CONTENTTYPE = NID_pkcs9_contentType,
    PKCS9_MESSAGEDIGEST = NID_pkcs9_messageDigest,
    PKCS9_SIGNINGTIME = NID_pkcs9_signingTime,
    PKCS9_COUNTERSIGNATURE = NID_pkcs9_countersignature,
    PKCS9_CHALLENGEPASSWORD = NID_pkcs9_challengePassword,
    PKCS9_UNSTRUCTUREDADDRESS = NID_pkcs9_unstructuredAddress,
    PKCS9_EXTCERTATTRIBUTES = NID_pkcs9_extCertAttributes,
    EXT_REQ = NID_ext_req,
    SMIMECAPABILITIES = NID_SMIMECapabilities,
    SMIME = NID_SMIME,
    ID_SMIME_MOD = NID_id_smime_mod,
    ID_SMIME_CT = NID_id_smime_ct,
    ID_SMIME_AA = NID_id_smime_aa,
    ID_SMIME_ALG = NID_id_smime_alg,
    ID_SMIME_CD = NID_id_smime_cd,
    ID_SMIME_SPQ = NID_id_smime_spq,
    ID_SMIME_CTI = NID_id_smime_cti,
    ID_SMIME_MOD_CMS = NID_id_smime_mod_cms,
    ID_SMIME_MOD_ESS = NID_id_smime_mod_ess,
    ID_SMIME_MOD_OID = NID_id_smime_mod_oid,
    ID_SMIME_MOD_MSG_V3 = NID_id_smime_mod_msg_v3,
    ID_SMIME_MOD_ETS_ESIGNATURE_88 = NID_id_smime_mod_ets_eSignature_88,
    ID_SMIME_MOD_ETS_ESIGNATURE_97 = NID_id_smime_mod_ets_eSignature_97,
    ID_SMIME_MOD_ETS_ESIGPOLICY_88 = NID_id_smime_mod_ets_eSigPolicy_88,
    ID_SMIME_MOD_ETS_ESIGPOLICY_97 = NID_id_smime_mod_ets_eSigPolicy_97,
    ID_SMIME_CT_RECEIPT = NID_id_smime_ct_receipt,
    ID_SMIME_CT_AUTHDATA = NID_id_smime_ct_authData,
    ID_SMIME_CT_PUBLISHCERT = NID_id_smime_ct_publishCert,
    ID_SMIME_CT_TSTINFO = NID_id_smime_ct_TSTInfo,
    ID_SMIME_CT_TDTINFO = NID_id_smime_ct_TDTInfo,
    ID_SMIME_CT_CONTENTINFO = NID_id_smime_ct_contentInfo,
    ID_SMIME_CT_DVCSREQUESTDATA = NID_id_smime_ct_DVCSRequestData,
    ID_SMIME_CT_DVCSRESPONSEDATA = NID_id_smime_ct_DVCSResponseData,
    ID_SMIME_CT_COMPRESSEDDATA = NID_id_smime_ct_compressedData,
    ID_SMIME_CT_CONTENTCOLLECTION = NID_id_smime_ct_contentCollection,
    ID_SMIME_CT_AUTHENVELOPEDDATA = NID_id_smime_ct_authEnvelopedData,
    ID_CT_ASCIITEXTWITHCRLF = NID_id_ct_asciiTextWithCRLF,
    ID_CT_XML = NID_id_ct_xml,
    ID_SMIME_AA_RECEIPTREQUEST = NID_id_smime_aa_receiptRequest,
    ID_SMIME_AA_SECURITYLABEL = NID_id_smime_aa_securityLabel,
    ID_SMIME_AA_MLEXPANDHISTORY = NID_id_smime_aa_mlExpandHistory,
    ID_SMIME_AA_CONTENTHINT = NID_id_smime_aa_contentHint,
    ID_SMIME_AA_MSGSIGDIGEST = NID_id_smime_aa_msgSigDigest,
    ID_SMIME_AA_ENCAPCONTENTTYPE = NID_id_smime_aa_encapContentType,
    ID_SMIME_AA_CONTENTIDENTIFIER = NID_id_smime_aa_contentIdentifier,
    ID_SMIME_AA_MACVALUE = NID_id_smime_aa_macValue,
    ID_SMIME_AA_EQUIVALENTLABELS = NID_id_smime_aa_equivalentLabels,
    ID_SMIME_AA_CONTENTREFERENCE = NID_id_smime_aa_contentReference,
    ID_SMIME_AA_ENCRYPKEYPREF = NID_id_smime_aa_encrypKeyPref,
    ID_SMIME_AA_SIGNINGCERTIFICATE = NID_id_smime_aa_signingCertificate,
    ID_SMIME_AA_SMIMEENCRYPTCERTS = NID_id_smime_aa_smimeEncryptCerts,
    ID_SMIME_AA_TIMESTAMPTOKEN = NID_id_smime_aa_timeStampToken,
    ID_SMIME_AA_ETS_SIGPOLICYID = NID_id_smime_aa_ets_sigPolicyId,
    ID_SMIME_AA_ETS_COMMITMENTTYPE = NID_id_smime_aa_ets_commitmentType,
    ID_SMIME_AA_ETS_SIGNERLOCATION = NID_id_smime_aa_ets_signerLocation,
    ID_SMIME_AA_ETS_SIGNERATTR = NID_id_smime_aa_ets_signerAttr,
    ID_SMIME_AA_ETS_OTHERSIGCERT = NID_id_smime_aa_ets_otherSigCert,
    ID_SMIME_AA_ETS_CONTENTTIMESTAMP = NID_id_smime_aa_ets_contentTimestamp,
    ID_SMIME_AA_ETS_CERTIFICATEREFS = NID_id_smime_aa_ets_CertificateRefs,
    ID_SMIME_AA_ETS_REVOCATIONREFS = NID_id_smime_aa_ets_RevocationRefs,
    ID_SMIME_AA_ETS_CERTVALUES = NID_id_smime_aa_ets_certValues,
    ID_SMIME_AA_ETS_REVOCATIONVALUES = NID_id_smime_aa_ets_revocationValues,
    ID_SMIME_AA_ETS_ESCTIMESTAMP = NID_id_smime_aa_ets_escTimeStamp,
    ID_SMIME_AA_ETS_CERTCRLTIMESTAMP = NID_id_smime_aa_ets_certCRLTimestamp,
    ID_SMIME_AA_ETS_ARCHIVETIMESTAMP = NID_id_smime_aa_ets_archiveTimeStamp,
    ID_SMIME_AA_SIGNATURETYPE = NID_id_smime_aa_signatureType,
    ID_SMIME_AA_DVCS_DVC = NID_id_smime_aa_dvcs_dvc,
    ID_SMIME_ALG_ESDHWITH3DES = NID_id_smime_alg_ESDHwith3DES,
    ID_SMIME_ALG_ESDHWITHRC2 = NID_id_smime_alg_ESDHwithRC2,
    ID_SMIME_ALG_3DESWRAP = NID_id_smime_alg_3DESwrap,
    ID_SMIME_ALG_RC2WRAP = NID_id_smime_alg_RC2wrap,
    ID_SMIME_ALG_ESDH = NID_id_smime_alg_ESDH,
    ID_SMIME_ALG_CMS3DESWRAP = NID_id_smime_alg_CMS3DESwrap,
    ID_SMIME_ALG_CMSRC2WRAP = NID_id_smime_alg_CMSRC2wrap,
    ID_ALG_PWRI_KEK = NID_id_alg_PWRI_KEK,
    ID_SMIME_CD_LDAP = NID_id_smime_cd_ldap,
    ID_SMIME_SPQ_ETS_SQT_URI = NID_id_smime_spq_ets_sqt_uri,
    ID_SMIME_SPQ_ETS_SQT_UNOTICE = NID_id_smime_spq_ets_sqt_unotice,
    ID_SMIME_CTI_ETS_PROOFOFORIGIN = NID_id_smime_cti_ets_proofOfOrigin,
    ID_SMIME_CTI_ETS_PROOFOFRECEIPT = NID_id_smime_cti_ets_proofOfReceipt,
    ID_SMIME_CTI_ETS_PROOFOFDELIVERY = NID_id_smime_cti_ets_proofOfDelivery,
    ID_SMIME_CTI_ETS_PROOFOFSENDER = NID_id_smime_cti_ets_proofOfSender,
    ID_SMIME_CTI_ETS_PROOFOFAPPROVAL = NID_id_smime_cti_ets_proofOfApproval,
    ID_SMIME_CTI_ETS_PROOFOFCREATION = NID_id_smime_cti_ets_proofOfCreation,
    FRIENDLYNAME = NID_friendlyName,
    LOCALKEYID = NID_localKeyID,
    MS_CSP_NAME = NID_ms_csp_name,
    LOCALKEYSET = NID_LocalKeySet,
    X509CERTIFICATE = NID_x509Certificate,
    SDSICERTIFICATE = NID_sdsiCertificate,
    X509CRL = NID_x509Crl,
    PBE_WITHSHA1AND128BITRC4 = NID_pbe_WithSHA1And128BitRC4,
    PBE_WITHSHA1AND40BITRC4 = NID_pbe_WithSHA1And40BitRC4,
    PBE_WITHSHA1AND3_KEY_TRIPLEDES_CBC = NID_pbe_WithSHA1And3_Key_TripleDES_CBC,
    PBE_WITHSHA1AND2_KEY_TRIPLEDES_CBC = NID_pbe_WithSHA1And2_Key_TripleDES_CBC,
    PBE_WITHSHA1AND128BITRC2_CBC = NID_pbe_WithSHA1And128BitRC2_CBC,
    PBE_WITHSHA1AND40BITRC2_CBC = NID_pbe_WithSHA1And40BitRC2_CBC,
    KEYBAG = NID_keyBag,
    PKCS8SHROUDEDKEYBAG = NID_pkcs8ShroudedKeyBag,
    CERTBAG = NID_certBag,
    CRLBAG = NID_crlBag,
    SECRETBAG = NID_secretBag,
    SAFECONTENTSBAG = NID_safeContentsBag,
    MD2 = NID_md2,
    MD4 = NID_md4,
    MD5 = NID_md5,
    MD5_SHA1 = NID_md5_sha1,
    HMACWITHMD5 = NID_hmacWithMD5,
    HMACWITHSHA1 = NID_hmacWithSHA1,
    HMACWITHSHA224 = NID_hmacWithSHA224,
    HMACWITHSHA256 = NID_hmacWithSHA256,
    HMACWITHSHA384 = NID_hmacWithSHA384,
    HMACWITHSHA512 = NID_hmacWithSHA512,
    RC2_CBC = NID_rc2_cbc,
    RC2_ECB = NID_rc2_ecb,
    RC2_CFB64 = NID_rc2_cfb64,
    RC2_OFB64 = NID_rc2_ofb64,
    RC2_40_CBC = NID_rc2_40_cbc,
    RC2_64_CBC = NID_rc2_64_cbc,
    RC4 = NID_rc4,
    RC4_40 = NID_rc4_40,
    DES_EDE3_CBC = NID_des_ede3_cbc,
    RC5_CBC = NID_rc5_cbc,
    RC5_ECB = NID_rc5_ecb,
    RC5_CFB64 = NID_rc5_cfb64,
    RC5_OFB64 = NID_rc5_ofb64,
    MS_EXT_REQ = NID_ms_ext_req,
    MS_CODE_IND = NID_ms_code_ind,
    MS_CODE_COM = NID_ms_code_com,
    MS_CTL_SIGN = NID_ms_ctl_sign,
    MS_SGC = NID_ms_sgc,
    MS_EFS = NID_ms_efs,
    MS_SMARTCARD_LOGIN = NID_ms_smartcard_login,
    MS_UPN = NID_ms_upn,
    IDEA_CBC = NID_idea_cbc,
    IDEA_ECB = NID_idea_ecb,
    IDEA_CFB64 = NID_idea_cfb64,
    IDEA_OFB64 = NID_idea_ofb64,
    BF_CBC = NID_bf_cbc,
    BF_ECB = NID_bf_ecb,
    BF_CFB64 = NID_bf_cfb64,
    BF_OFB64 = NID_bf_ofb64,
    ID_PKIX = NID_id_pkix,
    ID_PKIX_MOD = NID_id_pkix_mod,
    ID_PE = NID_id_pe,
    ID_QT = NID_id_qt,
    ID_KP = NID_id_kp,
    ID_IT = NID_id_it,
    ID_PKIP = NID_id_pkip,
    ID_ALG = NID_id_alg,
    ID_CMC = NID_id_cmc,
    ID_ON = NID_id_on,
    ID_PDA = NID_id_pda,
    ID_ACA = NID_id_aca,
    ID_QCS = NID_id_qcs,
    ID_CCT = NID_id_cct,
    ID_PPL = NID_id_ppl,
    ID_AD = NID_id_ad,
    ID_PKIX1_EXPLICIT_88 = NID_id_pkix1_explicit_88,
    ID_PKIX1_IMPLICIT_88 = NID_id_pkix1_implicit_88,
    ID_PKIX1_EXPLICIT_93 = NID_id_pkix1_explicit_93,
    ID_PKIX1_IMPLICIT_93 = NID_id_pkix1_implicit_93,
    ID_MOD_CRMF = NID_id_mod_crmf,
    ID_MOD_CMC = NID_id_mod_cmc,
    ID_MOD_KEA_PROFILE_88 = NID_id_mod_kea_profile_88,
    ID_MOD_KEA_PROFILE_93 = NID_id_mod_kea_profile_93,
    ID_MOD_CMP = NID_id_mod_cmp,
    ID_MOD_QUALIFIED_CERT_88 = NID_id_mod_qualified_cert_88,
    ID_MOD_QUALIFIED_CERT_93 = NID_id_mod_qualified_cert_93,
    ID_MOD_ATTRIBUTE_CERT = NID_id_mod_attribute_cert,
    ID_MOD_TIMESTAMP_PROTOCOL = NID_id_mod_timestamp_protocol,
    ID_MOD_OCSP = NID_id_mod_ocsp,
    ID_MOD_DVCS = NID_id_mod_dvcs,
    ID_MOD_CMP2000 = NID_id_mod_cmp2000,
    INFO_ACCESS = NID_info_access,
    BIOMETRICINFO = NID_biometricInfo,
    QCSTATEMENTS = NID_qcStatements,
    AC_AUDITENTITY = NID_ac_auditEntity,
    AC_TARGETING = NID_ac_targeting,
    AACONTROLS = NID_aaControls,
    SBGP_IPADDRBLOCK = NID_sbgp_ipAddrBlock,
    SBGP_AUTONOMOUSSYSNUM = NID_sbgp_autonomousSysNum,
    SBGP_ROUTERIDENTIFIER = NID_sbgp_routerIdentifier,
    AC_PROXYING = NID_ac_proxying,
    SINFO_ACCESS = NID_sinfo_access,
    PROXYCERTINFO = NID_proxyCertInfo,
    TLSFEATURE = NID_tlsfeature,
    ID_QT_CPS = NID_id_qt_cps,
    ID_QT_UNOTICE = NID_id_qt_unotice,
    TEXTNOTICE = NID_textNotice,
    SERVER_AUTH = NID_server_auth,
    CLIENT_AUTH = NID_client_auth,
    CODE_SIGN = NID_code_sign,
    EMAIL_PROTECT = NID_email_protect,
    IPSECENDSYSTEM = NID_ipsecEndSystem,
    IPSECTUNNEL = NID_ipsecTunnel,
    IPSECUSER = NID_ipsecUser,
    TIME_STAMP = NID_time_stamp,
    OCSP_SIGN = NID_OCSP_sign,
    DVCS = NID_dvcs,
    IPSEC_IKE = NID_ipsec_IKE,
    CAPWAPAC = NID_capwapAC,
    CAPWAPWTP = NID_capwapWTP,
    SSHCLIENT = NID_sshClient,
    SSHSERVER = NID_sshServer,
    SENDROUTER = NID_sendRouter,
    SENDPROXIEDROUTER = NID_sendProxiedRouter,
    SENDOWNER = NID_sendOwner,
    SENDPROXIEDOWNER = NID_sendProxiedOwner,
    ID_IT_CAPROTENCCERT = NID_id_it_caProtEncCert,
    ID_IT_SIGNKEYPAIRTYPES = NID_id_it_signKeyPairTypes,
    ID_IT_ENCKEYPAIRTYPES = NID_id_it_encKeyPairTypes,
    ID_IT_PREFERREDSYMMALG = NID_id_it_preferredSymmAlg,
    ID_IT_CAKEYUPDATEINFO = NID_id_it_caKeyUpdateInfo,
    ID_IT_CURRENTCRL = NID_id_it_currentCRL,
    ID_IT_UNSUPPORTEDOIDS = NID_id_it_unsupportedOIDs,
    ID_IT_SUBSCRIPTIONREQUEST = NID_id_it_subscriptionRequest,
    ID_IT_SUBSCRIPTIONRESPONSE = NID_id_it_subscriptionResponse,
    ID_IT_KEYPAIRPARAMREQ = NID_id_it_keyPairParamReq,
    ID_IT_KEYPAIRPARAMREP = NID_id_it_keyPairParamRep,
    ID_IT_REVPASSPHRASE = NID_id_it_revPassphrase,
    ID_IT_IMPLICITCONFIRM = NID_id_it_implicitConfirm,
    ID_IT_CONFIRMWAITTIME = NID_id_it_confirmWaitTime,
    ID_IT_ORIGPKIMESSAGE = NID_id_it_origPKIMessage,
    ID_IT_SUPPLANGTAGS = NID_id_it_suppLangTags,
    ID_REGCTRL = NID_id_regCtrl,
    ID_REGINFO = NID_id_regInfo,
    ID_REGCTRL_REGTOKEN = NID_id_regCtrl_regToken,
    ID_REGCTRL_AUTHENTICATOR = NID_id_regCtrl_authenticator,
    ID_REGCTRL_PKIPUBLICATIONINFO = NID_id_regCtrl_pkiPublicationInfo,
    ID_REGCTRL_PKIARCHIVEOPTIONS = NID_id_regCtrl_pkiArchiveOptions,
    ID_REGCTRL_OLDCERTID = NID_id_regCtrl_oldCertID,
    ID_REGCTRL_PROTOCOLENCRKEY = NID_id_regCtrl_protocolEncrKey,
    ID_REGINFO_UTF8PAIRS = NID_id_regInfo_utf8Pairs,
    ID_REGINFO_CERTREQ = NID_id_regInfo_certReq,
    ID_ALG_DES40 = NID_id_alg_des40,
    ID_ALG_NOSIGNATURE = NID_id_alg_noSignature,
    ID_ALG_DH_SIG_HMAC_SHA1 = NID_id_alg_dh_sig_hmac_sha1,
    ID_ALG_DH_POP = NID_id_alg_dh_pop,
    ID_CMC_STATUSINFO = NID_id_cmc_statusInfo,
    ID_CMC_IDENTIFICATION = NID_id_cmc_identification,
    ID_CMC_IDENTITYPROOF = NID_id_cmc_identityProof,
    ID_CMC_DATARETURN = NID_id_cmc_dataReturn,
    ID_CMC_TRANSACTIONID = NID_id_cmc_transactionId,
    ID_CMC_SENDERNONCE = NID_id_cmc_senderNonce,
    ID_CMC_RECIPIENTNONCE = NID_id_cmc_recipientNonce,
    ID_CMC_ADDEXTENSIONS = NID_id_cmc_addExtensions,
    ID_CMC_ENCRYPTEDPOP = NID_id_cmc_encryptedPOP,
    ID_CMC_DECRYPTEDPOP = NID_id_cmc_decryptedPOP,
    ID_CMC_LRAPOPWITNESS = NID_id_cmc_lraPOPWitness,
    ID_CMC_GETCERT = NID_id_cmc_getCert,
    ID_CMC_GETCRL = NID_id_cmc_getCRL,
    ID_CMC_REVOKEREQUEST = NID_id_cmc_revokeRequest,
    ID_CMC_REGINFO = NID_id_cmc_regInfo,
    ID_CMC_RESPONSEINFO = NID_id_cmc_responseInfo,
    ID_CMC_QUERYPENDING = NID_id_cmc_queryPending,
    ID_CMC_POPLINKRANDOM = NID_id_cmc_popLinkRandom,
    ID_CMC_POPLINKWITNESS = NID_id_cmc_popLinkWitness,
    ID_CMC_CONFIRMCERTACCEPTANCE = NID_id_cmc_confirmCertAcceptance,
    ID_ON_PERSONALDATA = NID_id_on_personalData,
    ID_ON_PERMANENTIDENTIFIER = NID_id_on_permanentIdentifier,
    ID_PDA_DATEOFBIRTH = NID_id_pda_dateOfBirth,
    ID_PDA_PLACEOFBIRTH = NID_id_pda_placeOfBirth,
    ID_PDA_GENDER = NID_id_pda_gender,
    ID_PDA_COUNTRYOFCITIZENSHIP = NID_id_pda_countryOfCitizenship,
    ID_PDA_COUNTRYOFRESIDENCE = NID_id_pda_countryOfResidence,
    ID_ACA_AUTHENTICATIONINFO = NID_id_aca_authenticationInfo,
    ID_ACA_ACCESSIDENTITY = NID_id_aca_accessIdentity,
    ID_ACA_CHARGINGIDENTITY = NID_id_aca_chargingIdentity,
    ID_ACA_GROUP = NID_id_aca_group,
    ID_ACA_ROLE = NID_id_aca_role,
    ID_ACA_ENCATTRS = NID_id_aca_encAttrs,
    ID_QCS_PKIXQCSYNTAX_V1 = NID_id_qcs_pkixQCSyntax_v1,
    ID_CCT_CRS = NID_id_cct_crs,
    ID_CCT_PKIDATA = NID_id_cct_PKIData,
    ID_CCT_PKIRESPONSE = NID_id_cct_PKIResponse,
    ID_PPL_ANYLANGUAGE = NID_id_ppl_anyLanguage,
    ID_PPL_INHERITALL = NID_id_ppl_inheritAll,
    INDEPENDENT = NID_Independent,
    AD_OCSP = NID_ad_OCSP,
    AD_CA_ISSUERS = NID_ad_ca_issuers,
    AD_TIMESTAMPING = NID_ad_timeStamping,
    AD_DVCS = NID_ad_dvcs,
    CAREPOSITORY = NID_caRepository,
    ID_PKIX_OCSP_BASIC = NID_id_pkix_OCSP_basic,
    ID_PKIX_OCSP_NONCE = NID_id_pkix_OCSP_Nonce,
    ID_PKIX_OCSP_CRLID = NID_id_pkix_OCSP_CrlID,
    ID_PKIX_OCSP_ACCEPTABLERESPONSES = NID_id_pkix_OCSP_acceptableResponses,
    ID_PKIX_OCSP_NOCHECK = NID_id_pkix_OCSP_noCheck,
    ID_PKIX_OCSP_ARCHIVECUTOFF = NID_id_pkix_OCSP_archiveCutoff,
    ID_PKIX_OCSP_SERVICELOCATOR = NID_id_pkix_OCSP_serviceLocator,
    ID_PKIX_OCSP_EXTENDEDSTATUS = NID_id_pkix_OCSP_extendedStatus,
    ID_PKIX_OCSP_VALID = NID_id_pkix_OCSP_valid,
    ID_PKIX_OCSP_PATH = NID_id_pkix_OCSP_path,
    ID_PKIX_OCSP_TRUSTROOT = NID_id_pkix_OCSP_trustRoot,
    ALGORITHM = NID_algorithm,
    MD5WITHRSA = NID_md5WithRSA,
    DES_ECB = NID_des_ecb,
    DES_CBC = NID_des_cbc,
    DES_OFB64 = NID_des_ofb64,
    DES_CFB64 = NID_des_cfb64,
    RSASIGNATURE = NID_rsaSignature,
    DSA_2 = NID_dsa_2,
    DSAWITHSHA = NID_dsaWithSHA,
    SHAWITHRSAENCRYPTION = NID_shaWithRSAEncryption,
    DES_EDE_ECB = NID_des_ede_ecb,
    DES_EDE3_ECB = NID_des_ede3_ecb,
    DES_EDE_CBC = NID_des_ede_cbc,
    DES_EDE_CFB64 = NID_des_ede_cfb64,
    DES_EDE3_CFB64 = NID_des_ede3_cfb64,
    DES_EDE_OFB64 = NID_des_ede_ofb64,
    DES_EDE3_OFB64 = NID_des_ede3_ofb64,
    DESX_CBC = NID_desx_cbc,
    SHA = NID_sha,
    SHA1 = NID_sha1,
    DSAWITHSHA1_2 = NID_dsaWithSHA1_2,
    SHA1WITHRSA = NID_sha1WithRSA,
    RIPEMD160 = NID_ripemd160,
    RIPEMD160WITHRSA = NID_ripemd160WithRSA,
    BLAKE2B512 = NID_blake2b512,
    BLAKE2S256 = NID_blake2s256,
    SXNET = NID_sxnet,
    X500 = NID_X500,
    X509 = NID_X509,
    COMMONNAME = NID_commonName,
    SURNAME = NID_surname,
    SERIALNUMBER = NID_serialNumber,
    COUNTRYNAME = NID_countryName,
    LOCALITYNAME = NID_localityName,
    STATEORPROVINCENAME = NID_stateOrProvinceName,
    STREETADDRESS = NID_streetAddress,
    ORGANIZATIONNAME = NID_organizationName,
    ORGANIZATIONALUNITNAME = NID_organizationalUnitName,
    TITLE = NID_title,
    DESCRIPTION = NID_description,
    SEARCHGUIDE = NID_searchGuide,
    BUSINESSCATEGORY = NID_businessCategory,
    POSTALADDRESS = NID_postalAddress,
    POSTALCODE = NID_postalCode,
    POSTOFFICEBOX = NID_postOfficeBox,
    PHYSICALDELIVERYOFFICENAME = NID_physicalDeliveryOfficeName,
    TELEPHONENUMBER = NID_telephoneNumber,
    TELEXNUMBER = NID_telexNumber,
    TELETEXTERMINALIDENTIFIER = NID_teletexTerminalIdentifier,
    FACSIMILETELEPHONENUMBER = NID_facsimileTelephoneNumber,
    X121ADDRESS = NID_x121Address,
    INTERNATIONALISDNNUMBER = NID_internationaliSDNNumber,
    REGISTEREDADDRESS = NID_registeredAddress,
    DESTINATIONINDICATOR = NID_destinationIndicator,
    PREFERREDDELIVERYMETHOD = NID_preferredDeliveryMethod,
    PRESENTATIONADDRESS = NID_presentationAddress,
    SUPPORTEDAPPLICATIONCONTEXT = NID_supportedApplicationContext,
    MEMBER = NID_member,
    OWNER = NID_owner,
    ROLEOCCUPANT = NID_roleOccupant,
    SEEALSO = NID_seeAlso,
    USERPASSWORD = NID_userPassword,
    USERCERTIFICATE = NID_userCertificate,
    CACERTIFICATE = NID_cACertificate,
    AUTHORITYREVOCATIONLIST = NID_authorityRevocationList,
    CERTIFICATEREVOCATIONLIST = NID_certificateRevocationList,
    CROSSCERTIFICATEPAIR = NID_crossCertificatePair,
    NAME = NID_name,
    GIVENNAME = NID_givenName,
    INITIALS = NID_initials,
    GENERATIONQUALIFIER = NID_generationQualifier,
    X500UNIQUEIDENTIFIER = NID_x500UniqueIdentifier,
    DNQUALIFIER = NID_dnQualifier,
    ENHANCEDSEARCHGUIDE = NID_enhancedSearchGuide,
    PROTOCOLINFORMATION = NID_protocolInformation,
    DISTINGUISHEDNAME = NID_distinguishedName,
    UNIQUEMEMBER = NID_uniqueMember,
    HOUSEIDENTIFIER = NID_houseIdentifier,
    SUPPORTEDALGORITHMS = NID_supportedAlgorithms,
    DELTAREVOCATIONLIST = NID_deltaRevocationList,
    DMDNAME = NID_dmdName,
    PSEUDONYM = NID_pseudonym,
    ROLE = NID_role,
    X500ALGORITHMS = NID_X500algorithms,
    RSA = NID_rsa,
    MDC2WITHRSA = NID_mdc2WithRSA,
    MDC2 = NID_mdc2,
    ID_CE = NID_id_ce,
    SUBJECT_DIRECTORY_ATTRIBUTES = NID_subject_directory_attributes,
    SUBJECT_KEY_IDENTIFIER = NID_subject_key_identifier,
    KEY_USAGE = NID_key_usage,
    PRIVATE_KEY_USAGE_PERIOD = NID_private_key_usage_period,
    SUBJECT_ALT_NAME = NID_subject_alt_name,
    ISSUER_ALT_NAME = NID_issuer_alt_name,
    BASIC_CONSTRAINTS = NID_basic_constraints,
    CRL_NUMBER = NID_crl_number,
    CRL_REASON = NID_crl_reason,
    INVALIDITY_DATE = NID_invalidity_date,
    DELTA_CRL = NID_delta_crl,
    ISSUING_DISTRIBUTION_POINT = NID_issuing_distribution_point,
    CERTIFICATE_ISSUER = NID_certificate_issuer,
    NAME_CONSTRAINTS = NID_name_constraints,
    CRL_DISTRIBUTION_POINTS = NID_crl_distribution_points,
    CERTIFICATE_POLICIES = NID_certificate_policies,
    ANY_POLICY = NID_any_policy,
    POLICY_MAPPINGS = NID_policy_mappings,
    AUTHORITY_KEY_IDENTIFIER = NID_authority_key_identifier,
    POLICY_CONSTRAINTS = NID_policy_constraints,
    EXT_KEY_USAGE = NID_ext_key_usage,
    FRESHEST_CRL = NID_freshest_crl,
    INHIBIT_ANY_POLICY = NID_inhibit_any_policy,
    TARGET_INFORMATION = NID_target_information,
    NO_REV_AVAIL = NID_no_rev_avail,
    ANYEXTENDEDKEYUSAGE = NID_anyExtendedKeyUsage,
    NETSCAPE = NID_netscape,
    NETSCAPE_CERT_EXTENSION = NID_netscape_cert_extension,
    NETSCAPE_DATA_TYPE = NID_netscape_data_type,
    NETSCAPE_CERT_TYPE = NID_netscape_cert_type,
    NETSCAPE_BASE_URL = NID_netscape_base_url,
    NETSCAPE_REVOCATION_URL = NID_netscape_revocation_url,
    NETSCAPE_CA_REVOCATION_URL = NID_netscape_ca_revocation_url,
    NETSCAPE_RENEWAL_URL = NID_netscape_renewal_url,
    NETSCAPE_CA_POLICY_URL = NID_netscape_ca_policy_url,
    NETSCAPE_SSL_SERVER_NAME = NID_netscape_ssl_server_name,
    NETSCAPE_COMMENT = NID_netscape_comment,
    NETSCAPE_CERT_SEQUENCE = NID_netscape_cert_sequence,
    NS_SGC = NID_ns_sgc,
    ORG = NID_org,
    DOD = NID_dod,
    IANA = NID_iana,
    DIRECTORY = NID_Directory,
    MANAGEMENT = NID_Management,
    EXPERIMENTAL = NID_Experimental,
    PRIVATE = NID_Private,
    SECURITY = NID_Security,
    SNMPV2 = NID_SNMPv2,
    MAIL = NID_Mail,
    ENTERPRISES = NID_Enterprises,
    DCOBJECT = NID_dcObject,
    MIME_MHS = NID_mime_mhs,
    MIME_MHS_HEADINGS = NID_mime_mhs_headings,
    MIME_MHS_BODIES = NID_mime_mhs_bodies,
    ID_HEX_PARTIAL_MESSAGE = NID_id_hex_partial_message,
    ID_HEX_MULTIPART_MESSAGE = NID_id_hex_multipart_message,
    ZLIB_COMPRESSION = NID_zlib_compression,
    AES_128_ECB = NID_aes_128_ecb,
    AES_128_CBC = NID_aes_128_cbc,
    AES_128_OFB128 = NID_aes_128_ofb128,
    AES_128_CFB128 = NID_aes_128_cfb128,
    ID_AES128_WRAP = NID_id_aes128_wrap,
    AES_128_GCM = NID_aes_128_gcm,
    AES_128_CCM = NID_aes_128_ccm,
    ID_AES128_WRAP_PAD = NID_id_aes128_wrap_pad,
    AES_192_ECB = NID_aes_192_ecb,
    AES_192_CBC = NID_aes_192_cbc,
    AES_192_OFB128 = NID_aes_192_ofb128,
    AES_192_CFB128 = NID_aes_192_cfb128,
    ID_AES192_WRAP = NID_id_aes192_wrap,
    AES_192_GCM = NID_aes_192_gcm,
    AES_192_CCM = NID_aes_192_ccm,
    ID_AES192_WRAP_PAD = NID_id_aes192_wrap_pad,
    AES_256_ECB = NID_aes_256_ecb,
    AES_256_CBC = NID_aes_256_cbc,
    AES_256_OFB128 = NID_aes_256_ofb128,
    AES_256_CFB128 = NID_aes_256_cfb128,
    ID_AES256_WRAP = NID_id_aes256_wrap,
    AES_256_GCM = NID_aes_256_gcm,
    AES_256_CCM = NID_aes_256_ccm,
    ID_AES256_WRAP_PAD = NID_id_aes256_wrap_pad,
    AES_128_CFB1 = NID_aes_128_cfb1,
    AES_192_CFB1 = NID_aes_192_cfb1,
    AES_256_CFB1 = NID_aes_256_cfb1,
    AES_128_CFB8 = NID_aes_128_cfb8,
    AES_192_CFB8 = NID_aes_192_cfb8,
    AES_256_CFB8 = NID_aes_256_cfb8,
    AES_128_CTR = NID_aes_128_ctr,
    AES_192_CTR = NID_aes_192_ctr,
    AES_256_CTR = NID_aes_256_ctr,
    AES_128_OCB = NID_aes_128_ocb,
    AES_192_OCB = NID_aes_192_ocb,
    AES_256_OCB = NID_aes_256_ocb,
    AES_128_XTS = NID_aes_128_xts,
    AES_256_XTS = NID_aes_256_xts,
    DES_CFB1 = NID_des_cfb1,
    DES_CFB8 = NID_des_cfb8,
    DES_EDE3_CFB1 = NID_des_ede3_cfb1,
    DES_EDE3_CFB8 = NID_des_ede3_cfb8,
    SHA256 = NID_sha256,
    SHA384 = NID_sha384,
    SHA512 = NID_sha512,
    SHA224 = NID_sha224,
    DSA_WITH_SHA224 = NID_dsa_with_SHA224,
    DSA_WITH_SHA256 = NID_dsa_with_SHA256,
    HOLD_INSTRUCTION_CODE = NID_hold_instruction_code,
    HOLD_INSTRUCTION_NONE = NID_hold_instruction_none,
    HOLD_INSTRUCTION_CALL_ISSUER = NID_hold_instruction_call_issuer,
    HOLD_INSTRUCTION_REJECT = NID_hold_instruction_reject,
    DATA = NID_data,
    PSS = NID_pss,
    UCL = NID_ucl,
    PILOT = NID_pilot,
    PILOTATTRIBUTETYPE = NID_pilotAttributeType,
    PILOTATTRIBUTESYNTAX = NID_pilotAttributeSyntax,
    PILOTOBJECTCLASS = NID_pilotObjectClass,
    PILOTGROUPS = NID_pilotGroups,
    IA5STRINGSYNTAX = NID_iA5StringSyntax,
    CASEIGNOREIA5STRINGSYNTAX = NID_caseIgnoreIA5StringSyntax,
    PILOTOBJECT = NID_pilotObject,
    PILOTPERSON = NID_pilotPerson,
    ACCOUNT = NID_account,
    DOCUMENT = NID_document,
    ROOM = NID_room,
    DOCUMENTSERIES = NID_documentSeries,
    DOMAIN = NID_Domain,
    RFC822LOCALPART = NID_rFC822localPart,
    DNSDOMAIN = NID_dNSDomain,
    DOMAINRELATEDOBJECT = NID_domainRelatedObject,
    FRIENDLYCOUNTRY = NID_friendlyCountry,
    SIMPLESECURITYOBJECT = NID_simpleSecurityObject,
    PILOTORGANIZATION = NID_pilotOrganization,
    PILOTDSA = NID_pilotDSA,
    QUALITYLABELLEDDATA = NID_qualityLabelledData,
    USERID = NID_userId,
    TEXTENCODEDORADDRESS = NID_textEncodedORAddress,
    RFC822MAILBOX = NID_rfc822Mailbox,
    INFO = NID_info,
    FAVOURITEDRINK = NID_favouriteDrink,
    ROOMNUMBER = NID_roomNumber,
    PHOTO = NID_photo,
    USERCLASS = NID_userClass,
    HOST = NID_host,
    MANAGER = NID_manager,
    DOCUMENTIDENTIFIER = NID_documentIdentifier,
    DOCUMENTTITLE = NID_documentTitle,
    DOCUMENTVERSION = NID_documentVersion,
    DOCUMENTAUTHOR = NID_documentAuthor,
    DOCUMENTLOCATION = NID_documentLocation,
    HOMETELEPHONENUMBER = NID_homeTelephoneNumber,
    SECRETARY = NID_secretary,
    OTHERMAILBOX = NID_otherMailbox,
    LASTMODIFIEDTIME = NID_lastModifiedTime,
    LASTMODIFIEDBY = NID_lastModifiedBy,
    DOMAINCOMPONENT = NID_domainComponent,
    ARECORD = NID_aRecord,
    PILOTATTRIBUTETYPE27 = NID_pilotAttributeType27,
    MXRECORD = NID_mXRecord,
    NSRECORD = NID_nSRecord,
    SOARECORD = NID_sOARecord,
    CNAMERECORD = NID_cNAMERecord,
    ASSOCIATEDDOMAIN = NID_associatedDomain,
    ASSOCIATEDNAME = NID_associatedName,
    HOMEPOSTALADDRESS = NID_homePostalAddress,
    PERSONALTITLE = NID_personalTitle,
    MOBILETELEPHONENUMBER = NID_mobileTelephoneNumber,
    PAGERTELEPHONENUMBER = NID_pagerTelephoneNumber,
    FRIENDLYCOUNTRYNAME = NID_friendlyCountryName,
    UNIQUEIDENTIFIER = NID_uniqueIdentifier,
    ORGANIZATIONALSTATUS = NID_organizationalStatus,
    JANETMAILBOX = NID_janetMailbox,
    MAILPREFERENCEOPTION = NID_mailPreferenceOption,
    BUILDINGNAME = NID_buildingName,
    DSAQUALITY = NID_dSAQuality,
    SINGLELEVELQUALITY = NID_singleLevelQuality,
    SUBTREEMINIMUMQUALITY = NID_subtreeMinimumQuality,
    SUBTREEMAXIMUMQUALITY = NID_subtreeMaximumQuality,
    PERSONALSIGNATURE = NID_personalSignature,
    DITREDIRECT = NID_dITRedirect,
    AUDIO = NID_audio,
    DOCUMENTPUBLISHER = NID_documentPublisher,
    ID_SET = NID_id_set,
    SET_CTYPE = NID_set_ctype,
    SET_MSGEXT = NID_set_msgExt,
    SET_ATTR = NID_set_attr,
    SET_POLICY = NID_set_policy,
    SET_CERTEXT = NID_set_certExt,
    SET_BRAND = NID_set_brand,
    SETCT_PANDATA = NID_setct_PANData,
    SETCT_PANTOKEN = NID_setct_PANToken,
    SETCT_PANONLY = NID_setct_PANOnly,
    SETCT_OIDATA = NID_setct_OIData,
    SETCT_PI = NID_setct_PI,
    SETCT_PIDATA = NID_setct_PIData,
    SETCT_PIDATAUNSIGNED = NID_setct_PIDataUnsigned,
    SETCT_HODINPUT = NID_setct_HODInput,
    SETCT_AUTHRESBAGGAGE = NID_setct_AuthResBaggage,
    SETCT_AUTHREVREQBAGGAGE = NID_setct_AuthRevReqBaggage,
    SETCT_AUTHREVRESBAGGAGE = NID_setct_AuthRevResBaggage,
    SETCT_CAPTOKENSEQ = NID_setct_CapTokenSeq,
    SETCT_PINITRESDATA = NID_setct_PInitResData,
    SETCT_PI_TBS = NID_setct_PI_TBS,
    SETCT_PRESDATA = NID_setct_PResData,
    SETCT_AUTHREQTBS = NID_setct_AuthReqTBS,
    SETCT_AUTHRESTBS = NID_setct_AuthResTBS,
    SETCT_AUTHRESTBSX = NID_setct_AuthResTBSX,
    SETCT_AUTHTOKENTBS = NID_setct_AuthTokenTBS,
    SETCT_CAPTOKENDATA = NID_setct_CapTokenData,
    SETCT_CAPTOKENTBS = NID_setct_CapTokenTBS,
    SETCT_ACQCARDCODEMSG = NID_setct_AcqCardCodeMsg,
    SETCT_AUTHREVREQTBS = NID_setct_AuthRevReqTBS,
    SETCT_AUTHREVRESDATA = NID_setct_AuthRevResData,
    SETCT_AUTHREVRESTBS = NID_setct_AuthRevResTBS,
    SETCT_CAPREQTBS = NID_setct_CapReqTBS,
    SETCT_CAPREQTBSX = NID_setct_CapReqTBSX,
    SETCT_CAPRESDATA = NID_setct_CapResData,
    SETCT_CAPREVREQTBS = NID_setct_CapRevReqTBS,
    SETCT_CAPREVREQTBSX = NID_setct_CapRevReqTBSX,
    SETCT_CAPREVRESDATA = NID_setct_CapRevResData,
    SETCT_CREDREQTBS = NID_setct_CredReqTBS,
    SETCT_CREDREQTBSX = NID_setct_CredReqTBSX,
    SETCT_CREDRESDATA = NID_setct_CredResData,
    SETCT_CREDREVREQTBS = NID_setct_CredRevReqTBS,
    SETCT_CREDREVREQTBSX = NID_setct_CredRevReqTBSX,
    SETCT_CREDREVRESDATA = NID_setct_CredRevResData,
    SETCT_PCERTREQDATA = NID_setct_PCertReqData,
    SETCT_PCERTRESTBS = NID_setct_PCertResTBS,
    SETCT_BATCHADMINREQDATA = NID_setct_BatchAdminReqData,
    SETCT_BATCHADMINRESDATA = NID_setct_BatchAdminResData,
    SETCT_CARDCINITRESTBS = NID_setct_CardCInitResTBS,
    SETCT_MEAQCINITRESTBS = NID_setct_MeAqCInitResTBS,
    SETCT_REGFORMRESTBS = NID_setct_RegFormResTBS,
    SETCT_CERTREQDATA = NID_setct_CertReqData,
    SETCT_CERTREQTBS = NID_setct_CertReqTBS,
    SETCT_CERTRESDATA = NID_setct_CertResData,
    SETCT_CERTINQREQTBS = NID_setct_CertInqReqTBS,
    SETCT_ERRORTBS = NID_setct_ErrorTBS,
    SETCT_PIDUALSIGNEDTBE = NID_setct_PIDualSignedTBE,
    SETCT_PIUNSIGNEDTBE = NID_setct_PIUnsignedTBE,
    SETCT_AUTHREQTBE = NID_setct_AuthReqTBE,
    SETCT_AUTHRESTBE = NID_setct_AuthResTBE,
    SETCT_AUTHRESTBEX = NID_setct_AuthResTBEX,
    SETCT_AUTHTOKENTBE = NID_setct_AuthTokenTBE,
    SETCT_CAPTOKENTBE = NID_setct_CapTokenTBE,
    SETCT_CAPTOKENTBEX = NID_setct_CapTokenTBEX,
    SETCT_ACQCARDCODEMSGTBE = NID_setct_AcqCardCodeMsgTBE,
    SETCT_AUTHREVREQTBE = NID_setct_AuthRevReqTBE,
    SETCT_AUTHREVRESTBE = NID_setct_AuthRevResTBE,
    SETCT_AUTHREVRESTBEB = NID_setct_AuthRevResTBEB,
    SETCT_CAPREQTBE = NID_setct_CapReqTBE,
    SETCT_CAPREQTBEX = NID_setct_CapReqTBEX,
    SETCT_CAPRESTBE = NID_setct_CapResTBE,
    SETCT_CAPREVREQTBE = NID_setct_CapRevReqTBE,
    SETCT_CAPREVREQTBEX = NID_setct_CapRevReqTBEX,
    SETCT_CAPREVRESTBE = NID_setct_CapRevResTBE,
    SETCT_CREDREQTBE = NID_setct_CredReqTBE,
    SETCT_CREDREQTBEX = NID_setct_CredReqTBEX,
    SETCT_CREDRESTBE = NID_setct_CredResTBE,
    SETCT_CREDREVREQTBE = NID_setct_CredRevReqTBE,
    SETCT_CREDREVREQTBEX = NID_setct_CredRevReqTBEX,
    SETCT_CREDREVRESTBE = NID_setct_CredRevResTBE,
    SETCT_BATCHADMINREQTBE = NID_setct_BatchAdminReqTBE,
    SETCT_BATCHADMINRESTBE = NID_setct_BatchAdminResTBE,
    SETCT_REGFORMREQTBE = NID_setct_RegFormReqTBE,
    SETCT_CERTREQTBE = NID_setct_CertReqTBE,
    SETCT_CERTREQTBEX = NID_setct_CertReqTBEX,
    SETCT_CERTRESTBE = NID_setct_CertResTBE,
    SETCT_CRLNOTIFICATIONTBS = NID_setct_CRLNotificationTBS,
    SETCT_CRLNOTIFICATIONRESTBS = NID_setct_CRLNotificationResTBS,
    SETCT_BCIDISTRIBUTIONTBS = NID_setct_BCIDistributionTBS,
    SETEXT_GENCRYPT = NID_setext_genCrypt,
    SETEXT_MIAUTH = NID_setext_miAuth,
    SETEXT_PINSECURE = NID_setext_pinSecure,
    SETEXT_PINANY = NID_setext_pinAny,
    SETEXT_TRACK2 = NID_setext_track2,
    SETEXT_CV = NID_setext_cv,
    SET_POLICY_ROOT = NID_set_policy_root,
    SETCEXT_HASHEDROOT = NID_setCext_hashedRoot,
    SETCEXT_CERTTYPE = NID_setCext_certType,
    SETCEXT_MERCHDATA = NID_setCext_merchData,
    SETCEXT_CCERTREQUIRED = NID_setCext_cCertRequired,
    SETCEXT_TUNNELING = NID_setCext_tunneling,
    SETCEXT_SETEXT = NID_setCext_setExt,
    SETCEXT_SETQUALF = NID_setCext_setQualf,
    SETCEXT_PGWYCAPABILITIES = NID_setCext_PGWYcapabilities,
    SETCEXT_TOKENIDENTIFIER = NID_setCext_TokenIdentifier,
    SETCEXT_TRACK2DATA = NID_setCext_Track2Data,
    SETCEXT_TOKENTYPE = NID_setCext_TokenType,
    SETCEXT_ISSUERCAPABILITIES = NID_setCext_IssuerCapabilities,
    SETATTR_CERT = NID_setAttr_Cert,
    SETATTR_PGWYCAP = NID_setAttr_PGWYcap,
    SETATTR_TOKENTYPE = NID_setAttr_TokenType,
    SETATTR_ISSCAP = NID_setAttr_IssCap,
    SET_ROOTKEYTHUMB = NID_set_rootKeyThumb,
    SET_ADDPOLICY = NID_set_addPolicy,
    SETATTR_TOKEN_EMV = NID_setAttr_Token_EMV,
    SETATTR_TOKEN_B0PRIME = NID_setAttr_Token_B0Prime,
    SETATTR_ISSCAP_CVM = NID_setAttr_IssCap_CVM,
    SETATTR_ISSCAP_T2 = NID_setAttr_IssCap_T2,
    SETATTR_ISSCAP_SIG = NID_setAttr_IssCap_Sig,
    SETATTR_GENCRYPTGRM = NID_setAttr_GenCryptgrm,
    SETATTR_T2ENC = NID_setAttr_T2Enc,
    SETATTR_T2CLEARTXT = NID_setAttr_T2cleartxt,
    SETATTR_TOKICCSIG = NID_setAttr_TokICCsig,
    SETATTR_SECDEVSIG = NID_setAttr_SecDevSig,
    SET_BRAND_IATA_ATA = NID_set_brand_IATA_ATA,
    SET_BRAND_DINERS = NID_set_brand_Diners,
    SET_BRAND_AMERICANEXPRESS = NID_set_brand_AmericanExpress,
    SET_BRAND_JCB = NID_set_brand_JCB,
    SET_BRAND_VISA = NID_set_brand_Visa,
    SET_BRAND_MASTERCARD = NID_set_brand_MasterCard,
    SET_BRAND_NOVUS = NID_set_brand_Novus,
    DES_CDMF = NID_des_cdmf,
    RSAOAEPENCRYPTIONSET = NID_rsaOAEPEncryptionSET,
    IPSEC3 = NID_ipsec3,
    IPSEC4 = NID_ipsec4,
    WHIRLPOOL = NID_whirlpool,
    CRYPTOPRO = NID_cryptopro,
    CRYPTOCOM = NID_cryptocom,
    ID_TC26 = NID_id_tc26,
    ID_GOSTR3411_94_WITH_GOSTR3410_2001 = NID_id_GostR3411_94_with_GostR3410_2001,
    ID_GOSTR3411_94_WITH_GOSTR3410_94 = NID_id_GostR3411_94_with_GostR3410_94,
    ID_GOSTR3411_94 = NID_id_GostR3411_94,
    ID_HMACGOSTR3411_94 = NID_id_HMACGostR3411_94,
    ID_GOSTR3410_2001 = NID_id_GostR3410_2001,
    ID_GOSTR3410_94 = NID_id_GostR3410_94,
    ID_GOST28147_89 = NID_id_Gost28147_89,
    GOST89_CNT = NID_gost89_cnt,
    GOST89_CNT_12 = NID_gost89_cnt_12,
    GOST89_CBC = NID_gost89_cbc,
    GOST89_ECB = NID_gost89_ecb,
    GOST89_CTR = NID_gost89_ctr,
    ID_GOST28147_89_MAC = NID_id_Gost28147_89_MAC,
    GOST_MAC_12 = NID_gost_mac_12,
    ID_GOSTR3411_94_PRF = NID_id_GostR3411_94_prf,
    ID_GOSTR3410_2001DH = NID_id_GostR3410_2001DH,
    ID_GOSTR3410_94DH = NID_id_GostR3410_94DH,
    ID_GOST28147_89_CRYPTOPRO_KEYMESHING = NID_id_Gost28147_89_CryptoPro_KeyMeshing,
    ID_GOST28147_89_NONE_KEYMESHING = NID_id_Gost28147_89_None_KeyMeshing,
    ID_GOSTR3411_94_TESTPARAMSET = NID_id_GostR3411_94_TestParamSet,
    ID_GOSTR3411_94_CRYPTOPROPARAMSET = NID_id_GostR3411_94_CryptoProParamSet,
    ID_GOST28147_89_TESTPARAMSET = NID_id_Gost28147_89_TestParamSet,
    ID_GOST28147_89_CRYPTOPRO_A_PARAMSET = NID_id_Gost28147_89_CryptoPro_A_ParamSet,
    ID_GOST28147_89_CRYPTOPRO_B_PARAMSET = NID_id_Gost28147_89_CryptoPro_B_ParamSet,
    ID_GOST28147_89_CRYPTOPRO_C_PARAMSET = NID_id_Gost28147_89_CryptoPro_C_ParamSet,
    ID_GOST28147_89_CRYPTOPRO_D_PARAMSET = NID_id_Gost28147_89_CryptoPro_D_ParamSet,
    ID_GOST28147_89_CRYPTOPRO_OSCAR_1_1_PARAMSET = NID_id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet,
    ID_GOST28147_89_CRYPTOPRO_OSCAR_1_0_PARAMSET = NID_id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet,
    ID_GOST28147_89_CRYPTOPRO_RIC_1_PARAMSET = NID_id_Gost28147_89_CryptoPro_RIC_1_ParamSet,
    ID_GOSTR3410_94_TESTPARAMSET = NID_id_GostR3410_94_TestParamSet,
    ID_GOSTR3410_94_CRYPTOPRO_A_PARAMSET = NID_id_GostR3410_94_CryptoPro_A_ParamSet,
    ID_GOSTR3410_94_CRYPTOPRO_B_PARAMSET = NID_id_GostR3410_94_CryptoPro_B_ParamSet,
    ID_GOSTR3410_94_CRYPTOPRO_C_PARAMSET = NID_id_GostR3410_94_CryptoPro_C_ParamSet,
    ID_GOSTR3410_94_CRYPTOPRO_D_PARAMSET = NID_id_GostR3410_94_CryptoPro_D_ParamSet,
    ID_GOSTR3410_94_CRYPTOPRO_XCHA_PARAMSET = NID_id_GostR3410_94_CryptoPro_XchA_ParamSet,
    ID_GOSTR3410_94_CRYPTOPRO_XCHB_PARAMSET = NID_id_GostR3410_94_CryptoPro_XchB_ParamSet,
    ID_GOSTR3410_94_CRYPTOPRO_XCHC_PARAMSET = NID_id_GostR3410_94_CryptoPro_XchC_ParamSet,
    ID_GOSTR3410_2001_TESTPARAMSET = NID_id_GostR3410_2001_TestParamSet,
    ID_GOSTR3410_2001_CRYPTOPRO_A_PARAMSET = NID_id_GostR3410_2001_CryptoPro_A_ParamSet,
    ID_GOSTR3410_2001_CRYPTOPRO_B_PARAMSET = NID_id_GostR3410_2001_CryptoPro_B_ParamSet,
    ID_GOSTR3410_2001_CRYPTOPRO_C_PARAMSET = NID_id_GostR3410_2001_CryptoPro_C_ParamSet,
    ID_GOSTR3410_2001_CRYPTOPRO_XCHA_PARAMSET = NID_id_GostR3410_2001_CryptoPro_XchA_ParamSet,
    ID_GOSTR3410_2001_CRYPTOPRO_XCHB_PARAMSET = NID_id_GostR3410_2001_CryptoPro_XchB_ParamSet,
    ID_GOSTR3410_94_A = NID_id_GostR3410_94_a,
    ID_GOSTR3410_94_ABIS = NID_id_GostR3410_94_aBis,
    ID_GOSTR3410_94_B = NID_id_GostR3410_94_b,
    ID_GOSTR3410_94_BBIS = NID_id_GostR3410_94_bBis,
    ID_GOST28147_89_CC = NID_id_Gost28147_89_cc,
    ID_GOSTR3410_94_CC = NID_id_GostR3410_94_cc,
    ID_GOSTR3410_2001_CC = NID_id_GostR3410_2001_cc,
    ID_GOSTR3411_94_WITH_GOSTR3410_94_CC = NID_id_GostR3411_94_with_GostR3410_94_cc,
    ID_GOSTR3411_94_WITH_GOSTR3410_2001_CC = NID_id_GostR3411_94_with_GostR3410_2001_cc,
    ID_GOSTR3410_2001_PARAMSET_CC = NID_id_GostR3410_2001_ParamSet_cc,
    ID_TC26_ALGORITHMS = NID_id_tc26_algorithms,
    ID_TC26_SIGN = NID_id_tc26_sign,
    ID_GOSTR3410_2012_256 = NID_id_GostR3410_2012_256,
    ID_GOSTR3410_2012_512 = NID_id_GostR3410_2012_512,
    ID_TC26_DIGEST = NID_id_tc26_digest,
    ID_GOSTR3411_2012_256 = NID_id_GostR3411_2012_256,
    ID_GOSTR3411_2012_512 = NID_id_GostR3411_2012_512,
    ID_TC26_SIGNWITHDIGEST = NID_id_tc26_signwithdigest,
    ID_TC26_SIGNWITHDIGEST_GOST3410_2012_256 = NID_id_tc26_signwithdigest_gost3410_2012_256,
    ID_TC26_SIGNWITHDIGEST_GOST3410_2012_512 = NID_id_tc26_signwithdigest_gost3410_2012_512,
    ID_TC26_MAC = NID_id_tc26_mac,
    ID_TC26_HMAC_GOST_3411_2012_256 = NID_id_tc26_hmac_gost_3411_2012_256,
    ID_TC26_HMAC_GOST_3411_2012_512 = NID_id_tc26_hmac_gost_3411_2012_512,
    ID_TC26_CIPHER = NID_id_tc26_cipher,
    ID_TC26_AGREEMENT = NID_id_tc26_agreement,
    ID_TC26_AGREEMENT_GOST_3410_2012_256 = NID_id_tc26_agreement_gost_3410_2012_256,
    ID_TC26_AGREEMENT_GOST_3410_2012_512 = NID_id_tc26_agreement_gost_3410_2012_512,
    ID_TC26_CONSTANTS = NID_id_tc26_constants,
    ID_TC26_SIGN_CONSTANTS = NID_id_tc26_sign_constants,
    ID_TC26_GOST_3410_2012_512_CONSTANTS = NID_id_tc26_gost_3410_2012_512_constants,
    ID_TC26_GOST_3410_2012_512_PARAMSETTEST = NID_id_tc26_gost_3410_2012_512_paramSetTest,
    ID_TC26_GOST_3410_2012_512_PARAMSETA = NID_id_tc26_gost_3410_2012_512_paramSetA,
    ID_TC26_GOST_3410_2012_512_PARAMSETB = NID_id_tc26_gost_3410_2012_512_paramSetB,
    ID_TC26_DIGEST_CONSTANTS = NID_id_tc26_digest_constants,
    ID_TC26_CIPHER_CONSTANTS = NID_id_tc26_cipher_constants,
    ID_TC26_GOST_28147_CONSTANTS = NID_id_tc26_gost_28147_constants,
    ID_TC26_GOST_28147_PARAM_Z = NID_id_tc26_gost_28147_param_Z,
    INN = NID_INN,
    OGRN = NID_OGRN,
    SNILS = NID_SNILS,
    SUBJECTSIGNTOOL = NID_subjectSignTool,
    ISSUERSIGNTOOL = NID_issuerSignTool,
    GRASSHOPPER_ECB = NID_grasshopper_ecb,
    GRASSHOPPER_CTR = NID_grasshopper_ctr,
    GRASSHOPPER_OFB = NID_grasshopper_ofb,
    GRASSHOPPER_CBC = NID_grasshopper_cbc,
    GRASSHOPPER_CFB = NID_grasshopper_cfb,
    GRASSHOPPER_MAC = NID_grasshopper_mac,
    CAMELLIA_128_CBC = NID_camellia_128_cbc,
    CAMELLIA_192_CBC = NID_camellia_192_cbc,
    CAMELLIA_256_CBC = NID_camellia_256_cbc,
    ID_CAMELLIA128_WRAP = NID_id_camellia128_wrap,
    ID_CAMELLIA192_WRAP = NID_id_camellia192_wrap,
    ID_CAMELLIA256_WRAP = NID_id_camellia256_wrap,
    CAMELLIA_128_ECB = NID_camellia_128_ecb,
    CAMELLIA_128_OFB128 = NID_camellia_128_ofb128,
    CAMELLIA_128_CFB128 = NID_camellia_128_cfb128,
    CAMELLIA_128_GCM = NID_camellia_128_gcm,
    CAMELLIA_128_CCM = NID_camellia_128_ccm,
    CAMELLIA_128_CTR = NID_camellia_128_ctr,
    CAMELLIA_128_CMAC = NID_camellia_128_cmac,
    CAMELLIA_192_ECB = NID_camellia_192_ecb,
    CAMELLIA_192_OFB128 = NID_camellia_192_ofb128,
    CAMELLIA_192_CFB128 = NID_camellia_192_cfb128,
    CAMELLIA_192_GCM = NID_camellia_192_gcm,
    CAMELLIA_192_CCM = NID_camellia_192_ccm,
    CAMELLIA_192_CTR = NID_camellia_192_ctr,
    CAMELLIA_192_CMAC = NID_camellia_192_cmac,
    CAMELLIA_256_ECB = NID_camellia_256_ecb,
    CAMELLIA_256_OFB128 = NID_camellia_256_ofb128,
    CAMELLIA_256_CFB128 = NID_camellia_256_cfb128,
    CAMELLIA_256_GCM = NID_camellia_256_gcm,
    CAMELLIA_256_CCM = NID_camellia_256_ccm,
    CAMELLIA_256_CTR = NID_camellia_256_ctr,
    CAMELLIA_256_CMAC = NID_camellia_256_cmac,
    CAMELLIA_128_CFB1 = NID_camellia_128_cfb1,
    CAMELLIA_192_CFB1 = NID_camellia_192_cfb1,
    CAMELLIA_256_CFB1 = NID_camellia_256_cfb1,
    CAMELLIA_128_CFB8 = NID_camellia_128_cfb8,
    CAMELLIA_192_CFB8 = NID_camellia_192_cfb8,
    CAMELLIA_256_CFB8 = NID_camellia_256_cfb8,
    KISA = NID_kisa,
    SEED_ECB = NID_seed_ecb,
    SEED_CBC = NID_seed_cbc,
    SEED_CFB128 = NID_seed_cfb128,
    SEED_OFB128 = NID_seed_ofb128,
    HMAC = NID_hmac,
    CMAC = NID_cmac,
    RC4_HMAC_MD5 = NID_rc4_hmac_md5,
    AES_128_CBC_HMAC_SHA1 = NID_aes_128_cbc_hmac_sha1,
    AES_192_CBC_HMAC_SHA1 = NID_aes_192_cbc_hmac_sha1,
    AES_256_CBC_HMAC_SHA1 = NID_aes_256_cbc_hmac_sha1,
    AES_128_CBC_HMAC_SHA256 = NID_aes_128_cbc_hmac_sha256,
    AES_192_CBC_HMAC_SHA256 = NID_aes_192_cbc_hmac_sha256,
    AES_256_CBC_HMAC_SHA256 = NID_aes_256_cbc_hmac_sha256,
    CHACHA20_POLY1305 = NID_chacha20_poly1305,
    CHACHA20 = NID_chacha20,
    DHPUBLICNUMBER = NID_dhpublicnumber,
    BRAINPOOLP160R1 = NID_brainpoolP160r1,
    BRAINPOOLP160T1 = NID_brainpoolP160t1,
    BRAINPOOLP192R1 = NID_brainpoolP192r1,
    BRAINPOOLP192T1 = NID_brainpoolP192t1,
    BRAINPOOLP224R1 = NID_brainpoolP224r1,
    BRAINPOOLP224T1 = NID_brainpoolP224t1,
    BRAINPOOLP256R1 = NID_brainpoolP256r1,
    BRAINPOOLP256T1 = NID_brainpoolP256t1,
    BRAINPOOLP320R1 = NID_brainpoolP320r1,
    BRAINPOOLP320T1 = NID_brainpoolP320t1,
    BRAINPOOLP384R1 = NID_brainpoolP384r1,
    BRAINPOOLP384T1 = NID_brainpoolP384t1,
    BRAINPOOLP512R1 = NID_brainpoolP512r1,
    BRAINPOOLP512T1 = NID_brainpoolP512t1,
    DHSINGLEPASS_STDDH_SHA1KDF_SCHEME = NID_dhSinglePass_stdDH_sha1kdf_scheme,
    DHSINGLEPASS_STDDH_SHA224KDF_SCHEME = NID_dhSinglePass_stdDH_sha224kdf_scheme,
    DHSINGLEPASS_STDDH_SHA256KDF_SCHEME = NID_dhSinglePass_stdDH_sha256kdf_scheme,
    DHSINGLEPASS_STDDH_SHA384KDF_SCHEME = NID_dhSinglePass_stdDH_sha384kdf_scheme,
    DHSINGLEPASS_STDDH_SHA512KDF_SCHEME = NID_dhSinglePass_stdDH_sha512kdf_scheme,
    DHSINGLEPASS_COFACTORDH_SHA1KDF_SCHEME = NID_dhSinglePass_cofactorDH_sha1kdf_scheme,
    DHSINGLEPASS_COFACTORDH_SHA224KDF_SCHEME = NID_dhSinglePass_cofactorDH_sha224kdf_scheme,
    DHSINGLEPASS_COFACTORDH_SHA256KDF_SCHEME = NID_dhSinglePass_cofactorDH_sha256kdf_scheme,
    DHSINGLEPASS_COFACTORDH_SHA384KDF_SCHEME = NID_dhSinglePass_cofactorDH_sha384kdf_scheme,
    DHSINGLEPASS_COFACTORDH_SHA512KDF_SCHEME = NID_dhSinglePass_cofactorDH_sha512kdf_scheme,
    DH_STD_KDF = NID_dh_std_kdf,
    DH_COFACTOR_KDF = NID_dh_cofactor_kdf,
    CT_PRECERT_SCTS = NID_ct_precert_scts,
    CT_PRECERT_POISON = NID_ct_precert_poison,
    CT_PRECERT_SIGNER = NID_ct_precert_signer,
    CT_CERT_SCTS = NID_ct_cert_scts,
    JURISDICTIONLOCALITYNAME = NID_jurisdictionLocalityName,
    JURISDICTIONSTATEORPROVINCENAME = NID_jurisdictionStateOrProvinceName,
    JURISDICTIONCOUNTRYNAME = NID_jurisdictionCountryName,
    ID_SCRYPT = NID_id_scrypt,
    TLS1_PRF = NID_tls1_prf,
    HKDF = NID_hkdf,
    ID_PKINIT = NID_id_pkinit,
    PKINITCLIENTAUTH = NID_pkInitClientAuth,
    PKINITKDC = NID_pkInitKDC,
    X25519 = NID_X25519,
    X448 = NID_X448,
    KX_RSA = NID_kx_rsa,
    KX_ECDHE = NID_kx_ecdhe,
    KX_DHE = NID_kx_dhe,
    KX_ECDHE_PSK = NID_kx_ecdhe_psk,
    KX_DHE_PSK = NID_kx_dhe_psk,
    KX_RSA_PSK = NID_kx_rsa_psk,
    KX_PSK = NID_kx_psk,
    KX_SRP = NID_kx_srp,
    KX_GOST = NID_kx_gost,
    AUTH_RSA = NID_auth_rsa,
    AUTH_ECDSA = NID_auth_ecdsa,
    AUTH_PSK = NID_auth_psk,
    AUTH_DSS = NID_auth_dss,
    AUTH_GOST01 = NID_auth_gost01,
    AUTH_GOST12 = NID_auth_gost12,
    AUTH_SRP = NID_auth_srp,
    AUTH_NULL = NID_auth_null
  };

  SO_API Result<ASN1_OBJECT_uptr> convertToObject(Nid nid);
  SO_API Result<ASN1_OBJECT_uptr> convertToObject(int rawNid);

  SO_API Result<std::string> getLongName(Nid nid);
  SO_API Result<std::string> getLongName(int rawNid);

  SO_API Result<std::string> getShortName(Nid nid);
  SO_API Result<std::string> getShortName(int rawNid);

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

  SO_API RSA_uptr create(); 
  SO_API Result<RSA_uptr> create(KeyBits keySize, Exponent exponent = Exponent::_65537_);

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

  enum class CrlExtensionId : int
  {
    // as of https://www.openssl.org/docs/man1.1.0/crypto/X509_REVOKED_add1_ext_i2d.html
    
    UNDEF                       = NID_undef, 
    CRL_NUMBER                  = NID_crl_number,
    CRL_DISTRIBUTION_POINTS     = NID_crl_distribution_points,
    DELTA_CRL_INDICATOR         = NID_delta_crl,
    FRESHEST_CRL                = NID_freshest_crl,
    INVALIDITY_DATE             = NID_invalidity_date,
    ISSUING_DISTRIBUTION_POINT  = NID_issuing_distribution_point
  };

  enum class CrlEntryExtensionId : int
  {
    // as of https://www.openssl.org/docs/man1.1.0/crypto/X509_REVOKED_add1_ext_i2d.html
    
    UNDEF                       = NID_undef,
    REASON                      = NID_crl_reason,
    CERTIFICATE_ISSUER          = NID_certificate_issuer
  };

  using CertExtension = internal::X509Extension<CertExtensionId>;
  using CrlExtension = internal::X509Extension<CrlExtensionId>;
  using CrlEntryExtension = internal::X509Extension<CrlEntryExtensionId>;
  using Issuer = internal::X509Name;
  using Subject = internal::X509Name;

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

  struct Revoked
  {
    std::string dateISO860;
    std::time_t date;
    Bytes serialNumAsn1;
    std::vector<CrlEntryExtension> extensions;
  };

  //---- Cerificates----------
  //----------------------------------------------------------------------------------------------
  SO_API X509_uptr create();

  SO_API Result<X509_uptr> convertPemToX509(const std::string &pemCert);
  SO_API Result<std::string> convertX509ToPem(X509 &cert);
  SO_API Result<X509_uptr> convertPemFileToX509(const std::string &pemFilePath);

  SO_API Result<ecdsa::Signature> getEcdsaSignature(const X509 &cert);
  SO_API Result<CertExtension> getExtension(const X509 &cert, CertExtensionId getExtensionId);
  SO_API Result<CertExtension> getExtension(const X509 &cert, const std::string &oidNumerical);
  SO_API Result<std::vector<CertExtension>> getExtensions(const X509 &cert);
  SO_API Result<size_t> getExtensionsCount(const X509 &cert);
  SO_API Result<Issuer> getIssuer(const X509 &cert);
  SO_API Result<std::string> getIssuerString(const X509 &cert); 
  SO_API Result<EVP_PKEY_uptr> getPubKey(X509 &cert);
  SO_API nid::Nid getPubKeyAlgorithm(X509 &cert);
  SO_API Result<Bytes> getSerialNumber(X509 &cert);
  SO_API Result<Bytes> getSignature(const X509 &cert);
  SO_API nid::Nid getSignatureAlgorithm(const X509 &cert);
  SO_API Result<Subject> getSubject(const X509 &cert);
  SO_API Result<std::string> getSubjectString(const X509 &cert);
  SO_API Result<Validity> getValidity(const X509 &cert);
  SO_API std::tuple<Version,long> getVersion(const X509 &cert);
  
  SO_API bool isCa(X509 &cert);
  SO_API bool isSelfSigned(X509 &cert);

  SO_API Result<void> setCustomExtension(X509 &cert, const std::string &oidNumerical, ASN1_OCTET_STRING &octet, bool critical = false);
  SO_API Result<void> setExtension(X509 &cert, CertExtensionId id, ASN1_OCTET_STRING &octet, bool critical = false);
  SO_API Result<void> setExtension(X509 &cert, nid::Nid nid, ASN1_OCTET_STRING &octet, bool critical = false);
  SO_API Result<void> setExtension(X509 &cert, const CertExtension &extension); 
  SO_API Result<void> setIssuer(X509 &cert, const X509 &rootCert);
  SO_API Result<void> setIssuer(X509 &cert, const Issuer &issuer);
  SO_API Result<void> setPubKey(X509 &cert, EVP_PKEY &pkey);
  SO_API Result<void> setSerial(X509 &cert, const Bytes &bytes);
  SO_API Result<void> setSubject(X509 &cert, const Subject &subject);
  SO_API Result<void> setValidity(X509 &cert, const Validity &validity);
  SO_API Result<void> setVersion(X509 &cert, Version version);
  SO_API Result<void> setVersion(X509 &cert, long version);
  
  SO_API Result<size_t> signSha1(X509 &cert, EVP_PKEY &pkey);
  SO_API Result<size_t> signSha256(X509 &cert, EVP_PKEY &pkey);
  SO_API Result<size_t> signSha384(X509 &cert, EVP_PKEY &pkey); 
  SO_API Result<size_t> signSha512(X509 &cert, EVP_PKEY &pkey);  
  
  SO_API Result<bool> verifySignature(X509 &cert, EVP_PKEY &pkey);

  
  //---- Revocation ----------
  //---------------------------------------------------------------------------------------------- 
  SO_API X509_CRL_uptr createCrl();

  SO_API Result<X509_CRL_uptr> convertPemToCRL(const std::string &pemCrl);
  SO_API Result<std::string> convertCrlToPem(X509_CRL &crl);
  SO_API Result<X509_CRL_uptr> convertPemFileToCRL(const std::string &pemCrlFile);

  SO_API Result<ecdsa::Signature> getEcdsaSignature(X509_CRL &crl);
  SO_API Result<std::vector<CrlExtension>> getExtensions(X509_CRL &crl);
  SO_API Result<size_t> getExtensionsCount(X509_CRL &crl);
  SO_API Result<Issuer> getIssuer(X509_CRL &crl);
  SO_API Result<std::string> getIssuerString(X509_CRL &crl);
  SO_API size_t getRevokedCount(X509_CRL &crl);
  SO_API Result<std::vector<Revoked>> getRevoked(X509_CRL &crl);
  SO_API Result<Bytes> getSignature(const X509_CRL &crl);
  SO_API nid::Nid getSignatureAlgorithm(const X509_CRL &crl);
  SO_API std::tuple<Version, long> getVersion(X509_CRL &crl);
 
} // namespace x509


/////////////////////////////////////////////////////////////////////////////////
//
//                Implementation
//
/////////////////////////////////////////////////////////////////////////////////

namespace internal {
  inline bool X509Name::operator ==(const X509Name &other) const
  {
    return commonName == other.commonName
      && surname == other.surname
      && countryName == other.countryName
      && localityName == other.localityName
      && stateOrProvinceName == other.stateOrProvinceName
      && organizationName == other.organizationName
      && organizationalUnitName == other.organizationalUnitName
      && title == other.title
      && name == other.name
      && givenName == other.givenName
      && initials == other.initials
      && generationQualifier == other.generationQualifier
      && dnQualifier == other.dnQualifier;
  }

  inline bool X509Name::operator !=(const X509Name &other) const
  {
    return !(*this == other);
  }

  SO_PRV std::string errCodeToString(unsigned long errCode)
  {
    static constexpr size_t SIZE = 1024;
    char buff[SIZE];
    std::memset(buff, 0x00, SIZE);
    ERR_error_string_n(errCode, buff, SIZE);
    return std::string(buff);
  }
} // namespace internal


template<typename T>
inline Result<T>::operator bool() const noexcept
{
  return hasValue(); 
}

template<typename T>
inline T&& Result<T>::moveValue()
{
  return std::move(value);
}

template<typename T>
inline bool Result<T>::hasValue() const noexcept
{ 
  return !hasError(); 
}

template<typename T>
inline bool Result<T>::hasError() const noexcept
{
  return internal::OSSL_NO_ERR_CODE != opensslErrCode;
}

template<typename T>
inline std::string Result<T>::msg() const
{
  if(hasValue())
    return "ok";

  return internal::errCodeToString(opensslErrCode); 
}
  
inline Result<void>::operator bool() const noexcept
{
  return !hasError();
}

inline bool Result<void>::hasError() const noexcept
{
  return internal::OSSL_NO_ERR_CODE != opensslErrCode;
}

inline std::string Result<void>::msg() const
{
  if(!hasError())
    return "ok";

  return internal::errCodeToString(opensslErrCode); 
}

namespace internal {
  template<typename ID>
  struct X509Extension
  {
    ID id;
    bool critical;
    std::string name;
    std::string oidNumerical;
    Bytes data;
  
    inline nid::Nid nid() const { return static_cast<nid::Nid>(id); }
    inline int nidRaw() const { return static_cast<int>(nid()); }

    inline bool operator==(const X509Extension<ID> &other) const
    {
      return std::tie(id, critical, name, oidNumerical, data)
          == std::tie(other.id, other.critical, other.name, other.oidNumerical, other.data);
    }

    inline bool operator!=(const X509Extension<ID> &other) const
    {
      return !(*this == other);
    }
  };

  template<typename T>
  struct uptr_underlying_type
  {
    using type = typename std::remove_pointer<decltype(std::declval<T>().get())>::type;
  };

  template<typename T>
  SO_PRV Result<T> err(T &&val)
  {
    return Result<T>{ std::move(val), ERR_get_error() };
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

  template
  <
    typename T,
    typename std::enable_if<!std::is_same<T, void>::value, int>::type = 0
  >
  SO_PRV Result<T> err(unsigned long errCode)
  { 
    return Result<T>{ T{}, errCode };
  }

  template<typename T>
  SO_PRV Result<T> ok(T &&val)
  {
    return Result<T>{ std::move(val), internal::OSSL_NO_ERR_CODE };
  }

  SO_PRV Result<void> err()
  {
    return Result<void>{ ERR_get_error() };
  }

  SO_PRV Result<void> err(unsigned long errCode)
  {
    return Result<void>{ errCode };
  }

  SO_PRV Result<void> ok()
  {
    return Result<void>{ internal::OSSL_NO_ERR_CODE };
  }

  /*
  template<typename EnumType, EnumType... Values> struct EnumCheck;

  template<typename EnumType>
  struct EnumCheck<EnumType>
  {
    template<typename IntType>
    static bool constexpr isValue(IntType) { return false; }
  };

  template<typename EnumType, EnumType V, EnumType... Next>
  struct EnumCheck<EnumType, V, Next...> : private EnumCheck<EnumType, Next...>
  {
    private:
      using super = EnumCheck<EnumType, Next...>;

    public:
      template<typename IntType>
      static bool constexpr is_value(IntType v)
      {
          return v == static_cast<IntType>(V) || super::is_value(v);
      }
  };

  // TODO: Recursive template instantiation exceeded maximum depth of 1024, need to figure out better solution.

  using NidEnumTest = EnumCheck<nid::Nid,nid::Nid::UNDEF,nid::Nid::ITU_T,nid::Nid::CCITT,nid::Nid::ISO, ...... nid::Nid::AUTH_NULL>;
 */

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

  SO_PRV Result<internal::X509Name> commonInfo(X509_NAME &name)
  {
    const auto error = [](unsigned long errCode){ return internal::err<internal::X509Name>(errCode); }; 
    const auto commonName = nameEntry2String(name, NID_commonName);
    if(!commonName)
      return error(commonName.opensslErrCode);

    const auto surname = nameEntry2String(name, NID_surname);
    if(!surname)
      return error(surname.opensslErrCode);
      
    const auto countryName = nameEntry2String(name, NID_countryName);
    if(!countryName)
      return error(countryName.opensslErrCode);

    const auto localityName = nameEntry2String(name, NID_localityName);
    if(!localityName)
      return error(localityName.opensslErrCode);

    const auto stateOrProvinceName = nameEntry2String(name, NID_stateOrProvinceName);
    if(!stateOrProvinceName)
      return error(stateOrProvinceName.opensslErrCode);

    const auto organizationName = nameEntry2String(name, NID_organizationName);
    if(!organizationName)
      return error(organizationName.opensslErrCode);

    const auto organizationalUnitName = nameEntry2String(name, NID_organizationalUnitName);
    if(!organizationalUnitName)
      return error(organizationalUnitName.opensslErrCode);
 
    const auto title = nameEntry2String(name, NID_title);
    if(!title)
      return error(title.opensslErrCode);

    const auto nameE = nameEntry2String(name, NID_name);
    if(!nameE)
      return error(nameE.opensslErrCode);

    const auto givenName = nameEntry2String(name, NID_givenName);
    if(!givenName)
      return error(givenName.opensslErrCode);

    const auto initials = nameEntry2String(name, NID_initials);
    if(!initials)
      return error(initials.opensslErrCode);

    const auto generationQualifier = nameEntry2String(name, NID_generationQualifier);
    if(!generationQualifier)
      return error(generationQualifier.opensslErrCode);

    const auto dnQualifier = nameEntry2String(name, NID_dnQualifier);
    if(!dnQualifier)
      return error(dnQualifier.opensslErrCode);

    return internal::ok<internal::X509Name>({ 
        commonName.value,
        surname.value,
        countryName.value,
        localityName.value,
        stateOrProvinceName.value,
        organizationName.value,
        organizationalUnitName.value,
        title.value,
        nameE.value,
        givenName.value,
        initials.value,
        generationQualifier.value,
        dnQualifier.value
    });
  }

  SO_PRV Result<X509_NAME_uptr> infoToX509Name(const internal::X509Name &info)
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

    if(!append(name.get(), NID_surname, info.surname))
      return err();

    if(!append(name.get(), NID_countryName, info.countryName))
      return err();

    if(!append(name.get(), NID_localityName, info.localityName))
      return err();

    if(!append(name.get(), NID_stateOrProvinceName, info.stateOrProvinceName))
      return err();

    if(!append(name.get(), NID_organizationName, info.organizationName))
      return err();

     if(!append(name.get(), NID_organizationalUnitName, info.organizationalUnitName))
      return err();

    if(!append(name.get(), NID_title, info.title))
      return err();

    if(!append(name.get(), NID_name, info.name))
      return err();

    if(!append(name.get(), NID_givenName, info.givenName))
      return err();

    if(!append(name.get(), NID_initials, info.initials))
      return err();

    if(!append(name.get(), NID_generationQualifier, info.generationQualifier))
      return err();

    if(!append(name.get(), NID_dnQualifier, info.dnQualifier))
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
    auto oidStr = asn1::convertObjToStr(*asn1Obj, asn1::Form::NUMERICAL);
    if(!oidStr)
      return internal::err<RetType>(oidStr.opensslErrCode);
 
    if(nid == NID_undef)
    {
      // most likely custom extension
      const auto val = X509_EXTENSION_get_data(&ex);

      Bytes data;
      data.reserve(static_cast<size_t>(val->length));
      std::copy_n(val->data, val->length, std::back_inserter(data));
       
      return internal::ok(RetType {
            static_cast<ID>(nid),
            static_cast<bool>(critical),
            "",
            oidStr.moveValue(),
            std::move(data)
      });
    }
   
    auto bio = make_unique(BIO_new(BIO_s_mem()));
    if(!X509V3_EXT_print(bio.get(), &ex, 0, 0))
    {
      const auto val = X509_EXTENSION_get_data(&ex);

      Bytes data;
      data.reserve(static_cast<size_t>(val->length));
      std::copy_n(val->data, val->length, std::back_inserter(data));

      return internal::ok(RetType{
        static_cast<ID>(nid),
        static_cast<bool>(critical),
        std::string(OBJ_nid2ln(nid)),
        oidStr.moveValue(),
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
        oidStr.moveValue(),
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
    auto bioRaw = make_unique(BIO_new_file(path.c_str(), "rb"));
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
    auto bio = make_unique(BIO_push(mdtmp, bioRaw.release()));
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
  SO_PRV Result<std::string> convertToPem(FUNC writeToBio, Types&& ...args)
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
  SO_PRV Result<Key> convertPemToKey(const std::string &pem, FUNC readBio, Types&& ...args)
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

  SO_PRV x509::Revoked getRevoked(STACK_OF(X509_REVOKED) *revStack, int index)
  {
    // TODO:
    // I should do proper error handling heere and get rid off
    // std::generate_n in calling function.
    // However I should not block user from setting garbage in his CRL
    const X509_REVOKED *revoked = sk_X509_REVOKED_value(revStack, index);
    if(!revoked)
      return {};

    const ASN1_INTEGER *serial = X509_REVOKED_get0_serialNumber(revoked);
    const ASN1_TIME *time = X509_REVOKED_get0_revocationDate(revoked);
    if(!serial || !time)
      return {};

    std::vector<x509::CrlEntryExtension> retExtensions;
    {
      const STACK_OF(X509_EXTENSION) *exts = X509_REVOKED_get0_extensions(revoked);
      if(exts)
      {
        const int count = sk_X509_EXTENSION_num(exts);
        retExtensions.reserve(static_cast<size_t>(count));
        for(int i = 0; i < count; ++i)
        {
          auto getExtension = internal::getExtension<x509::CrlEntryExtensionId>(*X509_REVOKED_get_ext(revoked, i));
          if(getExtension)
            retExtensions.push_back(getExtension.value);
        }
      }
    }

    const auto timeStr = asn1::convertToISO8601(*time);
    const auto date = asn1::convertToStdTime(*time);

    Bytes retSerial;
    retSerial.reserve(static_cast<size_t>(serial->length));
    std::copy_n(serial->data, serial->length, std::back_inserter(retSerial));

    return x509::Revoked{
      (timeStr ? timeStr.value : ""),
      (date ? date.value : std::time_t{}),
      std::move(retSerial),
      std::move(retExtensions)
    };
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
 
  SO_API Result<std::string> convertToISO8601(const ASN1_TIME &asnTime)
  {
    constexpr size_t size = 256; 
    auto bio = make_unique(BIO_new(BIO_s_mem()));
    if(0 >= ASN1_TIME_print(bio.get(), &asnTime))
      return internal::err<std::string>(); 

    char buff[size];
    BIO_gets(bio.get(), buff, size);

    return internal::ok(std::string(buff));
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
    return encodeOctet(bytes::fromString(str));
  } 
} // namespace asn1

namespace bignum {
  SO_API BIGNUM_uptr create()
  {
    return make_unique(BN_new());
  }

  SO_API Result<Bytes> convertToBytes(const BIGNUM &bn)
  {
    const auto sz = getByteLen(bn);
    if(!sz)
      return internal::err<Bytes>(sz.opensslErrCode);

    Bytes ret(sz.value);
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

namespace bytes {
  SO_API std::string toString(const Bytes &bt)
  {
    std::ostringstream ss;
    std::copy(bt.begin(), bt.end(), std::ostream_iterator<char>(ss, ""));
    return ss.str();
  }

  SO_API std::string toString(const Bytes &bt, const Bytes::const_iterator &start)
  {
    std::ostringstream ss;
    std::copy(start, bt.end(), std::ostream_iterator<char>(ss, ""));
    return ss.str();
  }

  SO_API Bytes fromString(const std::string &str)
  {
    so::Bytes ret;
    ret.reserve(str.size());
    std::transform(str.begin(), str.end(), std::back_inserter(ret), [](char chr){
        return static_cast<uint8_t>(chr);
    });

    return ret;
  }

} // namespace bytes

namespace ecdsa {
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
      return internal::err<std::string>(check.opensslErrCode);
  
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
      return internal::err<Bytes>(check.opensslErrCode);

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
      return internal::err<Bytes>(maybeR.opensslErrCode);

    auto maybeS = bignum::convertToBignum(signature.s);
    if(!maybeS)
      return internal::err<Bytes>(maybeS.opensslErrCode);
 
    auto sig = make_unique(ECDSA_SIG_new()); 
    if(!sig)
      return internal::err<Bytes>();

    auto r = maybeR.moveValue();
    auto s = maybeS.moveValue();
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
  
  SO_API Result<std::string> convertCurveToString(Curve curve)
  {
    return nid::getLongName(static_cast<int>(curve));
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

  SO_API Result<size_t> getKeySize(const EC_KEY &key)
  {
    const EC_GROUP *group = EC_KEY_get0_group(&key);
    if(!group)
      return internal::err<size_t>();

    const int size = EC_GROUP_get_degree(group);
    return internal::ok(static_cast<size_t>(size));
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

  SO_API EC_KEY_uptr create()
  {
    return make_unique(EC_KEY_new());
  }

  SO_API Result<EC_KEY_uptr> create(Curve curve)
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

    return internal::ecdsaSign(digest.value, key);
  }

  SO_API Result<Bytes> signSha224(const Bytes &message, EC_KEY &key)
  {
    const auto digest = hash::sha224(message);
    if(!digest)
      return digest; 

    return internal::ecdsaSign(digest.value, key);
  }

  SO_API Result<Bytes> signSha256(const Bytes &message, EC_KEY &key)
  {
    const auto digest = hash::sha256(message);
    if(!digest)
      return digest; 

    return internal::ecdsaSign(digest.value, key);
  }

  SO_API Result<Bytes> signSha384(const Bytes &message, EC_KEY &key)
  {
    const auto digest = hash::sha384(message);
    if(!digest)
      return digest;

    return internal::ecdsaSign(digest.value, key);
  }
  
  SO_API Result<Bytes> signSha512(const Bytes &message, EC_KEY &key)
  {
    const auto digest = hash::sha512(message);
    if(!digest)
      return digest;

    return internal::ecdsaSign(digest.value, key);
  }

  SO_API Result<bool> verifySha1Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey)
  {
    const auto digest = hash::sha1(message);
    if(!digest)
      return internal::err<bool>(digest.opensslErrCode);

    return internal::ecdsaVerify(signature, digest.value, publicKey);
  }

  SO_API Result<bool> verifySha224Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey)
  {
    const auto digest = hash::sha224(message);
    if(!digest)
      return internal::err<bool>(digest.opensslErrCode);

    return internal::ecdsaVerify(signature, digest.value, publicKey);
  }

  SO_API Result<bool> verifySha256Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey)
  {
    const auto digest = hash::sha256(message);
    if(!digest)
      return internal::err<bool>(digest.opensslErrCode);

    return internal::ecdsaVerify(signature, digest.value, publicKey);
  }

  SO_API Result<bool> verifySha384Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey)
  {
    const auto digest = hash::sha384(message);
    if(!digest)
      return internal::err<bool>(digest.opensslErrCode);

    return internal::ecdsaVerify(signature, digest.value, publicKey);
  }

  SO_API Result<bool> verifySha512Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey)
  {
    const auto digest = hash::sha512(message);
    if(!digest)
      return internal::err<bool>(digest.opensslErrCode);

    return internal::ecdsaVerify(signature, digest.value, publicKey);
  }
} //namespace ecdsa

namespace evp {
  SO_API EVP_PKEY_uptr create()
  {
    return make_unique(EVP_PKEY_new());
  }

  SO_API Result<void> assign(EVP_PKEY &evp, RSA &rsa)
  {
    if (1 != EVP_PKEY_assign_RSA(&evp, &rsa))
        return internal::err();
    
    return internal::ok();
  }
  
  SO_API Result<void> assign(EVP_PKEY &evp, EC_KEY &ec)
  {
    if (1 != EVP_PKEY_assign_EC_KEY(&evp, &ec))
        return internal::err();
    
    return internal::ok();
  }

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

  SO_API std::string convertPubkeyTypeToString(KeyType pubKeyType)
  {
    return nid::getLongName(static_cast<int>(pubKeyType)).value;
  }

  SO_API Result<EC_KEY_uptr> convertToEcdsa(EVP_PKEY &key)
  {
    auto *ec = EVP_PKEY_get1_EC_KEY(&key);
    if(!ec)
      return internal::err<EC_KEY_uptr>();

    return internal::ok(make_unique(ec));
  }

  SO_API Result<RSA_uptr> convertToRsa(EVP_PKEY &key)
  {
    auto *rsa = EVP_PKEY_get1_RSA(&key);
    if(!rsa)
      return internal::err<RSA_uptr>();

    return internal::ok(make_unique(rsa));
  }

  SO_API KeyType getKeyType(const EVP_PKEY &pubkey)
  {
    return static_cast<KeyType>(EVP_PKEY_base_id(&pubkey));
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
   SO_API Result<ASN1_OBJECT_uptr> convertToObject(Nid nid)
  {
    auto ret = make_unique(OBJ_nid2obj(static_cast<int>(nid)));
    if(!ret)
      return internal::err<ASN1_OBJECT_uptr>();

    return internal::ok(std::move(ret));
  }

  SO_API Result<ASN1_OBJECT_uptr> convertToObject(int rawNid)
  {
    auto ret = make_unique(OBJ_nid2obj(rawNid));
    if(!ret)
      return internal::err<ASN1_OBJECT_uptr>();

    return internal::ok(std::move(ret));
  }

  SO_API Result<std::string> getLongName(Nid nid)
  {
    const char *str = OBJ_nid2ln(static_cast<int>(nid));
    if(!str)
      return internal::err<std::string>();

    return internal::ok<std::string>(str);
  }

  SO_API Result<std::string> getLongName(int rawNid)
  {
    const char *str = OBJ_nid2ln(rawNid);
    if(!str)
      return internal::err<std::string>();

    return internal::ok<std::string>(str);
  }

  SO_API Result<std::string> getShortName(Nid nid)
  {
    const char *str = OBJ_nid2sn(static_cast<int>(nid));
    if(!str)
      return internal::err<std::string>();

    return internal::ok<std::string>(str);
  }

  SO_API Result<std::string> getShortName(int rawNid)
  {
    const char *str = OBJ_nid2sn(rawNid);
    if(!str)
      return internal::err<std::string>();

    return internal::ok<std::string>(str);
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
      return internal::err<std::string>(check.opensslErrCode);
  
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
      return internal::err<Bytes>(check.opensslErrCode);

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

  SO_API RSA_uptr create()
  {
    return make_unique(RSA_new());
  }

  SO_API Result<RSA_uptr> create(KeyBits keySize, Exponent exponent)
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
      return internal::err<KeyBits>(pub.opensslErrCode);

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

    return internal::rsaSign(NID_sha1, digest.value, privKey); 
  }

  SO_API Result<Bytes> signSha224(const Bytes &msg, RSA &privKey)
  {
    const auto digest = hash::sha224(msg);
    if(!digest)
      return digest;

    return internal::rsaSign(NID_sha224, digest.value, privKey); 
  }

  SO_API Result<Bytes> signSha256(const Bytes &msg, RSA &privKey)
  {
    const auto digest = hash::sha256(msg);
    if(!digest)
      return digest;

    return internal::rsaSign(NID_sha256, digest.value, privKey); 
  }

  SO_API Result<Bytes> signSha384(const Bytes &msg, RSA &privKey)
  {
    const auto digest = hash::sha384(msg);
    if(!digest)
      return digest;

    return internal::rsaSign(NID_sha384, digest.value, privKey); 
  }
  
  SO_API Result<Bytes> signSha512(const Bytes &msg, RSA &privKey)
  {
    const auto digest = hash::sha512(msg);
    if(!digest)
      return digest;

    return internal::rsaSign(NID_sha512, digest.value, privKey); 
  }
  
  SO_API Result<bool> verifySha1Signature(const Bytes &signature, const Bytes &message, RSA &pubKey)
  {
    const auto digest = hash::sha1(message);
    if(!digest)
      return internal::err<bool>(digest.opensslErrCode);

    return internal::rsaVerify(NID_sha1, signature, digest.value, pubKey); 
  }
  
  SO_API Result<bool> verifySha224Signature(const Bytes &signature, const Bytes &message, RSA &pubKey)
  {
    const auto digest = hash::sha224(message);
    if(!digest)
      return internal::err<bool>(digest.opensslErrCode);

    return internal::rsaVerify(NID_sha224, signature, digest.value, pubKey); 
  }

  SO_API Result<bool> verifySha256Signature(const Bytes &signature, const Bytes &message, RSA &pubKey)
  {
    const auto digest = hash::sha256(message);
    if(!digest)
      return internal::err<bool>(digest.opensslErrCode);

    return internal::rsaVerify(NID_sha256, signature, digest.value, pubKey); 
  }

  SO_API Result<bool> verifySha384Signature(const Bytes &signature, const Bytes &message, RSA &pubKey)
  {
    const auto digest = hash::sha384(message);
    if(!digest)
      return internal::err<bool>(digest.opensslErrCode);

    return internal::rsaVerify(NID_sha384, signature, digest.value, pubKey); 
  }

  SO_API Result<bool> verifySha512Signature(const Bytes &signature, const Bytes &message, RSA &pubKey)
  {
    const auto digest = hash::sha512(message);
    if(!digest)
      return internal::err<bool>(digest.opensslErrCode);

    return internal::rsaVerify(NID_sha512, signature, digest.value, pubKey); 
  }
} // namespace rsa

namespace x509 { 
  inline bool Validity::operator==(const Validity &other) const
  {
    return std::tie(notBefore, notAfter) == std::tie(other.notBefore, other.notAfter);
  }
  
  inline bool Validity::operator!=(const Validity &other) const
  {
    return !(*this == other);
  }

  SO_API Result<Issuer> getIssuer(const X509 &cert)
  {
    // this is internal ptr and must not be freed
    X509_NAME *getIssuer = X509_get_issuer_name(&cert);
    if(!getIssuer)
      return internal::err<Issuer>();

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

  SO_API X509_uptr create()
  {
    return make_unique(X509_new());
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

  SO_API Result<std::string> convertX509ToPem(X509 &cert)
  {
    return internal::convertToPem(PEM_write_bio_X509, &cert); 
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

  SO_API nid::Nid getPubKeyAlgorithm(X509 &cert)
  {
    auto *pkey = X509_get0_pubkey(&cert);
    if(!pkey)
      return nid::Nid::UNDEF;

    return static_cast<nid::Nid>(EVP_PKEY_base_id(pkey)); 
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
  
  SO_API nid::Nid getSignatureAlgorithm(const X509 &cert)
  {
    return static_cast<nid::Nid>(X509_get_signature_nid(&cert)); 
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
    return internal::ok(ecdsa::Signature{ bignum::convertToBytes(*r).value, bignum::convertToBytes(*s).value });
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
      return internal::err<CertExtension>(maybeObj.opensslErrCode);

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
      return internal::err<RetType>(extsCount.opensslErrCode);

    if(0 == extsCount.value)
      return internal::ok(RetType{});

    RetType ret;
    ret.reserve(extsCount.value); 
    for(int index = 0; index < static_cast<int>(extsCount.value); ++index)
    {
      auto getExtension = internal::getExtension<CertExtensionId>(*X509_get_ext(&cert, index));
      if(!getExtension)
        return internal::err<RetType>(getExtension.opensslErrCode);

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

  SO_API Result<Subject> getSubject(const X509 &cert)
  {
    // this is internal ptr and must not be freed
    X509_NAME *subject = X509_get_subject_name(&cert);
    if(!subject)
      return internal::err<Subject>();

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
      return internal::err<Validity>(notBeforeTime.opensslErrCode);

    auto notAfterTime = asn1::convertToStdTime(*notAfter);
    if(!notAfterTime)
      return internal::err<Validity>(notAfterTime.opensslErrCode);

    return internal::ok(Validity{notAfterTime.value, notBeforeTime.value});
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
      return internal::err(maybeAsn1Oid.opensslErrCode);

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
    return setExtension(cert, static_cast<nid::Nid>(id), octet, critical); 
  }

  SO_API Result<void> setExtension(X509 &cert, nid::Nid nid, ASN1_OCTET_STRING &octet, bool critical)
  {
    auto oid = make_unique(OBJ_nid2obj(static_cast<int>(nid)));
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
      return internal::err(maybeData.opensslErrCode);

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

  SO_API Result<void> setIssuer(X509 &cert, const Issuer &info)
  {
    auto maybeIssuer = internal::infoToX509Name(info);
    if(!maybeIssuer)
      return internal::err(maybeIssuer.opensslErrCode);

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
      return internal::err(maybeInt.opensslErrCode);

    auto integer = maybeInt.moveValue();
    if(1 != X509_set_serialNumber(&cert, integer.get()))
      return internal::err();

    return internal::ok();
  }

  SO_API Result<void> setSubject(X509 &cert, const Subject &info)
  {
    auto maybeSubject = internal::infoToX509Name(info); 
    if(!maybeSubject)
      return internal::err(maybeSubject.opensslErrCode);

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

  SO_API X509_CRL_uptr createCrl()
  {
    return make_unique(X509_CRL_new());
  }

  SO_API Result<X509_CRL_uptr> convertPemToCRL(const std::string &pemCrl)
  {
    BIO_uptr bio = make_unique(BIO_new(BIO_s_mem()));

    if(0 >= BIO_write(bio.get(), pemCrl.c_str(), static_cast<int>(pemCrl.length())))
      return internal::err<X509_CRL_uptr>(); 

    auto ret = make_unique(PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr));
    if(!ret)
      return internal::err<X509_CRL_uptr>();

    return internal::ok(std::move(ret));
  }
 
  SO_API Result<X509_CRL_uptr> convertPemFileToCRL(const std::string &pemCrl)
  {
    BIO_uptr bio = make_unique(BIO_new(BIO_s_file()));

    // I'd rather do copy here than drop const in argument or use
    // const_cast in BIO_read_filename
    std::vector<char> fn;
    fn.reserve(pemCrl.size() + 1);
    std::copy_n(pemCrl.begin(), pemCrl.size(), std::back_inserter(fn));
    fn.push_back('\0');

    if(0 >= BIO_read_filename(bio.get(), fn.data()))
      return internal::err<X509_CRL_uptr>(); 

    auto ret = make_unique(PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr));
    if(!ret)
      return internal::err<X509_CRL_uptr>();

    return internal::ok(std::move(ret));
  }

  SO_API Result<std::string> convertCrlToPem(X509_CRL &crl)
  {
    return internal::convertToPem(PEM_write_bio_X509_CRL, &crl); 
  }

  SO_API Result<ecdsa::Signature> getEcdsaSignature(X509_CRL &crl)
  {
    // both internal pointers and must not be freed
    const ASN1_BIT_STRING *psig = nullptr;
    const X509_ALGOR *palg = nullptr;
    X509_CRL_get0_signature(&crl, &psig, &palg);
    if(!palg || !psig)
      return internal::err<ecdsa::Signature>();

    const unsigned char *it = psig->data;
    const auto sig = make_unique(d2i_ECDSA_SIG(nullptr, &it, static_cast<long>(psig->length)));
    if(!sig)
      return internal::err<ecdsa::Signature>();

    // internal pointers
    const BIGNUM *r,*s;
    ECDSA_SIG_get0(sig.get(), &r, &s);
    return internal::ok(ecdsa::Signature{ bignum::convertToBytes(*r).value, bignum::convertToBytes(*s).value });
  }
  
  SO_API Result<std::vector<CrlExtension>> getExtensions(X509_CRL &crl)
  {
    using RetType = std::vector<CrlExtension>;
    const auto extsCount = getExtensionsCount(crl);
    if(!extsCount)
      return internal::err<RetType>(extsCount.opensslErrCode);

    if(0 == extsCount.value)
      return internal::ok(RetType{});

    RetType ret;
    ret.reserve(extsCount.value); 
    for(int index = 0; index < static_cast<int>(extsCount.value); ++index)
    {
      auto getExtension = internal::getExtension<CrlExtensionId>(*X509_CRL_get_ext(&crl, index));
      if(!getExtension)
        return internal::err<RetType>(getExtension.opensslErrCode);

      ret.push_back(getExtension.moveValue());
    }

    return internal::ok(std::move(ret));
  }

  SO_API Result<size_t> getExtensionsCount(X509_CRL &crl)
  {
    const int extsCount = X509_CRL_get_ext_count(&crl);
    if(extsCount < 0)
      return internal::err<size_t>(); 

    return internal::ok(static_cast<size_t>(extsCount));
  }

  SO_API Result<Issuer> getIssuer(X509_CRL &crl)
  {
    // this is internal ptr and must not be freed
    X509_NAME *getIssuer = X509_CRL_get_issuer(&crl);
    if(!getIssuer)
      return internal::err<Issuer>();

    return internal::commonInfo(*getIssuer);
  }

  SO_API Result<std::string> getIssuerString(X509_CRL &crl)
  {
    // this is internal ptr and must not be freed
    X509_NAME *getIssuer = X509_CRL_get_issuer(&crl);
    if(!getIssuer)
      return internal::err<std::string>();

    return internal::nameToString(*getIssuer);
  }

  SO_API size_t getRevokedCount(X509_CRL &crl)
  {
    const int ct = sk_X509_REVOKED_num(X509_CRL_get_REVOKED(&crl));
    if(0 > ct) // crl stack is null which does not mean error
      return 0;

    return static_cast<size_t>(ct);
  }
  
  SO_API Result<std::vector<x509::Revoked>> getRevoked(X509_CRL &crl)
  {
    using RetType = std::vector<x509::Revoked>;
    const size_t sz = x509::getRevokedCount(crl);
    if(0 == sz)
      return internal::ok(RetType{});

    STACK_OF(X509_REVOKED) *revokedStack = X509_CRL_get_REVOKED(&crl);
    if(!revokedStack)
        return internal::err<RetType>();

    RetType ret(sz);
    int index = 0;
    std::generate_n(ret.begin(), sz, [&revokedStack, &index]{return internal::getRevoked(revokedStack, index++);});

    return internal::ok(std::move(ret));
  }
  
  SO_API Result<Bytes> getSignature(const X509_CRL &crl)
  {
    // both internal pointers and must not be freed
    const ASN1_BIT_STRING *psig = nullptr;
    const X509_ALGOR *palg = nullptr;
    X509_CRL_get0_signature(&crl, &psig, &palg);
    if(!palg || !psig)
      return internal::err<Bytes>();

    Bytes rawDerSequence(static_cast<size_t>(psig->length));
    std::memcpy(rawDerSequence.data(), psig->data, static_cast<size_t>(psig->length));

    return internal::ok(std::move(rawDerSequence));
  }
  
  SO_API nid::Nid getSignatureAlgorithm(const X509_CRL &crl)
  {
    return static_cast<nid::Nid>(X509_CRL_get_signature_nid(&crl)); 
  }

  SO_API std::tuple<Version, long> getVersion(X509_CRL &crl)
  {
    const long version = X509_CRL_get_version(&crl);
    if(3 <= version || -1 >= version)
      return std::make_tuple(Version::vx, version);

    return std::make_tuple(static_cast<Version>(version), version);
  }
} // namespace x509

} // namepsace so

#endif
