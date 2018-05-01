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
template<>                                                  \
struct detail::is_uptr<detail::CustomDeleterUniquePtr<Type>> : std::true_type {};

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

template<typename T>
class Expected
{
public:
  
  template
  <
    typename U = T,
    typename = typename std::enable_if<std::is_move_constructible<U>::value>::type
  >
  explicit Expected(T &&val)
    : m_value{std::move(val)}, m_opensslErrCode{1} {}

  template
  < 
    typename U = T,
    typename = typename std::enable_if<std::is_default_constructible<U>::value>::type
  >
  explicit Expected(unsigned long opensslErrorCode)
    : m_value {}, m_opensslErrCode{opensslErrorCode} {} 
 
  explicit Expected(unsigned long opensslErrorCode, T &&value)
    : m_value {std::move(value)}, m_opensslErrCode{opensslErrorCode} {}
     

  constexpr operator bool() const noexcept
  {
    return 1 == m_opensslErrCode;
  }

  constexpr const T& operator*() const
  {
    // technicaly we can return reference to unique_ptr, buuut c'mon...
    static_assert(!detail::is_uptr<T>::value, "so::Expected<>::operator*(): Attempt to return reference to unique_ptr.");
    return m_value;
  }

  constexpr T&& operator*()
  {
    return std::move(m_value);
  }

  bool hasValue() const
  {
    // a little lie here but most likely user will call this to check
    // if we have an error
    return 1 == m_opensslErrCode;
  }

  unsigned long errorCode() const
  {
    return m_opensslErrCode;
  }

  std::string msg() const
  {
    if(1 == m_opensslErrCode) return "OK";
    constexpr size_t SIZE = 1024;
    char buff[SIZE];
    std::memset(buff, 0x00, SIZE);
    ERR_error_string_n(m_opensslErrCode, buff, SIZE);
    return std::string(buff);
  }

private:
  T m_value;
  const unsigned long m_opensslErrCode;

};

SO_API void init();
SO_API void cleanUp();

namespace asn1 {
  SO_API Expected<std::time_t> time2StdTime(const ASN1_TIME &asn1Time);
} // namepsace asn1

namespace bignum {
  SO_API Expected<Bytes> bn2Bytes(const BIGNUM &bn);
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

  SO_API Expected<EC_KEY_uptr> copyKey(const EC_KEY &ecKey);
  SO_API Expected<Curve> curveOf(const EC_KEY &key);
  SO_API Expected<EVP_PKEY_uptr> key2Evp(const EC_KEY &key);
  SO_API Expected<EC_KEY_uptr> generateKey(Curve curve);
  SO_API Expected<EC_KEY_uptr> pem2PrivateKey(const std::string &pemPriv);
  SO_API Expected<EC_KEY_uptr> pem2PublicKey(const std::string &pemPub);
  SO_API Expected<Bytes> signSha256(const Bytes &message, EC_KEY &key);
  SO_API Expected<bool> verifySha256Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey);
} // namespace ecdsa

namespace evp {
  SO_API Expected<EVP_PKEY_uptr> pem2PrivateKey(const std::string &pemPriv);
  SO_API Expected<EVP_PKEY_uptr> pem2PublicKey(const std::string &pemPub);
  SO_API Expected<Bytes> signSha1(const Bytes &message, EVP_PKEY &privateKey);
  SO_API Expected<Bytes> signSha256(const Bytes &msg, EVP_PKEY &privKey);
  SO_API Expected<bool> verifySha1Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey);
  SO_API Expected<bool> verifySha256Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey);
} // namepsace evp

namespace hash {
  SO_API Expected<Bytes> md4(const Bytes &data);
  SO_API Expected<Bytes> md5(const Bytes &data);
  SO_API Expected<Bytes> sha1(const Bytes &data);
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
    std::string raw;
    std::string commonName;
    std::string countryName;
    std::string organizationName;
    std::string locationName;
    std::string stateName;

    inline bool operator ==(const Info &other) const;
    inline bool operator !=(const Info &other) const;
  };

  struct Validity
  {
    bool operator ==(const Validity &other) const;
    bool operator !=(const Validity &other) const;

    std::time_t notBefore;
    std::time_t notAfter;
  };

  SO_API Expected<Info> issuer(const X509 &x509);
  SO_API Expected<X509_uptr> pem2X509(const std::string &pemCert);
  SO_API Expected<Bytes> serialNumber(X509 &x509);
  SO_API Expected<Info> subject(const X509 &x509);
  SO_API Expected<long> version(const X509 &x509);
  SO_API Expected<Validity> validity(const X509 &x509);
} // namespace x509


/////////////////////////////////////////////////////////////////////////////////
//
//                Implementation
//
/////////////////////////////////////////////////////////////////////////////////

namespace detail {
  template<typename T>
  struct uptr_underlying_type
  {
    using type = typename std::remove_pointer<decltype(std::declval<T>().get())>::type;
  };

  template<typename T>
  SO_LIB Expected<T> err(T &&val)
  {
    return Expected<T>(ERR_peek_error(), std::move(val));
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
    typename U = T, // TODO: U is placeholder to avoid of reassining default template param, I should use some smarter solution
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
 
  template<typename T>
  SO_LIB Expected<T> ok(T &&val)
  {
    return Expected<T>(1, std::move(val));
  }
  
  SO_LIB Expected<Bytes> evpSign(const Bytes &message, const EVP_MD *evpMd,  EVP_PKEY &privateKey)
  {
    const auto error = [&] { return detail::err<Bytes>(); };

    auto mdCtx = make_unique(EVP_MD_CTX_new());
    if(!mdCtx) return error();
    
    const int initStatus = EVP_DigestSignInit(mdCtx.get(), nullptr, evpMd, nullptr, &privateKey);
    if(1 != initStatus) return error();
    
    const int updateStatus = EVP_DigestSignUpdate(mdCtx.get(), message.data(), message.size());
    if(1 != updateStatus) return error();
    
    size_t sigLen = 0;
    int signStatus = EVP_DigestSignFinal(mdCtx.get(), nullptr, &sigLen);
    if(1 != signStatus) return error();
 
    Bytes tmp(sigLen);
    signStatus = EVP_DigestSignFinal(mdCtx.get(), tmp.data(), &sigLen);
    if(1 != signStatus) return error();
        
    Bytes signature(tmp.begin(), std::next(tmp.begin(), static_cast<long>(sigLen))); 
    return detail::ok(std::move(signature));
  }

  SO_LIB Expected<bool> evpVerify(const Bytes &sig, const Bytes &msg, const EVP_MD *evpMd, EVP_PKEY &pubKey)
  {
    auto ctx = make_unique(EVP_MD_CTX_new());
    if (!ctx) return detail::err<bool>();

    if (1 != EVP_DigestVerifyInit(ctx.get(), nullptr, evpMd, nullptr, &pubKey)){
      return detail::err<bool>();
    }
    
    if(1 != EVP_DigestVerifyUpdate(ctx.get(), msg.data(), msg.size())){
      return detail::err<bool>(); 
    }
   
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
    ret.reserve(len);
    const auto staticCaster = [](unsigned char chr){ return static_cast<char>(chr); };
    std::transform(strBuff.get(), strBuff.get() + len, std::back_inserter(ret), staticCaster);

    return detail::ok(std::move(ret)); 
  }

  SO_LIB Expected<std::string> name2String(const X509_NAME &name)
  {
    auto bio = make_unique(BIO_new(BIO_s_mem()));
    if(0 > X509_NAME_print_ex(bio.get(), &name, 0, XN_FLAG_RFC2253))
      return detail::err<std::string>();

    char *dataStart;
    const long nameLength = BIO_get_mem_data(bio.get(), &dataStart);
    if(nameLength < 0) return detail::err<std::string>();
    
    return detail::ok(std::string(dataStart, nameLength));
  }

  SO_LIB Expected<x509::Info> commonInfo(X509_NAME &name)
  {
    const auto error = [](long errCode){ return detail::err<x509::Info>(errCode); };
    const auto raw = name2String(name);
    if(!raw) return error(raw.errorCode());
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
        *raw,
        *commonName,
        *countryName,
        *organizationName,
        *localityName,
        *stateOrProvinceName
    });
  } 

} //namespace detail

SO_API void init()
{
  // Since openssl v.1.1.0 we no longer need to set
  // locking callback for multithreaded support

  // required for x509 for example
  OpenSSL_add_all_algorithms();

  // error more descriptive messages
  ERR_load_crypto_strings();
  ERR_load_BIO_strings();
}

SO_API void cleanUp()
{
  ERR_free_strings();
}

namespace asn1 { 
  SO_API Expected<std::time_t> time2StdTime(const ASN1_TIME &asn1Time)
  {
    // TODO: If we're extremly unlucky, can be off by whole second.
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
  SO_API Expected<Bytes> bn2Bytes(const BIGNUM &bn)
  {
    const auto sz = size(bn); 
    if(!sz) return detail::err<Bytes>(sz.errorCode());
    Bytes ret(*sz);
    if(1 != BN_bn2bin(&bn, ret.data())) return detail::err<Bytes>();
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
  SO_API Expected<Curve> curveOf(const EC_KEY &key)
  {
    const EC_GROUP* group = EC_KEY_get0_group(&key);
    if(!group) return detail::err<Curve>();
    const int nid = EC_GROUP_get_curve_name(group);
    if(0 == nid) return detail::err<Curve>();
    return detail::ok(static_cast<Curve>(nid)); 
  }

  SO_API Expected<EC_KEY_uptr> copyKey(const EC_KEY &ecKey)
  {
    auto copy = make_unique(EC_KEY_dup(&ecKey));
    if(!copy) return detail::err<EC_KEY_uptr>();
    return detail::ok(std::move(copy));
  }

  SO_API Expected<EVP_PKEY_uptr> key2Evp(const EC_KEY &ecKey)
  {
    auto copy = make_unique(EC_KEY_dup(&ecKey));
    if(!copy) return detail::err<EVP_PKEY_uptr>();

    EVP_PKEY_uptr evpKey = make_unique(EVP_PKEY_new());
    if (!evpKey) return detail::err<EVP_PKEY_uptr>();

    if (1 != EVP_PKEY_set1_EC_KEY(evpKey.get(), copy.get())){
        return detail::err<EVP_PKEY_uptr>();
    }

    return detail::ok(std::move(evpKey));
  }


  SO_API Expected<EC_KEY_uptr> pem2PublicKey(const std::string &pemPub)
  {
    auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPub.c_str()), pemPub.size()));
    if(!bio) return detail::err<EC_KEY_uptr>();
    EC_KEY *rawKey = PEM_read_bio_EC_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    if(!rawKey) return detail::err<EC_KEY_uptr>(); 
    return detail::ok(make_unique(rawKey));
  }

  SO_API Expected<EC_KEY_uptr> pem2PrivateKey(const std::string &pemPriv)
  {
    auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPriv.c_str()), pemPriv.size()));
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

  SO_API Expected<Bytes> signSha256(const Bytes &message, EC_KEY &key)
  {
    const auto digest = hash::sha256(message);
    if(!digest) return detail::err<Bytes>(digest.errorCode());

    const int sigLen = ECDSA_size(&key);
    if(0 >= sigLen) return detail::err<Bytes>();

    Bytes tmpSig(static_cast<size_t>(sigLen));
    unsigned int finalSigLen = 0;
    const auto dg = *digest;
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


  SO_API Expected<bool> verifySha256Signature(const Bytes &signature, const Bytes &message, EC_KEY &publicKey)
  {
    const auto digest = hash::sha256(message);
    if(!digest) return detail::err<bool>(digest.errorCode());

    const auto dg = *digest;
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
} //namespace ecdsa

namespace evp {
  SO_API Expected<EVP_PKEY_uptr> pem2PublicKey(const std::string &pemPub)
  {
    auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPub.c_str()), pemPub.size()));
    if(!bio) return detail::err<EVP_PKEY_uptr>(); 
    EVP_PKEY *rawKey = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr);
    if(!rawKey) return detail::err<EVP_PKEY_uptr>();
    return detail::ok(make_unique(rawKey));
  }

  SO_API Expected<EVP_PKEY_uptr> pem2PrivateKey(const std::string &pemPriv)
  {
    auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPriv.c_str()), pemPriv.size()));
    if(!bio) return detail::err<EVP_PKEY_uptr>(); 
    EVP_PKEY *rawKey = PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr);
    if(!rawKey) return detail::err<EVP_PKEY_uptr>();
    return detail::ok(make_unique(rawKey));
  }

  SO_API Expected<Bytes> signSha1(const Bytes &message, EVP_PKEY &privateKey)
  { 
    return detail::evpSign(message, EVP_sha1(), privateKey);
  }

  SO_API Expected<Bytes> signSha256(const Bytes &message, EVP_PKEY &privateKey)
  { 
    return detail::evpSign(message, EVP_sha256(), privateKey);
  }

  SO_API Expected<bool> verifySha1Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey)
  {
    return detail::evpVerify(signature, message, EVP_sha1(), pubKey); 
  }

  SO_API Expected<bool> verifySha256Signature(const Bytes &signature, const Bytes &message, EVP_PKEY &pubKey)
  {
    return detail::evpVerify(signature, message, EVP_sha256(), pubKey); 
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
    if(1 != RAND_bytes(ret.data(), static_cast<int>(numOfBytes))){
      return detail::err<Bytes>();
    }

    return detail::ok(std::move(ret));
  }
} // namespace rand

namespace x509 {
  inline bool Info::operator ==(const Info &other) const
  {
    return commonName == other.commonName &&
      countryName == other.countryName &&
      organizationName == other.organizationName &&
      locationName == other.locationName &&
      stateName == other.stateName;
  }

  inline bool Info::operator !=(const Info &other) const
  {
    return !(*this == other);
  }

  SO_API Expected<Info> issuer(const X509 &x509)
  {
    // this is internal ptr and must not be freed
    X509_NAME *issuer = X509_get_issuer_name(&x509);
    if(!issuer) return detail::err<Info>();
    return detail::commonInfo(*issuer); 
  }
  
  SO_API Expected<X509_uptr> pem2X509(const std::string &pemCert)
  {
    BIO_uptr bio = make_unique(BIO_new(BIO_s_mem()));

    if(0 >= BIO_write(bio.get(), pemCert.c_str(), static_cast<int>(pemCert.length())))
      return detail::err<X509_uptr>(); 

    auto ret = make_unique(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if(!ret) return detail::err<X509_uptr>();
    return detail::ok(std::move(ret));
  }

  SO_API Expected<Bytes> serialNumber(X509 &x509)
  {
    // both internal pointers, must not be freed
    const ASN1_INTEGER *serialNumber = X509_get_serialNumber(&x509);
    if(!serialNumber) return detail::err<Bytes>();
    const BIGNUM *bn = ASN1_INTEGER_to_BN(serialNumber, nullptr);
    if(!bn) return detail::err<Bytes>();
    return bignum::bn2Bytes(*bn);
  }

  SO_API Expected<Info> subject(const X509 &x509)
  {
    // this is internal ptr and must not be freed
    X509_NAME *subject = X509_get_subject_name(&x509);
    if(!subject) return detail::err<Info>();
    return detail::commonInfo(*subject); 
  }

  SO_API Expected<Validity> validity(const X509 &x509)
  {
    const auto notAfter = X509_get0_notAfter(&x509);
    if(!notAfter) return detail::err<Validity>();
    const auto notBefore = X509_get0_notBefore(&x509);
    if(!notBefore) return detail::err<Validity>();
    auto notBeforeTime = asn1::time2StdTime(*notBefore);
    if(!notBeforeTime) return detail::err<Validity>(notBeforeTime.errorCode());
    auto notAfterTime = asn1::time2StdTime(*notAfter);
    if(!notAfterTime) return detail::err<Validity>(notAfterTime.errorCode());
    return detail::ok(Validity{*notBeforeTime, *notAfterTime});
  }

  SO_API Expected<long> version(const X509 &x509)
  {
    // TODO: I prevented returning Expected<> to keep API
    // consistent, but I could just return long here....I don't know...
    // Version is zero indexed, thus +1
    return detail::ok(X509_get_version(&x509) + 1);
  }
} // namespace x509

} // namepsace so

#endif
