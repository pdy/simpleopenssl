#include <vector>
#include <algorithm>
#include <numeric>
#include <gtest/gtest.h>
#include <simpleopenssl/simpleopenssl.h>

#include "precalculated.h"


namespace so { namespace ut { namespace rsa {

namespace rsa = ::so::rsa;
namespace evp = ::so::evp;

struct SignVerifyInput
{
  std::string shortDesc;
  std::string privKeyPem;
  std::string pubKeyPem;
  ::so::Bytes privKeyDer;
  ::so::Bytes pubKeyDer;
  ::so::Bytes signedData;
  ::so::Bytes signature;
  std::function<::so::Result<::so::Bytes>(const ::so::Bytes&, RSA&)> signer;
  std::function<::so::Result<bool>(const ::so::Bytes&,const ::so::Bytes&, RSA&)> verifier;
  std::function<::so::Result<bool>(const ::so::Bytes&,const ::so::Bytes&, EVP_PKEY&)> evpVerifier;
};

std::ostream& operator<<(std::ostream &oss, const SignVerifyInput &input)
{
  return oss << input.shortDesc;
}

class RsaSignVerifyUT : public ::testing::TestWithParam<SignVerifyInput>
{};

TEST_P(RsaSignVerifyUT, verify_AgainstPrecalculatedSignature)
{
  // GIVEN
  const SignVerifyInput input { GetParam() };
  auto maybePemKey = rsa::convertPemToPubKey(input.pubKeyPem);
  ASSERT_TRUE(maybePemKey);
  auto keyPem = maybePemKey.moveValue();

  auto maybeDerKey = rsa::convertDerToPubKey(input.pubKeyDer);
  ASSERT_TRUE(maybeDerKey);
  auto keyDer = maybeDerKey.moveValue();

  // WHEN
  const auto verifiedPem = input.verifier(input.signature, input.signedData, *keyPem); 
  const auto verifiedDer = input.verifier(input.signature, input.signedData, *keyDer); 

  // THEN
  ASSERT_TRUE(verifiedPem);
  EXPECT_TRUE(*verifiedPem);
  ASSERT_TRUE(verifiedDer);
  EXPECT_TRUE(*verifiedDer);
}

TEST_P(RsaSignVerifyUT, signVerify_PemDerConversionsAgainstPrecalculatedKey)
{
  // GIVEN
  const SignVerifyInput input { GetParam() };
  auto maybePemKey = rsa::convertPemToPrivKey(input.privKeyPem);
  ASSERT_TRUE(maybePemKey);
  auto pemKey = maybePemKey.moveValue();
  
  auto maybeDerKey = rsa::convertDerToPrivKey(input.privKeyDer);
  ASSERT_TRUE(maybeDerKey);
  auto derKey = maybeDerKey.moveValue();

  // WHEN
  const auto sigPem = input.signer(input.signedData, *pemKey); 
  ASSERT_TRUE(sigPem);
  const auto pemVerified = input.verifier(*sigPem, input.signedData, *pemKey);
  ASSERT_TRUE(pemVerified);

  const auto sigDer = input.signer(input.signedData, *derKey); 
  ASSERT_TRUE(sigDer);
  const auto derVerified = input.verifier(*sigDer, input.signedData, *derKey);
  ASSERT_TRUE(derVerified);

  // THEN
  EXPECT_TRUE(*pemVerified);
  EXPECT_TRUE(*derVerified);
}


TEST_P(RsaSignVerifyUT, signVerify_ApiIntegrity)
{
  // GIVEN
  const SignVerifyInput input { GetParam() };
  std::vector<uint8_t> data(256);
  std::iota(data.begin(), data.end(), 0); 
  auto key = rsa::generateKey(rsa::KeyBits::_2048_);
  ASSERT_TRUE(key);

  auto keyUptr = key.moveValue();
  
  // WHEN
  const auto sig = input.signer(data, *keyUptr);
  const auto verResult = input.verifier(*sig, data, *keyUptr);

  // THEN
  ASSERT_TRUE(verResult);
  ASSERT_TRUE(*verResult);
}

TEST_P(RsaSignVerifyUT, signVerify_IntegrityWithEvp)
{
  // GIVEN
  const SignVerifyInput input { GetParam() };
  std::vector<uint8_t> data(256);
  std::iota(data.begin(), data.end(), 0); 
  auto key = rsa::generateKey(rsa::KeyBits::_2048_);
  ASSERT_TRUE(key);

  auto keyUptr = key.moveValue();
  
  const auto sig = input.signer(data, *keyUptr);
  const auto verResult = input.verifier(*sig, data, *keyUptr);

  // WHEN
  auto evpKey = rsa::convertToEvp(*keyUptr);
  const auto evpVerResult = input.evpVerifier(*sig, data, *evpKey.moveValue());
  
  // THEN
  ASSERT_TRUE(verResult);
  EXPECT_TRUE(*verResult);
  ASSERT_TRUE(evpVerResult);
  EXPECT_TRUE(*evpVerResult);
}

const auto testCases = ::testing::Values(
  SignVerifyInput {
    "Sign/Verify with SHA1",
    data::rsa3072PrivKeyPem,
    data::rsa3072PubKeyPem,
    data::rsa3072PrivKeyDer,
    data::rsa3072PubKeyDer,
    data::signedTextBytes,
    data::signature_rsa_sha1,
    &::so::rsa::signSha1,
    &::so::rsa::verifySha1Signature,
    &::so::evp::verifySha1Signature
  },

  SignVerifyInput {
    "Sign/Verify with SHA224",
    data::rsa3072PrivKeyPem,
    data::rsa3072PubKeyPem,
    data::rsa3072PrivKeyDer,
    data::rsa3072PubKeyDer,
    data::signedTextBytes,
    data::signature_rsa_sha224,
    &::so::rsa::signSha224,
    &::so::rsa::verifySha224Signature,
    &::so::evp::verifySha224Signature
  },

  SignVerifyInput {
    "Sign/Verify with SHA256",
    data::rsa3072PrivKeyPem,
    data::rsa3072PubKeyPem,
    data::rsa3072PrivKeyDer,
    data::rsa3072PubKeyDer,
    data::signedTextBytes,
    data::signature_rsa_sha256,
    &::so::rsa::signSha256,
    &::so::rsa::verifySha256Signature,
    &::so::evp::verifySha256Signature
  },

  SignVerifyInput {
    "Sign/Verify with SHA384",
    data::rsa3072PrivKeyPem,
    data::rsa3072PubKeyPem,
    data::rsa3072PrivKeyDer,
    data::rsa3072PubKeyDer,
    data::signedTextBytes,
    data::signature_rsa_sha384,
    &::so::rsa::signSha384,
    &::so::rsa::verifySha384Signature,
    &::so::evp::verifySha384Signature
  },

  SignVerifyInput {
    "Sign/Verify with SHA512",
    data::rsa3072PrivKeyPem,
    data::rsa3072PubKeyPem,
    data::rsa3072PrivKeyDer,
    data::rsa3072PubKeyDer,
    data::signedTextBytes,
    data::signature_rsa_sha512,
    &::so::rsa::signSha512,
    &::so::rsa::verifySha512Signature,
    &::so::evp::verifySha512Signature
  }

);

INSTANTIATE_TEST_CASE_P(
    Rsa,
    RsaSignVerifyUT,
    testCases 
);

}}}
