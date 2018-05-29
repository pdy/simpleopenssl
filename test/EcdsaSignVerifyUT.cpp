#include <vector>
#include <algorithm>
#include <numeric>
#include <gtest/gtest.h>
#include <simpleopenssl/simpleopenssl.h>

#include "precalculated.h"


namespace so { namespace ut { namespace ecdsa {

namespace ecdsa = ::so::ecdsa;
namespace evp = ::so::evp;

struct SignVerifyInput
{
  std::string shortDesc;
  std::string privKeyPem;
  std::string pubKeyPem;
  ::so::Bytes signedData;
  ::so::Bytes signature;
  std::function<::so::Expected<::so::Bytes>(const ::so::Bytes&, EC_KEY&)> signer;
  std::function<::so::Expected<bool>(const ::so::Bytes&,const ::so::Bytes&, EC_KEY&)> verifier;
  std::function<::so::Expected<bool>(const ::so::Bytes&,const ::so::Bytes&, EVP_PKEY&)> evpVerifier;
};

// so that gtest failure log would be more descriptive
std::ostream& operator<<(std::ostream &s, const SignVerifyInput &input)
{
  return s << input.shortDesc;
}

class EcdsaSignVerifyUT : public ::testing::TestWithParam<SignVerifyInput>
{};

TEST_P(EcdsaSignVerifyUT, verify_AgainstPrecalculatedSignature)
{
  // GIVEN
  const SignVerifyInput input { GetParam() };
  auto maybeKey = ecdsa::pemToPublicKey(input.pubKeyPem);
  ASSERT_TRUE(maybeKey);
  auto key = maybeKey.moveValue();

  // WHEN
  const auto verified = input.verifier(input.signature, input.signedData, *key); 

  // THEN
  ASSERT_TRUE(verified);
  EXPECT_TRUE(*verified);
}

TEST_P(EcdsaSignVerifyUT, signVerify_AgainstPrecalculatedKey)
{
  // GIVEN
  const SignVerifyInput input { GetParam() };
  auto maybeKey = ecdsa::pemToPrivateKey(input.privKeyPem);
  ASSERT_TRUE(maybeKey);
  auto key = maybeKey.moveValue();

  // WHEN
  const auto sig = input.signer(input.signedData, *key); 
  ASSERT_TRUE(sig);
  const auto verified = input.verifier(*sig, input.signedData, *key);
  ASSERT_TRUE(verified);

  // THEN
  EXPECT_TRUE(*verified);
}

TEST_P(EcdsaSignVerifyUT, signVerify_ApiIntegrity)
{
  // GIVEN
  const SignVerifyInput input { GetParam() };
  std::vector<uint8_t> data(256);
  std::iota(data.begin(), data.end(), 0); 
  auto key = ecdsa::generateKey(ecdsa::Curve::secp224r1);
  ASSERT_TRUE(key);

  auto keyUptr = key.moveValue();
  
  // WHEN
  const auto sig = input.signer(data, *keyUptr);
  const auto verResult = input.verifier(*sig, data, *keyUptr);

  // THEN
  ASSERT_TRUE(verResult);
  ASSERT_TRUE(*verResult);
}

TEST_P(EcdsaSignVerifyUT, signVerify_IntegrityWithEvp)
{
  // GIVEN
  const SignVerifyInput input { GetParam() };
  std::vector<uint8_t> data(256);
  std::iota(data.begin(), data.end(), 0); 
  auto key = ecdsa::generateKey(ecdsa::Curve::sect233k1);
  ASSERT_TRUE(key);

  auto keyUptr = key.moveValue();
  
  const auto sig = input.signer(data, *keyUptr);
  const auto verResult = input.verifier(*sig, data, *keyUptr);

  // WHEN
  auto evpKey = ecdsa::keyToEvp(*keyUptr);
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
    data::secp256k1PrivKeyPem,
    data::secp256PubKeyPem,
    data::signedTextBytes,
    data::signature_sha1,
    &::so::ecdsa::signSha1,
    &::so::ecdsa::verifySha1Signature,
    &::so::evp::verifySha1Signature   
  },
    
  SignVerifyInput {
    "Sign/Verify with SHA256",
    data::secp256k1PrivKeyPem,
    data::secp256PubKeyPem,
    data::signedTextBytes,
    data::signature_sha256,
    &::so::ecdsa::signSha256,
    &::so::ecdsa::verifySha256Signature,
    &::so::evp::verifySha256Signature   
  }
  
);

INSTANTIATE_TEST_CASE_P(
    Ecdsa,
    EcdsaSignVerifyUT,
    testCases 
);

}}} //namespace so { namespace ut { namespace ecdsa {
