#include <vector>
#include <algorithm>
#include <numeric>
#include <gtest/gtest.h>
#include <simpleopenssl/simpleopenssl.h>

#include "precalculated.h"

namespace so { namespace ut { namespace evp {

namespace evp = ::so::evp;

struct EvpSignVerifyInput
{
  std::string shortDesc;
  std::string privKeyPem;
  std::string pubKeyPem;
  ::so::Bytes signedData;
  ::so::Bytes signature;
  std::function<::so::Expected<::so::Bytes>(const ::so::Bytes&, EVP_PKEY&)> signer;
  std::function<::so::Expected<bool>(const ::so::Bytes&,const ::so::Bytes&, EVP_PKEY&)> verifier;
};

// so that gtest failure log would be more descriptive
std::ostream& operator<<(std::ostream &s, const EvpSignVerifyInput &input)
{
  return s << input.shortDesc;
}

class EvpSignVerifyUT : public ::testing::TestWithParam<EvpSignVerifyInput>
{};

TEST_P(EvpSignVerifyUT, verify_AgainstPrecalculatedSignature)
{
  // GIVEN
  const EvpSignVerifyInput input{ GetParam() };
  auto maybeKey = evp::pemToPublicKey(input.pubKeyPem);
  ASSERT_TRUE(maybeKey);
  auto key = maybeKey.moveValue();

  // WHEN
  const auto verified = input.verifier(input.signature, input.signedData, *key);

  // THEN
  ASSERT_TRUE(verified);
  EXPECT_TRUE(*verified);
}

TEST_P(EvpSignVerifyUT, signVerify_AgainstPrecalculatedKey)
{
  // GIVEN
  const EvpSignVerifyInput input{ GetParam() };
  auto maybeKey = evp::pemToPrivateKey(input.privKeyPem);
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

TEST_P(EvpSignVerifyUT, signVerify_ApiIntegrity)
{
  // GIVEN
  const EvpSignVerifyInput input{ GetParam() };
  std::vector<uint8_t> data(256);
  std::iota(data.begin(), data.end(), 0); 
  auto key = ecdsa::generateKey(ecdsa::Curve::sect571r1);
  ASSERT_TRUE(key);

  auto keyUptr = key.moveValue();
  auto maybeEvp = ecdsa::keyToEvp(*keyUptr);
  ASSERT_TRUE(maybeEvp);
  auto evpKey = maybeEvp.moveValue();
  
  // WHEN
  const auto sig = input.signer(data, *evpKey);
  ASSERT_TRUE(sig);
  const auto verResult = input.verifier(*sig, data, *evpKey);

  // THEN
  ASSERT_TRUE(verResult);
  ASSERT_TRUE(*verResult);
}

const auto testCases = ::testing::Values(
  EvpSignVerifyInput {
    "Sign/Verify with SHA1",
    data::secp256k1PrivKeyPem,
    data::secp256PubKeyPem,
    data::signedTextBytes,
    data::signature_sha1,
    &::so::evp::signSha1,
    &::so::evp::verifySha1Signature
  },
  
  EvpSignVerifyInput {
    "Sign/Verify with SHA256",
    data::secp256k1PrivKeyPem,
    data::secp256PubKeyPem,
    data::signedTextBytes,
    data::signature_sha256,
    &::so::evp::signSha256,
    &::so::evp::verifySha256Signature
  },

  EvpSignVerifyInput {
    "Sign/Verify with SHA384",
    data::secp256k1PrivKeyPem,
    data::secp256PubKeyPem,
    data::signedTextBytes,
    data::signature_sha384,
    &::so::evp::signSha384,
    &::so::evp::verifySha384Signature
  },
  EvpSignVerifyInput {
    "Sign/Verify with SHA512",
    data::secp256k1PrivKeyPem,
    data::secp256PubKeyPem,
    data::signedTextBytes,
    data::signature_sha512,
    &::so::evp::signSha512,
    &::so::evp::verifySha512Signature
  }
);

INSTANTIATE_TEST_CASE_P(
    Evp,
    EvpSignVerifyUT,
    testCases 
);

}}}
