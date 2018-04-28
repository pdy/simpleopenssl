#include <vector>
#include <algorithm>
#include <numeric>
#include <gtest/gtest.h>
#include <simpleopenssl/simpleopenssl.h>

#include "precalculated.h"


namespace so { namespace ut { namespace ecdsa {

namespace ecdsa = ::so::ecdsa;
namespace evp = ::so::evp;

TEST(EcdsaUT, verifySha256_AgainstPrecalculatedSignature)
{
  // GIVEN
  auto maybeKey = ecdsa::pem2PublicKey(data::secp256PubKeyPem);
  ASSERT_TRUE(maybeKey);
  auto key = *maybeKey;
  std::vector<uint8_t> msg(data::signedText.size());
  std::transform(data::signedText.begin(), data::signedText.end(), msg.begin(), [](char chr){return static_cast<uint8_t>(chr);});

  // WHEN
  const auto verified = ecdsa::verifySha256Signature(data::signature_sha256, msg, *key);

  // THEN
  ASSERT_TRUE(verified);
  EXPECT_TRUE(*verified);
}

TEST(EcdsaUT, signVerifySHA256_AgainstPrecalculatedKey)
{
  // GIVEN
  auto maybeKey = ecdsa::pem2PrivateKey(data::secp256k1PrivKeyPem);
  ASSERT_TRUE(maybeKey);
  auto key = *maybeKey;
  std::vector<uint8_t> msg(data::signedText.size());
  std::transform(data::signedText.begin(), data::signedText.end(), msg.begin(), [](char chr){return static_cast<uint8_t>(chr);});

  // WHEN
  const auto sig = ecdsa::signSha256(msg, *key); 
  ASSERT_TRUE(sig);
  const auto verified = ecdsa::verifySha256Signature(*sig, msg, *key);
  ASSERT_TRUE(verified);

  // THEN
  EXPECT_TRUE(*verified);
}

TEST(EcdsaUT, signVerifySHA256_ApiIntegrity)
{
  // GIVEN
  std::vector<uint8_t> data(256);
  std::iota(data.begin(), data.end(), 0); 
  auto key = ecdsa::generateKey(ecdsa::Curve::secp224r1);
  ASSERT_TRUE(key);

  auto keyUptr = *key; 
  
  // WHEN
  const auto sig = ecdsa::signSha256(data, *keyUptr);
  const auto verResult = ecdsa::verifySha256Signature(*sig, data, *keyUptr);

  // THEN
  ASSERT_TRUE(verResult);
  ASSERT_TRUE(*verResult);
}

TEST(EcdsaUT, signVerify_IntegrityWithEvp)
{
  // GIVEN
  std::vector<uint8_t> data(256);
  std::iota(data.begin(), data.end(), 0); 
  auto key = ecdsa::generateKey(ecdsa::Curve::secp224r1);
  ASSERT_TRUE(key);

  auto keyUptr = *key;
  
  const auto sig = ecdsa::signSha256(data, *keyUptr);
  const auto verResult = ecdsa::verifySha256Signature(*sig, data, *keyUptr);

  // WHEN
  auto evpKey = ecdsa::key2Evp(*keyUptr);
  const auto evpVerResult = evp::verifySha256Signature(*sig, data, **evpKey);
  
  // THEN
  ASSERT_TRUE(verResult);
  ASSERT_TRUE(*verResult);
  ASSERT_TRUE(*evpVerResult);
}

}}}// namespace so { namespace ut { namepsace ecdsa
