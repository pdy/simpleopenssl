#include <vector>
#include <algorithm>
#include <numeric>
#include <gtest/gtest.h>
#include <simpleopenssl/simpleopenssl.h>

#include "precalculated.h"


namespace so { namespace ut { namespace ecdsa {

namespace ecdsa = ::so::ecdsa;

TEST(EcdsaKeyUT, pem2PubKeyConversion_shouldSuccess)
{
  // WHEN
  auto maybeKey = ecdsa::pemToPublicKey(data::secp256PubKeyPem);

  // THEN
  EXPECT_TRUE(maybeKey);
}

TEST(EcdsaKeyUT, copyKey_shouldSuccess)
{
  // WHEN
  auto maybeKey = ecdsa::pemToPublicKey(data::secp256PubKeyPem);
  ASSERT_TRUE(maybeKey);

  auto key = *maybeKey;
  auto copied = ecdsa::copyKey(*key);
  EXPECT_TRUE(copied);
}

TEST(EcdsaKeyUT, pem2PubKeyConversion_shouldFailWithInvalidPemFormat)
{
  // GIVEN
  const std::string incorrectPem = data::secp256PubKeyPem.substr(1);

  // WHEN
  auto maybeKey = ecdsa::pemToPublicKey(incorrectPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(EcdsaKeyUT, pem2PubKeyConversion_shouldFailWithPrivKey)
{
  // WHEN
  auto maybeKey = ecdsa::pemToPublicKey(data::secp256k1PrivKeyPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(EcdsaKeyUT, pem2PrivKeyConversion_shouldSuccess)
{
  // WHEN
  auto maybeKey = ecdsa::pemToPrivateKey(data::secp256k1PrivKeyPem);

  // THEN
  EXPECT_TRUE(maybeKey);
}

TEST(EcdsaKeyUT, pem2PrivKeyConversion_shouldFailWithInvalidPemFormat)
{
  // GIVEN
  const std::string incorrectPem = data::secp256k1PrivKeyPem.substr(1);

  // WHEN
  auto maybeKey = ecdsa::pemToPrivateKey(incorrectPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(EcdsaKeyUT, pem2PrivKeyConversion_shouldFailWithPubKey)
{
  // WHEN
  auto maybeKey = ecdsa::pemToPrivateKey(data::secp256PubKeyPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(EcdsaKeyUT, curveOf_AgainstPrecalculatedData)
{
  // GIVEN
  auto maybePriv = ecdsa::pemToPrivateKey(data::secp256k1PrivKeyPem);
  ASSERT_TRUE(maybePriv);
  auto priv = *maybePriv;

  // WHEN
  const auto actual = ecdsa::curveOf(*priv);

  //THEN
  EXPECT_EQ(ecdsa::Curve::secp256k1, *actual);
}

TEST(EcdsaKeyUT, extractPublicKeyOK)
{
  // GIVEN
  auto maybePriv = ecdsa::generateKey(ecdsa::Curve::secp160r2);
  ASSERT_TRUE(maybePriv);
  auto priv = *maybePriv;

  auto maybePub = ecdsa::extractPublic(*priv);
  ASSERT_TRUE(maybePub);
  auto pub = *maybePub;
  ::so::Bytes data(256);
  std::iota(data.begin(), data.end(), 0);

  // WHEN
  const auto signResult = ecdsa::signSha256(data, *priv);
  ASSERT_TRUE(signResult);
  const auto verResult = ecdsa::verifySha256Signature(*signResult, data, *pub);

  // THEN
  ASSERT_TRUE(verResult);
  EXPECT_TRUE(*verResult);
}

TEST(EcdsaKeyUT, extractedPublicKeyCantBeUsedForSign)
{
  // GIVEN
  auto maybePriv = ecdsa::generateKey(ecdsa::Curve::secp160r2);
  ASSERT_TRUE(maybePriv);
  auto priv = *maybePriv;

  auto maybePub = ecdsa::extractPublic(*priv);
  ASSERT_TRUE(maybePub);
  auto pub = *maybePub;
  ::so::Bytes data(256);
  std::iota(data.begin(), data.end(), 0);

  // WHEN
  const auto signResult = ecdsa::signSha256(data, *pub);

  // THEN
  EXPECT_FALSE(signResult);
}

TEST(EcdsaKeyUT, checkKeyOK)
{
  // GIVEN
  auto maybeKey = ecdsa::generateKey(ecdsa::Curve::secp112r1);
  ASSERT_TRUE(maybeKey);
  auto key = *maybeKey; 
  
  // WHEN/THEN
  EXPECT_TRUE(ecdsa::checkKey(*key));
}

TEST(EcdsaKeyUT, checkKeyFail)
{
  // GIVEN
  auto key = ::so::make_unique(EC_KEY_new());
  
  // WHEN/THEN
  EXPECT_FALSE(ecdsa::checkKey(*key));
}

}}} // namespace so { namespace ut { namespace ecdsa {
