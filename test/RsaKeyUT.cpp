#include <vector>
#include <algorithm>
#include <numeric>
#include <gtest/gtest.h>
#include <simpleopenssl/simpleopenssl.h>

#include "precalculated.h"


namespace so { namespace ut { namespace rsa {

namespace rsa = ::so::rsa;

TEST(RsaKeyUT, pem2PubKeyConversion_shouldSuccess)
{
  // WHEN
  auto maybeKey = rsa::convertPemToPubKey(data::rsa3072PubKeyPem);

  // THEN
  EXPECT_TRUE(maybeKey);
}

/*TEST(RsaKeyUT, copyKey_shouldSuccess)
{
  // WHEN
  auto maybeKey = rsa::convertPemToPubKey(data::rsa3072PubKeyPem);
  ASSERT_TRUE(maybeKey);

  auto key = maybeKey.moveValue();
  auto copied = rsa::copyKey(*key);
  EXPECT_TRUE(copied);
}*/

TEST(RsaKeyUT, pem2PubKeyConversion_shouldFailWithInvalidPemFormat)
{
  // GIVEN
  const std::string incorrectPem = data::rsa3072PubKeyPem.substr(1);

  // WHEN
  auto maybeKey = rsa::convertPemToPubKey(incorrectPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(RsaKeyUT, pem2PubKeyConversion_shouldFailWithPrivKey)
{
  // WHEN
  auto maybeKey = rsa::convertPemToPubKey(data::rsa3072PrivKeyPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(RsaKeyUT, pem2PrivKeyConversion_shouldSuccess)
{
  // WHEN
  auto maybeKey = rsa::convertPemToPrivKey(data::rsa3072PrivKeyPem);

  // THEN
  EXPECT_TRUE(maybeKey);
}

TEST(RsaKeyUT, pem2PrivKeyConversion_shouldFailWithInvalidPemFormat)
{
  // GIVEN
  const std::string incorrectPem = data::rsa3072PrivKeyPem.substr(1);

  // WHEN
  auto maybeKey = rsa::convertPemToPrivKey(incorrectPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(RsaKeyUT, pem2PrivKeyConversion_shouldFailWithPubKey)
{
  // WHEN
  auto maybeKey = rsa::convertPemToPrivKey(data::rsa3072PubKeyPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}
/*
TEST(RsaKeyUT, curveOf_AgainstPrecalculatedData)
{
  // GIVEN
  auto maybePriv = rsa::convertPemToPrivKey(data::secp256k1PrivKeyPem);
  ASSERT_TRUE(maybePriv);
  auto priv = maybePriv.moveValue();

  // WHEN
  const auto actual = rsa::getSize(*priv);

  //THEN
  EXPECT_EQ(rsa::Curve::secp256k1, *actual);
}

TEST(RsaKeyUT, extractPublicKeyOK)
{
  // GIVEN
  auto maybePriv = rsa::generateKey(rsa::Curve::secp160r2);
  ASSERT_TRUE(maybePriv);
  auto priv = maybePriv.moveValue();

  auto maybePub = rsa::getPublic(*priv);
  ASSERT_TRUE(maybePub);
  auto pub = maybePub.moveValue();
  ::so::Bytes data(256);
  std::iota(data.begin(), data.end(), 0);

  // WHEN
  const auto signResult = rsa::signSha256(data, *priv);
  ASSERT_TRUE(signResult);
  const auto verResult = rsa::verifySha256Signature(*signResult, data, *pub);

  // THEN
  ASSERT_TRUE(verResult);
  EXPECT_TRUE(*verResult);
}

TEST(RsaKeyUT, extractedPublicKeyCantBeUsedForSign)
{
  // GIVEN
  auto maybePriv = rsa::generateKey(rsa::Curve::secp160r2);
  ASSERT_TRUE(maybePriv);
  auto priv = maybePriv.moveValue();

  auto maybePub = rsa::getPublic(*priv);
  ASSERT_TRUE(maybePub);
  auto pub = maybePub.moveValue();
  ::so::Bytes data(256);
  std::iota(data.begin(), data.end(), 0);

  // WHEN
  const auto signResult = rsa::signSha256(data, *pub);

  // THEN
  EXPECT_FALSE(signResult);
}

TEST(RsaKeyUT, checkKeyOK)
{
  // GIVEN
  auto maybeKey = rsa::generateKey(rsa::Curve::secp112r1);
  ASSERT_TRUE(maybeKey);
  auto key = maybeKey.moveValue();
  
  // WHEN/THEN
  EXPECT_TRUE(rsa::checkKey(*key));
}

TEST(RsaKeyUT, checkKeyFail)
{
  // GIVEN
  auto key = ::so::make_unique(EC_KEY_new());
  
  // WHEN/THEN
  EXPECT_FALSE(rsa::checkKey(*key));
}
*/
}}} // namespace so { namespace ut { namespace rsa {
