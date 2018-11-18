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

TEST(RsaKeyUT, extractPublicKeyOK)
{
  // GIVEN
  auto maybePriv = rsa::generateKey(rsa::KeyBits::_2048_);
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

TEST(RsaKeyUT, DISABLED_extractedPublicKeyCantBeUsedForSign)
{
  // GIVEN
  auto maybePriv = rsa::generateKey(rsa::KeyBits::_2048_);
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
  auto maybeKey = rsa::generateKey(rsa::KeyBits::_2048_);
  ASSERT_TRUE(maybeKey);
  auto key = maybeKey.moveValue();
 
  // WHEN
  const auto result = rsa::checkKey(*key);

  // THEN
  EXPECT_TRUE(result);
}

TEST(RsaKeyUT, checkKeyOnPrecalculatedPrivKeyOK)
{
  // GIVEN
  auto maybeKey = rsa::convertPemToPrivKey(data::rsa3072PrivKeyPem);
  ASSERT_TRUE(maybeKey);
  auto key = maybeKey.moveValue();
  
  // WHEN
  const auto result = rsa::checkKey(*key);

  // THEN
  ASSERT_TRUE(result);
}

TEST(RsaKeyUT, checkKeyOnPrecalculatedPubKeyShouldFail)
{
  // GIVEN
  auto maybeKey = rsa::convertPemToPubKey(data::rsa3072PubKeyPem);
  ASSERT_TRUE(maybeKey);
  auto key = maybeKey.moveValue();
  
  // WHEN
  const auto result = rsa::checkKey(*key);

  // THEN
  EXPECT_FALSE(result);
}

TEST(RsaKeyUT, checkKeyOnNewlyCreatedStructureShouldFail)
{
  // GIVEN
  auto key = ::so::make_unique(RSA_new());
 
  // WHEN
  auto result = rsa::checkKey(*key);

  //THEN
  EXPECT_FALSE(result);
}

}}} // namespace so { namespace ut { namespace rsa {
