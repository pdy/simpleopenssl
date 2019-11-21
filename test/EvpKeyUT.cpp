#include <gtest/gtest.h>
#include <simpleopenssl/simpleopenssl.h>

#include "precalculated.h"


namespace so { namespace ut { namespace evp {

namespace evp = ::so::evp;

TEST(EvpKeyUT, pem2PubKeyConversion_shouldSuccess)
{
  // WHEN
  auto maybeKey = evp::convertPemToPubKey(data::secp256PubKeyPem);

  // THEN
  EXPECT_TRUE(maybeKey);
}

TEST(EvpKeyUT, pem2PubKeyConversion_shouldFailWithInvalidPemFormat)
{
  // GIVEN
  const std::string incorrectPem = data::secp256PubKeyPem.substr(1);

  // WHEN
  auto maybeKey = evp::convertPemToPubKey(incorrectPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(EvpKeyUT, pem2PubKeyConversion_shouldFailWithPrivKey)
{
  // WHEN
  auto maybeKey = evp::convertPemToPubKey(data::secp256k1PrivKeyPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(EvpKeyUT, pem2PrivKeyConversion_shouldSuccess)
{
  // WHEN
  auto maybeKey = evp::convertPemToPrivKey(data::secp256k1PrivKeyPem);

  // THEN
  EXPECT_TRUE(maybeKey);
}

TEST(EvpKeyUT, pem2PrivKeyConversion_shouldFailWithInvalidPemFormat)
{
  // GIVEN
  const std::string incorrectPem = data::secp256k1PrivKeyPem.substr(1);

  // WHEN
  auto maybeKey = evp::convertPemToPrivKey(incorrectPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(EvpKeyUT, pem2PrivKeyConversion_shouldFailWithPubKey)
{
  // WHEN
  auto maybeKey = evp::convertPemToPrivKey(data::secp256PubKeyPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

}}} //namespace so { namespace ut { namespace evp {

