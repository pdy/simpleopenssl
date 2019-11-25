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

TEST(RsaKeyUT, privKey2PemConversion_ok)
{
  // GIVEN
  const auto pemPriv= data::rsa3072PrivKeyPem;
  auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPriv.c_str()), static_cast<int>(pemPriv.size())));
  ASSERT_TRUE(bio);

  auto key = make_unique(PEM_read_bio_RSAPrivateKey(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(key);

  // WHEN
  const auto maybePemPriv = rsa::convertPrivKeyToPem(*key);

  // THEN
  ASSERT_TRUE(maybePemPriv);
  EXPECT_EQ(pemPriv, *maybePemPriv); 
}

TEST(RsaKeyUT, pubKey2PemConversion_ok)
{
  // GIVEN
  const auto pemPub= data::rsa3072PubKeyPem;
  auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPub.c_str()), static_cast<int>(pemPub.size())));
  ASSERT_TRUE(bio);

  auto key = make_unique(PEM_read_bio_RSA_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(key);

  // WHEN
  const auto maybePemPub = rsa::convertPubKeyToPem(*key);

  // THEN
  ASSERT_TRUE(maybePemPub);
  EXPECT_EQ(pemPub, *maybePemPub); 
}

TEST(RsaKeyUT, privKey2PemConversion_shouldFailWhenGivenPubKey)
{
  // GIVEN
  const auto pemPub= data::rsa3072PubKeyPem;
  auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPub.c_str()), static_cast<int>(pemPub.size())));
  ASSERT_TRUE(bio);

  auto key = make_unique(PEM_read_bio_RSA_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(key);

  // WHEN
  const auto maybePemPriv = rsa::convertPrivKeyToPem(*key);

  // THEN
  EXPECT_FALSE(maybePemPriv);
}

TEST(RsaKeyUT, pubKey2PemConversion_shouldSuccessWhenGivenPrivKey)
{
  // GIVEN
  const auto pemPriv= data::rsa3072PrivKeyPem;
  auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPriv.c_str()), static_cast<int>(pemPriv.size())));
  ASSERT_TRUE(bio);

  auto key = make_unique(PEM_read_bio_RSAPrivateKey(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(key);

  // WHEN
  const auto maybePemPub = rsa::convertPubKeyToPem(*key);

  // THEN
  EXPECT_TRUE(maybePemPub);
  EXPECT_EQ(data::rsa3072PubKeyPem, *maybePemPub); 
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

TEST(RsaKeyUT, extractedPublicKeyCantBeUsedForSign)
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
