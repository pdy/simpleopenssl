#include <gtest/gtest.h>
#include <functional>
#include <simpleopenssl/simpleopenssl.h>

#include "../precalculated.h"


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

TEST(EvpKeyUT, privKey2DerConversion_ok)
{
  // GIVEN
  const auto pemPriv= data::rsa3072PrivKeyPem;
  auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPriv.c_str()), static_cast<int>(pemPriv.size())));
  ASSERT_TRUE(bio);

  auto key = make_unique(PEM_read_bio_RSAPrivateKey(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(key);
  
  EVP_PKEY_uptr evpKey = make_unique(EVP_PKEY_new());
  ASSERT_TRUE(evpKey);
  ASSERT_TRUE(EVP_PKEY_set1_RSA(evpKey.get(), key.get()));

  // WHEN
  const auto maybeDerPriv = evp::convertPrivKeyToDer(*evpKey);

  // THEN
  ASSERT_TRUE(maybeDerPriv);
  EXPECT_EQ(data::rsa3072PrivKeyDer, *maybeDerPriv);
}

TEST(EvpKeyUT, derToPrivKeyConversion_ok)
{
  // WHEN
  auto maybePrivKey = evp::convertDerToPrivKey(data::rsa3072PrivKeyDer);

  // THEN
  ASSERT_TRUE(maybePrivKey);
  auto privKey = maybePrivKey.moveValue();
  EXPECT_EQ(1, RSA_check_key(EVP_PKEY_get0_RSA(privKey.get())));
  // TODO:
  // EVP_PKEY_check available in 1.1.1
  //EXPECT_EQ(1, EVP_PKEY_check(privKey.get()));
}

TEST(EvpKeyUT, derToPrivKeyConversion_shouldFailWhenPubKeyGiven)
{
  // WHEN
  auto maybePrivKey = evp::convertDerToPrivKey(data::rsa3072PubKeyDer);

  // THEN
  ASSERT_FALSE(maybePrivKey);
}

TEST(EvpKeyUT, pubKey2DerConversion_ok)
{
  // GIVEN
  const auto pemPub = data::rsa3072PubKeyPem;
  auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPub.c_str()), static_cast<int>(pemPub.size())));
  ASSERT_TRUE(bio);

  auto key = make_unique(PEM_read_bio_RSA_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(key);
  
  EVP_PKEY_uptr evpKey = make_unique(EVP_PKEY_new());
  ASSERT_TRUE(evpKey);
  ASSERT_TRUE(EVP_PKEY_set1_RSA(evpKey.get(), key.get()));

  // WHEN
  const auto maybeDerPub = evp::convertPubKeyToDer(*evpKey);

  // THEN
  ASSERT_TRUE(maybeDerPub);
  EXPECT_EQ(data::rsa3072PubKeyDer, *maybeDerPub);
}

TEST(EvpKeyUT, derToPubKeyConversion_ok)
{
  // WHEN
  auto maybePubKey = evp::convertDerToPubKey(data::rsa3072PubKeyDer);

  // THEN
  ASSERT_TRUE(maybePubKey);
}

TEST(EvpKeyUT, getKeyType)
{
  // GIVEN
  auto maybeCert = x509::convertPemToX509(data::meaninglessValidPemCert);
  ASSERT_TRUE(maybeCert);
  auto cert = maybeCert.moveValue();
  auto maybePubKey = x509::getPubKey(*cert);
  ASSERT_TRUE(maybePubKey);
  auto pubKey = maybePubKey.moveValue();

  // WHEN
  
  const auto pubKeyType = evp::getKeyType(*pubKey) ;

  // THEN
  EXPECT_EQ(evp::KeyType::EC, pubKeyType);
  EXPECT_EQ("id-ecPublicKey", evp::convertPubkeyTypeToString(pubKeyType));
}

}}} //namespace so { namespace ut { namespace evp {

