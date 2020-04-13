#include <vector>
#include <numeric>
#include <gtest/gtest.h>
#include <simpleopenssl/simpleopenssl.h>

#include "precalculated.h"


namespace so { namespace ut { namespace ecdsa {

namespace ecdsa = ::so::ecdsa;

TEST(EcdsaKeyUT, pem2PubKeyConversion_shouldSuccess)
{
  // WHEN
  auto maybeKey = ecdsa::convertPemToPubKey(data::secp256PubKeyPem);

  // THEN
  EXPECT_TRUE(maybeKey);
}

TEST(EcdsaKeyUT, copyKey_shouldSuccess)
{
  // WHEN
  auto maybeKey = ecdsa::convertPemToPubKey(data::secp256PubKeyPem);
  ASSERT_TRUE(maybeKey);

  auto key = maybeKey.moveValue();
  auto copied = ecdsa::copyKey(*key);
  EXPECT_TRUE(copied);
}

TEST(EcdsaKeyUT, pem2PubKeyConversion_shouldFailWithInvalidPemFormat)
{
  // GIVEN
  const std::string incorrectPem = data::secp256PubKeyPem.substr(1);

  // WHEN
  auto maybeKey = ecdsa::convertPemToPubKey(incorrectPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(EcdsaKeyUT, pem2PubKeyConversion_shouldFailWithPrivKey)
{
  // WHEN
  auto maybeKey = ecdsa::convertPemToPubKey(data::secp256k1PrivKeyPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(EcdsaKeyUT, pem2PrivKeyConversion_shouldSuccess)
{
  // WHEN
  auto maybeKey = ecdsa::convertPemToPrivKey(data::secp256k1PrivKeyPem);

  // THEN
  EXPECT_TRUE(maybeKey);
}

TEST(EcdsaKeyUT, pem2PrivKeyConversion_shouldFailWithInvalidPemFormat)
{
  // GIVEN
  const std::string incorrectPem = data::secp256k1PrivKeyPem.substr(1);

  // WHEN
  auto maybeKey = ecdsa::convertPemToPrivKey(incorrectPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(EcdsaKeyUT, pem2PrivKeyConversion_shouldFailWithPubKey)
{
  // WHEN
  auto maybeKey = ecdsa::convertPemToPrivKey(data::secp256PubKeyPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(EcdsaKeyUT, privKey2PemConversion_ok)
{
  // GIVEN
  const auto pemPriv= data::secp256k1PrivKeyPem;
  auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPriv.c_str()), static_cast<int>(pemPriv.size())));
  ASSERT_TRUE(bio);

  auto key = make_unique(PEM_read_bio_ECPrivateKey(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(key);

  // WHEN
  const auto maybePemPriv = ecdsa::convertPrivKeyToPem(*key);

  // THEN
  ASSERT_TRUE(maybePemPriv);
  EXPECT_EQ(pemPriv, *maybePemPriv); 
}

TEST(EcdsaKeyUT, pubKey2PemConversion_ok)
{
  // GIVEN
  const auto pemPub= data::secp256PubKeyPem;
  auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPub.c_str()), static_cast<int>(pemPub.size())));
  ASSERT_TRUE(bio);

  auto key = make_unique(PEM_read_bio_EC_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(key);

  // WHEN
  const auto maybePemPub = ecdsa::convertPubKeyToPem(*key);

  // THEN
  ASSERT_TRUE(maybePemPub);
  EXPECT_EQ(pemPub, *maybePemPub); 
}

TEST(EcdsaKeyUT, privKey2DerConversion_ok)
{
  // GIVEN
  const auto pemPriv = data::secp256k1PrivKeyPem;
  auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPriv.c_str()), static_cast<int>(pemPriv.size())));
  ASSERT_TRUE(bio);

  auto key = make_unique(PEM_read_bio_ECPrivateKey(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(key);

  // WHEN
  const auto maybeDerPriv = ecdsa::convertPrivKeyToDer(*key);

  // THEN
  ASSERT_TRUE(maybeDerPriv);
  EXPECT_EQ(data::secp256k1PrivKeyDer, *maybeDerPriv);
}

TEST(EcdsaKeyUT, derToPrivKeyConversion_ok)
{
  // WHEN
  auto maybePrivKey = ecdsa::convertDerToPrivKey(data::secp256k1PrivKeyDer);

  // THEN
  ASSERT_TRUE(maybePrivKey);
  auto privKey = maybePrivKey.moveValue();
  EXPECT_EQ(1, EC_KEY_check_key(privKey.get()));
}

TEST(EcdsaKeyUT, derToPrivKeyConversion_shouldFailWhenPubKeyGiven)
{
  // WHEN
  auto maybePrivKey = rsa::convertDerToPrivKey(data::secp256PubKeyDer);

  // THEN
  ASSERT_FALSE(maybePrivKey);
}

TEST(EcdsaKeyUT, pubKey2DerConversion_ok)
{
  // GIVEN
  const auto pemPub = data::secp256PubKeyPem;
  auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPub.c_str()), static_cast<int>(pemPub.size())));
  ASSERT_TRUE(bio);

  auto key = make_unique(PEM_read_bio_EC_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(key);

  // WHEN
  const auto maybeDerPub = ecdsa::convertPubKeyToDer(*key);

  // THEN
  ASSERT_TRUE(maybeDerPub);
  EXPECT_EQ(data::secp256PubKeyDer, *maybeDerPub);
}

TEST(EcdsaKeyUT, derToPubKeyConversion_ok)
{
  // WHEN
  auto maybePubKey = ecdsa::convertDerToPubKey(data::secp256PubKeyDer);

  // THEN
  ASSERT_TRUE(maybePubKey);
}

TEST(EcdsaKeyUT, curveOf_AgainstPrecalculatedData)
{
  // GIVEN
  auto maybePriv = ecdsa::convertPemToPrivKey(data::secp256k1PrivKeyPem);
  ASSERT_TRUE(maybePriv);
  auto priv = maybePriv.moveValue();

  // WHEN
  const auto actual = ecdsa::getCurve(*priv);

  //THEN
  EXPECT_EQ(ecdsa::Curve::secp256k1, *actual);
}

TEST(EcdsaKeyUT, extractPublicKeyOK)
{
  // GIVEN
  auto maybePriv = ecdsa::generateKey(ecdsa::Curve::secp160r2);
  ASSERT_TRUE(maybePriv);
  auto priv = maybePriv.moveValue();

  auto maybePub = ecdsa::getPublic(*priv);
  ASSERT_TRUE(maybePub);
  auto pub = maybePub.moveValue();
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
  auto priv = maybePriv.moveValue();

  auto maybePub = ecdsa::getPublic(*priv);
  ASSERT_TRUE(maybePub);
  auto pub = maybePub.moveValue();
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
  auto key = maybeKey.moveValue();
  
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

TEST(EcdsaKeyUT, getPubKeySize)
{
  // GIVEN
  auto maybeKey = ecdsa::generateKey(ecdsa::Curve::secp112r1);
  ASSERT_TRUE(maybeKey);
  auto key = maybeKey.moveValue();
  
  // WHEN
  auto size = ecdsa::getKeySize(*key);
 
  // THEN 
  ASSERT_TRUE(size);
  EXPECT_EQ(112, *size);
}

TEST(EcdsaKeyUT, getPubKeySizeOnEmptyKey)
{
  // GIVEN
  auto key = make_unique(EC_KEY_new()); 
  ASSERT_TRUE(key);

  // WHEN
  auto size = ecdsa::getKeySize(*key);
   
  // THEN 
  ASSERT_FALSE(size);
}

TEST(EcdsaKeyUT, curveToString)
{
  const ecdsa::Curve curve = ecdsa::Curve::secp112r2;

  const auto curveName = ecdsa::convertCurveToString(curve);

  ASSERT_TRUE(curveName);
  EXPECT_EQ("secp112r2", *curveName );
}

}}} // namespace so { namespace ut { namespace ecdsa {
