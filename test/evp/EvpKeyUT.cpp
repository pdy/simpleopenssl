/*
* Copyright (c) 2018 - 2022 Pawel Drzycimski
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
* SOFTWARE.
*
*/

#include <gtest/gtest.h>
#include <functional>
#include <simpleopenssl/simpleopenssl.hpp>

#include "../precalculated.h"
#include "../utils.h"

namespace so { namespace ut { namespace evp {

namespace evp = ::so::evp;

TEST(EvpKeyUT, create)
{
  // WHEN
  auto evp = evp::create();
  ASSERT_TRUE(evp);
  const auto type = evp::getKeyType(*evp.value);

  // THEN
  EXPECT_EQ(evp::KeyType::NONE, type);
}

TEST(EvpKeyUT, pem2PubKeyConversion_shouldSuccess)
{
  // WHEN
  auto maybeKey = evp::convertPemToPubKey(data::secp256PubKeyPem.c_str(), data::secp256PubKeyPem.size());

  // THEN
  EXPECT_TRUE(maybeKey);
}

TEST(EvpKeyUT, pem2PubKeyConversion_shouldFailWithInvalidPemFormat)
{
  // GIVEN
  const std::string incorrectPem = data::secp256PubKeyPem.substr(1);

  // WHEN
  auto maybeKey = evp::convertPemToPubKey(incorrectPem.c_str(), incorrectPem.size());

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(EvpKeyUT, pem2PubKeyConversion_shouldFailWithPrivKey)
{
  // WHEN
  auto maybeKey = evp::convertPemToPubKey(data::secp256k1PrivKeyPem.c_str(), data::secp256k1PrivKeyPem.size());

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(EvpKeyUT, pem2PrivKeyConversion_shouldSuccess)
{
  // WHEN
  auto maybeKey = evp::convertPemToPrivKey(data::secp256k1PrivKeyPem.c_str(), data::secp256k1PrivKeyPem.size());

  // THEN
  EXPECT_TRUE(maybeKey);
}

TEST(EvpKeyUT, pem2PrivKeyConversion_shouldFailWithInvalidPemFormat)
{
  // GIVEN
  const std::string incorrectPem = data::secp256k1PrivKeyPem.substr(1);

  // WHEN
  auto maybeKey = evp::convertPemToPrivKey(incorrectPem.c_str(), incorrectPem.size());

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(EvpKeyUT, pem2PrivKeyConversion_shouldFailWithPubKey)
{
  // WHEN
  auto maybeKey = evp::convertPemToPrivKey(data::secp256PubKeyPem.c_str(), data::secp256PubKeyPem.size());

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
  EXPECT_EQ(data::rsa3072PrivKeyDer, maybeDerPriv.value);
}

TEST(EvpKeyUT, derToPrivKeyConversion_ok)
{
  // WHEN
  auto maybePrivKey = evp::convertDerToPrivKey(data::rsa3072PrivKeyDer.data(), data::rsa3072PrivKeyDer.size());

  // THEN
  ASSERT_TRUE(maybePrivKey);
  auto privKey = maybePrivKey.moveValue();
  EXPECT_EQ(1, RSA_check_key(EVP_PKEY_get0_RSA(privKey.get())));
  
  auto ctx = ::so::make_unique(EVP_PKEY_CTX_new(privKey.get(), nullptr));
  ASSERT_TRUE(ctx);
  EXPECT_EQ(1, EVP_PKEY_check(ctx.get()));
}

TEST(EvpKeyUT, derToPrivKeyConversion_shouldFailWhenPubKeyGiven)
{
  // WHEN
  auto maybePrivKey = evp::convertDerToPrivKey(data::rsa3072PubKeyDer.data(), data::rsa3072PubKeyDer.size());

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
  EXPECT_EQ(data::rsa3072PubKeyDer, maybeDerPub.value);
}

TEST(EvpKeyUT, derToPubKeyConversion_ok)
{
  // WHEN
  auto maybePubKey = evp::convertDerToPubKey(data::rsa3072PubKeyDer.data(), data::rsa3072PubKeyDer.size());

  // THEN
  ASSERT_TRUE(maybePubKey);
}

TEST(EvpKeyUT, privKeyToPemConversion_ok)
{
  // GIVEN
  const auto pemPriv = data::evpPrivKey;
  auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPriv.c_str()), static_cast<int>(pemPriv.size())));
  ASSERT_TRUE(bio);

  auto key = so::make_unique(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(key);

  // WHEN
  const auto actualPemPriv = evp::convertPrivKeyToPem(*key);

  // THEN
  ASSERT_TRUE(actualPemPriv);
  EXPECT_EQ(pemPriv, actualPemPriv.value);
}

TEST(EvpKeyUT, privKeyToPemConversion_shouldFailWithPubkey)
{
  // GIVEN
  const auto pemPub = data::evpPubKey;
  auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPub.c_str()), static_cast<int>(pemPub.size())));
  ASSERT_TRUE(bio);

  auto key = so::make_unique(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(key);

  // WHEN
  const auto actualPemPriv = evp::convertPrivKeyToPem(*key);

  // THEN
  EXPECT_FALSE(actualPemPriv);
}

TEST(EvpKeyUT, pubKeyToPemConversion_ok)
{
  // GIVEN
  const auto pemPub = data::evpPubKey;
  auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPub.c_str()), static_cast<int>(pemPub.size())));
  ASSERT_TRUE(bio);

  auto key = so::make_unique(PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(key);

  // WHEN
  const auto actualPemPub = evp::convertPubKeyToPem(*key);

  // THEN
  ASSERT_TRUE(actualPemPub);
  EXPECT_EQ(pemPub, actualPemPub.value);
}

TEST(EvpKeyUT, pubKeyToPemConversion_shouldSuccessWithPrivKey)
{
  // GIVEN
  const auto pemPriv = data::evpPrivKey;
  auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPriv.c_str()), static_cast<int>(pemPriv.size())));
  ASSERT_TRUE(bio);

  auto key = so::make_unique(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(key);

  // WHEN
  const auto actualPemPub = evp::convertPubKeyToPem(*key);

  // THEN
  EXPECT_TRUE(actualPemPub);
  EXPECT_EQ(data::evpPubKey, actualPemPub.value);
}

TEST(EvpKeyUT, getKeyType)
{
  // GIVEN
  auto maybeCert = x509::convertPemToX509(data::selfSignedCAPemCert.c_str(), data::selfSignedCAPemCert.size());
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

