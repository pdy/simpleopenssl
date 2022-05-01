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

#include <vector>
#include <numeric>
#include <gtest/gtest.h>
#include <simpleopenssl/simpleopenssl.h>

#include "../precalculated.h"
#include "../utils.h"

namespace so { namespace ut { namespace ecdsa {

namespace ecdsa = ::so::ecdsa;

TEST(EcdsaKeyConversionsUT, pem2PubKeyConversion_shouldSuccess)
{
  // WHEN
  auto maybeKey = ecdsa::convertPemToPubKey(data::secp256PubKeyPem);

  // THEN
  EXPECT_TRUE(maybeKey);
}

TEST(EcdsaKeyConversionsUT, pem2PubKeyConversion_shouldFailWithInvalidPemFormat)
{
  // GIVEN
  const std::string incorrectPem = data::secp256PubKeyPem.substr(1);

  // WHEN
  auto maybeKey = ecdsa::convertPemToPubKey(incorrectPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(EcdsaKeyConversionsUT, pem2PubKeyConversion_shouldFailWithPrivKey)
{
  // WHEN
  auto maybeKey = ecdsa::convertPemToPubKey(data::secp256k1PrivKeyPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(EcdsaKeyConversionsUT, pem2PrivKeyConversion_shouldSuccess)
{
  // WHEN
  auto maybeKey = ecdsa::convertPemToPrivKey(data::secp256k1PrivKeyPem);

  // THEN
  EXPECT_TRUE(maybeKey);
}

TEST(EcdsaKeyConversionsUT, pem2PrivKeyConversion_shouldFailWithInvalidPemFormat)
{
  // GIVEN
  const std::string incorrectPem = data::secp256k1PrivKeyPem.substr(1);

  // WHEN
  auto maybeKey = ecdsa::convertPemToPrivKey(incorrectPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(EcdsaKeyConversionsUT, pem2PrivKeyConversion_shouldFailWithPubKey)
{
  // WHEN
  auto maybeKey = ecdsa::convertPemToPrivKey(data::secp256PubKeyPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(EcdsaKeyConversionsUT, privKey2PemConversion_ok)
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
  EXPECT_EQ(pemPriv, maybePemPriv.value); 
}

TEST(EcdsaKeyConversionsUT, pubKey2PemConversion_ok)
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
  EXPECT_EQ(pemPub, maybePemPub.value); 
}

TEST(EcdsaKeyConversionsUT, pubKeyFromPemPriv)
{
  // GIVEN
  const auto pemPriv= data::secp256k1PrivKeyPem;
  auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPriv.c_str()), static_cast<int>(pemPriv.size())));
  ASSERT_TRUE(bio);

  auto key = make_unique(PEM_read_bio_ECPrivateKey(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(key);

  // WHEN
  const auto pub = ecdsa::convertPubKeyToPem(*key);

  // THEN
  ASSERT_TRUE(pub);
  EXPECT_EQ(data::secp256PubKeyPem, pub.value); 
}

TEST(EcdsaKeyConversionsUT, privKey2DerConversion_ok)
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
  EXPECT_EQ(data::secp256k1PrivKeyDer, maybeDerPriv.value);
}

TEST(EcdsaKeyConversionsUT, derToPrivKeyConversion_ok)
{
  // WHEN
  auto maybePrivKey = ecdsa::convertDerToPrivKey(data::secp256k1PrivKeyDer);

  // THEN
  ASSERT_TRUE(maybePrivKey);
  auto privKey = maybePrivKey.moveValue();
  EXPECT_EQ(1, EC_KEY_check_key(privKey.get()));
}

TEST(EcdsaKeyConversionsUT, derToPrivKeyConversion_shouldFailWhenPubKeyGiven)
{
  // WHEN
  auto maybePrivKey = rsa::convertDerToPrivKey(data::secp256PubKeyDer);

  // THEN
  ASSERT_FALSE(maybePrivKey);
}

TEST(EcdsaKeyConversionsUT, pubKey2DerConversion_ok)
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
  EXPECT_EQ(data::secp256PubKeyDer, maybeDerPub.value);
}

TEST(EcdsaKeyConversionsUT, derToPubKeyConversion_ok)
{
  // WHEN
  auto maybePubKey = ecdsa::convertDerToPubKey(data::secp256PubKeyDer);

  // THEN
  ASSERT_TRUE(maybePubKey);
}

TEST(EcdsaKeyConversionsUT, pubKeyDerFromPrivDer)
{
  // GIVEN
  const auto pemPriv = data::secp256k1PrivKeyPem;
  auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPriv.c_str()), static_cast<int>(pemPriv.size())));
  ASSERT_TRUE(bio);

  auto key = make_unique(PEM_read_bio_ECPrivateKey(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(key);

  // WHEN
  const auto pub = ecdsa::convertPubKeyToDer(*key);

  // THEN
  ASSERT_TRUE(pub);
  EXPECT_EQ(data::secp256PubKeyDer, pub.value);
}

}}} // so::ut::ecdsa

