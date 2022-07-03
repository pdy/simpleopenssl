/*
* Copyright (c) 2022 Pawel Drzycimski
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
#include <algorithm>
#include <numeric>
#include <gtest/gtest.h>
#include <simpleopenssl/simpleopenssl.hpp>

#include "../precalculated.h"


namespace so { namespace ut { namespace rsa {

namespace rsa = ::so::rsa;

TEST(RsaKeyConversionsUT, pem2PubKeyConversion_shouldSuccess)
{
  // WHEN
  auto maybeKey = rsa::convertPemToPubKey(data::rsa3072PubKeyPem);

  // THEN
  EXPECT_TRUE(maybeKey);
}

TEST(RsaKeyConversionsUT, pem2PubKeyConversion_shouldFailWithInvalidPemFormat)
{
  // GIVEN
  const std::string incorrectPem = data::rsa3072PubKeyPem.substr(1);

  // WHEN
  auto maybeKey = rsa::convertPemToPubKey(incorrectPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(RsaKeyConversionsUT, pem2PubKeyConversion_shouldFailWithPrivKey)
{
  // WHEN
  auto maybeKey = rsa::convertPemToPubKey(data::rsa3072PrivKeyPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(RsaKeyConversionsUT, pem2PrivKeyConversion_shouldSuccess)
{
  // WHEN
  auto maybeKey = rsa::convertPemToPrivKey(data::rsa3072PrivKeyPem);

  // THEN
  EXPECT_TRUE(maybeKey);
}

TEST(RsaKeyConversionsUT, pem2PrivKeyConversion_shouldFailWithInvalidPemFormat)
{
  // GIVEN
  const std::string incorrectPem = data::rsa3072PrivKeyPem.substr(1);

  // WHEN
  auto maybeKey = rsa::convertPemToPrivKey(incorrectPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(RsaKeyConversionsUT, pem2PrivKeyConversion_shouldFailWithPubKey)
{
  // WHEN
  auto maybeKey = rsa::convertPemToPrivKey(data::rsa3072PubKeyPem);

  // THEN
  EXPECT_FALSE(maybeKey);
}

TEST(RsaKeyConversionsUT, privKey2PemConversion_ok)
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
  EXPECT_EQ(pemPriv, maybePemPriv.value); 
}

TEST(RsaKeyConversionsUT, pubKey2PemConversion_ok)
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
  EXPECT_EQ(pemPub, maybePemPub.value); 
}

TEST(RsaKeyConversionsUT, privKey2PemConversion_shouldFailWhenGivenPubKey)
{
  // GIVEN
  const auto pemPub = data::rsa3072PubKeyPem;
  auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPub.c_str()), static_cast<int>(pemPub.size())));
  ASSERT_TRUE(bio);

  auto key = make_unique(PEM_read_bio_RSA_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(key);

  // WHEN
  const auto maybePemPriv = rsa::convertPrivKeyToPem(*key);

  // THEN
  EXPECT_FALSE(maybePemPriv);
}

TEST(RsaKeyConversionsUT, pubKey2PemConversion_shouldSuccessWhenGivenPrivKey)
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
  ASSERT_TRUE(maybePemPub);
  EXPECT_EQ(data::rsa3072PubKeyPem, maybePemPub.value); 
}

TEST(RsaKeyConversionsUT, privKey2DerConversion_ok)
{
  // GIVEN
  const auto pemPriv= data::rsa3072PrivKeyPem;
  auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPriv.c_str()), static_cast<int>(pemPriv.size())));
  ASSERT_TRUE(bio);

  auto key = make_unique(PEM_read_bio_RSAPrivateKey(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(key);

  // WHEN
  const auto maybeDerPriv = rsa::convertPrivKeyToDer(*key);

  // THEN
  ASSERT_TRUE(maybeDerPriv);
  EXPECT_EQ(data::rsa3072PrivKeyDer, maybeDerPriv.value);
}

TEST(RsaKeyConversionsUT, derToPrivKeyConversion_ok)
{
  // WHEN
  auto maybePrivKey = rsa::convertDerToPrivKey(data::rsa3072PrivKeyDer.data(), data::rsa3072PrivKeyDer.size());
  auto maybePrivKey_2 = rsa::convertDerToPrivKey(data::rsa3072PrivKeyDer.data(), data::rsa3072PrivKeyDer.size());

  // THEN
  ASSERT_TRUE(maybePrivKey);
  auto privKey = maybePrivKey.moveValue();
  EXPECT_EQ(1, RSA_check_key(privKey.get()));

  ASSERT_TRUE(maybePrivKey_2);
  EXPECT_EQ(1, RSA_check_key(maybePrivKey_2.value.get()));
}

TEST(RsaKeyConversionsUT, derToPrivKeyConversion_shouldFailWhenPubKeyGiven)
{
  // WHEN
  auto maybePrivKey = rsa::convertDerToPrivKey(data::rsa3072PubKeyDer.data(), data::rsa3072PubKeyDer.size());
  auto maybePrivKey_2 = rsa::convertDerToPrivKey(data::rsa3072PubKeyDer.data(), data::rsa3072PubKeyDer.size());

  // THEN
  EXPECT_FALSE(maybePrivKey);
  EXPECT_FALSE(maybePrivKey_2);
}

TEST(RsaKeyConversionsUT, pubKey2DerConversion_FromPemPub)
{
  // GIVEN
  const auto pemPub = data::rsa3072PubKeyPem;
  auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPub.c_str()), static_cast<int>(pemPub.size())));
  ASSERT_TRUE(bio);

  auto key = make_unique(PEM_read_bio_RSA_PUBKEY(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(key);

  // WHEN
  const auto maybeDerPub = rsa::convertPubKeyToDer(*key);

  // THEN
  ASSERT_TRUE(maybeDerPub);
  EXPECT_EQ(data::rsa3072PubKeyDer, maybeDerPub.value);
}

TEST(RsaKeyConversionsUT, pubKey2DerConversion_FromDerPriv)
{
  const auto derPriv = data::rsa3072PrivKeyDer;
  const uint8_t *it = derPriv.data();
  auto priv = make_unique(d2i_RSAPrivateKey(nullptr, &it, static_cast<long>(derPriv.size())));
  ASSERT_TRUE(it);

  // WHEN
  auto pub = rsa::convertPubKeyToDer(*priv);

  // THEN
  ASSERT_TRUE(pub);
  EXPECT_EQ(data::rsa3072PubKeyDer, pub.value);
}

TEST(RsaKeyConversionsUT, derToPubKeyConversion_ok)
{
  // WHEN
  auto maybePubKey = rsa::convertDerToPubKey(data::rsa3072PubKeyDer.data(), data::rsa3072PubKeyDer.size());
  auto maybePubKey_2 = rsa::convertDerToPubKey(data::rsa3072PubKeyDer.data(), data::rsa3072PubKeyDer.size());

  // THEN
  EXPECT_TRUE(maybePubKey);
  EXPECT_TRUE(maybePubKey_2);
}

TEST(RsaKeyConversionsUT, pubKeyDerFromPriv)
{
  // GIVEN
  const auto pemPriv= data::rsa3072PrivKeyPem;
  auto bio = make_unique(BIO_new_mem_buf(static_cast<const void*>(pemPriv.c_str()), static_cast<int>(pemPriv.size())));
  ASSERT_TRUE(bio);

  auto key = make_unique(PEM_read_bio_RSAPrivateKey(bio.get(), nullptr, nullptr, nullptr));
  ASSERT_TRUE(key);

  // WHEN
  const auto pub = rsa::convertPubKeyToDer(*key);

  // THEN
  ASSERT_TRUE(pub);
  EXPECT_EQ(data::rsa3072PubKeyDer, pub.value); 
}

}}} // so::ut::rsa
