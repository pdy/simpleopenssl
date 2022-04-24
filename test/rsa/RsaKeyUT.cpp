/*
* Copyright (c) 2018 Pawel Drzycimski
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
#include <simpleopenssl/simpleopenssl.h>

#include "../precalculated.h"


namespace so { namespace ut { namespace rsa {

namespace rsa = ::so::rsa;

namespace {
inline bool operator==(const Bytes &lhs, const Bytes &rhs)
{
  if(lhs.size() == rhs.size())
    return std::equal(lhs.begin(), lhs.end(), rhs.begin());

  return false;
}
} // anonymouns namespace

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
  EXPECT_EQ(pemPriv, maybePemPriv.value); 
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
  EXPECT_EQ(pemPub, maybePemPub.value); 
}

TEST(RsaKeyUT, privKey2PemConversion_shouldFailWhenGivenPubKey)
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
  EXPECT_EQ(data::rsa3072PubKeyPem, maybePemPub.value); 
}

TEST(RsaKeyUT, privKey2DerConversion_ok)
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

TEST(RsaKeyUT, derToPrivKeyConversion_ok)
{
  // WHEN
  auto maybePrivKey = rsa::convertDerToPrivKey(data::rsa3072PrivKeyDer);
  auto maybePrivKey_2 = rsa::convertDerToPrivKey(data::rsa3072PrivKeyDer.data(), data::rsa3072PrivKeyDer.size());

  // THEN
  ASSERT_TRUE(maybePrivKey);
  auto privKey = maybePrivKey.moveValue();
  EXPECT_EQ(1, RSA_check_key(privKey.get()));

  ASSERT_TRUE(maybePrivKey_2);
  EXPECT_EQ(1, RSA_check_key(maybePrivKey_2.value.get()));
}

TEST(RsaKeyUT, derToPrivKeyConversion_shouldFailWhenPubKeyGiven)
{
  // WHEN
  auto maybePrivKey = rsa::convertDerToPrivKey(data::rsa3072PubKeyDer);
  auto maybePrivKey_2 = rsa::convertDerToPrivKey(data::rsa3072PubKeyDer.data(), data::rsa3072PubKeyDer.size());

  // THEN
  EXPECT_FALSE(maybePrivKey);
  EXPECT_FALSE(maybePrivKey_2);
}

TEST(RsaKeyUT, pubKey2DerConversion_ok)
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

TEST(RsaKeyUT, derToPubKeyConversion_ok)
{
  // WHEN
  auto maybePubKey = rsa::convertDerToPubKey(data::rsa3072PubKeyDer);
  auto maybePubKey_2 = rsa::convertDerToPubKey(data::rsa3072PubKeyDer.data(), data::rsa3072PubKeyDer.size());

  // THEN
  EXPECT_TRUE(maybePubKey);
  EXPECT_TRUE(maybePubKey_2);
}

TEST(RsaKeyUT, extractPublicKeyOK)
{
  // GIVEN
  auto maybePriv = rsa::create(rsa::KeyBits::_2048_);
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
  const auto verResult = rsa::verifySha256Signature(signResult.value, data, *pub);
  // THEN
  ASSERT_TRUE(verResult);
  EXPECT_TRUE(verResult.value);
}

TEST(RsaKeyUT, extractPublicPartFromFreshStructureShouldFail)
{
  // GIVEN
  auto key = ::so::make_unique(RSA_new()); 

  // WHEN
  const auto result = rsa::getPublic(*key);
  
  // THEN
  EXPECT_FALSE(result);
}

TEST(RsaKeyUT, extractedPublicKeyCantBeUsedForSign)
{
  // GIVEN
  auto maybePriv = rsa::create(rsa::KeyBits::_2048_);
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
  auto maybeKey = rsa::create(rsa::KeyBits::_2048_);
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

TEST(RsaKeyUT, getKeyBitsOK)
{
  // GIVEN
  auto maybeKey = rsa::create(rsa::KeyBits::_2048_);
  ASSERT_TRUE(maybeKey);
  auto key = maybeKey.moveValue();
 
  // WHEN
  const auto result = rsa::getKeyBits(*key);

  // THEN
  ASSERT_TRUE(result);
  EXPECT_EQ(rsa::KeyBits::_2048_, result.value);
}

TEST(RsaKeyUT, getKeyBitsFromFreshStructShouldFail)
{
  // GIVEN
  auto key = ::so::make_unique(RSA_new()); 

  // WHEN
  const auto result = rsa::getKeyBits(*key);
  
  // THEN
  EXPECT_FALSE(result);
}

}}} // namespace so { namespace ut { namespace rsa {
