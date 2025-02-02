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
#include <simpleopenssl/simpleopenssl.hpp>

#include "../precalculated.h"

namespace so { namespace ut { namespace rsa {

namespace rsa = ::so::rsa;

TEST(RsaKeyUT, getPublic)
{
  // GIVEN
  auto key = rsa::convertDerToPrivKey(data::rsa3072PrivKeyDer.data(), data::rsa3072PrivKeyDer.size());
  ASSERT_TRUE(key);

  // WHEN
  auto pub = rsa::getPublic(*key.value);
  ASSERT_TRUE(pub);
  const auto pubDer = rsa::convertPubKeyToDer(*pub.value);

  // THEN
  ASSERT_TRUE(pubDer);
  EXPECT_EQ(data::rsa3072PubKeyDer, pubDer.value);
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
