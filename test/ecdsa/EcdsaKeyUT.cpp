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


namespace so { namespace ut { namespace ecdsa {

namespace ecdsa = ::so::ecdsa;

TEST(EcdsaKeyUT, copyKey_shouldSuccess)
{
  // WHEN
  auto maybeKey = ecdsa::convertPemToPubKey(data::secp256PubKeyPem);
  ASSERT_TRUE(maybeKey);

  auto key = maybeKey.moveValue();
  auto copied = ecdsa::copyKey(*key);
  EXPECT_TRUE(copied);
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
  EXPECT_EQ(ecdsa::Curve::SECP256K1, actual.value);
}

TEST(EcdsaKeyUT, extractPublicKeyOK)
{
  // GIVEN
  auto maybePriv = ecdsa::create(ecdsa::Curve::SECP160R2);
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
  const auto verResult = ecdsa::verifySha256Signature(signResult.value, data, *pub);

  // THEN
  ASSERT_TRUE(verResult);
  EXPECT_TRUE(verResult.value);
}

TEST(EcdsaKeyUT, extractedPublicKeyCantBeUsedForSign)
{
  // GIVEN
  auto maybePriv = ecdsa::create(ecdsa::Curve::SECP160R2);
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
  auto maybeKey = ecdsa::create(ecdsa::Curve::SECP112R1);
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
  auto maybeKey = ecdsa::create(ecdsa::Curve::SECP112R1);
  ASSERT_TRUE(maybeKey);
  auto key = maybeKey.moveValue();
  
  // WHEN
  auto size = ecdsa::getKeySize(*key);
 
  // THEN 
  ASSERT_TRUE(size);
  EXPECT_EQ(112, size.value);
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
  const ecdsa::Curve curve = ecdsa::Curve::SECP112R2;

  const auto curveName = ecdsa::convertCurveToString(curve);

  ASSERT_TRUE(curveName);
  EXPECT_EQ("secp112r2", curveName.value );
}

}}} // namespace so { namespace ut { namespace ecdsa {
