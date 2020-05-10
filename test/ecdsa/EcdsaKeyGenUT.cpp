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

#include <gtest/gtest.h>
#include <simpleopenssl/simpleopenssl.h>

namespace so { namespace ut { namespace ecdsa {

namespace ecdsa = ::so::ecdsa;

struct KeyGenTestInput
{
  ecdsa::Curve curve;
  int opensslNid;
};

class EcdsaKeyGenUT : public ::testing::TestWithParam<KeyGenTestInput>
{};

TEST_P(EcdsaKeyGenUT, shouldExtractCurveInfoFromGeneratedKey)
{
  const auto input = GetParam();
  
  auto maybeKey = ecdsa::create(input.curve);
  ASSERT_TRUE(maybeKey);
  
  auto key = maybeKey.moveValue();

  const auto curve = ecdsa::getCurve(*key);
  ASSERT_TRUE(curve);
  ASSERT_EQ(1, EC_KEY_check_key(key.get()));
  EXPECT_EQ(input.curve, *curve);
  EXPECT_EQ(input.opensslNid, static_cast<int>(*curve));
}


INSTANTIATE_TEST_CASE_P(
    Ecdsa,
    EcdsaKeyGenUT,
    ::testing::Values(
      KeyGenTestInput{ ecdsa::Curve::secp112r1, NID_secp112r1 },
      KeyGenTestInput{ ecdsa::Curve::secp112r2, NID_secp112r2 },
      KeyGenTestInput{ ecdsa::Curve::secp128r1, NID_secp128r1 },
      KeyGenTestInput{ ecdsa::Curve::secp160k1, NID_secp160k1 },
      KeyGenTestInput{ ecdsa::Curve::secp160r1, NID_secp160r1 },
      KeyGenTestInput{ ecdsa::Curve::secp160r2, NID_secp160r2 },
      KeyGenTestInput{ ecdsa::Curve::secp192k1, NID_secp192k1 },
      KeyGenTestInput{ ecdsa::Curve::secp224k1, NID_secp224k1 },
      KeyGenTestInput{ ecdsa::Curve::secp224r1, NID_secp224r1 },
      KeyGenTestInput{ ecdsa::Curve::secp256k1, NID_secp256k1 },
      KeyGenTestInput{ ecdsa::Curve::secp384r1, NID_secp384r1 },
      KeyGenTestInput{ ecdsa::Curve::secp521r1, NID_secp521r1 }, 
      KeyGenTestInput{ ecdsa::Curve::sect113r1, NID_sect113r1 },
      KeyGenTestInput{ ecdsa::Curve::sect113r2, NID_sect113r2 },
      KeyGenTestInput{ ecdsa::Curve::sect131r1, NID_sect131r1 },
      KeyGenTestInput{ ecdsa::Curve::sect131r2, NID_sect131r2 },
      KeyGenTestInput{ ecdsa::Curve::sect163k1, NID_sect163k1 },
      KeyGenTestInput{ ecdsa::Curve::sect163r1, NID_sect163r1 },
      KeyGenTestInput{ ecdsa::Curve::sect163r2, NID_sect163r2 },
      KeyGenTestInput{ ecdsa::Curve::sect193r1, NID_sect193r1 },
      KeyGenTestInput{ ecdsa::Curve::sect193r2, NID_sect193r2 },
      KeyGenTestInput{ ecdsa::Curve::sect233k1, NID_sect233k1 },
      KeyGenTestInput{ ecdsa::Curve::sect233r1, NID_sect233r1 },
      KeyGenTestInput{ ecdsa::Curve::sect239k1, NID_sect239k1 },
      KeyGenTestInput{ ecdsa::Curve::sect283k1, NID_sect283k1 },
      KeyGenTestInput{ ecdsa::Curve::sect283r1, NID_sect283r1 },
      KeyGenTestInput{ ecdsa::Curve::sect409k1, NID_sect409k1 },
      KeyGenTestInput{ ecdsa::Curve::sect571k1, NID_sect571k1 },
      KeyGenTestInput{ ecdsa::Curve::sect571r1, NID_sect571r1 }
    )
);

}}}
