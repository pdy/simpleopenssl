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

namespace so { namespace ut { namespace rsa {

namespace rsa = ::so::rsa;

struct KeyGenTestInput
{
  rsa::KeyBits keyBits;
  rsa::Exponent exponent;
};

class RsaKeyGenUT : public ::testing::TestWithParam<KeyGenTestInput>
{};

TEST_P(RsaKeyGenUT, shouldGenerateAndPassChecks)
{
  // GIVEN
  const auto input = GetParam();
  
  // WHEN
  auto maybeKey = rsa::create(input.keyBits, input.exponent);
  ASSERT_TRUE(maybeKey);
  
  auto key = maybeKey.moveValue();

  // THEN
  const auto keyBits = static_cast<rsa::KeyBits>(RSA_bits(key.get()));
  ASSERT_EQ(1, RSA_check_key_ex(key.get(), nullptr));
  EXPECT_EQ(input.keyBits, keyBits);
}


INSTANTIATE_TEST_CASE_P(
    Rsa,
    RsaKeyGenUT,
    ::testing::Values(
      KeyGenTestInput{ rsa::KeyBits::_1024_, rsa::Exponent::_3_ },
      KeyGenTestInput{ rsa::KeyBits::_1024_, rsa::Exponent::_17_ },
      KeyGenTestInput{ rsa::KeyBits::_1024_, rsa::Exponent::_65537_ },

      KeyGenTestInput{ rsa::KeyBits::_2048_, rsa::Exponent::_3_ },
      KeyGenTestInput{ rsa::KeyBits::_2048_, rsa::Exponent::_17_ },
      KeyGenTestInput{ rsa::KeyBits::_2048_, rsa::Exponent::_65537_ }/*,
      
      // anything below takes too much time to have it run every time

      KeyGenTestInput{ rsa::KeyBits::_3072_, rsa::Exponent::_3_ },
      KeyGenTestInput{ rsa::KeyBits::_3072_, rsa::Exponent::_17_ },
      KeyGenTestInput{ rsa::KeyBits::_3072_, rsa::Exponent::_65537_ },

      KeyGenTestInput{ rsa::KeyBits::_4096_, rsa::Exponent::_3_ },
      KeyGenTestInput{ rsa::KeyBits::_4096_, rsa::Exponent::_17_ },
      KeyGenTestInput{ rsa::KeyBits::_4096_, rsa::Exponent::_65537_ },

      KeyGenTestInput{ rsa::KeyBits::_5120_, rsa::Exponent::_3_ },
      KeyGenTestInput{ rsa::KeyBits::_5120_, rsa::Exponent::_17_ },
      KeyGenTestInput{ rsa::KeyBits::_5120_, rsa::Exponent::_65537_ },

      KeyGenTestInput{ rsa::KeyBits::_6144_, rsa::Exponent::_3_ },
      KeyGenTestInput{ rsa::KeyBits::_6144_, rsa::Exponent::_17_ },
      KeyGenTestInput{ rsa::KeyBits::_6144_, rsa::Exponent::_65537_ },

      KeyGenTestInput{ rsa::KeyBits::_7168_, rsa::Exponent::_3_ },
      KeyGenTestInput{ rsa::KeyBits::_7168_, rsa::Exponent::_17_ },
      KeyGenTestInput{ rsa::KeyBits::_7168_, rsa::Exponent::_65537_ }
      */
      
    )
);

}}} // namespace so { namespace ut { namespace rsa {
