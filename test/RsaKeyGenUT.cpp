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
  auto maybeKey = rsa::generateKey(input.keyBits, input.exponent);
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
