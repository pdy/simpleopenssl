#include <gtest/gtest.h>
#include <simpleopenssl/simpleopenssl.h>

namespace so { namespace ut { namespace rsa {

namespace rsa = ::so::rsa;

struct KeyGenTestInput
{
  rsa::KeySize keySize;
  rsa::Exponent exponent;
};

class RsaKeyGenUT : public ::testing::TestWithParam<KeyGenTestInput>
{};

TEST_P(RsaKeyGenUT, shouldGenerateAndPassChecks)
{
  const auto input = GetParam();
  
  auto maybeKey = rsa::generateKey(input.keySize, input.exponent);
  ASSERT_TRUE(maybeKey);
  
  auto key = maybeKey.moveValue();

//  const auto curve = rsa::getCurve(*key);
 // ASSERT_TRUE(curve);
  ASSERT_EQ(1, RSA_check_key_ex(key.get(), nullptr));
//  EXPECT_EQ(input.curve, *curve);
//  EXPECT_EQ(input.opensslNid, static_cast<int>(*curve));
}


INSTANTIATE_TEST_CASE_P(
    Rsa,
    RsaKeyGenUT,
    ::testing::Values(
      KeyGenTestInput{ rsa::KeySize::_1024_, rsa::Exponent::_3_ },
      KeyGenTestInput{ rsa::KeySize::_1024_, rsa::Exponent::_17_ },
      KeyGenTestInput{ rsa::KeySize::_1024_, rsa::Exponent::_65537_ },

      KeyGenTestInput{ rsa::KeySize::_2048_, rsa::Exponent::_3_ },
      KeyGenTestInput{ rsa::KeySize::_2048_, rsa::Exponent::_17_ },
      KeyGenTestInput{ rsa::KeySize::_2048_, rsa::Exponent::_65537_ },

      KeyGenTestInput{ rsa::KeySize::_3072_, rsa::Exponent::_3_ },
      KeyGenTestInput{ rsa::KeySize::_3072_, rsa::Exponent::_17_ },
      KeyGenTestInput{ rsa::KeySize::_3072_, rsa::Exponent::_65537_ }/*,

      // anything below takes too much time to have it run every time
      KeyGenTestInput{ rsa::KeySize::_4096_, rsa::Exponent::_3_ },
      KeyGenTestInput{ rsa::KeySize::_4096_, rsa::Exponent::_17_ },
      KeyGenTestInput{ rsa::KeySize::_4096_, rsa::Exponent::_65537_ } 
      */
    )
);

}}} // namespace so { namespace ut { namespace rsa {
