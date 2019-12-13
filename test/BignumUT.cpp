#include <gtest/gtest.h>
#include <simpleopenssl/simpleopenssl.h>
#include <numeric>
#include "utils.h"
namespace so { namespace ut { namespace bignum {

namespace bignum = ::so::bignum;

TEST(BignumUT, convertersAPIIntegrityShouldSuccess)
{
  constexpr size_t SIZE = 20;

  std::vector<uint8_t> buffer(SIZE);
  std::iota(buffer.begin(), buffer.end(), 0x7f);

  auto maybeBignum = bignum::convertToBignum(buffer);
  ASSERT_TRUE(maybeBignum);
  auto bignum = maybeBignum.moveValue();
  ASSERT_EQ(SIZE, *bignum::getByteLen(*bignum));

  auto maybeReturnedBuffer = bignum::convertToBytes(*bignum);
  ASSERT_TRUE(maybeReturnedBuffer);
  auto returnedBuffer = *maybeReturnedBuffer;
  ASSERT_EQ(SIZE, returnedBuffer.size());

  EXPECT_EQ(buffer, returnedBuffer);
}

}}} // namespace so { namespace ut { namespace bignum {
