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

#include <gtest/gtest.h>
#include <simpleopenssl/simpleopenssl.hpp>
#include <numeric>
#include "utils.h"

namespace so { namespace ut { namespace bignum {

namespace bignum = ::so::bignum;

TEST(BignumUT, convertersAPIIntegrityShouldSuccess)
{
  constexpr size_t SIZE = 20;

  so::ByteBuffer buffer(SIZE);
  std::iota(buffer.begin(), buffer.end(), 0x7f);

  auto maybeBignum = bignum::convertToBignum(buffer);
  ASSERT_TRUE(maybeBignum);
  auto bignum = maybeBignum.moveValue();
  ASSERT_EQ(SIZE, bignum::getByteLen(*bignum).value);

  auto maybeReturnedBuffer = bignum::convertToByteBuffer(*bignum);
  ASSERT_TRUE(maybeReturnedBuffer);
  auto returnedBuffer = maybeReturnedBuffer.moveValue();
  ASSERT_EQ(SIZE, returnedBuffer.size());

  EXPECT_EQ(buffer, returnedBuffer);
}

}}} // namespace so { namespace ut { namespace bignum {
