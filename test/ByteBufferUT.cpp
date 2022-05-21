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

#include <gtest/gtest.h>
#include <simpleopenssl/simpleopenssl.h>
#include <numeric>
#include "utils.h"

namespace so { namespace ut { namespace bytebuffer {

TEST(ByteBuffer, osslByteBuffer)
{
  uint8_t *rc = reinterpret_cast<uint8_t*>(OPENSSL_malloc(3));
  rc[0] = 0x01;
  rc[1] = 0x02;
  rc[2] = 0x03;

  ::so::ByteBuffer bt(rc, 3);

  ASSERT_EQ(3, bt.size());
  EXPECT_TRUE(utils::equals(rc, 3, bt));
}

TEST(ByteBuffer, checkTypes)
{
  EXPECT_TRUE((std::is_same<typename ::so::ByteBuffer::value_type, uint8_t>::value));
  EXPECT_TRUE((std::is_same<typename ::so::ByteBuffer::size_type, size_t>::value));
  EXPECT_TRUE((std::is_same<typename ::so::ByteBuffer::pointer_type, uint8_t*>::value));
  EXPECT_TRUE((std::is_same<typename ::so::ByteBuffer::memory_type, std::unique_ptr<uint8_t[], ::so::internal::OSSLFreeDeleter<uint8_t>>>::value));
  EXPECT_TRUE((std::is_const<typename ::so::ByteBuffer::const_iterator>::value));
}

TEST(ByteBuffer, create)
{
  // GIVEN
  const uint8_t ARRAY[] = {0x01, 0x01, 0x03};

  // WHEN
  ByteBuffer buff(3);
  ASSERT_TRUE(buff);
  ASSERT_EQ(3, buff.size());
  for(size_t i = 0; i < 3; ++i)
    buff[i] = ARRAY[i];


  // THEN
  EXPECT_TRUE(utils::equals(ARRAY, buff));
}

}}} // so::ut::bytebuffer
