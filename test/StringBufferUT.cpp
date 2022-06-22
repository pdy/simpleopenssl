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
#include "utils.h"

namespace so { namespace ut { namespace stringbuffer {

namespace {
  
  template<size_t N>
  StringBuffer initSB(const char(&arr)[N])
  {
    StringBuffer ret(N);
    for(size_t i = 0; i < N; ++i)
      ret[i] = arr[i];

    return ret;
  }

} // namespace

TEST(StringBuffer, CheckTypes)
{
  EXPECT_TRUE((std::is_same<typename StringBuffer::value_type, char>::value));
  EXPECT_TRUE((std::is_same<typename StringBuffer::size_type, size_t>::value));
  EXPECT_TRUE((std::is_same<typename StringBuffer::pointer_type, char*>::value));
  EXPECT_TRUE((std::is_same<typename StringBuffer::memory_type, char*>::value));
  EXPECT_TRUE((std::is_const<typename StringBuffer::const_iterator>::value));
}

TEST(StringBuffer, DefaultCtor)
{
  StringBuffer buff;

  EXPECT_EQ(0, buff.capacity());
  EXPECT_EQ(0, buff.size());
  EXPECT_TRUE(buff.get() == nullptr);
  EXPECT_TRUE(buff.data() == nullptr);
  EXPECT_FALSE(buff);
  EXPECT_EQ(buff.begin(), buff.end());
}

TEST(StringBuffer, CreateBuffer)
{
  StringBuffer buff(3);

  ASSERT_TRUE(buff);
  EXPECT_EQ(3, buff.capacity());
  EXPECT_EQ(3, buff.size());
  EXPECT_TRUE(buff.get() != nullptr);
  EXPECT_TRUE(buff.data() != nullptr);
}

TEST(StringBuffer, InitializerRelease)
{
  StringBuffer buff = {0x01, 0x02, 0x03};
  
  ASSERT_TRUE(buff);
  EXPECT_EQ(3, buff.capacity());
  EXPECT_EQ(3, buff.size());
  EXPECT_TRUE(buff.get() != nullptr);
  EXPECT_TRUE(buff.data() != nullptr);

  EXPECT_EQ(0x01, buff[0]);
  EXPECT_EQ(0x02, buff[1]);
  EXPECT_EQ(0x03, buff[2]);
}

TEST(StringBuffer, CopyCtor)
{
  static constexpr char ARR[] = {0x01, 0x02, 0x03};
  StringBuffer buff = initSB(ARR);

  StringBuffer copy(buff);

  ASSERT_TRUE(copy);
  EXPECT_EQ(3, copy.capacity());
  EXPECT_EQ(3, copy.size());
  EXPECT_TRUE(copy.get() != nullptr);
  EXPECT_TRUE(copy.data() != nullptr);

  EXPECT_EQ(buff, copy);
}

TEST(StringBuffer, IteratorCopyCtor)
{
  static constexpr char ARR[] = {0x01, 0x02, 0x03};
  StringBuffer buff = initSB(ARR);

  StringBuffer copy(buff.begin(), buff.end());

  ASSERT_TRUE(copy);
  EXPECT_EQ(3, copy.capacity());
  EXPECT_EQ(3, copy.size());
  EXPECT_TRUE(copy.get() != nullptr);
  EXPECT_TRUE(copy.data() != nullptr);

  EXPECT_EQ(buff, copy);
}

TEST(StringBuffer, IteratorSizeCopyCtor)
{
  static constexpr char ARR[] = {0x01, 0x02, 0x03};
  StringBuffer buff = initSB(ARR);

  StringBuffer copy(buff.begin(), buff.size());

  ASSERT_TRUE(copy);
  EXPECT_EQ(3, copy.capacity());
  EXPECT_EQ(3, copy.size());
  EXPECT_TRUE(copy.get() != nullptr);
  EXPECT_TRUE(copy.data() != nullptr);

  EXPECT_EQ(buff, copy);
}

TEST(StringBuffer, MoveCtor)
{
  static constexpr char ARR[] = {0x01, 0x02, 0x03};
  StringBuffer buff = initSB(ARR);

  StringBuffer copy(std::move(buff));

  ASSERT_TRUE(copy);
  EXPECT_EQ(3, copy.capacity());
  EXPECT_EQ(3, copy.size());
  EXPECT_TRUE(copy.get() != nullptr);
  EXPECT_TRUE(copy.data() != nullptr);
}

TEST(StringBuffer, CopyWithBegin)
{
  const char ARRAY[3] = {0x01, 0x02, 0x03};
  StringBuffer buff(3);

  ASSERT_TRUE(buff);
  EXPECT_EQ(3, buff.capacity());
  EXPECT_EQ(3, buff.size());
  EXPECT_TRUE(buff.get() != nullptr);
  EXPECT_TRUE(buff.data() != nullptr);
  
  std::copy_n(std::begin(ARRAY), 3, buff.begin());

  ASSERT_TRUE(buff);
  EXPECT_EQ(3, buff.capacity());
  EXPECT_EQ(3, buff.size());
  EXPECT_TRUE(buff.get() != nullptr);
  EXPECT_TRUE(buff.data() != nullptr);
  EXPECT_TRUE(utils::equals(ARRAY, buff));
}

TEST(StringBuffer, ReserveAndPushBackCopy)
{
  const char ARRAY[3] = {0x01, 0x02, 0x03};
  StringBuffer buff; buff.reserve(3);

  ASSERT_TRUE(buff);
  EXPECT_EQ(3, buff.capacity());
  EXPECT_EQ(0, buff.size());
  EXPECT_TRUE(buff.get() != nullptr);
  EXPECT_TRUE(buff.data() != nullptr);
  
  for(size_t i = 0; i < 3; ++i)
    buff.push_back(ARRAY[i]);

  ASSERT_TRUE(buff);
  EXPECT_EQ(3, buff.capacity());
  EXPECT_EQ(3, buff.size());
  EXPECT_TRUE(buff.get() != nullptr);
  EXPECT_TRUE(buff.data() != nullptr);
  EXPECT_TRUE(utils::equals(ARRAY, buff));
}

TEST(StringBuffer, ReserveAndBackInserter)
{
  const char ARRAY[3] = {0x01, 0x02, 0x03};
  StringBuffer buff; buff.reserve(3);

  ASSERT_TRUE(buff);
  EXPECT_EQ(3, buff.capacity());
  EXPECT_EQ(0, buff.size());
  EXPECT_TRUE(buff.get() != nullptr);
  EXPECT_TRUE(buff.data() != nullptr);
  
  std::copy_n(std::begin(ARRAY), 3, std::back_inserter(buff));

  ASSERT_TRUE(buff);
  EXPECT_EQ(3, buff.capacity());
  EXPECT_EQ(3, buff.size());
  EXPECT_TRUE(buff.get() != nullptr);
  EXPECT_TRUE(buff.data() != nullptr);
  EXPECT_TRUE(utils::equals(ARRAY, buff));
}

TEST(StringBuffer, TakeResource)
{
  char *rc = reinterpret_cast<char*>(OPENSSL_malloc(3));
  rc[0] = 0x01;
  rc[1] = 0x02;
  rc[2] = 0x03;

  auto bt = StringBuffer::take(rc, 3);

  ASSERT_EQ(3, bt.size());
  EXPECT_TRUE(utils::equals(rc, 3, bt));
}

TEST(StringBuffer, SquareBracketAssign)
{
  // GIVEN
  const char ARRAY[] = {0x01, 0x01, 0x03};

  // WHEN
  StringBuffer buff(3);
  ASSERT_TRUE(buff);
  ASSERT_EQ(3, buff.size());
  for(size_t i = 0; i < 3; ++i)
    buff[i] = ARRAY[i];

  // THEN
  EXPECT_TRUE(utils::equals(ARRAY, buff));
}

TEST(StringBuffer, Release)
{
  StringBuffer tmp = {0x01, 0x02, 0x03};

  ASSERT_TRUE(tmp);
  EXPECT_EQ(3, tmp.capacity());
  EXPECT_EQ(3, tmp.size());
  EXPECT_TRUE(tmp.get() != nullptr);
  EXPECT_TRUE(tmp.data() != nullptr);

  const auto size = tmp.size();
  StringBuffer buff = StringBuffer::take(tmp.release(), size);

  EXPECT_FALSE(tmp);
  EXPECT_EQ(0, tmp.capacity());
  EXPECT_EQ(0, tmp.size());
  EXPECT_TRUE(tmp.get() == nullptr);
  EXPECT_TRUE(tmp.data() == nullptr);

  ASSERT_TRUE(buff);
  EXPECT_EQ(3, buff.capacity());
  EXPECT_EQ(3, buff.size());
  EXPECT_TRUE(buff.get() != nullptr);
  EXPECT_TRUE(buff.data() != nullptr);

  EXPECT_TRUE(utils::equals({0x01, 0x02, 0x03}, buff));
}

}}} // so::ut::bytebuffer
