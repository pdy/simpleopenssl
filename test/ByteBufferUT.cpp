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

template<size_t SIZE>
static bool equal(const uint8_t (&arr)[SIZE], const so::ByteBuffer &buff)
{
  if(buff && !arr)
    return false;

  if(!buff && arr)
    return false;

  for(size_t i = 0; i < SIZE; ++i)
    if(buff.memory[i] != arr[i])
      return false;

  return true;
}

TEST(ByteBuffer, create)
{
  // GIVEN
  const uint8_t ARRAY[] = {0x01, 0x01, 0x03};

  // WHEN
  ByteBuffer buff = ByteBuffer::create(3);
  ASSERT_TRUE(buff);
  for(size_t i = 0; i < 3; ++i)
    buff.memory[i] = ARRAY[i];

  // THEN
  EXPECT_TRUE(equal(ARRAY, buff));
}

}}} // so::ut::bytebuffer
