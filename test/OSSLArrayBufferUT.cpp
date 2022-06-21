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

namespace so { namespace ut { namespace osslarraybuffer {

struct Type
{
  Type()
    : x{0}, y{0}
  { log << "Type ctor"; }

  ~Type() { log << "Type dtor"; }

  int x{0},y{0};
};

TEST(OSSLArrayBuffer, ArrayBuffer_TryCustomType)
{
  using TypeArray = internal::OSSLArrayBuffer<Type>;
  
  TypeArray ta(3);
 
  for(const auto &el : ta)
  {
    EXPECT_EQ(0, el.x);
    EXPECT_EQ(0, el.y);
  }

 // log << "built in";
//  auto *ta2 = new Type[3];
//  (void)ta2;
}

/*
TEST(OSSLArrayBuffer, StringBuffer)
{
  so::StringBuffer str = {'c', 'a', 'b'};
  std::stringstream ss;
  // ss << str;
  
  std::cout << str;

}
*/

}}} // so::ut::osslarraybuffer
