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

#include <cmdline.h> 
#define SO_IMPLEMENTATION
#include <simpleopenssl/simpleopenssl.hpp>

#include <iostream>
#include <iomanip>

using namespace so;

Result<Bytes> makeHash(const std::string& filePath, const std::string &type);
std::string bin2Hex(const so::Bytes &buff);

int main(int argc, char *argv[])
{
  cmdline::parser arg;
  arg.add("help", 'h', "Print help.");
  arg.add<std::string>("file", 'f', "File to be hashed.", true);
  arg.add<std::string>("type", 't', "Type of hash [sha1, sha256, sha512].", false, "sha256");
    
  if(!arg.parse(argc, const_cast<const char* const*>(argv)))
  {
    const auto fullErr = arg.error_full();
    if(!fullErr.empty())
      std::cout << fullErr << '\n';
     
    std::cout << arg.usage() << '\n';
    return 0;
  }
  
  if(arg.exist("help"))
  {
    std::cout << arg.usage();
    return 0;
  } 

  if(!arg.exist("file"))
  {
    std::cout << "--file or -f argument is mandatory!\n";
    std::cout << arg.usage() << '\n';
    return 0;
  }

  const std::string file = arg.get<std::string>("file");
  const std::string hashType = arg.get<std::string>("type");
  const auto hash = makeHash(file, hashType);
  if(!hash)
    std::cout << "ERROR: " << hash.msg() << "\n";
  else
    std::cout << bin2Hex(hash.value) << "\n";
     
  return 0;
}

Result<Bytes> makeHash(const std::string& filePath, const std::string &type)
{
  if(type == "sha1")
    return hash::fileSHA1(filePath);
  else if(type == "sha256")
    return hash::fileSHA256(filePath);
  else if(type == "sha512")
    return hash::fileSHA512(filePath);

  return hash::fileSHA256(filePath);
}

std::string bin2Hex(const so::Bytes &buff)
{
  std::ostringstream oss;
  for(const auto bt : buff){
    oss << std::setfill('0') << std::setw(2) << std::hex << +bt;
  }
  return oss.str(); 
}
