/*
* Copyright (c) 2021 Pawel Drzycimski
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
#include <chrono>
#include <ctime>
#define SO_IMPLEMENTATION
#include <simpleopenssl/simpleopenssl.h>
#include "simplelog/simplelog.h"
#include <iomanip>

using namespace so;

int main(int argc, char *argv[])
{
  cmdline::parser arg;
  arg.add("help", 'h', "Print help.");
  arg.add<std::string>("format", 'f', "'pem' (default) or 'der'", false);
  arg.add<std::string>("out", 'o', "Output certificate name. Default 'cert.<format>'", false);
  arg.add<std::string>("keyout", 'k', "Output key name. Default 'key.<format>'", false);
 
  if(!arg.parse(argc, const_cast<const char* const*>(argv)))
  {
    const auto fullErr = arg.error_full();
    if(!fullErr.empty())
      log << fullErr;
     
    log << arg.usage();
    return 0;
  }
  
  if(arg.exist("help"))
  {
    log << arg.usage();
    return 0;
  }  
  
  const std::string format = [&] {
    const auto fmt = arg.get<std::string>("format");
    if(fmt == "pem" || fmt == "der")
      return fmt;

    return std::string{"pem"};
  }();

  const std::string certName = [&]{
    if(arg.exist("out"))
      return arg.get<std::string>("out"); 

    return std::string{"cert"};
  }();

  const std::string keyName = [&]{
    if(arg.exist("keyout"))
      return arg.get<std::string>("keyout"); 

    return std::string{"key"};
  }();

  const auto certPath = certName + "." + format;
  const auto keyPath = keyName + "." + format;

  auto cert = x509::create();
  if(!cert)
  {
    log << cert.msg();
    return 0;
  }

  const auto subject = x509::Subject{
    "ECDSA Self Signed", // common name
    "", // surname
    "US", // country name
    "", // locality
    "", // state or province
    "My Company", // organization name
  };

  if(const auto result = x509::setSubject(*cert.value, subject); !result)
  {
    log << "Subject set: " << result.msg();
    return 0;
  }

  if(const auto result = x509::setIssuer(*cert.value, subject); !result)
  {
    log << result.msg();
    return 0;
  }

  const auto now = std::chrono::system_clock::now();
  const auto nowPlus30Days = now + std::chrono::hours(30 * 24); 

  const auto validity = x509::Validity{
    std::chrono::system_clock::to_time_t(nowPlus30Days),
    std::chrono::system_clock::to_time_t(now)
  };

  if(const auto result = x509::setValidity(*cert.value, validity); !result)
  {
    log << result.msg();
    return 0;
  }

  auto key = ecdsa::create(ecdsa::Curve::SECP112R1);
  if(!key)
  {
    log << key.msg();
    return 0;
  }

  auto evpKey = evp::create();
  if(!evpKey)
  {
    log << evpKey.msg();
    return 0;
  }
  
  if(const auto result = evp::assign(*evpKey.value, *key.value.release()); !result)
  {
    log << result.msg();
    return 0;
  }
  
  if(const auto result = x509::setPubKey(*cert.value, *evpKey.value); !result)
  {
    log << result.msg();
    return 0;
  }

  if(const auto result = x509::signSha1(*cert.value, *evpKey.value); !result)
  {
    log << result.msg();
    return 0;
  }

  if(format == "pem")
  {
    /*
    if(const auto result = evp::converKe(*cert.value, *evpKey.value); !result)
    {
      log << result.msg();
      return 0;
    }
    */

    if(const auto result = x509::convertX509ToPemFile(*cert.value, certPath); !result)
    {
      log << result.msg();
      return 0;
    }

  }


  return 0;
}



