#include "cmdline/cmdline.h"
#include <simpleopenssl/simpleopenssl.h>

#include <iostream>

int main(int argc, char *argv[])
{
  cmdline::parser arg;
  arg.add("help", 'h', "Print help.");
  arg.add<std::string>("format", 'f', "Output keys format [pem, der]", false, "pem");
  arg.add<int>("key", 'k', "Key size [1024, 2048, 3072, 4096, 5120, 6144, 7168].", false, 3072);
  arg.add<unsigned long>("exponent", 'e', "Exponent value [3, 17, 65537]", false, 65537);
    
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


  return 0;
}
