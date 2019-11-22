#include "cmdline/cmdline.h"
#include <simpleopenssl/simpleopenssl.h>

#include <iostream>

int main(int argc, char *argv[])
{
  cmdline::parser arg;
  arg.add("help", 'h', "Print help.");
  arg.add<std::string>("file", 'f', "File to be hashed.", true);
  arg.add<std::string>("type", 't', "Type of hash [sha1, sha256, sha512]. Default sha256.", false, "sha256");
 
   
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

  return 0;
}
