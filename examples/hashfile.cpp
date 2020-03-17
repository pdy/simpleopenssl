#include "cmdline/cmdline.h"
#include <simpleopenssl/simpleopenssl.h>

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
    std::cout << bin2Hex(*hash) << "\n";
     
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
