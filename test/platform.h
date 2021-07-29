#ifndef PDY_TEST_PLATFORM_H_
#define PDY_TEST_PLATFORM_H_

#include <string>

#ifdef __unix__

#include <unistd.h>

inline bool removeFile(const std::string &filePath)
{
 return unlink(filePath.c_str()) == 0; 
}

#endif


#endif
