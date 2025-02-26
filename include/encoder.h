#ifndef ENCODER_H
#define ENCODER_H
#include <iostream>
#include <encoder_def.h>

namespace ghillie575
{
    namespace glintglide
    {
        std::string encode(const std::string &input, const std::string &key);
        std::string decode(const std::string &input, const std::string &key);
    }
}
#endif