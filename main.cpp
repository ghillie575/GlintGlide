#include <iostream>
#include <encoder.h>
#include <algorithm>
using namespace ghillie575::glintglide;
int main(int, char**){
    std::cout << "Hello, from GlintGlide!\n";
    std::string userKey;
    std::cout << "Enter a 5-digit encryption code: ";
    std::cin >> userKey;

    if (userKey.length() != 5 || !std::all_of(userKey.begin(), userKey.end(), ::isdigit)) {
        std::cerr << "Invalid key! Must be a 5-digit number.\n";
        return 1;
    }

    std::string inputText;
    std::cout << "Enter the text to encrypt: ";
    std::cin.ignore();
    std::getline(std::cin, inputText);

    std::string encodedText = encode(inputText, userKey + "00000000000000000000");
    std::cout << "Encoded text: " << encodedText << std::endl;  
    std::string decodedText = decode(encodedText, userKey + "00000000000000000000");
    std::cout << "Decoded text: " << decodedText << std::endl;
    return 0;
    
}
