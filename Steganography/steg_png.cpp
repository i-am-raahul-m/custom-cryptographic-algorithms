#include "steg_png_common.hpp"

int main() {
    try {
        std::string inputImage, outputImage, message, keyText;
        int cipherId;

        std::cout << "Input carrier PNG image: ";
        std::getline(std::cin, inputImage);
        std::cout << "Output stego PNG image: ";
        std::getline(std::cin, outputImage);
        std::cout << "Cipher choice (1=signal substitution, 2=cylindrical transposition): ";
        std::cin >> cipherId;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        std::cout << "Message to hide: ";
        std::getline(std::cin, message);

        if (cipherId == 1) {
            std::cout << "Signal cipher key example: 1(12,3)02(4) or 123024\n";
        } else if (cipherId == 2) {
            std::cout << "Cylindrical key example: 4,1,2,1,3\n";
        } else {
            throw std::runtime_error("Cipher must be 1 or 2");
        }

        std::cout << "Key: ";
        std::getline(std::cin, keyText);

        PNGImage img = loadPNG(inputImage);
        std::string ciphertext = encryptByCipher(cipherId, message, keyText);

        std::vector<unsigned char> payload = {'S','T','E','G', static_cast<unsigned char>(cipherId)};
        std::vector<unsigned char> lenBytes = uint32ToBytes(static_cast<uint32_t>(ciphertext.size()));
        payload.insert(payload.end(), lenBytes.begin(), lenBytes.end());
        std::vector<unsigned char> body = stringToBytes(ciphertext);
        payload.insert(payload.end(), body.begin(), body.end());

        size_t capacityBytes = pngCapacityBytes(img);
        std::cout << "Carrier capacity: " << capacityBytes << " bytes\n";
        std::cout << "Payload size   : " << payload.size() << " bytes\n";

        embedBytesPNG(img, payload);
        savePNG(outputImage, img);

        std::cout << "Encrypted text : " << ciphertext << "\n";
        std::cout << "Stego image written to: " << outputImage << "\n";
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}