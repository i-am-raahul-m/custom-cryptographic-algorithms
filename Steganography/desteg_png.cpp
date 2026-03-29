#include "steg_png_common.hpp"

int main() {
    try {
        std::string inputImage, keyText;
        std::cout << "Input stego PNG image: ";
        std::getline(std::cin, inputImage);

        PNGImage img = loadPNG(inputImage);
        std::vector<unsigned char> header = extractBytesPNG(img, 9);

        if (!(header[0] == 'S' && header[1] == 'T' && header[2] == 'E' && header[3] == 'G')) {
            throw std::runtime_error("No valid payload header found");
        }

        int cipherId = header[4];
        uint32_t messageLen = bytesToUint32(header, 5);
        std::vector<unsigned char> payload = extractBytesPNG(img, 9 + messageLen);
        std::string ciphertext = bytesToString(payload, 9);

        std::cout << "Detected cipher: " << cipherId << "\n";
        std::cout << "Extracted encrypted text: " << ciphertext << "\n";

        if (cipherId == 1) {
            std::cout << "Enter signal cipher key: ";
        } else if (cipherId == 2) {
            std::cout << "Enter cylindrical key: ";
        } else {
            throw std::runtime_error("Unsupported cipher stored in image");
        }
        std::getline(std::cin, keyText);

        std::string plaintext = decryptByCipher(cipherId, ciphertext, keyText);
        std::cout << "Recovered plaintext: " << plaintext << "\n";
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}