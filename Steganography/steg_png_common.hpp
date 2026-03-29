#include "steg_cipher_common.hpp"
#include <png.h>

struct PNGImage {
    int width = 0;
    int height = 0;
    std::vector<unsigned char> data; // RGBA
};

static PNGImage loadPNG(const std::string &path) {
    FILE *fp = fopen(path.c_str(), "rb");
    if (!fp) throw std::runtime_error("Could not open input PNG image");

    png_structp png = png_create_read_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
    if (!png) {
        fclose(fp);
        throw std::runtime_error("Failed to initialize libpng read struct");
    }

    png_infop info = png_create_info_struct(png);
    if (!info) {
        png_destroy_read_struct(&png, nullptr, nullptr);
        fclose(fp);
        throw std::runtime_error("Failed to initialize libpng info struct");
    }

    if (setjmp(png_jmpbuf(png))) {
        png_destroy_read_struct(&png, &info, nullptr);
        fclose(fp);
        throw std::runtime_error("Failed while reading PNG image");
    }

    png_init_io(png, fp);
    png_read_info(png, info);

    png_uint_32 width = png_get_image_width(png, info);
    png_uint_32 height = png_get_image_height(png, info);
    png_byte color_type = png_get_color_type(png, info);
    png_byte bit_depth = png_get_bit_depth(png, info);

    if (bit_depth == 16) png_set_strip_16(png);
    if (color_type == PNG_COLOR_TYPE_PALETTE) png_set_palette_to_rgb(png);
    if (color_type == PNG_COLOR_TYPE_GRAY && bit_depth < 8) png_set_expand_gray_1_2_4_to_8(png);
    if (png_get_valid(png, info, PNG_INFO_tRNS)) png_set_tRNS_to_alpha(png);
    if (color_type == PNG_COLOR_TYPE_GRAY || color_type == PNG_COLOR_TYPE_GRAY_ALPHA) png_set_gray_to_rgb(png);
    if (color_type == PNG_COLOR_TYPE_RGB || color_type == PNG_COLOR_TYPE_GRAY || color_type == PNG_COLOR_TYPE_PALETTE) png_set_add_alpha(png, 0xFF, PNG_FILLER_AFTER);

    png_read_update_info(png, info);

    PNGImage img;
    img.width = static_cast<int>(width);
    img.height = static_cast<int>(height);
    img.data.resize(static_cast<size_t>(img.width) * img.height * 4);

    std::vector<png_bytep> rows(img.height);
    for (int y = 0; y < img.height; y++) {
        rows[y] = reinterpret_cast<png_bytep>(img.data.data() + static_cast<size_t>(y) * img.width * 4);
    }

    png_read_image(png, rows.data());
    png_read_end(png, nullptr);
    png_destroy_read_struct(&png, &info, nullptr);
    fclose(fp);
    return img;
}

static void savePNG(const std::string &path, const PNGImage &img) {
    FILE *fp = fopen(path.c_str(), "wb");
    if (!fp) throw std::runtime_error("Could not open output PNG image");

    png_structp png = png_create_write_struct(PNG_LIBPNG_VER_STRING, nullptr, nullptr, nullptr);
    if (!png) {
        fclose(fp);
        throw std::runtime_error("Failed to initialize libpng write struct");
    }

    png_infop info = png_create_info_struct(png);
    if (!info) {
        png_destroy_write_struct(&png, nullptr);
        fclose(fp);
        throw std::runtime_error("Failed to initialize libpng info struct");
    }

    if (setjmp(png_jmpbuf(png))) {
        png_destroy_write_struct(&png, &info);
        fclose(fp);
        throw std::runtime_error("Failed while writing PNG image");
    }

    png_init_io(png, fp);
    png_set_IHDR(
        png,
        info,
        static_cast<png_uint_32>(img.width),
        static_cast<png_uint_32>(img.height),
        8,
        PNG_COLOR_TYPE_RGBA,
        PNG_INTERLACE_NONE,
        PNG_COMPRESSION_TYPE_DEFAULT,
        PNG_FILTER_TYPE_DEFAULT
    );
    png_write_info(png, info);

    std::vector<png_bytep> rows(img.height);
    for (int y = 0; y < img.height; y++) {
        rows[y] = reinterpret_cast<png_bytep>(const_cast<unsigned char *>(img.data.data() + static_cast<size_t>(y) * img.width * 4));
    }

    png_write_image(png, rows.data());
    png_write_end(png, nullptr);
    png_destroy_write_struct(&png, &info);
    fclose(fp);
}

static size_t pngUsableChannelCount(const PNGImage &img) {
    return (img.data.size() / 4) * 3;
}

static size_t pngCapacityBytes(const PNGImage &img) {
    return pngUsableChannelCount(img) / 8;
}

static void embedBytesPNG(PNGImage &img, const std::vector<unsigned char> &payload) {
    size_t totalBits = payload.size() * 8;
    size_t usable = pngUsableChannelCount(img);
    if (totalBits > usable) throw std::runtime_error("Payload too large for carrier PNG image");

    size_t usedBits = 0;
    for (size_t i = 0; i < img.data.size() && usedBits < totalBits; i++) {
        if ((i % 4) == 3) continue;
        unsigned char bit = static_cast<unsigned char>((payload[usedBits / 8] >> (7 - (usedBits % 8))) & 1);
        img.data[i] = static_cast<unsigned char>((img.data[i] & 0xFE) | bit);
        usedBits++;
    }
}

static std::vector<unsigned char> extractBytesPNG(const PNGImage &img, size_t byteCount) {
    size_t totalBits = byteCount * 8;
    size_t usable = pngUsableChannelCount(img);
    if (totalBits > usable) throw std::runtime_error("PNG image does not contain enough embedded data");

    std::vector<unsigned char> out(byteCount, 0);
    size_t usedBits = 0;
    for (size_t i = 0; i < img.data.size() && usedBits < totalBits; i++) {
        if ((i % 4) == 3) continue;
        out[usedBits / 8] = static_cast<unsigned char>((out[usedBits / 8] << 1) | (img.data[i] & 1));
        usedBits++;
    }
    return out;
}