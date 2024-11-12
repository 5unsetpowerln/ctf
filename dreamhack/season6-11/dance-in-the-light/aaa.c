#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// デバッグ情報を表示する関数
void print_header_info(uint8_t *header) {
    printf("Header: %02X %02X %02X %02X\n", header[0], header[1], header[2], header[3]);
    printf("Sync: %02X %02X\n", header[0], header[1] >> 5);
    printf("Version: %d\n", (header[1] >> 3) & 3);
    printf("Layer: %d\n", (header[1] >> 1) & 3);
    printf("Protection: %d\n", header[1] & 1);
    printf("Bitrate index: %d\n", (header[2] >> 4) & 0xF);
    printf("Sampling rate: %d\n", (header[2] >> 2) & 0x3);
    printf("Padding: %d\n", (header[2] >> 1) & 0x1);
    printf("Private: %d\n", header[2] & 0x1);
    printf("------------------\n");
}

// MP3フレームからビットを抽出する関数
int get_frame_bit(FILE *fp, int *frame_count) {
    uint8_t header[4];

    // ヘッダーを4バイト読み込む
    size_t read_size = fread(header, 1, 4, fp);
    if (read_size != 4) {
        printf("Failed to read header (read %zu bytes)\n", read_size);
        return -1;
    }

    (*frame_count)++;
    printf("Frame %d: ", *frame_count);
    print_header_info(header);

    // // フレーム同期チェック
    // if (header[0] != 0xFF || (header[1] >> 5) != 7) {
    //     printf("Frame sync failed\n");
    //     return -1;
    // }

    // MPEGバージョンとレイヤーチェック
    uint8_t version = (header[1] >> 3) & 3;
    uint8_t layer = (header[1] >> 1) & 3;
    // if (version == 1 || layer != 1) {
    //     printf("Invalid version or layer\n");
    //     return -1;
    // }

    // フレームサイズの計算
    static const int bitrates[] = {0,32,40,48,56,64,80,96,112,128,160,192,224,256,320,0};
    static const int samplerates[] = {44100, 48000, 32000, 0};

    uint8_t bitrate_index = (header[2] >> 4) & 0xF;
    uint8_t samplerate_index = (header[2] >> 2) & 0x3;
    uint8_t padding = (header[2] >> 1) & 0x1;

    // if (bitrates[bitrate_index] == 0 || samplerates[samplerate_index] == 0) {
    //     printf("Invalid bitrate or sample rate\n");
    //     return -1;
    // }

    int frame_size = (144000 * bitrates[bitrate_index]) / samplerates[samplerate_index] + padding - 4;
    printf("Frame size: %d bytes\n", frame_size + 4);

    // フレームデータを読み飛ばす
    if (fseek(fp, frame_size, SEEK_CUR) != 0) {
        printf("Failed to seek to next frame\n");
        return -1;
    }

    int bit = header[2] & 1;
    printf("Extracted bit: %d\n\n", bit);
    return bit;
}

void decode_message(const char* input_file) {
    FILE *fp = fopen(input_file, "rb");
    if (!fp) {
        printf("Failed to open input file: %s\n", input_file);
        return;
    }

    printf("Starting decoding process...\n\n");

    int bit_count = 0;
    uint8_t current_char = 0;
    int frame_count = 0;

    printf("Collecting bits:\n");
    while (1) {
        int bit = get_frame_bit(fp, &frame_count);
        if (bit == -1) {
            printf("Reached end of file or encountered error\n");
            break;
        }

        current_char = (current_char << 1) | bit;
        bit_count++;

        printf("Current bits collected: ");
        for (int i = 0; i < bit_count; i++) {
            printf("%d", (current_char >> (bit_count - 1 - i)) & 1);
        }
        printf(" (%d/8)\n", bit_count);

        if (bit_count == 8) {
            printf("Complete byte: %02X (ASCII: '%c')\n\n",
                   current_char,
                   (current_char >= 32 && current_char <= 126) ? current_char : '.');

            if (current_char >= 32 && current_char <= 126) {
                printf("Found printable character: %c\n", current_char);
            }

            current_char = 0;
            bit_count = 0;
        }
    }

    fclose(fp);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s [input_mp3_file]\n", argv[0]);
        return 1;
    }

    printf("MP3 Steganography Decoder\n");
    printf("Input file: %s\n\n", argv[1]);

    decode_message(argv[1]);
    return 0;
}
