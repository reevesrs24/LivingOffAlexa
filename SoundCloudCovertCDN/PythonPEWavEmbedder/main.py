import io
import copy

from pydub import AudioSegment

# extract the embedded exe from the wav file
def extract_exe_from_wav():
    exe_data = bytearray()
    extracted_exe_byte = 0
    
    # open up the wav file with the emebbedded exe
    with open('test_new.wav', 'rb') as f:
        # seek to data offset
        # first 44 bytes are wav file metadata
        f.seek(44)
        raw_data = f.read()

    
    # open the exe that was embeeded and store the byte length 
    length = len(open('yo.exe', 'rb').read()) 

    # iterate over wav file data
    # every 8 bytes of wav file data is 1 byte of exe data
    for i in range(length*8+1):
        
        # After every 8 byyes append the raw exe byte 
        if i % 8 == 0 and i != 0:
            exe_data.append(copy.deepcopy(extracted_exe_byte))
            # reset the newly constructed exe byte back to 0 
            extracted_exe_byte = 0

        # reasssemble the embedded exe bit bby bit
        byte = raw_data[i]
        bit = byte & 0x1

        bit <<= (i % 8)
        extracted_exe_byte = extracted_exe_byte | bit

    # write the extracted exe data to a file
    with open('extracted.exe', 'wb') as f:
        f.write(exe_data)

# embed the exe in the wav file
def embed_exe_in_wav():
    # Open the wav file which is to be used to embed the yo.exe
    # Noted: the wav will need to be greater than 8 times the size of the exe
    # each exe byte will use 8 bytes of the wav file 
    sound = AudioSegment.from_mp3("banger.wav")

    # Create a byte array with the sound data (This excludes the first 44 bytes of metadata)
    raw_data = bytearray(sound._data)

    # set the raw data index to 0
    raw_data_idx = 0

    # open the exe file which is to be emebedded in the wav file
    with open('yo.exe', 'rb') as f:
        # read the bytes into a byte array
        exe_bytes = f.read()

        # iterate over each byte in the exe
        for i in range(len(exe_bytes)):
            byte = exe_bytes[i]

            # Iterate over each bit within the exe byte and flip the least significant bit of the wav data byte to the corresponding exe bit
            for _ in range(8):
                # get the exe bit
                bit = byte  & 0x1

                # Flip the bit to the exe data bit
                raw_data[raw_data_idx] = (raw_data[raw_data_idx] & 0xFE) | bit

                # shift the byte to extact the next bit in the sequence
                byte  >>= 1

                # increment the raw data count
                raw_data_idx += 1




    recording = AudioSegment.from_file(io.BytesIO(raw_data), 
                                        format="raw", 
                                        frame_rate=44100,
                                        channels=2, 
                                        sample_width=2
                                        )

    recording.export('test_new.wav', format='wav')

def main():
    embed_exe_in_wav()
    extract_exe_from_wav()

if __name__ == '__main__':
    main()
