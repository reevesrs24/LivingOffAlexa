import io
import copy

from pydub import AudioSegment


def extract_exe_from_wav():
    pe_data = bytearray()
    length = 0
    new_byte = 0
    
    with open('new.wav', 'rb') as f:
        f.seek(44)
        raw_data = f.read()


    with open('yo.exe', 'rb') as f:
        exe_bytes = f.read()
        length = len(exe_bytes)

    

    for i in range(length*8+1):
        
        if i % 8 == 0 and i != 0:
            pe_data.append(copy.deepcopy(new_byte))
            new_byte = 0

        byte = raw_data[i]
        bit = byte & 0x1

        bit <<= (i % 8)
        new_byte = new_byte | bit

    with open('extracted.exe', 'wb') as f:
        f.write(pe_data)

def embed_exe_in_wav():
    sound = AudioSegment.from_mp3("banger.wav")

    raw_data = bytearray(sound._data)

    raw_data_count = 0
    with open('yo.exe', 'rb') as f:
        exe_bytes = f.read()
        for i in range(len(exe_bytes)):
            byte = exe_bytes[i]

            for i in range(8):
                bit = byte & 0x1

                if bit == 1:
                    raw_data[raw_data_count] = raw_data[raw_data_count] | bit
                else:
                    raw_data[raw_data_count] = raw_data[raw_data_count] & 0xFE

                byte >>= 1
                raw_data_count += 1




    recording = AudioSegment.from_file(io.BytesIO(raw_data), 
                                        format="raw", 
                                        frame_rate=44100,
                                        channels=2, 
                                        sample_width=2
                                        )

    recording.export('new.wav', format='wav')

def main():
    #embed_exe_in_wav()
    extract_exe_from_wav()

if __name__ == '__main__':
    main()
