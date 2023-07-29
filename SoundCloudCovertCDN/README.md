# SoundCloudCovertCDN
Using SoundCloud as a Covert CDN

This project utilizes the SoundCloud infrastructure as a covert CDN.  An executable file is embedded into a wav file using basic steganographic techniques which only causes minor pertubations to the original music.  The file is then uploaded to SoundCloud where red teams can store beacon files in a covert manner.  Utilizing legitimate domains makes it more difficult for IOC's to be developed and mitigates the change that these domains will be added to a blocklist.  

# How to Use
1.  Create a wav file that is greater than 8 times the size of the x86 Windows Portable Executable (PE) file that you want to embed.
2.  Use the [main.py](https://github.com/reevesrs24/LivingOffAlexa/blob/main/SoundCloudCovertCDN/PythonPEWavEmbedder/main.py) to embed the exe file into your wav file.
3.  Upload the wav to your SoundCloud account.
4.  Edit the permissions of the track to allow downloads.
5.  Next extract the download URL.  To do this use the developer tools for whatever choice of browser you prefer.  Once the `Download File` button has been clicked in the `More` list retrieve the URL.  The URK should begin with this domain and path `https://api-v2.soundcloud.com/tracks/<track id>/download?<params>`
6.  Take the extracted URL for your download and in [main.cpp](https://github.com/reevesrs24/LivingOffAlexa/blob/main/SoundCloudCovertCDN/main.cpp) replace `<SoundCloud Download Track URL>` with the URL.
7.  Build the `SoundClooudCovertCSN.sln` using visual studio with platform toolset `Visual Studio 2019 (v142)` and the C++ language standard `ISO C++17 Standard (/std:c++17)`
