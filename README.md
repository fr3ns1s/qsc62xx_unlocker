# qsc62xx unlocker
Tested on
* ZTE F116 H3G_IT_P640A30V1.0.0B11-S
* ZTE T95 TEL_AU_P622C6V1.0.2B03-S
Later i will upload some infos for add new phone/version

# How to compile shellcode
you use a raspberry pi3:
 >as shellcode.s -mlittle-endian -o zte && objcopy -O binary zte zte_shellcode.bin

## Requirements
* PyPI dependencies:
  python3 -m pip install -r requirements.txt

## Usage
* ./zte.py -i => read info
* ./zte.py -u => unlock
* ./zte.py -d 20 => dump 20 nand pages
* ./zte.py -w file.bin  => write file to nand

## WARNING
No warranty!
Keep in mind that if something goes wrong and you poweroff the phone than only jtag can it save from trash bin 

Someone will not be happy :)




