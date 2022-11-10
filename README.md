# qsc62xx unlocker
Tested on
* ZTE F116 H3G_IT_P640A30V1.0.0B11-S
* ZTE T95 TEL_AU_P622C6V1.0.2B03-S
* ZTE RIO II ORG_UK_P671A80V1.0.0B23-S
* ZTE F116 MTC_MD_P640A30V1.0.0B05-S 
* ZTE T95 TEL_AU_P622C6V1.0.2B04-S
* ZTE 107 H3G_GB_P607C5V1.0.0B11-S
* ZTE 10 2H3G_GB_P607C3V2.0.0B04-S

[VIDEO UNLOCK ZTE RIO II aka JACK 3G](https://youtu.be/fIWjqIO-FrA "UNLOCK ZTE RIO II aka JACK 3G")

# How to compile shellcode
you can use a raspberry pi3:
 >as shellcode.s -mlittle-endian -o zte && objcopy -O binary zte zte_shellcode.bin

## Requirements
* PyPI dependencies:
  python3 -m pip install -r requirements.txt

## Usage
* python3 zte.py -i => read info
* python3 zte.py -u => unlock
* python3 zte.py -d 20 => dump 20 nand pages
* python3 zte.py -w file.bin  => write file to nand
* python3 zte.py -m  => dump full ram in download mode

## How add new firmwares/phone
1. save full ram: python3 zte.py -m
2. python3 offsets_finder.py full_ram_dump.bin
3. add firmware version and result array string from 2 in 
> getOffsets(firmware_version)


## WARNING
No warranty!
Keep in mind that if something goes wrong and you poweroff the phone than only jtag can it save from trash bin 

Someone will not be happy :)
