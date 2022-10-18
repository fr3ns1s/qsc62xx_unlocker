
from genericpath import isfile
import os
import serial
import serial.tools.list_ports
import crcmod
import struct
import binascii
import time
from datetime import datetime
import progressbar
import hashlib
import sys, getopt
import typing


DEBUG = False
DIAG_PORT_NAME = "ZTE Handset Diagnostic Interface"
PAGES_NUMBER = 0x40
BASE_ADR = 0x02FF0000
BUFFER_ADR = 0x2FF0600
SHA1_GARBAGE_DATA = "1716ceb1ddb775abd1aab979caa75c208d648df0"
SIMLOCK_PAGE = 0x3f

#shellcode command
CMD_EXEC = "40"
CMD_INIT = "41"
CMD_READ = "42"
CMD_ERASE = "43"
CMD_COPY = "44"
CMD_WRITE = "45"
HEADER_CLIENT = "AB"
HEADER_HOST = "BA"
FRAME_OK = "BA010001B90A7E"

n = bytearray.fromhex("15F0D805A5579FF27AB9BFE11D54DECEAB56EDAF7697AE372639C84CEB6BE443783D87267FAAD" \
    "124C6C671080ED7989A57BA468505D7003D2B3DB17CD70645D3DF7C0C1295EC571D3C59C4AC504878CA6EC50DEBAC737" \
    "295CC619D4A85E0BCD10A104C7A05FF46FDA10D1CC2A364E8C4BC9373EDC875CF4357E32A8A4F04B9B6")
e = bytearray.fromhex("010001")

crc_qualcom = crcmod.mkCrcFun(0x11021,rev=True,initCrc=0,xorOut=0xffff)
serial_port = serial.Serial()

def log(msg):
    if DEBUG:
        print(msg)

#utils
def bytes2hex(bytes):
    return binascii.hexlify(bytes).decode("utf8").upper()

def bytes2Str(bytes):
    return bytes.decode("utf8")

def str2Bytes(str):
    return str.encode("utf8")

def int_to_bytes(integer: int, length: typing.Optional[int] = None) -> bytes:
    return integer.to_bytes(
        length or (integer.bit_length() + 7) // 8 or 1, "big"
    )
    
def update_bar(bar,value,sleep_time):
    
    value +=1
    bar.update(value)
    time.sleep(sleep_time)
    return value

#serial port
def getDiagnosticPort():
    
    port_selected = None
    ports = serial.tools.list_ports.comports()
    print("Finding Diagnostic Port...")
    for port, desc, hwid in sorted(ports):
        log("- {}: {} [{}]".format(port, desc, hwid))
        if DIAG_PORT_NAME in desc:
            port_selected = port
    return port_selected

def initSerialPort(port_name):
    
    try:
        serial_port.baudrate = 115200
        serial_port.port = port_name
        serial_port.timeout = 5
        serial_port.write_timeout = 5
    except:
        print("Fail to init the port")

#qualcomm commands utils
def calcCRC (command):
    
    crc = crc_qualcom(bytearray.fromhex(command))
    crc = struct.unpack("<H",struct.pack(">H",crc))[0]
    crc = f"{crc:04X}"
    return crc

def buildFrame(command,with_header = True):
  
    if len(command) < 2: 
        command = "0" + command
    if len(command) % 2 != 0:
        return None

    command += calcCRC(command)
    frame = bytearray.fromhex(command)
    
    frame = frame.replace(bytes.fromhex("7D"),bytes.fromhex("7D5D"))
    frame = frame.replace(bytes.fromhex("7E"),bytes.fromhex("7D5E"))
    if with_header:
       frame.insert(0,bytes.fromhex("7E")[0])
    frame.append(0x7E)

    log("-> " + "".join("{:02X}".format(x) for x in frame))
    return frame

def cleanFrame(frame):
     
     if len(frame) < 3:
        log("<- ")
        return None

     frame = frame.replace(bytes.fromhex("7D5E"),bytes.fromhex("7E"))
     frame = frame.replace(bytes.fromhex("7D5D"),bytes.fromhex("7D"))
     log("<- " + bytes2hex(frame))
     return frame[:-3]

#info commands
def readSWInfo():
    
    cmd = "7C00"
    frame_to_write = buildFrame(cmd)
    written = serial_port.write(frame_to_write)
    if written <= 0:
        return None
    readed = serial_port.read_until(b"\x7E")
    readed = cleanFrame(readed)
    return readed

def readSWDates():
    
    cmd = "00"
    frame_to_write = buildFrame(cmd)
    written = serial_port.write(frame_to_write)
    if written <= 0:
        return None
    readed = serial_port.read_until(b"\x7E")
    readed = cleanFrame(readed)
    return readed

def imei_format(bytes):
   
    imei_str = ""
    i = 0
    for b in bytes:
        if i==0:
            imei_str +="{:X}".format(b >> 4)
            i = 1
        else:
             imei_str += "{:02X}".format(((b & 0xf) * 0x10) + (b >> 4))
    return imei_str

def readImei():
    
    cmd = "262602"
    frame_to_write = buildFrame(cmd)
    written = serial_port.write(frame_to_write)
    if written <= 0:
        return None
    readed = serial_port.read_until(b"\x7E")
    readed = cleanFrame(readed)
    return readed

def readBTAddress():
    
    cmd = "26BF01"
    frame_to_write = buildFrame(cmd)
    written = serial_port.write(frame_to_write)
    if written <= 0:
        return None
    readed = serial_port.read_until(b"\x7E")
    readed = cleanFrame(readed)
    return readed

def readUserCode():
    cmd = "265200"
    frame_to_write = buildFrame(cmd)
    written = serial_port.write(frame_to_write)
    if written <= 0:
        return None
    readed = serial_port.read_until(b"\x7E")
    readed = cleanFrame(readed)
    return readed


def readInfo():
    
    print("Reading info...")
    fw_version = readSWInfo()
    if fw_version: 
        fw_version = bytes2Str(fw_version[12:37])
    dates = readSWDates()
    if dates:
        comp_date = bytes2Str(dates[1:20])
        rel_date = bytes2Str(dates[20:39])
    imei = readImei()
    if imei:
        imei = imei_format(imei[4:12])
    bt_adr = readBTAddress()
    if bt_adr:
        bt_adr = bytes2hex(bt_adr[3:9])
    user_code = readUserCode()
    if user_code:
        user_code = bytes2Str(user_code[3:7])
    print("=========================================")
    print("FW INFO: {}\nCOMPILED AT: {}\nRELEASED AT: {}\nIMEI: {}\nBLUETOOTH: {}\nUSER CODE: {}".format(fw_version,comp_date,rel_date,imei,bt_adr,user_code)) 
    print("=========================================")
    return fw_version

#unlocking
def getOffsets(firmware_version):

    print("Selecting offsets ...")

    #diagpkt_master_table_ptr
    #diag_ptr: .word 0x41414141
    #nand_probe_ptr: .word 0x42424242
    #nand_read_ptr: .word 0x43434343
    #nand_erase_ptr: .word 0x44444444
    #nand_write_ptr: .word 0x45454545
    #nand_probe_array_ptr: .word 0x46464646
    #buffer_ptr: .word 0x47474747

    #all offsets except the 1st(diagpkt_master_table) are address+1 (thumb mode)
    
    if "H3G_IT_P640A30V1.0.0B11-S" in firmware_version:
        return [0x015AB4D0,0x11985B3,0xC3E83D,0xC3E973,0xC3E8FF,0xC3E877,0x2ff0f00,BUFFER_ADR]
    elif "TEL_AU_P622C6V1.0.2B03-S" in firmware_version:
        return [0x019D9CA4,0x1264DF7,0x29E0CD,0x29E203,0x29E18F,0x29E107,0x2ff0f00,BUFFER_ADR]
    elif "ORG_UK_P671A80V1.0.0B23-S" in firmware_version:
        return [0x23041E4,0x169D3A5,0x408AF9,0x408C2F,0x408BBB,0x408B33,0x2ff0f00,BUFFER_ADR]
    if "MTC_MD_P640A30V1.0.0B05-S" in firmware_version:
        return [0x2C96620,0x2C964B3,0x30C9A49,0x30C9B7F,0x30C9B0B,0x30C9A83,0x2FF0F00,BUFFER_ADR]
    elif "TEL_AU_P622C6V1.0.2B04-S" in firmware_version:
        return [0x2B425D0,0x2B4245F,0x2C1D375,0x2C1D4AB,0x2C1D437,0x2C1D3AF,0x2FF0F00,BUFFER_ADR]
    else:
        print("Firmware not supported")
        exit(-1)
    
def sendShellCode(firmware_version):

    offsets = getOffsets(firmware_version)    
    start_adr = BASE_ADR
    shellcode_file = "zte_shellcode.bin"
    shellcode_size = os.stat(shellcode_file).st_size
    i = 0
 
    print("Sending shellcode ...")
    
    with progressbar.ProgressBar(max_value=int(shellcode_size/0x4) + 9) as bar:
        with open(shellcode_file,"rb") as f:
            chunk = f.read(0x4)
            while chunk:
                bytes_hex = bytes2hex(chunk)
                if bytes_hex == "41414141":
                    for offset in offsets[1:]:
                        offset = struct.pack("<I",offset) 
                        serial_port.write(buildFrame("07" + bytes2hex(struct.pack("<I",start_adr)) + "01" + bytes2hex(offset) + "00000000"))
                        readed = serial_port.read_until(b"\x7E")
                        log("<- " + bytes2hex(readed))
                        start_adr +=4
                        i = update_bar(bar,i,0.05)
                        chunk = None
                else:
                    serial_port.write(buildFrame("07" + bytes2hex(struct.pack("<I",start_adr)) + "01" + bytes_hex + "00000000"))
                    readed = serial_port.read_until(b"\x7E")
                    log("<- " + bytes2hex(readed))
                    chunk = f.read(0x4)
                    start_adr +=4
                    i = update_bar(bar,i,0.05)
        f.close()
        
        xs = bytearray()
        xs.extend(struct.pack("<I",offsets[0]))
        xs.extend(bytearray.fromhex("01"))
        xs.extend(struct.pack("<I",start_adr+4))
        xs.extend(bytearray.fromhex("00000000"))

        xs.extend(struct.pack("<I",start_adr))
        xs.extend(bytearray.fromhex("010100010000000000"))
        start_adr +=4

        xs.extend(struct.pack("<I",start_adr))
        xs.extend(bytearray.fromhex("010000ff0000000000"))
        start_adr +=4

        xs.extend(struct.pack("<I",start_adr))
        xs.extend(bytearray.fromhex("01ff00010000000000"))
        start_adr +=4

        xs.extend(struct.pack("<I",start_adr))
        xs.extend(bytearray.fromhex("010000000000000000"))
        start_adr +=4

        xs.extend(struct.pack("<I",start_adr))
        xs.extend(bytearray.fromhex("01"))
        xs.extend(struct.pack("<I",start_adr+4))
        xs.extend(bytearray.fromhex("00000000"))
        start_adr +=4
        
        xs.extend(struct.pack("<I",start_adr))
        xs.extend(bytearray.fromhex("01" + HEADER_CLIENT + "00" + HEADER_CLIENT + "0000000000"))
        start_adr +=4

        xs.extend(struct.pack("<I",start_adr))
        xs.extend(bytearray.fromhex("01"))
        xs.extend(struct.pack("<I",BASE_ADR+1))
        xs.extend(bytearray.fromhex("00000000"))
        start_adr +=4

        xs.extend(struct.pack("<I",start_adr))
        xs.extend(bytearray.fromhex("01"))
        xs.extend(struct.pack("<I",start_adr-0x18))
        xs.extend(bytearray.fromhex("00000000"))

        for n in range(0,9):
            bytes_hex = bytes2hex(xs[n*13:(n*13)+13])
            serial_port.write(buildFrame("07" + bytes_hex ))
            readed = serial_port.read_until(b"\x7E")
            log("<- " + bytes2hex(readed))
            i = update_bar(bar,i,0.10)

    return True

def execShellCode():
    
    print("Executing shellcode ...")
    serial_port.write(buildFrame(HEADER_CLIENT + CMD_EXEC)) 
    readed = serial_port.read_until(b"\x7E")
    log("<- " + bytes2hex(readed))
    if readed[0:1] != bytes.fromhex(HEADER_HOST):
        print("Shellcode not ready ... exiting")
        exit(1)
    len = struct.unpack("<h",readed[1:3])[0]
    print("Shellcode version: {}".format(bytes2Str(readed[3:len+3])))

def initNand():
    
    print("Initing nand ...")
    serial_port.write(buildFrame(HEADER_CLIENT + CMD_INIT))
    readed = serial_port.read_until(b"\x7E")
    log("<- " + bytes2hex(readed))
    if readed != bytes.fromhex(FRAME_OK):
         print("Init fail ... exiting")
         exit(1)
    #flash name
    serial_port.write(buildFrame("04900FFF020400"))
    readed = serial_port.read_until(b"\x7E")
    log("<- " + bytes2hex(readed))
    adr_of_name = struct.unpack(">I",readed[7:11])[0]
    serial_port.write(buildFrame("04{:08X}0400".format(adr_of_name)))
    nand_name_bytes = serial_port.read_until(b"\x7E")
    log("<- " + bytes2hex(nand_name_bytes))
    #ids
    serial_port.write(buildFrame("04A40FFF020400"))
    readed = serial_port.read_until(b"\x7E")
    log("<- " + bytes2hex(readed))
    mark_id = struct.unpack("<h",readed[7:9])[0]
    flash_id = struct.unpack("<h",readed[7+4:9+4])[0]
    #size
    serial_port.write(buildFrame("049C0FFF020400"))
    readed = serial_port.read_until(b"\x7E")
    log("<- " + bytes2hex(readed))
    page_size = struct.unpack("<H",readed[7:9])[0]
    total_page = struct.unpack("<I",readed[9:13])[0]
    
    print("=========================================")
    print("NAND: {}, {:04X}:{:04X} ".format(bytes2Str(nand_name_bytes[7:-3]),mark_id,flash_id))
    print("TOTAL SIZE: {}Mb, PAGE SIZE: {}".format(int((int(total_page)/1024)/1024),int(page_size)))
    print("=========================================")
   

def readNand(pages,file_name):
   
    print("Saving nand pages 0x{:04X} on file: {} ...".format(pages,file_name))
    with open(file_name,"wb") as f:
        i = 0
        with progressbar.ProgressBar(max_value=pages) as bar:
            for i in range(0,pages):
                adr = struct.pack("<I",i)
                serial_port.write(buildFrame(HEADER_CLIENT + CMD_READ + bytes2hex(adr)))
                readed = serial_port.read_until(b"\x7E")
                len = struct.unpack("<h",readed[1:3])[0]
                if len == 0x800:
                    chunk = cleanFrame(readed[3:])
                    f.write(chunk)
                else:
                    f.write(b'\x2D' * 0x800)
                i = update_bar(bar,i,0.02)
    f.close()
    return True

def clearNand():
    
    print("Clearing nand ...")
    serial_port.write(buildFrame(HEADER_CLIENT + CMD_ERASE +"00000000"))
    readed = serial_port.read_until(b"\x7E")
    log("<- " + bytes2hex(readed))
    if readed != bytes.fromhex(FRAME_OK):
         print("Clear nand fail ... exiting")
         exit(1)


def decryptSignature(page,chunk):
 
 found = False
 try:
     sign_enc = chunk[0x65:0x65+0x80]
     res_dec = pow(int.from_bytes(sign_enc,"big"), int.from_bytes(e,"little"),int.from_bytes(n,"little"))
     res_dec = bytes2hex(int_to_bytes(res_dec))
 except Exception as message:
    print(message)
 finally:
     if "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF" \
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00" in res_dec:
        print("Simlock Signature at 0x{:04X} {}".format(page,res_dec))
        found = True
     return found

def writeNand(pages,file_name):
    
    print("Writing nand pages 0x{:04X} from {} ...".format(pages,file_name))
    page = 0
    i = 0
    with open(file_name,"rb") as f:
        chunk = f.read(0x800)
        while chunk:
            hash = hashlib.sha1(chunk)
            if hash.hexdigest() != SHA1_GARBAGE_DATA:
                print("Writing page 0x{:02X}".format(page))
                with progressbar.ProgressBar(max_value=int(0x800/0x200)) as bar:
                    for i in range(0,int(0x800/0x200)):
                        sub_chunk = chunk[i*0x200:(i*0x200)+0x200]
                        serial_port.write(buildFrame(HEADER_CLIENT + CMD_COPY + bytes2hex(struct.pack("<I",BUFFER_ADR + i*0x200)) + "00020000" +  bytes2hex(sub_chunk)))
                        readed = serial_port.read_until(b"\x7E")
                        log("<- " + bytes2hex(readed))
                        i = update_bar(bar,i,0.2)
                serial_port.write(buildFrame(HEADER_CLIENT + CMD_WRITE + bytes2hex(struct.pack("<I",page))))
                readed = serial_port.read_until(b"\x7E")
                log("<- " + bytes2hex(readed))
            else:
                print("Skipping page 0x{:02X}".format(page))
            chunk = f.read(0x800)
            page +=1
            if page == pages:
               break
           
    f.close()

def setupSerialPort():
    
    port_name = getDiagnosticPort()
    if port_name == None:
        print("No port found!")
        exit(-1)
    print("Port selected: {}".format(port_name))
    initSerialPort(port_name)
    serial_port.open()
    if not serial_port.is_open:
        print("Fail to open the port")
        exit(-1)

def backupFileName():
   
    now = datetime.now()
    return "backup_{}.bin".format(now.strftime("%Y%m%d_%H%M%S"))

def unlock():
   
    fw_version = readInfo()
    if not sendShellCode(fw_version):
        print("Error on sending ... exiting")
        serial_port.close()
    execShellCode()
    initNand()
    file_name = backupFileName()
    if readNand(PAGES_NUMBER,file_name):
        clearNand()
        #pages = int(os.stat(file_name).st_size / 0x800)
        writeNand(SIMLOCK_PAGE,file_name)
        print("All done! Please power off your phone")
        

def dumpNand(pages):
 
    fw_version = readInfo()
    if not sendShellCode(fw_version):
        print("Error on sending ... exiting")
        serial_port.close()
    execShellCode()
    initNand()
    file_name = backupFileName()
    if readNand(pages,file_name):
         print("All done!")

def restoreNand(file_name):
   
    if not os.path.isfile(file_name):
        print("File {} missing ... exiting".format(file_name))
        exit(-1)

    pages = int(os.stat(file_name).st_size / 0x800)

    if pages <= 0:
        print("Invalid files size ... exiting")
        exit(-1)
        
    fw_version = readInfo()
    if not sendShellCode(fw_version):
        print("Error on sending ... exiting")
        serial_port.close()
    execShellCode()
    initNand()
    clearNand()
    writeNand(pages,file_name)
    print("All done! Please power off your phone")



def dumpFullRam():
   
    print ("Setting download mode ...")
    auth_cmd = "4BCB0200321170B2DCEC4257F087EDCACB09C8AFB6F39A70F4E9F49980AA1141ABB872E6CBD263E279502A35624DA"\
        "19A6EFE5AF90B9DE95C67004B1DCC4628781B8123433D2760A57CD54FF7455B6CB5EBA0612002725050A4BC7D5D841764F4D" \
            "6C55AE121CB787D5D5BD874B7373102AFD3FD15C5D89C2CC30C46C3C270CDC371DB43E58B77765E7E"
    log("-> " + auth_cmd)
    frame_to_write = bytearray.fromhex(auth_cmd)
    serial_port.write(frame_to_write)
    readed = serial_port.read_until(b"\x7E")
    log("<- " + bytes2hex(readed))
    frame_to_write = buildFrame("3A")
    serial_port.write(frame_to_write)
    readed = serial_port.read_until(b"\x7E")
    serial_port.close()
    log("<- " + bytes2hex(readed))
    print("Waiting 10s ...")
    time.sleep(10)
    setupSerialPort()
    frame_to_write = buildFrame("0C")
    serial_port.write(frame_to_write)
    readed = serial_port.read_until(b"\x7E")
    readed_hex = bytes2hex(readed)
    log("<- " + readed_hex)

    if readed_hex == "130CD27A7E":
        print("Download mode error ... exiting")
        serial_port.close()
        return
    
    print("Download mode: {}".format(bytes2Str(readed[2:-3])))
    
    frame_to_write = buildFrame("10")
    serial_port.write(frame_to_write)
    readed = serial_port.read_until(b"\x7E")
    log("<- " +  bytes2hex(readed))
    readed = readed[3:]
    type = struct.unpack("<B",readed[0:1])[0]
    base = struct.unpack(">I",readed[1:5])[0]
    length = struct.unpack(">I",readed[5:9])[0]
    print("Getting memory info ...")
    print("Base: 0x{:08X} Length: 0x{:08X} Type: 0x{:02X}".format(base,length,type))
    
    file_name = "full_ram_dump.bin"
    print("Saving nand dump on file: {} ...".format(file_name))
    print("Started at {}".format(datetime.now()))
    with open(file_name,"wb") as f:
         with progressbar.ProgressBar(max_value=int(length)) as bar:
            for i in range(base,length, 0x7f8):
                frame_to_write = buildFrame("12" + bytes2hex(struct.pack(">I",base + i)) + bytes2hex(struct.pack(">H",0x7f8)))
                serial_port.write(frame_to_write)
                readed = serial_port.read_until(b"\x7E")
                if len(readed) >= 0x7f8:
                    chunk = cleanFrame(readed)
                    f.write(chunk[7:])
                else:
                    break
                bar.update(base + i)  
    f.close()
    print("Finished at {}".format(datetime.now()))


def print_help():
    
    print("read info => python3 zte.py -i")
    print("unlock => python3 zte.py -u")
    print("dump nand => python3 zte -d 63")
    print("restore nand =>python3  zte -r file.bin")
    print("dump ram => python3 zte.py -m")

def main(argv):
    try:
        opts, args = getopt.getopt(argv,"iud:r:m",["pages==","fileName=="])
    except getopt.GetoptError:
        print_help()
        exit(-1)

    if len(opts) == 0:
        print("Please select an option:")
        print_help()
        exit(0)

    for opt, arg in opts:
        if opt == "-h":
            print_help()
            exit(0)
        elif opt in ("-i","--info"):
            setupSerialPort()
            readInfo()
            break
        elif opt in ("-u","--unlock"):
            setupSerialPort()
            unlock()
            break
        elif opt in ("-d","--dump"):
            setupSerialPort()
            pages = PAGES_NUMBER
            pages_value = arg.split()
            if len(pages_value) == 1:
                pages = int(pages_value[0])
            dumpNand(pages)
        elif opt in ("-r","--restore"):
            setupSerialPort()
            values = arg.split()
            if len(values) == 1:
                restoreNand((values[0]))
        elif opt in ("-m","--download_mode"):
            setupSerialPort()
            dumpFullRam()
          
    if serial_port.is_open:
        serial_port.close()

if __name__ == "__main__":  
    main(sys.argv[1:])