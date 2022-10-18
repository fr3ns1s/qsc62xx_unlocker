from ast import Break
import binascii
import struct
import sys,os
from capstone import *
from capstone.arm import *

def bytes2hex(bytes):
    return binascii.hexlify(bytes).decode("utf8").upper()


def processChunk(f, pos, chunk_size, opcode):
    while (chunk_size > 0):
        s = f.read(0x2)
        chunk_size -= 2
        if s == bytes.fromhex(opcode):
            return pos
        else:
            pos -=2
            f.seek(pos)
    return -1 


def main(filename):
    if not os.path.isfile(filename):
        print("File {} missing ... exiting".format(filename))
        exit(-1)
    
    print("Analyzing file {}".format(filename)) 
    f = open(filename,"rb")
    chunks = f.read()


    BASE = chunks.find(bytes.fromhex("51434F4D13001300010001001300FFFF"))
    print ("BASE: 0x{:08X}".format(BASE))

    opcode_pos = chunks.find(bytes.fromhex ("FF2251321458002C"))
    if opcode_pos != -1:
        flash_nand_write_page  = processChunk(f,opcode_pos,0x200,"38B5")
        if  flash_nand_write_page != -1:
            flash_nand_write_page +=1
            print("flash_nand_write_page at: {:08X}".format(flash_nand_write_page))
        else:
            print("flash_nand_write_page not found")

    opcode_pos = chunks.find(bytes.fromhex ("FF2261321258002A"))
    if opcode_pos != -1:
        flash_nand_erase_block = processChunk(f,opcode_pos,0x200,"021C")
        if  flash_nand_erase_block == -1:
            print("flash_nand_erase_block not found")
        else:
            flash_nand_erase_block +=1
            print("flash_nand_erase_block at: {:08X}".format(flash_nand_erase_block))
            flash_nand_device_probe = processChunk(f,flash_nand_erase_block-1,0x200,"70B5")
            if  flash_nand_device_probe != -1:
                flash_nand_device_probe +=1
                print("Found flash_nand_device_probe at: {:08X}".format(flash_nand_device_probe))
            else:
                print("flash_nand_device_probe not found")

    opcode_pos = chunks.find(bytes.fromhex ("FF2335331B58002B"))
    if opcode_pos != -1:
        flash_nand_read_page  = processChunk(f,opcode_pos,0x200,"B0B5")
        if  flash_nand_read_page != -1:
            flash_nand_read_page +=1
            print("Found flash_nand_read_page at: {:08X}".format(flash_nand_read_page))
        else:
            print("flash_nand_read_page not found")


    addendum = 0
    diagptk_alloc = -1
    _0DD0ADDE_pos = -1
    opcode_pos = chunks.find(bytes.fromhex ("490023"))
    while (opcode_pos != -1 and addendum < len(chunks)):
        addendum += opcode_pos+3
        sub_chunks = chunks[addendum+0x160:addendum+0x160+0x30]
        _0DD0ADDE_pos = sub_chunks.find(bytes.fromhex("0DD0ADDE"))
        if _0DD0ADDE_pos != -1:
            _0DD0ADDE_pos = addendum-2+0x168+4
            diagptk_alloc  = processChunk(f,addendum,0x200,"F3B5")
        if  diagptk_alloc != -1:
            diagptk_alloc += 1
            print("diagptk_alloc at: {:08X}".format(diagptk_alloc))
            break
        else:
            sub = chunks[addendum:]
            opcode_pos = sub.find(bytes.fromhex ("490023"))
        
    diagptk_master_table = -1

    if _0DD0ADDE_pos != -1:
       sub = chunks[_0DD0ADDE_pos-0x80:_0DD0ADDE_pos]
       diagptk_master_table = sub.find(bytes.fromhex("FFFF0000"))
       if diagptk_master_table != -1:
         diagptk_master_table = _0DD0ADDE_pos -diagptk_master_table -8
         print("diagptk_master_table at: {:08X}".format(diagptk_master_table))
       else:
        print ("diagptk_master_table not found")

    
    print("[0x{:04X},0x{:04X},0x{:04X},0x{:04X},0x{:04X},0x{:04X},0x2FF0F00,BUFFER_ADR]".format(diagptk_master_table,diagptk_alloc,flash_nand_device_probe,
    flash_nand_read_page,flash_nand_erase_block,flash_nand_write_page))
    f.close()


def print_help():
    print("python3 zte.py -i")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Error: no file selected")
    else:
        main(sys.argv[1])