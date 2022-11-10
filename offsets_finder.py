from ast import Break
import binascii
from operator import add
import struct
import sys,os
from traceback import print_tb
from capstone import *
from capstone.arm import *

def bytes2hex(bytes):
    return binascii.hexlify(bytes).decode("utf8").upper()

def bytes2Str(bytes):
    return bytes.decode("utf8")

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

def getVersionString(address,chunks):
   
   strings = []
   string = bytearray()
   i = 0
   for n in range(0,0x200):
        b = chunks[address+n:address+n+1]
        if b != b"\0":
            string.append(int.from_bytes(b,"big"))
        else:
            strings.append(string)
            string = bytearray()
            if i == 6:
                return bytes2Str(strings[i])
            i +=1
    
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
            print("flash_nand_write_page at: 0x{:08X}".format(flash_nand_write_page))
        else:
            print("flash_nand_write_page not found")

    opcode_pos = chunks.find(bytes.fromhex ("FF2261321258002A"))
    if opcode_pos != -1:
        flash_nand_erase_block = processChunk(f,opcode_pos,0x200,"021C")
        if  flash_nand_erase_block == -1:
            print("flash_nand_erase_block not found")
        else:
            flash_nand_erase_block +=1
            print("flash_nand_erase_block at: 0x{:08X}".format(flash_nand_erase_block))
            flash_nand_device_probe = processChunk(f,flash_nand_erase_block-1,0x200,"70B5")
            if  flash_nand_device_probe != -1:
                flash_nand_device_probe +=1
                print("Found flash_nand_device_probe at: 0x{:08X}".format(flash_nand_device_probe))
            else:
                print("flash_nand_device_probe not found")

    opcode_pos = chunks.find(bytes.fromhex ("FF2335331B58002B"))
    if opcode_pos != -1:
        flash_nand_read_page  = processChunk(f,opcode_pos,0x200,"B0B5")
        if  flash_nand_read_page != -1:
            flash_nand_read_page +=1
            print("Found flash_nand_read_page at: 0x{:08X}".format(flash_nand_read_page))
        else:
            print("flash_nand_read_page not found")


    diagptk_master_table = -1
    diagptk_alloc = -1
    fw_version_buffer = -1
    addendum = 0
    
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    
    while(1):    
        if fw_version_buffer != -1 and diagptk_alloc != -1:
            break
        for ins in md.disasm(chunks[addendum:addendum+2],addendum):
            operands = ins.operands
            if ins.id == ARM_INS_PUSH and len(ins.operands) == 2 \
                and operands[0].type == ARM_OP_REG and operands[0].value.reg == ARM_REG_R4 \
                and operands[1].type == ARM_OP_REG and operands[1].value.reg == ARM_REG_LR:
                   for ins in md.disasm(chunks[addendum+2:addendum+2+2],addendum+2):
                        operands = ins.operands
                        if ins.id == ARM_INS_MOV and len(ins.operands) == 2 \
                and operands[0].type == ARM_OP_REG and operands[0].value.reg == ARM_REG_R1 \
                and operands[1].type == ARM_OP_IMM and operands[1].value.imm == 0x34:
                            for ins in md.disasm(chunks[addendum+2+2:addendum+2+2+2],addendum+2+2):
                                operands = ins.operands
                                if ins.id == ARM_INS_MOV and len(ins.operands) == 2 \
                        and operands[0].type == ARM_OP_REG and operands[0].value.reg == ARM_REG_R0 \
                        and operands[1].type == ARM_OP_IMM and operands[1].value.imm == 0x38:
                                    print("sw_version_handler at: 0x{:08X}".format(ins.address-4))
                                    for ins in md.disasm(chunks[addendum+2+2+2:addendum+2+2+2+4],addendum+2+2+2):
                                        operands = ins.operands
                                        if ins.id == ARM_INS_BLX and len(ins.operands) == 1:
                                            ptr = operands[0].value.imm
                                            md = Cs(CS_ARCH_ARM, CS_MODE_ARM)
                                            md.detail = True
                                            for ins in md.disasm(chunks[ptr:ptr+8],ptr):
                                                operands = ins.operands
                                                if ins.id == ARM_INS_LDR and len(ins.operands) == 2 \
                                                    and operands[0].type == ARM_OP_REG and operands[0].value.reg == ARM_REG_R12 \
                                                    and operands[1].type == ARM_OP_MEM:
                                                    diagptk_alloc_ptr = ins.address + operands[1].value.mem.disp + 8
                                                    diagptk_alloc = chunks[diagptk_alloc_ptr:diagptk_alloc_ptr + 4]
                                                    diagptk_alloc = struct.unpack("<I",diagptk_alloc)[0]
                                                    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
                                                    md.detail = True
                                                    for ins in md.disasm(chunks[addendum+2+2+2+4:addendum+2+2+2+4+2],addendum+2+2+2+4):
                                                        operands = ins.operands
                                                        if ins.id == ARM_INS_LDR and len(ins.operands) == 2 \
                                                            and operands[0].type == ARM_OP_REG and operands[0].value.reg == ARM_REG_R3 \
                                                            and operands[1].type == ARM_OP_MEM:
                                                                 fw_version_buffer_ptr = ins.address + operands[1].value.mem.disp + 4
                                                                 fw_version_buffer = chunks[fw_version_buffer_ptr:fw_version_buffer_ptr+4]
                                                                 fw_version_buffer = struct.unpack("<I",fw_version_buffer)[0]
                                                                 print("version string at: 0x{:08X}".format(fw_version_buffer))
                                                                         
                 
        addendum +=2
    
        
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB)
    md.detail = True
    addendum = diagptk_alloc-1
    diagptk_master_table = -1
    
    while(1):    
        if diagptk_master_table != -1:
            break
        for ins in md.disasm(chunks[addendum:addendum+2],addendum):
             operands = ins.operands
             if ins.id == ARM_INS_LDR and len(ins.operands) == 2 \
             and operands[0].type == ARM_OP_REG and operands[0].value.reg == ARM_REG_R1 \
             and operands[1].type == ARM_OP_MEM:
                  value_ptr = ins.address + operands[1].value.mem.disp + 4
                  value = chunks[value_ptr:value_ptr+4]
                  if value == b"\x0D\xD0\xAD\xDE":
                      for ins in md.disasm(chunks[ins.address+6:ins.address+6+2],ins.address+6):
                           operands = ins.operands
                           if ins.id == ARM_INS_LDR and len(ins.operands) == 2 \
                              and operands[0].type == ARM_OP_REG and operands[0].value.reg == ARM_REG_R1 \
                              and operands[1].type == ARM_OP_MEM:
                                    value_ptr = ins.address + operands[1].value.mem.disp + 2
                                    value = chunks[value_ptr:value_ptr+4]
                                    value = struct.unpack("<I",value)[0]
                                    for ins in md.disasm(chunks[ins.address+2:ins.address+2+2],ins.address+2):
                                         operands = ins.operands
                                         if ins.id == ARM_INS_ADD and operands[0].type == ARM_OP_REG \
                                             and operands[0].value.reg == ARM_REG_R1 \
                                             and operands[1].type == ARM_OP_IMM:
                                                diagptk_master_table = value + operands[1].value.imm + (4*6)
                                                print("diagptk_master_table at: 0x{:08X}".format(diagptk_master_table))
                                                break
                                                
        addendum +=2
   
    print("======================================================================================")
    print("Version: {}".format(getVersionString(fw_version_buffer,chunks)))
    print("Offsets: [0x{:04X},0x{:04X},0x{:04X},0x{:04X},0x{:04X},0x{:04X},0x2FF0F00,BUFFER_ADR]".format(diagptk_master_table,diagptk_alloc,flash_nand_device_probe,
    flash_nand_read_page,flash_nand_erase_block,flash_nand_write_page))
    print("======================================================================================")
    f.close()


def print_help():
    print("python3 zte.py -i")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Error: no file selected")
    else:
        main(sys.argv[1])