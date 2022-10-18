import binascii
import struct
import sys,os


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


    opcode_pos = chunks.find(bytes.fromhex ("490023C160"))
    if opcode_pos != -1:
        opcode_pos +=-1
        diagptk_alloc  = processChunk(f,opcode_pos,0x200,"F3B5")
        if  diagptk_alloc == -1:
            print ("diagptk_alloc not found")
        else:
            diagptk_alloc +=1
            print("diagptk_alloc at: {:08X}".format(diagptk_alloc))
        
    opcode_pos = chunks.find(bytes.fromhex ("0000FF0027000100"))
    if opcode_pos == -1:
        print ("diagptk_master_table not found")
    else:
        diagptk_master_table = chunks.find(bytes.fromhex ("00000000" + bytes2hex(struct.pack("<I",opcode_pos))))
        if diagptk_master_table == -1:
            print ("diagptk_master_table not found")
        else:
            diagptk_master_table +=4
            print("diagptk_master_table at: {:08X}".format(diagptk_master_table))   

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