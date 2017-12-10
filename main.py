import os
import pefile
import binascii
from tornado.template import Template
import sys
import random
import hashlib
import string
import re
import cpuid
import sqlite3

"""
TODO: Hide form post login
"""
CODE_SELECTION_SIZE = 6000

IMPORT_LIB = [dict(LibraryString = "kernel32", LibraryName = "kernel32.dll", hLibrary = "hKernel32"),
              dict(LibraryString = "user32", LibraryName = "user32.dll", hLibrary = "hUser32"),
              dict(LibraryString = "wsock32", LibraryName = "wsock32.dll", hLibrary = "hWsock32")]

IMPORT_FUNCTION = [dict(NameString = "_GetProcAddress", SimbolicName = "GetProcAddress", hLibrary = "hKernel32"), dict(NameString="_LoadLibraryA", SimbolicName="LoadLibraryA", hLibrary="hKernel32"),
    dict(NameString = "_ExitProcess", SimbolicName = "ExitProcess", hLibrary = "hKernel32"),
    dict(NameString = "_CreateThread", SimbolicName = "CreateThread", hLibrary = "hKernel32"),
    dict(NameString = "_MessageBoxA", SimbolicName="MessageBoxA", hLibrary="hUser32"),
    dict(NameString = "_GetModuleHandleA", SimbolicName="GetModuleHandleA", hLibrary="hKernel32"),
    dict(NameString="_LoadIconA", SimbolicName="LoadIconA", hLibrary="hUser32"),
    dict(NameString="_LoadCursorA", SimbolicName="LoadCursorA", hLibrary="hUser32"),
    dict(NameString="_GetMessageA", SimbolicName="GetMessageA", hLibrary="hUser32"),
    dict(NameString="_RegisterClassA", SimbolicName="RegisterClassA", hLibrary="hUser32"),
    dict(NameString="_CreateWindowExA", SimbolicName="CreateWindowExA", hLibrary="hUser32"),
    dict(NameString="_IsDialogMessageA", SimbolicName="IsDialogMessageA", hLibrary="hUser32"),
    dict(NameString="_TranslateMessage", SimbolicName="TranslateMessage", hLibrary="hUser32"),
    dict(NameString="_DispatchMessageA", SimbolicName="DispatchMessageA", hLibrary="hUser32"),
    dict(NameString="_DefWindowProcA", SimbolicName="DefWindowProcA", hLibrary="hUser32"),
    dict(NameString="_SetFocus", SimbolicName="SetFocus", hLibrary="hUser32"),
    dict(NameString="_SendMessageA", SimbolicName="SendMessageA", hLibrary="hUser32"),
    dict(NameString="_PostQuitMessage", SimbolicName="PostQuitMessage", hLibrary="hUser32"),
    dict(NameString="_WSAStartup", SimbolicName="WSAStartup", hLibrary="hWsock32"),
    dict(NameString="_socket", SimbolicName="socket", hLibrary="hWsock32"),
    dict(NameString="_connect", SimbolicName="connect", hLibrary="hWsock32"),
    dict(NameString="_gethostbyname", SimbolicName="gethostbyname", hLibrary="hWsock32"),
    dict(NameString="_send", SimbolicName="send", hLibrary="hWsock32"),
    dict(NameString="_recv", SimbolicName="recv", hLibrary="hWsock32"),
    dict(NameString="_closesocket", SimbolicName="closesocket", hLibrary="hWsock32"),
    dict(NameString="_WSACleanup", SimbolicName="WSACleanup", hLibrary="hWsock32"),
    dict(NameString="_GetComputerNameA", SimbolicName="GetComputerNameA", hLibrary="hKernel32"),
    dict(NameString="_wsprintfA", SimbolicName="wsprintfA", hLibrary="hUser32"),
    dict(NameString="_DestroyWindow", SimbolicName="DestroyWindow", hLibrary="hUser32"),


    ]


def Disable_Aslr(pe):
    print("[*] Check ASLR")
    IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE  = 0x40
    if (pe.OPTIONAL_HEADER.DllCharacteristics & IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE):
        pe.OPTIONAL_HEADER.DllCharacteristics &= ~IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE
        print "ASLR disabled"
    else:
        print "ASLR not enabled"

def GenerateDecoder(Key):
    encode_instructions = ["add", "sub"]
    decoder = ""
    next_xor = True
    for i in range(len(Key)):
        if next_xor:
            instruction = "xor"
            next_xor = False
        else:
            instruction= random.choice(encode_instructions)
            next_xor = True
        decoder += instruction + " al, byte[edx+"+str(i)+"]\n"
    decoder = decoder.split("\n")
    decoder = filter(None, decoder)
    return decoder

def ParsingSelection(pe):
    CODE_SECTION = ["text", "code"]
    DATA_SECTION = ["data"]
    #DATA_SECTION = ["-"]
    NO_PACKED_SECTION = ["idata", "rdata", "tls" "iat", "import", "it"]
    result = {}
    result["CS"] = []
    result["DS"] = []
    i = -1
    print("[*] Start section analysis")
    for section in pe.sections:
        next = False
        i += 1
        print(" - Determination of '"+section.Name+"'")
        for s_name in NO_PACKED_SECTION:
            if section.Name.lower().find(s_name) != -1:
                next = True
                break
        if next:
            continue
        for s_name in CODE_SECTION:
            if section.Name.lower().find(s_name)!=-1:
                result["CS"].append(i)
                print("    -detect CODE selection")
                next = True
        if next:
            continue
        for s_name in DATA_SECTION:
            if section.Name.lower().find(s_name)!=-1:
                result["DS"].append(i)
                print("    -detect DATA selection")
    return result

def main():
    try:
        pe = pefile.PE(sys.argv[1])
    except:
        print("Cannon open file.")
        sys.exit(-1)
    build_id = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(50, 50)))
    key = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(random.randint(20, 20)))
    #key = "LRHHQSMYKEPML9PSOJ11"

    conn = sqlite3.connect('Decoders.db')
    c = conn.cursor()
    c.execute("INSERT INTO `builds` VALUES (NULL,'"+build_id+"','"+key+"')")
    conn.commit()
    conn.close()


    decoder = GenerateDecoder(key)
    SectionMap = ParsingSelection(pe)
    pe.add_last_section(size=CODE_SELECTION_SIZE, selection_name=".xcode")
    SectionMap[".xcode"] = len(pe.sections) - 1
    SectionMap[".XDS"] = []
    SectionMap[".XCS"] = []
    EncodeSelecion = []
    gi = 0
    for section in SectionMap["CS"]:
        EncodeSelecion.append(dict(
            DecodeAddr = int(pe.OPTIONAL_HEADER.ImageBase + pe.sections[section].VirtualAddress),
            DecodeSize=int(pe.sections[section].Misc_VirtualSize),
            loop_iteration = gi,
            crc32=binascii.crc32(pe.get_data(pe.sections[section].PointerToRawData, pe.sections[section].Misc_VirtualSize)) & 0xffffffff
        ))
        gi += 1
        pe.sections[section].Characteristics |= pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_WRITE"]
        i = 0
        for enc in list(reversed(decoder)):
            if enc.split(" ")[0] == "add":
                pe.sections[section].sub_data(ord(key[i]))
            if enc.split(" ")[0] == "sub":
                pe.sections[section].add_data(ord(key[i]))
            if enc.split(" ")[0] == "xor":
                pe.sections[section].xor_data(ord(key[i]))
            i += 1

    for section in SectionMap["DS"]:
        EncodeSelecion.append(dict(
            DecodeAddr = int(pe.OPTIONAL_HEADER.ImageBase + pe.sections[section].VirtualAddress),
            DecodeSize=int(pe.sections[section].Misc_VirtualSize),
            loop_iteration = gi,
            crc32=binascii.crc32(pe.get_data(pe.sections[section].PointerToRawData, pe.sections[section].Misc_VirtualSize)) & 0xffffffff
        ))
        gi += 1
        pe.sections[section].Characteristics |= pefile.SECTION_CHARACTERISTICS["IMAGE_SCN_MEM_WRITE"]
        i = 0
        for enc in list(reversed(decoder)):
            if enc.split(" ")[0] == "add":
                pe.sections[section].sub_data(ord(key[i]))
            if enc.split(" ")[0] == "sub":
                pe.sections[section].add_data(ord(key[i]))
            if enc.split(" ")[0] == "xor":
                pe.sections[section].xor_data(ord(key[i]))
            i += 1
    asm = Template(open("ProtectorSelection.tpl.asm", "r").read()).generate(
        xor_len=pe.sections[0].Misc_VirtualSize,
        Encoder='\n'.join(map(str, decoder)),
        OriginalEP = pe.OPTIONAL_HEADER.ImageBase + pe.OPTIONAL_HEADER.AddressOfEntryPoint,
        CodeBase = pe.OPTIONAL_HEADER.ImageBase + pe.sections[SectionMap[".xcode"]].VirtualAddress,
        EncodeSelecion = EncodeSelecion,
        DecodeKey=key[::-1],
        IMPORT_LIB = IMPORT_LIB,
        IMPORT_FUNCTION = IMPORT_FUNCTION,
        build_id = build_id

    )

    with open("ProtectorSelection.asm", "w") as f:
        f.write(asm)

    print("[*] Compiling assembler dynamic code copy.asm")
    os.system(os.getcwd() + r"\fasm\FASM.EXE ProtectorSelection.asm")
    ProtectorSelection = open("ProtectorSelection.bin", "rb").read()
    pe.data_replace(offset=pe.sections[SectionMap[".xcode"]].PointerToRawData, new_data=ProtectorSelection)

    pe.OPTIONAL_HEADER.AddressOfEntryPoint = pe.sections[SectionMap[".xcode"]].VirtualAddress
    Disable_Aslr(pe)
    pe.write(filename=sys.argv[1][:-4] + "_packed.exe")

if __name__=="__main__":
    main()