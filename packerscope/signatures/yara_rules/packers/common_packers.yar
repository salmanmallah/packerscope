/*
 * PackerScope — YARA Rules for Common Packers
 * Defensive security research and malware analysis only.
 */

rule UPX_packed {
    meta:
        author = "PackerScope"
        description = "Detects UPX packed executables"
        packer = "UPX"
        confidence = "0.90"
    strings:
        $upx_magic = "UPX!" ascii
        $upx_sec0 = "UPX0" ascii
        $upx_sec1 = "UPX1" ascii
        $stub1 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 83 CD FF }
        $stub2 = { 60 BE ?? ?? ?? ?? 8D BE ?? ?? ?? ?? 57 89 E5 8D 9C 24 }
    condition:
        uint16(0) == 0x5A4D and
        ($upx_magic or ($upx_sec0 and $upx_sec1) or $stub1 or $stub2)
}

rule ASPack_packed {
    meta:
        author = "PackerScope"
        description = "Detects ASPack packed executables"
        packer = "ASPack"
        confidence = "0.85"
    strings:
        $sec_name = ".aspack" ascii
        $sec_name2 = ".adata" ascii
        $stub1 = { 60 E8 03 00 00 00 E9 EB 04 5D 45 55 C3 E8 01 }
        $stub2 = { 60 E8 02 00 00 00 EB 09 5D 55 }
    condition:
        uint16(0) == 0x5A4D and
        ($sec_name or $sec_name2 or $stub1 or $stub2)
}

rule MPRESS_packed {
    meta:
        author = "PackerScope"
        description = "Detects MPRESS packed executables"
        packer = "MPRESS"
        confidence = "0.85"
    strings:
        $sec1 = ".MPRESS1" ascii
        $sec2 = ".MPRESS2" ascii
        $stub = { 60 E8 00 00 00 00 58 05 ?? ?? ?? ?? 8B 30 03 F0 }
    condition:
        uint16(0) == 0x5A4D and
        (($sec1 and $sec2) or $stub)
}

rule FSG_packed {
    meta:
        author = "PackerScope"
        description = "Detects FSG packed executables"
        packer = "FSG"
        confidence = "0.80"
    strings:
        $stub1 = { BE ?? ?? ?? ?? AD 93 AD 97 AD 56 96 B2 80 }
        $stub2 = { 87 25 ?? ?? ?? ?? 61 94 55 A4 B6 80 FF 13 }
        $stub3 = { BB D0 01 40 00 BF 00 10 40 00 BE ?? ?? ?? ?? 53 }
    condition:
        uint16(0) == 0x5A4D and ($stub1 or $stub2 or $stub3)
}

rule PECompact_packed {
    meta:
        author = "PackerScope"
        description = "Detects PECompact packed executables"
        packer = "PECompact"
        confidence = "0.85"
    strings:
        $marker = "PECompact2" ascii nocase
        $stub = { B8 ?? ?? ?? ?? 50 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 33 C0 89 08 50 }
        $sec = ".pec" ascii
    condition:
        uint16(0) == 0x5A4D and ($marker or $stub or $sec)
}

rule NSPack_packed {
    meta:
        author = "PackerScope"
        description = "Detects NSPack packed executables"
        packer = "NSPack"
        confidence = "0.85"
    strings:
        $stub1 = { 9C 60 E8 00 00 00 00 5D 83 ED 07 8D 85 }
        $stub2 = { 9C 60 E8 00 00 00 00 5D B8 07 00 00 00 2B E8 }
        $sec = ".nsp" ascii
    condition:
        uint16(0) == 0x5A4D and ($stub1 or $stub2 or $sec)
}

rule Petite_packed {
    meta:
        author = "PackerScope"
        description = "Detects Petite packed executables"
        packer = "Petite"
        confidence = "0.85"
    strings:
        $stub = { B8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 66 9C 60 50 }
        $sec = ".petite" ascii
    condition:
        uint16(0) == 0x5A4D and ($stub or $sec)
}

rule Themida_packed {
    meta:
        author = "PackerScope"
        description = "Detects Themida/WinLicense protected executables"
        packer = "Themida"
        confidence = "0.80"
    strings:
        $stub1 = { B8 00 00 00 00 60 0B C0 74 68 E8 00 00 00 00 }
        $stub2 = { 8B C5 8B D4 60 E8 00 00 00 00 5D 81 ED }
        $sec = ".themida" ascii nocase
    condition:
        uint16(0) == 0x5A4D and ($stub1 or $stub2 or $sec)
}

rule VMProtect_packed {
    meta:
        author = "PackerScope"
        description = "Detects VMProtect protected executables"
        packer = "VMProtect"
        confidence = "0.80"
    strings:
        $sec0 = ".vmp0" ascii
        $sec1 = ".vmp1" ascii
        $sec2 = ".VMProtect" ascii nocase
        $stub = { 68 ?? ?? ?? ?? E8 01 00 00 00 C3 }
    condition:
        uint16(0) == 0x5A4D and
        ($sec0 or $sec1 or $sec2 or $stub)
}

rule MEW_packed {
    meta:
        author = "PackerScope"
        description = "Detects MEW packed executables"
        packer = "MEW"
        confidence = "0.80"
    strings:
        $stub1 = { E9 ?? ?? ?? FF 00 00 00 02 00 00 00 0C 00 }
        $stub2 = { 50 BE ?? ?? ?? ?? 8D BE ?? ?? ?? FF 57 }
    condition:
        uint16(0) == 0x5A4D and ($stub1 or $stub2)
}

rule Armadillo_packed {
    meta:
        author = "PackerScope"
        description = "Detects Armadillo protected executables"
        packer = "Armadillo"
        confidence = "0.80"
    strings:
        $stub1 = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 83 EC 58 }
        $stub2 = { 60 E8 00 00 00 00 5D 50 51 EB 0F B9 EB 0F B8 EB 07 }
    condition:
        uint16(0) == 0x5A4D and ($stub1 or $stub2)
}

rule Enigma_packed {
    meta:
        author = "PackerScope"
        description = "Detects Enigma Protector executables"
        packer = "Enigma"
        confidence = "0.80"
    strings:
        $stub1 = { 60 E8 00 00 00 00 5D 83 ED 06 80 BD ?? ?? ?? ?? 01 }
        $sec1 = ".enigma1" ascii
        $sec2 = ".enigma2" ascii
    condition:
        uint16(0) == 0x5A4D and ($stub1 or $sec1 or $sec2)
}

rule Obsidium_packed {
    meta:
        author = "PackerScope"
        description = "Detects Obsidium protected executables"
        packer = "Obsidium"
        confidence = "0.80"
    strings:
        $stub1 = { EB 02 ?? ?? E8 ?? 00 00 00 }
        $stub2 = { EB 04 ?? ?? ?? ?? E8 29 00 00 00 }
    condition:
        uint16(0) == 0x5A4D and ($stub1 or $stub2)
}

rule UPack_packed {
    meta:
        author = "PackerScope"
        description = "Detects UPack/WinUpack packed executables"
        packer = "UPack"
        confidence = "0.80"
    strings:
        $stub = { BE ?? ?? ?? ?? AD 8B F8 95 AD 91 F3 A5 AD }
        $sec1 = ".Upack" ascii
        $sec2 = ".ByDwing" ascii
    condition:
        uint16(0) == 0x5A4D and ($stub or $sec1 or $sec2)
}

rule MoleBox_packed {
    meta:
        author = "PackerScope"
        description = "Detects MoleBox packed executables"
        packer = "MoleBox"
        confidence = "0.80"
    strings:
        $stub = { E8 00 00 00 00 60 E8 4F 00 00 00 }
        $sec1 = ".mbox" ascii
        $sec2 = ".mole" ascii
    condition:
        uint16(0) == 0x5A4D and ($stub or $sec1 or $sec2)
}

rule Generic_packed_pushad {
    meta:
        author = "PackerScope"
        description = "Generic packer detection via PUSHAD+CALL $+0 stub"
        packer = "Generic"
        confidence = "0.60"
    strings:
        $stub1 = { 60 E8 00 00 00 00 5D 81 ED }
        $stub2 = { 9C 60 E8 00 00 00 00 5D }
    condition:
        uint16(0) == 0x5A4D and ($stub1 or $stub2)
}
