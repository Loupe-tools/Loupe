// ─── Suspicious Patterns ───
// 7 rules

rule Embedded_PE_Header
{
    meta:
        description = "File contains an embedded MZ PE header — hidden executable inside document"
        severity    = "critical"

    strings:
        $mz = { 4D 5A 90 00 }

    condition:
        $mz
}

rule Suspicious_COM_Hijack_CLSID
{
    meta:
        description = "File references COM object CLSIDs commonly abused for hijacking persistence"
        severity    = "medium"

    strings:
        $clsid_mmcfx   = "{49CBB1C7-97D1-485A-9EC1-A26065633066}" nocase
        $inproc         = "InprocServer32" nocase
        $treatAs        = "TreatAs" nocase
        $clsid_generic  = /CLSID\\{[0-9A-Fa-f\-]{36}}/ nocase

    condition:
        ($inproc or $treatAs) and $clsid_generic
}

rule General_XOR_Decode_Loop
{
    meta:
        description = "File contains XOR decoding patterns — common payload deobfuscation"
        severity    = "medium"

    strings:
        $a     = "xor" nocase fullword
        $b     = "fromCharCode" nocase
        $c     = "charCodeAt" nocase
        $d     = "Chr(" nocase

    condition:
        $a and any of ($b, $c, $d)
}

rule General_Base64_With_Execution
{
    meta:
        description = "File decodes base64 and passes result to execution function"
        severity    = "high"

    strings:
        $b64_1 = "base64" nocase
        $b64_2 = "FromBase64String" nocase
        $b64_3 = "atob(" nocase
        $exec1 = "eval(" nocase
        $exec2 = "Invoke-Expression" nocase
        $exec3 = "iex " nocase
        $exec4 = "Execute(" nocase
        $exec5 = "ExecuteGlobal(" nocase
        $exec6 = "Function(" nocase

    condition:
        any of ($b64_1, $b64_2, $b64_3) and any of ($exec1, $exec2, $exec3, $exec4, $exec5, $exec6)
}

rule General_Hex_Encoded_Shellcode
{
    meta:
        description = "File contains patterns consistent with hex-encoded shellcode blobs"
        severity    = "high"

    strings:
        $hex_prefix = /\\x[0-9a-fA-F]{2}(\\x[0-9a-fA-F]{2}){15,}/
        $hex_comma  = /0x[0-9a-fA-F]{2}(,\s*0x[0-9a-fA-F]{2}){15,}/

    condition:
        any of them
}

rule Embedded_ZIP_In_Non_Archive
{
    meta:
        description = "ZIP local file header (PK\\x03\\x04) found inside a non-archive file"
        severity    = "medium"

    strings:
        $pk = { 50 4B 03 04 }

    condition:
        #pk > 1
}

rule Embedded_Compressed_Stream
{
    meta:
        description = "Zlib or gzip compressed stream embedded in file"
        severity    = "info"

    strings:
        $zlib_default = { 78 9C }
        $zlib_best    = { 78 DA }
        $gzip_magic   = { 1F 8B 08 }

    condition:
        any of them
}

// ════════════════════════════════════════════════════════════════════════
// REG — Windows Registry File rules
// ════════════════════════════════════════════════════════════════════════

