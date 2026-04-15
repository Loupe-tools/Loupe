// ─── Network Indicators ───
// 3 rules

rule UNC_Path_NTLM_Theft
{
    meta:
        description = "File contains UNC path reference — may trigger NTLM authentication to attacker"
        severity    = "high"

    strings:
        $a = /\\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\/
        $b = /\\\\[a-zA-Z0-9\-]+\.[a-z]{2,4}\\/

    condition:
        any of them
}

rule WebDAV_Reference
{
    meta:
        description = "File references WebDAV path — can fetch remote payloads or steal NTLM hashes"
        severity    = "high"

    strings:
        $a = "\\\\DavWWWRoot\\" nocase
        $b = "\\DavWWWRoot\\" nocase
        $c = "@SSL\\DavWWWRoot" nocase

    condition:
        any of them
}

rule Credential_Dumping_Commands
{
    meta:
        description = "File references credential dumping tools or techniques beyond mimikatz"
        severity    = "critical"

    strings:
        $a     = "procdump" nocase
        $b     = "lsass" nocase
        $c     = "comsvcs.dll" nocase
        $d     = "MiniDump" nocase
        $e     = "ntdsutil" nocase
        $f     = "vssadmin" nocase
        $g     = "ntds.dit" nocase

    condition:
        ($a and $b) or ($c and $d) or ($e and ($f or $g))
}

