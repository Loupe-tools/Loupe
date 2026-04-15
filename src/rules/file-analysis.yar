// ─── File Analysis ───
// 5 rules

rule PE_Process_Injection_APIs
{
    meta:
        description = "PE binary imports classic process injection APIs (alloc + write + thread)"
        severity    = "critical"

    strings:
        $mz       = { 4D 5A }
        $alloc    = "VirtualAlloc" nocase
        $allocex  = "VirtualAllocEx" nocase
        $write    = "WriteProcessMemory" nocase
        $thread   = "CreateRemoteThread" nocase
        $protect  = "VirtualProtect" nocase
        $move     = "RtlMoveMemory" nocase

    condition:
        $mz at 0 and (
            ($alloc or $allocex) and ($write or $move) and $thread
        )
}

rule PE_Shellcode_Loader_Pattern
{
    meta:
        description = "PE imports memory manipulation APIs commonly used for shellcode loading"
        severity    = "high"

    strings:
        $mz       = { 4D 5A }
        $alloc    = "VirtualAlloc" nocase
        $protect  = "VirtualProtect" nocase
        $move     = "RtlMoveMemory" nocase
        $load     = "LoadLibraryA" nocase

    condition:
        $mz at 0 and 3 of ($alloc, $protect, $move, $load)
}

rule PE_Download_Execute
{
    meta:
        description = "PE binary downloads remote content and executes it"
        severity    = "critical"

    strings:
        $mz      = { 4D 5A }
        $dl1     = "InternetConnectA" nocase
        $dl2     = "URLDownloadToFile" nocase
        $dl3     = "URLDownloadToFileA" nocase
        $dl4     = "InternetOpenA" nocase
        $dl5     = "InternetReadFile" nocase
        $exec1   = "WinExec" nocase
        $exec2   = "CreateProcessA" nocase
        $exec3   = "CreateProcessW" nocase
        $exec4   = "ShellExecuteA" nocase

    condition:
        $mz at 0 and any of ($dl1, $dl2, $dl3, $dl4, $dl5) and any of ($exec1, $exec2, $exec3, $exec4)
}

rule PE_Suspicious_Imports_Cluster
{
    meta:
        description = "PE binary imports 3+ suspicious APIs (injection, download, execution)"
        severity    = "high"

    strings:
        $mz   = { 4D 5A }
        $a    = "VirtualAlloc" nocase
        $b    = "WriteProcessMemory" nocase
        $c    = "CreateRemoteThread" nocase
        $d    = "InternetConnectA" nocase
        $e    = "URLDownloadToFile" nocase
        $f    = "WinExec" nocase
        $g    = "CreateProcessA" nocase
        $h    = "VirtualProtect" nocase
        $i    = "RtlMoveMemory" nocase
        $j    = "LoadLibraryA" nocase
        $k    = "NtUnmapViewOfSection" nocase

    condition:
        $mz at 0 and 3 of ($a, $b, $c, $d, $e, $f, $g, $h, $i, $j, $k)
}

rule PE_Process_Hollowing
{
    meta:
        description = "PE imports APIs consistent with process hollowing technique"
        severity    = "critical"

    strings:
        $mz     = { 4D 5A }
        $a      = "NtUnmapViewOfSection" nocase
        $b      = "ZwUnmapViewOfSection" nocase
        $c      = "WriteProcessMemory" nocase
        $d      = "CreateProcessA" nocase
        $e      = "CreateProcessW" nocase
        $f      = "ResumeThread" nocase

    condition:
        $mz at 0 and ($a or $b) and $c and ($d or $e) and $f
}

