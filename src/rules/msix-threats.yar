rule MSIX_Capability_RunFullTrust {
    meta:
        description = "MSIX manifest requests rescap:runFullTrust or allowElevation — package runs outside the AppContainer sandbox"
        category    = "privilege-escalation"
        mitre       = "T1548"
        severity    = "high"
    strings:
        $pkg   = "<Package" ascii wide nocase
        $c1    = "Name=\"runFullTrust\"" ascii wide nocase
        $c2    = "Name=\"allowElevation\"" ascii wide nocase
    condition:
        $pkg and 1 of ($c*)
}

rule MSIX_Capability_BroadFileSystem {
    meta:
        description = "MSIX manifest requests broad file-system or package-management capabilities"
        category    = "discovery"
        mitre       = "T1083"
        severity    = "high"
    strings:
        $pkg   = "<Package" ascii wide nocase
        $c1    = "Name=\"broadFileSystemAccess\"" ascii wide nocase
        $c2    = "Name=\"packageManagement\"" ascii wide nocase
        $c3    = "Name=\"packageQuery\"" ascii wide nocase
        $c4    = "Name=\"unvirtualizedResources\"" ascii wide nocase
    condition:
        $pkg and 1 of ($c*)
}

rule MSIX_Extension_FullTrustProcess {
    meta:
        description = "MSIX manifest declares a windows.fullTrustProcess helper — spawns arbitrary binaries outside the sandbox"
        category    = "privilege-escalation"
        mitre       = "T1574.002"
        severity    = "high"
    strings:
        $pkg   = "<Package" ascii wide nocase
        $ft    = "Category=\"windows.fullTrustProcess\"" ascii wide nocase
    condition:
        $pkg and $ft
}

rule MSIX_Extension_StartupTask {
    meta:
        description = "MSIX manifest declares a windows.startupTask — program launches automatically on sign-in"
        category    = "persistence"
        mitre       = "T1547.001"
        severity    = "medium"
    strings:
        $pkg   = "<Package" ascii wide nocase
        $st    = "Category=\"windows.startupTask\"" ascii wide nocase
        $en    = "Enabled=\"true\"" ascii wide nocase
    condition:
        $pkg and $st and $en
}

rule MSIX_AppExecutionAlias_CommonName {
    meta:
        description = "MSIX windows.appExecutionAlias claims a common CLI name (python/curl/wget/pwsh/git) — hijacks invocations from an admin shell"
        category    = "defense-evasion"
        mitre       = "T1574.009"
        severity    = "high"
    strings:
        $pkg   = "<Package" ascii wide nocase
        $aea   = "windows.appExecutionAlias" ascii wide nocase
        $a1    = "Alias=\"python.exe\"" ascii wide nocase
        $a2    = "Alias=\"python3.exe\"" ascii wide nocase
        $a3    = "Alias=\"pip.exe\"" ascii wide nocase
        $a4    = "Alias=\"curl.exe\"" ascii wide nocase
        $a5    = "Alias=\"wget.exe\"" ascii wide nocase
        $a6    = "Alias=\"git.exe\"" ascii wide nocase
        $a7    = "Alias=\"pwsh.exe\"" ascii wide nocase
        $a8    = "Alias=\"node.exe\"" ascii wide nocase
        $a9    = "Alias=\"ssh.exe\"" ascii wide nocase
        $a10   = "Alias=\"openssl.exe\"" ascii wide nocase
        $a11   = "Alias=\"java.exe\"" ascii wide nocase
        $a12   = "Alias=\"code.exe\"" ascii wide nocase
    condition:
        $pkg and $aea and 1 of ($a*)
}

rule MSIX_AppInstaller_HTTP {
    meta:
        description = "App Installer file (.appinstaller) fetches MainPackage/MainBundle over plain HTTP — MITM swaps the payload on every auto-update"
        category    = "command-and-control"
        mitre       = "T1557.001"
        severity    = "high"
    strings:
        $root  = "<AppInstaller" ascii wide nocase
        $mp    = "<MainPackage" ascii wide nocase
        $mb    = "<MainBundle" ascii wide nocase
        $http  = "Uri=\"http://" ascii wide nocase
    condition:
        $root and ($mp or $mb) and $http
}

rule MSIX_AppInstaller_Suspicious_TLD {
    meta:
        description = "App Installer Uri points to a free-TLD, tunnel, or paste host"
        category    = "command-and-control"
        mitre       = "T1608.001"
        severity    = "high"
    strings:
        $root  = "<AppInstaller" ascii wide nocase
        $uri   = "Uri=" ascii wide nocase
        $t1    = ".trycloudflare.com" ascii wide nocase
        $t2    = ".ngrok.io" ascii wide nocase
        $t3    = ".ngrok-free.app" ascii wide nocase
        $t4    = ".serveo.net" ascii wide nocase
        $t5    = ".loca.lt" ascii wide nocase
        $t6    = ".duckdns.org" ascii wide nocase
        $t7    = ".sytes.net" ascii wide nocase
        $t8    = ".zapto.org" ascii wide nocase
        $t9    = ".hopto.org" ascii wide nocase
        $t10   = ".serveftp.com" ascii wide nocase
        $t11   = "pastebin.com" ascii wide nocase
        $t12   = "transfer.sh" ascii wide nocase
    condition:
        $root and $uri and 1 of ($t*)
}

rule MSIX_AppInstaller_Silent_AutoUpdate {
    meta:
        description = "App Installer configures on-launch updates with ShowPrompt=\"false\" or ForceUpdateFromAnyVersion — silent auto-update channel"
        category    = "persistence"
        mitre       = "T1195"
        severity    = "medium"
    strings:
        $root  = "<AppInstaller" ascii wide nocase
        $ol    = "<OnLaunch" ascii wide nocase
        $sp    = "ShowPrompt=\"false\"" ascii wide nocase
        $fu    = "<ForceUpdateFromAnyVersion>true" ascii wide nocase
    condition:
        $root and ($ol or $fu) and ($sp or $fu)
}

rule MSIX_Protocol_Claim_Common {
    meta:
        description = "MSIX manifest claims a common URI scheme (http/https/ftp/file/ms-appinstaller) via windows.protocol — intercepts system-wide links"
        category    = "defense-evasion"
        mitre       = "T1574.010"
        severity    = "high"
    strings:
        $pkg   = "<Package" ascii wide nocase
        $proto = "Category=\"windows.protocol\"" ascii wide nocase
        $p1    = "Name=\"http\"" ascii wide nocase
        $p2    = "Name=\"https\"" ascii wide nocase
        $p3    = "Name=\"ftp\"" ascii wide nocase
        $p4    = "Name=\"file\"" ascii wide nocase
        $p5    = "Name=\"ms-appinstaller\"" ascii wide nocase
    condition:
        $pkg and $proto and 1 of ($p*)
}
