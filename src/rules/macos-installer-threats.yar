rule PKG_Xar_Archive {
    meta:
        description = "macOS flat Installer Package (xar archive) — scripts execute with root privileges during install"
        category    = "suspicious"
        mitre       = "T1546"
        severity    = "info"
    strings:
        $xar = { 78 61 72 21 }
    condition:
        $xar at 0
}

rule PKG_PreInstall_Script_Present {
    meta:
        description = "Installer package ships a preinstall script — runs before files are laid down (common macOS malware persistence vector)"
        category    = "execution"
        mitre       = "T1546.014"
        severity    = "high"
    strings:
        $xar         = { 78 61 72 21 }
        $scripts_dir = "Scripts/preinstall" ascii
        $name_tag    = "<name>preinstall</name>" ascii nocase
    condition:
        $xar at 0 and ($scripts_dir or $name_tag)
}

rule PKG_PostInstall_Script_Present {
    meta:
        description = "Installer package ships a postinstall script — runs after files are laid down, primary macOS malware payload trigger"
        category    = "execution"
        mitre       = "T1546.014"
        severity    = "high"
    strings:
        $xar         = { 78 61 72 21 }
        $scripts_dir = "Scripts/postinstall" ascii
        $name_tag    = "<name>postinstall</name>" ascii nocase
    condition:
        $xar at 0 and ($scripts_dir or $name_tag)
}

rule PKG_Legacy_Flight_Scripts {
    meta:
        description = "Installer package uses legacy preflight/postflight/InstallationCheck/VolumeCheck scripts — macOS pre-PackageMaker delivery path"
        category    = "execution"
        mitre       = "T1546.014"
        severity    = "medium"
    strings:
        $xar   = { 78 61 72 21 }
        $pf    = "preflight" ascii
        $pof   = "postflight" ascii
        $ic    = "InstallationCheck" ascii
        $vc    = "VolumeCheck" ascii
    condition:
        $xar at 0 and 1 of ($pf, $pof, $ic, $vc)
}

rule PKG_Unsigned_Installer {
    meta:
        description = "Xar archive toc XML declares no <signature> element — installer is unsigned and publisher cannot be verified"
        category    = "defense-evasion"
        mitre       = "T1553.002"
        severity    = "medium"
    strings:
        $xar        = { 78 61 72 21 }
        $no_sig_tag = "<toc>" ascii
        $has_sig    = "<signature" ascii nocase
        $has_xsig   = "<x-signature" ascii nocase
    condition:
        $xar at 0 and $no_sig_tag and not ($has_sig or $has_xsig)
}

rule PKG_Run_As_Root {
    meta:
        description = "Installer package declares auth=\"Root\" — scripts execute with elevated privileges"
        category    = "privilege-escalation"
        mitre       = "T1548.003"
        severity    = "high"
    strings:
        $xar   = { 78 61 72 21 }
        $auth1 = "auth=\"Root\"" ascii nocase
        $auth2 = "auth=\"root\"" ascii
    condition:
        $xar at 0 and 1 of ($auth*)
}

rule PKG_Installer_Curl_Pipe_Bash {
    meta:
        description = "Installer script body contains curl|bash / wget|sh download-and-execute pattern"
        category    = "command-and-control"
        mitre       = "T1105"
        severity    = "high"
    strings:
        $xar     = { 78 61 72 21 }
        $cpb1    = "curl " ascii
        $cpb2    = "wget " ascii
        $pipesh1 = "| sh" ascii
        $pipesh2 = "| bash" ascii
        $pipesh3 = "|sh" ascii
        $pipesh4 = "|bash" ascii
    condition:
        $xar at 0 and 1 of ($cpb*) and 1 of ($pipesh*)
}

rule DMG_UDIF_Disk_Image {
    meta:
        description = "Apple Disk Image (UDIF) — bypasses macOS Mark-of-the-Web quarantine attribute once mounted"
        category    = "defense-evasion"
        mitre       = "T1553.005"
        severity    = "info"
    strings:
        $koly = { 6B 6F 6C 79 }
    condition:
        $koly in (filesize - 512 .. filesize)
}

rule DMG_Encrypted {
    meta:
        description = "Encrypted Apple Disk Image — contents cannot be statically inspected without the passphrase (common malware packaging)"
        category    = "defense-evasion"
        mitre       = "T1027.013"
        severity    = "high"
    strings:
        $aea      = { 41 45 41 31 }
        $encrcdsa = "encrcdsa" ascii
        $cdsaencr = "cdsaencr" ascii
    condition:
        $aea at 0 or $encrcdsa at 0 or $cdsaencr at 0
}

rule DMG_Contains_App_Launcher {
    meta:
        description = "DMG contains both an Applications symlink and a .app bundle — classic drag-to-install social-engineering layout used by AdLoad / AMOS / Atomic Stealer"
        category    = "initial-access"
        mitre       = "T1204.002"
        severity    = "high"
    strings:
        $koly     = { 6B 6F 6C 79 }
        $apps_sym = "Applications" ascii
        $app_bun  = ".app" ascii
    condition:
        $koly in (filesize - 512 .. filesize)
        and $apps_sym and #app_bun >= 2
}

rule DMG_Contains_Hidden_App {
    meta:
        description = "DMG contains a hidden .app bundle (leading dot) — used to obscure the real payload behind a visible decoy"
        category    = "defense-evasion"
        mitre       = "T1564.001"
        severity    = "high"
    strings:
        $koly       = { 6B 6F 6C 79 }
        $hidden1    = "/.app" ascii
        $hidden2    = /\/\.[A-Za-z0-9_\- ]{1,40}\.app/
    condition:
        $koly in (filesize - 512 .. filesize) and ($hidden1 or $hidden2)
}

rule PKG_LaunchDaemon_Payload {
    meta:
        description = "Installer package drops a LaunchDaemon or LaunchAgent plist — macOS persistence mechanism"
        category    = "persistence"
        mitre       = "T1543.001"
        severity    = "high"
    strings:
        $xar     = { 78 61 72 21 }
        $ld      = "LaunchDaemons" ascii
        $la      = "LaunchAgents" ascii
        $plabel  = "<key>Label</key>" ascii nocase
    condition:
        $xar at 0 and ($ld or $la) and $plabel
}
