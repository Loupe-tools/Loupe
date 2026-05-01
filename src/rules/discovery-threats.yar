rule Discovery_Cluster_Windows
{
    meta:
        description = "Three or more Windows host/domain reconnaissance verbs co-located — typical post-access enumeration cluster (T1082 host info + T1087 account discovery + T1018 remote system discovery)"
        severity    = "medium"
        category    = "discovery"
        mitre       = "T1082"
        applies_to  = "text_like, decoded-payload"

    strings:
        $whoami_all     = "whoami /all" nocase
        $whoami_groups  = "whoami /groups" nocase
        $whoami_priv    = "whoami /priv" nocase
        $systeminfo     = "systeminfo" nocase
        $ipconfig_all   = "ipconfig /all" nocase
        $getmac         = "getmac" nocase
        $net_user       = "net user" nocase
        $net_localgroup = "net localgroup" nocase
        $net_view       = "net view" nocase
        $net_session    = "net session" nocase
        $net_share      = "net share" nocase
        $net_accounts   = "net accounts" nocase
        $netstat_ano    = "netstat -ano" nocase
        $arp_a          = "arp -a" nocase
        $route_print    = "route print" nocase
        $tasklist       = "tasklist" nocase
        $qwinsta        = "qwinsta" nocase
        $quser          = "quser" nocase
        $dsquery        = "dsquery" nocase
        $nltest_trusts  = "nltest /domain_trusts" nocase
        $nltest_dclist  = "nltest /dclist" nocase
        $gpresult       = "gpresult /R" nocase
        $setspn_q       = "setspn -Q" nocase
        $wmic_proc      = "wmic process" nocase
        $wmic_cs        = "wmic computersystem" nocase
        $wmic_os        = "wmic os get" nocase
        $klist          = "klist" nocase
        $cmdkey_list    = "cmdkey /list" nocase
        $wevtutil_qe    = "wevtutil qe" nocase
        $driverquery    = "driverquery" nocase
        $hostname       = "hostname" ascii wide nocase

    condition:
        3 of them
}

rule Discovery_Cluster_Unix
{
    meta:
        description = "Three or more Unix/Linux/macOS reconnaissance verbs co-located — typical post-access enumeration cluster (uname/id/sudo -l/ps/network/sensitive files)"
        severity    = "medium"
        category    = "discovery"
        mitre       = "T1082"
        applies_to  = "text_like, decoded-payload"

    strings:
        $uname_a    = "uname -a" nocase
        $id_cmd     = /\bid\s+-[a-zA-Z]\b/
        $who_am_i   = "who am i" nocase
        $sudo_l     = "sudo -l" nocase
        $ps_aux     = "ps aux" nocase
        $ps_ef      = "ps -ef" nocase
        $cat_passwd = "/etc/passwd"
        $cat_shadow = "/etc/shadow"
        $cat_group  = "/etc/group"
        $cat_sudoer = "/etc/sudoers"
        $crontab_l  = "crontab -l" nocase
        $find_suid  = /find\s+\/[^\r\n]{0,80}-perm\s+-?(u=s|4000|2000|6000)/
        $getcap     = "getcap -r" nocase
        $lsblk      = /\blsblk\b/ nocase
        $mount_cmd  = /^\s*mount\s*$/ nocase
        $lsmod      = /\blsmod\b/ nocase
        $dmesg      = /\bdmesg\b/ nocase
        $last_cmd   = /\blast\s+(-[anRfx]|reboot|root)\b/ nocase
        $lastlog    = /\blastlog\b/ nocase
        $getent     = "getent passwd" nocase
        $ip_a       = /\bip\s+(a|addr|address)\s+(show|list|s|l)\b/ nocase
        $ifconfig   = "ifconfig" nocase
        $arp_n      = /\barp\s+-n\b/ nocase
        $route_n    = /\broute\s+-n\b/ nocase
        $ss_tnp     = /\bss\s+-[a-z]*t[a-z]*n/ nocase
        $netstat_tnp = /\bnetstat\s+-[a-z]*t[a-z]*n/ nocase
        $env_cmd    = /\bprintenv\b/ nocase
        $whoami_u   = /\bwhoami\b/ nocase
        $hostname_u = /\bhostname\s+-[Ifia]\b/ nocase

    condition:
        3 of them
}

rule Discovery_SPN_Kerberoast_Precursor
{
    meta:
        description = "SPN enumeration / Kerberoast precursor — `setspn -Q */*`, `Get-ADUser -Properties servicePrincipalName`, Rubeus/Invoke-Kerberoast references"
        severity    = "low"
        category    = "discovery"
        mitre       = "T1558.003"
        applies_to  = "text_like, decoded-payload"

    strings:
        $a = "setspn -Q */*" nocase
        $b = "setspn.exe -Q */*" nocase
        $c = "setspn -T" nocase
        $d = "servicePrincipalName" nocase
        $e = "Get-ADUser" nocase
        $f = "Get-ADComputer" nocase
        $g = "Rubeus.exe kerberoast" nocase
        $h = "Invoke-Kerberoast" nocase
        $i = "kerberoast.py" nocase
        $j = "GetUserSPNs.py" nocase
        $k = "GetUserSPNs" nocase

    condition:
        ($a or $b or $c or $g or $h or $i or $j) or ($d and ($e or $f or $k))
}
