rule BrowserExt_Permission_NativeMessaging {
    meta:
        description = "WebExtension manifest requests nativeMessaging — content script can pipe stdio to a native host binary installed on disk"
        severity    = "high"
        category    = "execution"
        mitre       = "T1559"
    strings:
        $mv    = "\"manifest_version\"" ascii wide nocase
        $p     = "\"nativeMessaging\"" ascii wide nocase
    condition:
        $mv and $p
}

rule BrowserExt_HostPermission_AllUrls {
    meta:
        description = "WebExtension claims <all_urls> or *://*/* host access — content scripts / webRequest see every site the user visits"
        severity    = "high"
        category    = "collection"
        mitre       = "T1539"
    strings:
        $mv    = "\"manifest_version\"" ascii wide nocase
        $h1    = "\"<all_urls>\"" ascii wide nocase
        $h2    = "\"*://*/*\"" ascii wide nocase
        $h3    = "\"http://*/*\"" ascii wide nocase
        $h4    = "\"https://*/*\"" ascii wide nocase
    condition:
        $mv and 1 of ($h*)
}

rule BrowserExt_CSP_UnsafeEval {
    meta:
        description = "WebExtension manifest relaxes content_security_policy with 'unsafe-eval' or 'unsafe-inline' — lets the extension run runtime-assembled JS"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027"
    strings:
        $mv    = "\"manifest_version\"" ascii wide nocase
        $csp   = "\"content_security_policy\"" ascii wide nocase
        $e1    = "'unsafe-eval'" ascii wide nocase
        $e2    = "'unsafe-inline'" ascii wide nocase
    condition:
        $mv and $csp and 1 of ($e*)
}

rule BrowserExt_Debugger_Management {
    meta:
        description = "WebExtension requests debugger, management, or declarativeNetRequestFeedback — can inspect / kill other extensions or attach to tabs as a debugger"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1562.001"
    strings:
        $mv    = "\"manifest_version\"" ascii wide nocase
        $d1    = "\"debugger\"" ascii wide nocase
        $d2    = "\"management\"" ascii wide nocase
        $d3    = "\"declarativeNetRequestFeedback\"" ascii wide nocase
    condition:
        $mv and 1 of ($d*)
}

rule BrowserExt_ExternallyConnectable_Wide {
    meta:
        description = "WebExtension exposes an externally_connectable port to <all_urls> or *://*/* — any web page can postMessage into the extension's background"
        severity    = "high"
        category    = "initial-access"
        mitre       = "T1189"
    strings:
        $mv    = "\"manifest_version\"" ascii wide nocase
        $ext   = "\"externally_connectable\"" ascii wide nocase
        $w1    = "\"<all_urls>\"" ascii wide nocase
        $w2    = "\"*://*/*\"" ascii wide nocase
    condition:
        $mv and $ext and 1 of ($w*)
}

rule BrowserExt_Proxy_Permission {
    meta:
        description = "WebExtension requests the proxy permission — can silently redirect every HTTP/S request through an attacker-controlled proxy"
        severity    = "medium"
        category    = "command-and-control"
        mitre       = "T1090.002"
    strings:
        $mv    = "\"manifest_version\"" ascii wide nocase
        $p     = "\"proxy\"" ascii wide nocase
    condition:
        $mv and $p
}

rule BrowserExt_Cookies_History_Combo {
    meta:
        description = "WebExtension combines cookies / history / webRequest permissions — classic session- and browsing-history-harvesting shape"
        severity    = "medium"
        category    = "collection"
        mitre       = "T1539"
    strings:
        $mv    = "\"manifest_version\"" ascii wide nocase
        $c     = "\"cookies\"" ascii wide nocase
        $h     = "\"history\"" ascii wide nocase
        $wr    = "\"webRequest\"" ascii wide nocase
    condition:
        $mv and (($c and $h) or ($c and $wr) or ($h and $wr))
}

rule BrowserExt_UpdateUrl_NonStore {
    meta:
        description = "WebExtension manifest points update_url at an HTTP or non-store host — self-updates off the official Chrome Web Store / AMO channel"
        severity    = "medium"
        category    = "persistence"
        mitre       = "T1546"
    strings:
        $mv    = "\"manifest_version\"" ascii wide nocase
        $uu    = "\"update_url\"" ascii wide nocase
        $http  = "\"http://" ascii wide nocase
        $ngrok = ".ngrok" ascii wide nocase
        $cf    = ".trycloudflare.com" ascii wide nocase
        $paste = "pastebin.com" ascii wide nocase
        $gist  = "gist.githubusercontent.com" ascii wide nocase
        $raw   = "raw.githubusercontent.com" ascii wide nocase
    condition:
        $mv and $uu and 1 of ($http, $ngrok, $cf, $paste, $gist, $raw)
}

rule BrowserExt_LegacyXUL_Bootstrap {
    meta:
        description = "Legacy Firefox install.rdf with em:bootstrap=true — pre-WebExtension add-on with full XPCOM/chrome access"
        severity    = "medium"
        category    = "execution"
        mitre       = "T1218"
    strings:
        $rdf   = "install.rdf" ascii wide nocase
        $ns    = "em:bootstrap" ascii wide nocase
        $tgt   = "{ec8030f7-c20a-464f-9b0e-13a3a9e97384}" ascii wide nocase
        $t     = "em:targetApplication" ascii wide nocase
    condition:
        ($ns or $tgt) and ($rdf or $t)
}

rule BrowserExt_WebAccessibleResources_AllUrls {
    meta:
        description = "WebExtension exposes web_accessible_resources to <all_urls> — any page can load the extension's internal scripts / HTML as a same-origin-to-extension asset"
        severity    = "medium"
        category    = "defense-evasion"
        mitre       = "T1027"
    strings:
        $mv    = "\"manifest_version\"" ascii wide nocase
        $war   = "\"web_accessible_resources\"" ascii wide nocase
        $all   = "\"<all_urls>\"" ascii wide nocase
        $star  = "\"*://*/*\"" ascii wide nocase
    condition:
        $mv and $war and 1 of ($all, $star)
}

rule BrowserExt_NativeHost_Bridge {
    meta:
        description = "Native-messaging host manifest bundled inside the extension — path + allowed_origins ties the browser bridge directly to a local executable"
        severity    = "high"
        category    = "execution"
        mitre       = "T1559"
    strings:
        $ao    = "\"allowed_origins\"" ascii wide nocase
        $path  = "\"path\"" ascii wide nocase
        $type  = "\"stdio\"" ascii wide nocase
        $proto = "\"chrome-extension://" ascii wide nocase
    condition:
        $ao and $path and ($type or $proto)
}

rule BrowserExt_Eval_InScript {
    meta:
        description = "Bundled extension script calls eval() / Function() / chrome.tabs.executeScript({code:…}) on attacker-controllable strings — classic obfuscated-loader shape"
        severity    = "medium"
        category    = "defense-evasion"
        mitre       = "T1140"
    strings:
        $api1  = "chrome.runtime" ascii wide nocase
        $api2  = "browser.runtime" ascii wide nocase
        $e1    = "new Function(" ascii wide nocase
        $e2    = "eval(atob(" ascii wide nocase
        $e3    = "executeScript({code:" ascii wide nocase
        $e4    = "executeScript({ code:" ascii wide nocase
    condition:
        1 of ($api*) and 1 of ($e*)
}
