rule SVG_Embedded_Script {
    meta:
        description = "SVG contains embedded <script> element — potential JavaScript execution"
        severity    = "critical"
        category    = "execution"
        mitre       = "T1059.007"
    strings:
        $svg     = "<svg" nocase
        $script1 = "<script" nocase
        $script2 = "&lt;script" nocase
    condition:
        $svg and any of ($script*)
}

rule SVG_ForeignObject_Form {
    meta:
        description = "SVG <foreignObject> contains HTML form — potential credential phishing"
        severity    = "high"
        category    = "phishing"
        mitre       = "T1566.002"
    strings:
        $fo   = "<foreignObject" nocase
        $form = "<form" nocase
    condition:
        $fo and $form
}

rule SVG_ForeignObject_Password {
    meta:
        description = "SVG <foreignObject> contains password field — credential harvesting"
        severity    = "critical"
        category    = "credential-access"
        mitre       = "T1056.003"
    strings:
        $fo   = "<foreignObject" nocase
        $pwd1 = "type=\"password\"" nocase
        $pwd2 = "type='password'" nocase
        $pwd3 = "type=password" nocase
    condition:
        $fo and any of ($pwd*)
}

rule SVG_ForeignObject_Iframe {
    meta:
        description = "SVG <foreignObject> contains <iframe> — potential redirect or phishing page"
        severity    = "high"
        category    = "phishing"
        mitre       = "T1566.002"
    strings:
        $fo     = "<foreignObject" nocase
        $iframe = "<iframe" nocase
    condition:
        $fo and $iframe
}

rule SVG_Event_Handler_OnLoad {
    meta:
        description = "SVG element with onload handler — JavaScript executes when SVG renders"
        severity    = "high"
        category    = "execution"
        mitre       = "T1059.007"
    strings:
        $svg     = "<svg" nocase
        $onload1 = /onload\s*=\s*["'][^"']{1,500}["']/i
        $onload2 = /onload\s*=\s*[^"'\s>]{1,200}/i
    condition:
        $svg and any of ($onload*)
}

rule SVG_Event_Handler_Mouse {
    meta:
        description = "SVG element with mouse event handler — JavaScript on user interaction"
        severity    = "high"
        category    = "execution"
        mitre       = "T1059.007"
    strings:
        $svg    = "<svg" nocase
        $mouse1 = /onmouseover\s*=\s*["'][^"']{1,500}["']/i
        $mouse2 = /onclick\s*=\s*["'][^"']{1,500}["']/i
        $mouse3 = /onmouseenter\s*=\s*["'][^"']{1,500}["']/i
        $mouse4 = /onmousedown\s*=\s*["'][^"']{1,500}["']/i
    condition:
        $svg and any of ($mouse*)
}

rule SVG_Event_Handler_Error {
    meta:
        description = "SVG element with onerror handler — forced error triggers JavaScript"
        severity    = "high"
        category    = "execution"
        mitre       = "T1059.007"
    strings:
        $svg     = "<svg" nocase
        $onerror = /onerror\s*=\s*["'][^"']{1,500}["']/i
    condition:
        $svg and $onerror
}

rule SVG_Base64_Script_Payload {
    meta:
        description = "SVG contains Base64-encoded JavaScript payload in data: URI"
        severity    = "critical"
        category    = "obfuscation"
        mitre       = "T1027"
    strings:
        $data_js1 = "data:text/javascript;base64," nocase
        $data_js2 = "data:application/javascript;base64," nocase
        $data_js3 = "data:text/ecmascript;base64," nocase
    condition:
        any of ($data_js*)
}

rule SVG_Data_URI_HTML {
    meta:
        description = "SVG contains data:text/html URI — potential embedded phishing page"
        severity    = "high"
        category    = "phishing"
        mitre       = "T1566.002"
    strings:
        $data_html1 = "data:text/html;base64," nocase
        $data_html2 = "data:text/html," nocase
    condition:
        any of ($data_html*)
}

rule SVG_JavaScript_Obfuscation {
    meta:
        description = "SVG contains obfuscated JavaScript patterns (eval, atob, fromCharCode)"
        severity    = "high"
        category    = "obfuscation"
        mitre       = "T1027"
    strings:
        $svg   = "<svg" nocase
        $eval  = /eval\s*\(/ nocase
        $atob  = /atob\s*\(/ nocase
        $fcc   = "String.fromCharCode" nocase
        $unesc = /unescape\s*\(/ nocase
        $func  = /Function\s*\(/ nocase
    condition:
        $svg and any of ($eval, $atob, $fcc, $unesc, $func)
}

rule SVG_Document_Cookie {
    meta:
        description = "SVG accesses document.cookie — potential session theft"
        severity    = "critical"
        category    = "credential-access"
        mitre       = "T1539"
    strings:
        $cookie = "document.cookie" nocase
        $svg    = "<svg" nocase
    condition:
        $cookie and $svg
}

rule SVG_Location_Redirect {
    meta:
        description = "SVG contains location redirect — potential phishing redirect"
        severity    = "high"
        category    = "phishing"
        mitre       = "T1566.002"
    strings:
        $loc1 = "window.location" nocase
        $loc2 = "document.location" nocase
        $loc3 = "location.href" nocase
        $loc4 = "location.replace" nocase
        $svg  = "<svg" nocase
    condition:
        any of ($loc*) and $svg
}

rule SVG_XMLHttpRequest_Fetch {
    meta:
        description = "SVG makes network request — potential data exfiltration"
        severity    = "high"
        category    = "exfiltration"
        mitre       = "T1048"
    strings:
        $xhr   = "XMLHttpRequest" nocase
        $fetch = /fetch\s*\(/ nocase
        $svg   = "<svg" nocase
    condition:
        ($xhr or $fetch) and $svg
}

rule SVG_External_Use_Reference {
    meta:
        description = "SVG <use> element references external resource"
        severity    = "medium"
        category    = "command-and-control"
        mitre       = "T1105"
    strings:
        $use   = "<use" nocase
        $http1 = /xlink:href\s*=\s*["']https?:\/\//i
        $http2 = /href\s*=\s*["']https?:\/\//i
    condition:
        $use and any of ($http*)
}

rule SVG_Animate_Href_Manipulation {
    meta:
        description = "SVG <animate>/<set> modifies href attribute — runtime URL manipulation"
        severity    = "high"
        category    = "defense-evasion"
        mitre       = "T1027"
    strings:
        $anim1 = "<animate" nocase
        $anim2 = "<set" nocase
        $attr1 = "attributeName=\"href\"" nocase
        $attr2 = "attributeName='href'" nocase
        $attr3 = "attributeName=\"xlink:href\"" nocase
        $attr4 = "attributeName='xlink:href'" nocase
    condition:
        any of ($anim*) and any of ($attr*)
}

rule SVG_XXE_Entity {
    meta:
        description = "SVG contains XML entity declaration — potential XXE attack"
        severity    = "high"
        category    = "initial-access"
        mitre       = "T1190"
    strings:
        $svg    = "<svg" nocase
        $entity = /<!ENTITY\s+\w+/i
        $system = /SYSTEM\s+["']/i
    condition:
        $entity or ($system and $svg)
}

rule SVG_Meta_Refresh_Redirect {
    meta:
        description = "SVG contains meta refresh redirect — automatic navigation to phishing URL"
        severity    = "high"
        category    = "phishing"
        mitre       = "T1566.002"
    strings:
        $meta = /http-equiv\s*=\s*["']?refresh/i
        $url  = /url\s*=\s*["']?https?:\/\//i
        $fo   = "<foreignObject" nocase
    condition:
        $meta and $url and $fo
}

rule SVG_Phishing_Multi_Indicator {
    meta:
        description = "SVG exhibits multiple phishing indicators (script + form/redirect + obfuscation)"
        severity    = "critical"
        category    = "phishing"
        mitre       = "T1566.002"
    strings:
        $script = "<script" nocase
        $fo     = "<foreignObject" nocase
        $form   = "<form" nocase
        $pwd    = "password" nocase
        $eval   = /eval\s*\(/ nocase
        $atob   = /atob\s*\(/ nocase
        $loc    = "location" nocase
    condition:
        $script and ($fo or $form) and ($pwd or $eval or $atob or $loc)
}
