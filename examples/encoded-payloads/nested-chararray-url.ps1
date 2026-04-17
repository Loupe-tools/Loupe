# Char array obfuscation hiding a phishing URL
# Tests: character code array detection and IOC extraction

$chars = @(104,116,116,112,58,47,47,112,104,105,115,104,105,110,103,46,101,120,97,109,112,108,101,46,99,111,109,47,108,111,103,105,110,46,104,116,109,108)
$url = -join ($chars | ForEach-Object { [char]$_ })
Start-Process $url
