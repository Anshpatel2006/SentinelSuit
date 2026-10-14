rule Suspicious_Strings
{
    meta:
        description = "Detects common suspicious strings often found in malware"
        author = "AI Malware Analysis Platform"
        date = "2026-08-12"
    strings:
        $http = "http://" ascii wide
        $https = "https://" ascii wide
        $cmd = "cmd.exe" nocase ascii wide
        $powershell = "powershell.exe" nocase ascii wide
        $reg = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase ascii wide
    condition:
        any of them
}

rule Packed_UPX
{
    meta:
        description = "Detects UPX packed files"
        author = "AI Malware Analysis Platform"
    strings:
        $upx0 = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $upx2 = "UPX2" ascii
        $upx_magic = { 55 50 58 21 } // UPX!
    condition:
        $upx_magic and 2 of ($upx*)
}
