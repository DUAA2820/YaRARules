rule Unkown_malware {
	meta:
        author = "Duaa Suliman, Jude Abutaha and Ayah Alajloni"
		description = "Rule to detect the malware based on specific strings"
        date = "2023-05-28"
        md5= "288ED41EFF190F69A1BC3D156743834E"
		filename = "Unknown_Malware.exe"		
	strings:
		$magic_byte = "MZ"
		$PSUTdll = "PSUT.dll is missing!" wide
		$hacked = "C:\\Users\\Hacked2.txt" wide
		$updator = "C:\\windows\\updator.exe" wide
		$post_handler = "http://www.example.com/post_handler" wide
	condition:
		($magic_byte at 0) and ($PSUTdll and $hacked and $updator) or ($PSUTdll and $post_handler)	
}