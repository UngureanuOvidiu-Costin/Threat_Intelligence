# Gamaredon Group


## Terms and Processes 
- Aliases: ACTINIUM, Actinium, Aqua Blizzard, Blue Otso, BlueAlpha, DEV-0157, G0047, IRON TILDEN, PRIMITIVE BEAR, Shuckworm, Trident Ursa, UAC-0010, UNC530 and Winterflounder 
- First apparition: at least 2013
- Last apparition: 2024-04-12 (DPO_SEC23-1_OMA_P-3_18-ENG.pdf.cmd): 
	- Where to find: https://bazaar.abuse.ch/sample/8f8abfa6717ad2043a295d16b5aeeac3e7084b7994f6eec8351e18a9a3c59997/
    - SHA256 hash:	8f8abfa6717ad2043a295d16b5aeeac3e7084b7994f6eec8351e18a9a3c59997
	- Malicious cmd file disguised as pdf file
	

## Script

Their script is obfuscated using b64 and dynamic string encoding.
The big script hides 3 smaller powershell scripts. For each of them, we have deobfuscated them using PowerDecode and manually decoded the links.

How the scripts are started:
```batch
@echo off
set xps1=malicious_script1
set xwp0=powershell
set xwp1=-windowStyle
set xwp2=hidden
cmd /c start /min "" %xwp0% %xwp1% %xwp2% -c (%xwp0% %xwp1% %xwp2% -enC ($env:xps1))

set xps2=malicious_script2
cmd /c start /min "" %xwp0% %xwp1% %xwp2% -c (%xwp0% %xwp1% %xwp2% -enC ($env:xps2))

set xps3=malicious_script3
cmd /c start /min "" %xwp0% %xwp1% %xwp2% -c (%xwp0% %xwp1% %xwp2% -enC ($env:xps3))
```

The deobfuscated powershell scripts have been uploaded to this repo: https://github.com/UngureanuOvidiu-Costin/Threat_Intelligence/tree/main/Gamaredon

This is the sequence diagram for the malware:
<img src="https://github.com/UngureanuOvidiu-Costin/Threat_Intelligence/blob/main/Gamaredon/sequence_diagram.png">

The behaviour of the malware is as follows:

1. The user clicks the fake pdf
2. The bat script launches 3 b64 encoded scripts, one after the other
3. The first script starts a decoy pdf file, for the unsuspecting user
4. The second script will launch itself and run indefinitely in RAM. This script executes C2 commands at 2-3 seconds delay.
5. The third script assures persistence of the second script, as it writes the content of it into decoy registers XBoxD(i). Also, makes a register XBoxCache in autorun for the script to run at the start of the computer.
