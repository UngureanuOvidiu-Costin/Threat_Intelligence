# Lazarus Group


## Terms and Processes 
- Aliases: Hidden Cobra, Zinc, APT-C-26, Guardians of Peace, Group 77, Who Is Hacking Team, Stardust Chollima, and Nickel Academy
- First apparition: 2009
- Last apparition: 2024-03-22
	- Malitious DLL used
	- MITRE ATT&CK Tactics and Techniques:
		- TA0002
		- TA0004
		- TA0007
		- TA0011

# News 
* [SANS ISC](https://isc.sans.edu/diary/Loader+activity+for+Formbook+QM18/30020)
* [The Hacker News Logo](https://thehackernews.com/2023/12/lazarus-group-using-log4j-exploits-to.html)

# Intrusion Campaigns
* [CVE-2024-21338](https://digvel.com/blog/lazarus-group-exploits-windows-zero-day-for-kernel-privileges/)
* [Healthcare](https://therecord.media/lazarus-new-malware-manageengine-open-source)

## Operation Interception
  - Operation Interception - 2020 - Espionage campaign
  - Compromised domains:
	  -  fabianiarte.com
	  -  krnetworkcloud.org

## Operation North Star
- Operation North Star - 2020 - Espionage campaign
- Domain list:
  	- saemaeul.mireene.com
	- orblog.mireene.com
	- sgmedia.mireene.com
	- vnext.mireene.com
	- nhpurumy.mireene.com
	- jmable.mireene.com
	- jmdesign.mireene.com
	- all200.mireene.com

## Other campaigns: 
- Operation Flame
- Operation 1Mission
- Operation Troy
- DarkSeoul
- Ten Days of Rain
- Operation Blockbuster

# Third Party Intelligence 
  * [AlienVault](https://otx.alienvault.com/adversary/Lazarus%20Group) - **Date Received: 2024-01-17**
  * [Malpedia](https://malpedia.caad.fkie.fraunhofer.de/actor/lazarus_group) - **Date Received: 2024-02-07**
  * MISP - **Date Received: 2024-03-22**

# Known Malicious Tools 
- Responder
- DRATzarus
- Torisma
- Destover
- Malitious DLL files
- Customized dbxcli
- Malitious Office files
- Malitious XSL scripts to download next stage


## Exploits 
  - Responder - used for LLMNR, NBT-NS and MDNS poisoning, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication.
  - Torisma - Used for Remode Desktop connections

## Implants 
- Malitious DLLs
- LNK files in startup folder
- Torism - Monitoring tool on victim's computer

## Utilities 
- Both Operation Interception and Operation North Star used most likely the same utilities, which is one more reason why they are called  Operation Dream Job as an umbrella term.
- The utilities:
  - Malitious DOCX files to run Macros
  - Used `regsvr32` to execute malware
  - Digitally signed their own malware to evade detection
  - *LinkedIn*  - phishing
  - *OneDrive*  and *OneDrive* - phishing links
  - **Themida** packer
  - `IsDebuggerPresent` call to detect debuggers
  - VBS and Powershell scripts
  - WMIC - Execute remote XSL script
  - delivered updates using HTTP and HTTPS requests
  - Wake-On-Lan combined with dbxcli to exfiltrate user's data on OneDrive

## Money:
	Lazarus Group has been operation for more than 10 years, and according to U.S. officials, has stolen over 2$ bilion worth of cryptocurrency.
	

## Timeline


![Lazarus drawio](https://github.com/UngureanuOvidiu-Costin/Threat_Intelligence/assets/102877918/4d8c28b2-6388-4e96-bcf5-8f031dc28681)


