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
* [Twitter](https://twitter.com/IT_securitynews/status/1769003278379921892)


# Intrusion Campaigns
* [CVE-2024-21338](https://digvel.com/blog/lazarus-group-exploits-windows-zero-day-for-kernel-privileges/)
* [Healthcare](https://therecord.media/lazarus-new-malware-manageengine-open-source)
* 

## Organization

- North Korean state-sponsored actors
- Espionage, sabotage, funding for the regime

- "If warfare was about bullets and oil until now, warfare in the 21st
century is about information. War is won and lost by who has
greater access to the adversary’s military technical information in
peacetime, how effectively one can disrupt the adversary’s military
command and control information, and how effectively one can
utilize one’s own information." - Kin Jong-Un, 2010

- “With intensive information and communication technology, and the brave RGB with its [cyber] warriors, we can penetrate any
sanctions for the construction of a strong and prosperous nation.” - Kim Jong-Un, 2013

- Reconnaisance General Bureau (RGB)
- "Lazarus" - catch-all term for North Korean actors
- CrowdStrike: 5 North Korean groups with different purposes
  - Labyrinth Chollima
    - Bureau 121
    - espionage / funding dual-purpose
  - Stardust
    - Specialized in cryptocurrency and financial services targeting
  - Silent
    - Economic espionage
  - Velvet
    - NGO, think-tanks, academia - intelligence collection
  - Ricochet
    - Similar to Velvet, specialized in South Korea, higher technical level
    - E.g. fake religious applications to track people bringing religion in North Korea
  using "accessibility mode" to silently turn on all other permissions
- References: CS Adversary Universe podcast NK episode (https://www.crowdstrike.com/resources/adversary-universe-podcast/),
  The All-Purpose Sword: North Korea's Cyber Operations and Strategies, by Ji Young, Kong, Jong In, Lim, and Kyoung Gon, Kim

### Command structure

![image](./nk/command.png)

- Reference:
  - The All-Purpose Sword: North Korea's Cyber Operations and Strategies, by Ji Young, Kong, Jong In, Lim, and Kyoung Gon, Kim

### Motivation
- Military first mentality since NK creation after the Korean war
- Distruptive-destructive provocation attacks
- Shift in 2016 (along with government reshuffle)
- National Economic Development Strategy
- Transition from to revenue generation and economic espionage
- Reference: CS Adversary Universe podcast

### Known members
- Park Jin Hyok

![image](./handsome_fellows/park_jin_hyok.png)

![image](./handsome_fellows/park_jin_hyok_fbi_wanted.png)

- Jon Chang Hyok

![image](./handsome_fellows/jon_chang_hyok.png)

- Kim Il

![image](./handsome_fellows/kim_il.png)

- Reference: [US Indictment against hackers](https://www.justice.gov/usao-cdca/press-release/file/1367721/download)

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
 - https://www.fbi.gov/news/press-releases/fbi-identifies-lazarus-group-cyber-actors-as-responsible-for-theft-of-41-million-from-stakecom
   ![image](https://github.com/UngureanuOvidiu-Costin/Threat_Intelligence/assets/102877918/88143cd3-0fe6-45e8-9b50-23796a016394)
 - https://securityaffairs.com/150957/apt/lazarus-stole-240m-crypto-assets.html
   ![image](https://github.com/UngureanuOvidiu-Costin/Threat_Intelligence/assets/102877918/fc19321f-87fd-4de3-8a0b-b605b5d3d5f5)

### Known used BTC addresses:
 - 3LU8wRu4ZnXP4UM8Yo6kkTiGHM9BubgyiG
 - 39idqitN9tYNmq3wYanwg3MitFB5TZCjWu
   - 24.03.2024 - Outgoing -109.88308933 BTC ($7,074,422)
 - 3AAUBbKJorvNhEUFhKnep9YTwmZECxE4Nk
 - 3PjNaSeP8GzLjGeu51JR19Q2Lu8W2Te9oc
   - 14.04.2024 - Outgoing -277.99983140 BTC ($17,779,676)
 - 3NbdrezMzAVVfXv5MTQJn4hWqKhYCTCJoB
 - 34VXKa5upLWVYMXmgid6bFM4BaQXHxSUoL
 - References:
   - https://www.fbi.gov/news/press-releases/fbi-identifies-cryptocurrency-funds-stolen-by-dprk
   - https://www.blockchain.com/explorer/addresses/btc/39idqitN9tYNmq3wYanwg3MitFB5TZCjWu
   - https://www.blockchain.com/explorer/addresses/btc/3PjNaSeP8GzLjGeu51JR19Q2Lu8W2Te9oc
	
## Timeline


![Lazarus drawio](https://github.com/UngureanuOvidiu-Costin/Threat_Intelligence/assets/102877918/4d8c28b2-6388-4e96-bcf5-8f031dc28681)


## TraderTraitor 
 - Malicious cryptocurrency applications
 - Spear-phishing campaign aimed at employees of cryptocurrency companies
 - Reference: https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-108a

### IoCs:
 - DAFOM
   - Cryptocurrency portfolio application
   - Mach-O binary packaged within the Electron application
   - Signed by an Apple digital signature issued for the Apple Developer Team W58CYKFH67
   - URL: dafom[.]dev
   - IP Address: 45.14.227[.]58
   - SHA-256: 60b3cfe2ec3100caf4afde734cfd5147f78acf58ab17d4480196831db4aa5f18
 - TokenAIS
   - “build a portfolio of AI-based trading” for cryptocurrencies.
   - Apple Developer Team RN4BTXA4SA
   - URL: tokenais[.]com
   - IP Address: 199.188.103[.]115
   - SHA-256: 5b40b73934c1583144f41d8463e227529fa7157e26e6012babd062e3fd7e0b03
 - AlticGO
   - Nullsoft Scriptable Install System (NSIS) Windows executables that extracted an Electron application packaged for Windows
   - URL: alticgo[.]com
   - IP Address: 108.170.55[.]202
   - SHA-256:
     - 765a79d22330098884e0f7ce692d61c40dfcf288826342f33d976d8314cfd819
     - e3d98cc4539068ce335f1240deb1d72a0b57b9ca5803254616ea4999b66703ad
     - 8acd7c2708eb1119ba64699fd702ebd96c0d59a66cba5059f4e089f4b0914925
 - Esilet
   - claims to offer live cryptocurrency prices and price predictions
   - URL: esilet[.]com
   - IP Address: 104.168.98[.]156
   - SHA-256:
     - 9ba02f8a985ec1a99ab7b78fa678f26c0273d91ae7cbe45b814e6775ec477598 (MacOS)
   - C2 Endpoints:
     - hxxps://greenvideo[.]nl/wp‐content/themes/top.php
     - hxxps://dafnefonseca[.]com/wp‐content/themes/top.php
     - hxxps://haciendadeclarevot[.]com/wp‐content/top.php
 - CreAI Deck:
   - platform for “artificial intelligence and deep learning.”
   - URL: creaideck[.]com
     - IP Address: 38.132.124[.]161
   - URL: aideck[.]net
     - IP Address: 89.45.4[.]151

## Suricata / Snort rules examples (remove square brackets before use)
- drop tcp any any -> 45.14.227[.]58 any ( sid:25000; rev:1; )
- alert dns any any -> any any (msg:"DNS Query for TraderTraitor domain dafom[.]com"; dns\_query; content:"dafom[.]com"; sid:1234; rev:1;)

## WannaCry Demo
![image](https://github.com/UngureanuOvidiu-Costin/Threat_Intelligence/assets/102877918/46ee882f-dfc3-467a-9219-50cde6f80891)
MD5: db349b97c37d22f5ea1d1841e3c89eb4
SHA256: 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c

### IoCs:
- http://www.iuqerfsodp9ifjaposdfjhgosurijarwrwergwea.com

### Behaviour:
1. ![image](https://github.com/UngureanuOvidiu-Costin/Threat_Intelligence/assets/102877918/92b10425-12b3-40c4-a647-dcb4b2e32e94)
Performs a request on the URL and if it fails, the main execution thread enters the `function wanna_cry_entr()`.
2. What is the compiler of the PE?<br>
![alt text](image.png)<br>
3. What sections does this PE contain?
 - .text
 - .rdata
 - .data
 - .rsrc
4. What is the compiler timestamp value?<br>
**Sat Nov 20 11:03:08 2010**
5.  IDA displays the imported APIs and their respective modules inside the Imports window.<br>
 ● CryptAcquireContextA, CryptGenRandom indicate that the PE might be doing
 cryptographic actions;<br>
 ● CreateFileA, MoveFileExA, GetFileSize, ReadFile tell us that the process will<br>
 manipulate different files on the file system;<br>
 ● CreateServiceA,
 OpenServiceA,
 RegisterServiceCtrlHandlerA,
 StartServiceA, StartServiceCtrlDispatcherA, ChangeServiceConfig2, these
 are used to interact with Windows Services;<br>
 ● FindResourceA, LoadResource, SizeofResource are used to manipulate
 different attachments inside the PE binary;<br>
 ● GetAdaptersInfo, GetPerAdapterInfo acquires information about the network
 cards and their settings;<br>
 ● GetProcAddress will dynamically resolve the address of other functions from
 different modules;<br>
 ● InternetOpenA, InternetOpenUrlA can be used to open a web resource;<br>
 ● inet_addr, recv, send, socket, connect, WSAStartup can be used for network
 communication over different ports and protocols.<br>
 6. Do the embedded strings help you find OSINT about the file?
 - mssecsvc.exe
 - http[:]//www[.]iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com
 - mssecsvc2.0
 - tasksche.exe
 7. Does the PE have any embedded file?<br>
The FindResource, LoadResource and LockResource Windows APIs indicate the use of embedded files and these functions help the programmer to easily grab a handle of the
resources.
8. Moving into the code:
![alt text](image-3.png)
    1. The URLis moved from one memory location to another using rep movsd
    2.  InternetOpenA will initialise the use WinInit library
    3.  InternetOpenUrlA will open an HTTP resource pointed at by the second argument
    4. Tests out the return value to see if the HTTP request was successful
     -  if the return is not equal to 0 (JNZ), it jumps on the True branch
     -  if the return is equal to 0, it will continue execution on the False branch<br>
    True: will close handles and will end/finish the process
    False: will close handles and will call the subroutine from 0x408090 <br>
    Can you tell us why ? 
    <br>
9. The subroutine from 0x00408090:<br>
![alt text](image-5.png)
- Fetches the full name of the process including the path on the disk and gets the number
 of arguments that were passed to the process. If the number of arguments is at least 2, it
 will jump on True branch, if not it will continue on the False branch
- Will call the subroutine from 0x407F20
- Establishes a connection to the service control manager on the specified computer and
 opens the specified service control manager database
- Fetches a handle to an existing service that can be used to interact with it
-  A call to the subroutine from 0x407FA0 is made and it also receives the handle to the
 service along with a second integer argument. This subroutine will change the service
 configuration
- This call indicates that the PE can run as a service, this API function specifies the
 service control subroutine that the service control manager will call. The service control
 subroutine is moved into a SERVICE_TABLE_ENTRY structure at 0x0040810E

 10. Subroutine from 0x00407CE0:
 ![alt text](image-6.png)
 In the first block of this subroutine, a call to GetModuleHandleW will get a handle of
 Kernel32DLL. The second block will dynamically resolve four Windows APIs using the
 GetProcAddress. GetProcAddress receives the Kernel32 handle along with the name of the
 API. The four APIs are CreateProcessA, CreateFileA, WriteFile, CloseHandle, the pointer to
 them will be returned in eax, then moved(saved) to a different location in memory.

 The code proves the fact that there are threads used to parallelize tasks.
 Also, contains a block of code which performs `Sleep` with `0x5265C00` as argument: 24h. 

#### Stage 2:
MD5: 84c82835a5d21bbcf75a61706d8ab549 <br>
SHA-256: ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa <br>

1. Does any Windows API catch your attention? Why?
In addition to our first stage sample, the second stage imports several other APIs:<br>
 - **RegSetValueExA, RegQueryValueExA, RegCreateKeyW, RegCloseKey** are
 used to manipulate values inside the Windows Registry Hives
 - **CreateProcessA, TerminateProcess** are used to start and kill processes
 - **GetComputerNameW** will get the name of the infected machine
 - **OpenMutexAwill** return a handle to a synchronization object of type Mutex.
 - **CreateDirectory, CreateFile, GetFileAttributes, GetFileSize, ReadFile,
 SetFilePointer** enables interaction with files and directories from the file system

![alt text](image-1.png)

The embedded resource is located at 2058:
![alt text](image-2.png)<br>
Based on the `magic number` it is a ZIP file.<br>
The password of the archive is **WNcry@2ol7**. 

## How does it spread ?
1. Generates a random IP address.
2. Performs an EternalBlue attack on the IP, which is an exploit of Microsoft's implementation of their Server Message Block (SMB) protocol.
https://en.wikipedia.org/wiki/EternalBlue


## What do these strings could mean?
 ● 13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94<br>
 ● 12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw<br>
 ● 115p7UMMngoj1pMvkpHijcRdfJNXj6LrLn
