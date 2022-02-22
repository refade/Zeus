# Zeus
Retrieval for Zeus Malware Analysis 

## Commercial Antivirus Limitation

Technically, the modus operandi for the identification of malicious files and servers refers to consult in named blacklist databases. The VirusTotal platform issues the diagnoses regarding malignant characteristics related to files and web servers.

When it comes to suspicious files, VirusTotal issues the diagnostics provided by the world's leading commercial antivirus products. Regarding suspicious web servers, VirusTotal uses the database responsible for sensing virtual addresses with malicious practices.

VirusTotal has Application Programming Interface (APIs) that allow programmers to query the platform in an automated way and without the use of the graphical web interface. The proposed paper employs two of the APIs made available by VirusTotal. The first one is responsible for sending the investigated files to the platform server. The second API, in turn, makes commercial antivirus diagnostics available for files submitted to the platform by the first API.

Initially, the executable malwares are sent to the server belonging to the VirusTotal platform. After that, the executables are analyzed by the 93 commercial antiviruses linked to VirusTotal. Therefore, the antivirus provides its diagnostics for the executables submitted to the platform. VirusTotal allows the possibility of issuing three different types of diagnostics: malware, benign and omission.

Then, through the VirusTotal platform, the proposed paper investigates 93 commercial antiviruses with their respective results presented in Table 1. We used  12,540 malicious executables for 32-bit architecture. The goal of the work is to check the number of virtual pests cataloged by antivirus. The motivation is that the acquisition of new virtual plagues plays an important role in combating malicious applications. Therefore, the larger the database of malwares blacklisted, the better it tends to be the defense provided by the antivirus.

As for the first possibility of VirusTotal, the antivirus detects the malignity of the suspicious file. In the proposed experimental environment, all submitted executables are public domain malwares. Therefore, in the proposed study, the antivirus hits when it detects the malignity of the investigated executable. Malware detection indicates that the antivirus provides a robust service against cyber-intrusions. As larger the blacklist database, better tends to be the defense provided by the antivirus.

In the second possibility, the antivirus attests to the benignity of the investigated file. Therefore, in the proposed study, when the antivirus attests the benignity of the file, it is a case of a false negative – since all the samples are malicious. That is, the investigated executable is a malware; however, the antivirus attests to benignity in the wrong way.

In the third possibility, the antivirus does not emit opinion about the suspect executable. The omission indicates that the file investigated has never been evaluated by the antivirus neither it has the robustness to evaluate it in real time. The omission of the diagnosis by the antivirus points to its limitation on large-scale services.

In the third possibility, the antivirus does not emit opinion about the suspect executable. The omission indicates that the file investigated has never been evaluated by the antivirus neither it has the robustness to evaluate it in real time. The omission of the diagnosis by the antivirus points to its limitation on large-scale services.

Table 1 shows the results of the evaluated 93 antivirus products. Three of these antiviruses scored above 99%. These antiviruses were: MicroWorld-eScan, Ad-Aware, and BitDefender. Malware detection indicates that these antivirus programs provide a robust service against cyber-intrusions.

A major adversity in combating malicious applications is the fact that antivirus makers do not share their malware blacklists due to commercial disputes. Through Table 1 analyse, the proposed work points to an aggravating factor of this adversity: the same antivirus vendor does not even share its databases between its different antivirus programs. Note, for example, that McAfee and McAfee-GW-Edition antiviruses belong to the same company. Their blacklists, though robust, are not shared with each other. Therefore, the commercial strategies of the same company hinder the confrontation with malware. It complements that antivirus vendors are not necessarily concerned with avoiding cyber-invasions, but with optimizing their business income.

Malware detection ranged from 0% to 99.41%, depending on the antivirus being investigated. On average, the 93 antiviruses were able to detect 61.40% of the evaluated virtual pests, with a standard deviation of 39.94%. The high standard deviation indicates that the detection of malicious executables may suffer abrupt variations depending on the antivirus chosen. It is determined that the protection, against cybernetic invasions, is due to the choice of a robust antivirus with a large and updated blacklist.

As for the false negatives, the Kingsoft and Zoner antiviruses wrongly stated that malware was benign in more than 90% of cases. On average, antiviruses attested false negatives in 12.56% of the cases, with a standard deviation of 22.62%. Tackling the benignity of malware can lead to irrecoverable damage. A person or institution, for example, would rely on a particular malicious application when, in fact, it is malware.

On average, the antiviruses were missing in 26.03% of the cases, with a standard deviation of 39.86%. The omission of the diagnosis points to the limitation of these antiviruses that have limited blacklists for detection of malware in real time.

It is included as adversity, in the combat to malicious applications, the fact of the commercial antiviruses do not possess a pattern in the classification of the malwares as seen in Table 2. We choose 3 of 12,540 malwares samples in order to exemplify the miscellaneous classifications of commercial antiviruses. In this way, the time when manufacturers react to a new virtual plague is affected dramatically. As there is no a pattern, antiviruses give the names that they want, for example, a company can identify a malware as "Malware.1" and a second company identify it as "Malware12310". Therefore, the lack of a pattern, besides the no-sharing of information among the antivirus manufacturers, hinders the fast and effective detection of a malicious application.


###### Table 1 Results of 93 commercial antiviruses:

Antivirus | Deteccion (%) | False Negative (%) | Omission (%)
--------- | ------------- | ------------------ | -------------
MicroWorld-eScan |	99.41 |	0.57 |	0.02 |
Ad-Aware	| 99.24 |	0.73 |	0.02 |
BitDefender	| 99.19 |	0.57 | 0.23 |
ESET-NOD32 | 98.94 |	1.02 |	0.04 |
GData |	98.88 |	0.59 | 0.53 |
NANO-Antivirus |	98.87 |	1.05 |	0.08 |
McAfee |	98.82 |	0.96 |	0.22 |
AVG	| 98.81	| 0.12	| 1.07 |
MAX |	98.8 |	0.99 |	0.21 |
Kaspersky |	98.72 |	0.86 |	0.42 |
Sophos |	98.59 |	1.17 |	0.24 |
Emsisoft |	98.57 |	1.04 |	0.39 |
Fortinet |	98.51 |	1.45 |	0.04 |
Panda |	98.5 |	1.48 |	0.02 |
Avira |	98.37 |	1.19 |	0.45 |
Alibaba |	98.25 |	1.71 |	0.03 |
Microsoft |	97.81 |	1.52 |	0.68 |
VIPRE |	97.74 |	1.69 |	0.57 |
DrWeb |	97.65 |	2.22 |	0.14 |
VBA32 |	97.61 |	2.16 |	0.23 |
CrowdStrike |	97.03 |	2.86 |	0.1 |
Avast |	97.01 |	1.14 |	1.85 |
Ikarus |	96.96 |	0.38 |	2.66 |
TrendMicro-HouseCall |	96.86 |	3.06 |	0.08 |
Symantec |	96.59 |	1.25 |	2.16 |
SentinelOne |	96.52 |	3.4 |	0.08 |
Comodo |	96.52 |	3.04 |	0.44 |
Rising |	96.41 |	2.98 |	0.61 |
FireEye |	96.3 |	0.31 |	3.39 |
TrendMicro |	95.95 |	3.63 |	0.42 |
Qihoo-360 |	95.65 |	2.38 |	1.97 |
Cylance |	95.64 |	1.05 |	3.31 |
Jiangmin |	95.5 |	2.58 |	1.91 |
McAfee-GW-Edition |	95.39 |	1.25 |	3.36 |
Zillya |	95.02 |	4.71 |	0.26 |
Cybereason |	94.84 |	0.96 |	4.2 |
Arcabit	| 94.78 |	5.21 |	0.01 |
BitDefenderTheta |	94.05 |	2.88	| 3.07 |
ZoneAlarm |	93.88 |	5.85 |	0.27 |
Yandex |	93.76 |	5.93 |	0.31 |
ALYac |	91.5 |	4.82 |	3.68 |
APEX |	90.39	| 9.54 |	0.07 |
F-Secure |	89.31 |	10 |	0.69 |
K7GW |	86.46 |	13.53 |	0.01 |
K7AntiVirus |	85.8 |	14.13 |	0.07 |
AhnLab-V3 |	85.74 |	14.23 |	0.03 |
Cyren |	80.38 |	19.55 |	0.06 |
CAT-QuickHeal |	80.11 |	16.51 |	3.38 |
Acronis |	78.54 |	21.41 |	0.05 |
Invincea |	74.85 |	2.73 |	22.42 |
Endgame |	74.39 |	1.59 |	24.02 |
Webroot |	71.44 |	28.23 |	0.33 |
Paloalto |	69.19 |	30.73 |	0.08 |
ClamAV |	62.83 |	36.01 |	1.16 |
ViRobot |	60.45 |	39.54 |	0.02 |
F-Prot |	58.57 |	17.05 |	24.38 |
Trapmine	| 58.4 |	4.94 |	36.66 |
TotalDefense |	53.29 |	38.56 |	8.15 |
SUPERAntiSpyware |	45.69 |	54.3 |	0.01 |
MaxSecure |	45.37 |	13.21 |	41.42 |
Malwarebytes |	40.65 |	58.88 |	0.46 |
Bkav	| 38.53 |	53.72 |	7.75 |
Antiy-AVL |	36.28 |	5.86 |	57.86 |
TACHYON |	34.34 |	65.61 |	0.05 |
Tencent |	33.85 |	64.98 |	1.16 |
Lionic |	32.19 |	8.17 |	59.63 |
CMC	| 30.13 |	69.77 |	0.1 |
Sangfor |	29.34 |	1.13 |	69.53 |
Cynet	| 26.04 |	0.35 |	73.6 |
Elastic |	21.91 |	1.62 |	76.47 |
eGambit |	20.12 |	10.84 |	69.04 |
Baidu |	14.11 |	85.48 |	0.41 |
Gridinsoft	| 8.88 |	13.64 |	77.49 |
Kingsoft |	8.79 |	90.35 |	0.86 |
Zoner |	6.48 |	92.98 |	0.53
SymantecMobileInsight |	0.1 |	0 |	99.9 |
Kaspersky21	| 0.02 |	0	| 99.98 |
AntiVir |	0.01 |	0 |	99.99 |
NOD32 |	0.01 |	0	| 99.99 |
CyrenCloud |	0.01 |	0	| 99.99 |
TheHacker |	0	| 0.01 |	99.99 |
VirusBuster |	0 |	0.01 |	99.99 |
Babable |	0 |	0.02 |	99.98 |
Trustlook |	0 |	0.22 |	99.78 |
eSafe |	0	| 0.01 |	99.99 |
Avast-Mobile |	0	| 76.15 |	23.85 |
eTrust-Vet |	0 |	0.01 |	99.99 |
Prevx |	0 |	0.01 |	99.99 |
Commtouch |	0 |	0.01 |	99.99 |
PCTools |	0 |	0.01 |	99.99 |
Avast5 |	0	| 0.01 |	99.99 |
BitDefenderFalx	| 0 |	0.02 |	99.98 |
Norman |	0 |	0.01 |	99.99 |


###### Table 2 Miscellaneous classifications of commercial antiviruses:

Antivírus | VirusShare_0000204fd1337637ed400305e0082940 | VirusShare_002e498ae7abc8465dede81943f7557d | VirusShare_002d8c9201971059f23173a098f2c430
--------- | ------------- | ------------------ | -------------
Acronis | null |null |suspicious |
Ad-Aware | Trojan.Dropper.WYO |null |Gen:Variant.Mikey.66498 |
AhnLab-V3 | Win-Trojan/Agent.700416.DW |null |Spyware/Win32.Zbot.R25976 |
Alibaba | TrojanSpy:Win32/PWSZbot.76413eaf |Worm:Win32/Gamarue.266089bc |VirTool:Win32/Injector.f1f6d212 |
ALYac | Trojan.Dropper.WYO |Gen:Variant.Ser.Razy.7042 |Gen:Variant.Mikey.66498 |
Antiy-AVL | Trojan[Spy]/Win32.Zbot |Trojan[Backdoor]/Win32.Androm.a |Trojan[Spy]/Win32.Zbot |
APEX | Malicious |Malicious |Malicious |
Arcabit | Trojan.Dropper.WYO |Trojan.Ser.Razy.D1B82 |Trojan.Mikey.D103C2 |
Avast | Win32:Malware-gen |Sf:Citadel-A [Trj] |Win32:Citadel [Trj] |
AVG | Win32:Malware-gen |Sf:Citadel-A [Trj] |Win32:Citadel [Trj] |
Avira | TR/Rogue.700416.2 |WORM/Gamarue.itza |TR/Crypt.ZPACK.Gen2 |
Baidu | null |null |null |
BitDefender | Trojan.Dropper.WYO |Gen:Variant.Ser.Razy.7042 |Gen:Variant.Mikey.66498 |
BitDefenderTheta | AI:Packer.6A7612301F |AI:Packer.2E3E93F71E |Gen:NN.ZexaF.34590.oqX@aKxw4Chc |
Bkav | W32.Common.82DFDB92 |W32.AIDetect.malware1 |null |
CAT-QuickHeal | TrojanPWS.Zbot.J5 |Worm.Gamarue.I1 |Trojan.Generic |
ClamAV | Win.Trojan.Zbot-57541 |Win.Trojan.Gamarue-6986405-0 |Win.Trojan.Zbot-22540 |
CMC | null |null |null |
Comodo | TrojWare.Win32.Zbot.VAA@5abhvp |TrojWare.Win32.Kryptik.AFJS@4p06v2 |TrojWare.Win32.Kryptik.ADEV@4p1shw |
CrowdStrike | win/malicious_confidence_90% (W) |null |win/malicious_confidence_100% (W) |
Cybereason | malicious.fd1337 |malicious.ae7abc |malicious.201971 |
Cylance | Unsafe |Unsafe |Unsafe |
Cynet | Malicious (score: 100) |Malicious (score: 85) |Malicious (score: 100) |
Cyren | W32/Trojan.TORZ-7187 |W32/Andromeda.A.gen!Eldorado |W32/CeeInject.AN.gen!Eldorado |
DrWeb | Trojan.PWS.Panda.5676 |BackDoor.Andromeda.22 |Trojan.PWS.Panda.547 |
eGambit | Unsafe.AI_Score_75% |null |Unsafe.AI_Score_61% |
Elastic | malicious (high confidence) |malicious (high confidence) |malicious (high confidence) |
Emsisoft | Trojan.Dropper.WYO (B) |Gen:Variant.Ser.Razy.7042 (B) |Gen:Variant.Mikey.66498 (B) |
ESET-NOD32 | Win32/Spy.Zbot.AAU |Win32/TrojanDownloader.Wauchos.A |a variant of Win32/Kryptik.AFVU |
F-Secure | Trojan.TR/Rogue.700416.2 |Worm.WORM/Gamarue.itza |Trojan.TR/Crypt.ZPACK.Gen2 |
FireEye | Generic.mg.0000204fd1337637 |Gen:Variant.Ser.Razy.7042 |Generic.mg.002d8c9201971059 |
Fortinet | W32/Kryptik.BXXO!tr |W32/Citadel.A!tr |W32/Kryptik.AFVU!tr |
GData | Trojan.Dropper.WYO |Gen:Variant.Ser.Razy.7042 |Gen:Variant.Mikey.66498 |
Gridinsoft | PWS.Win32.Zbot.cc!s1 |null |Trojan.Win32.Downloader.sa |
Ikarus | Trojan.Zbot |Backdoor.Win32.Androm |Trojan.SuspectCRC |
Jiangmin | TrojanSpy.Zbot.eetv |Backdoor/Androm.ag |TrojanSpy.Zbot.brsm |
K7AntiVirus | Unwanted-Program ( 004a8e8b1 ) |Trojan ( 00536d121 ) |Riskware ( 0040eff71 ) |
K7GW | Unwanted-Program ( 004a8e8b1 ) |Trojan ( 00536d121 ) |Riskware ( 0040eff71 ) |
Kaspersky | Trojan-Spy.Win32.Zbot.sbch |Backdoor.Win32.Androm.a |HEUR:Trojan.Win32.Generic |
Kingsoft | Win32.Troj.ZBot.sb.(kcloud) |Win32.Hack.Androm.a.(kcloud) |null |
Lionic | Trojan.Win32.Zbot.tnc2 |Trojan.Win32.Androm.m!c |null |
Malwarebytes | Generic.Malware/Suspicious |Generic.Malware/Suspicious |Malware.AI.4036571117 |
MAX | malware (ai score=100) |malware (ai score=100) |malware (ai score=99) |
MaxSecure | null |Win.MxResIcn.Heur.Gen |Trojan.Malware.4006265.susgen |
McAfee | PWSZbot-FQY!0000204FD133 |Artemis!002E498AE7AB |PWS-Zbot.gen.bfo |
McAfee-GW-Edition | PWSZbot-FQY!0000204FD133 |W32/Worm-FFE!92F03DCA09AC |BehavesLike.Win32.ZBot.dh |
Microsoft | PWS:Win32/Zbot.GOV |Worm:Win32/Gamarue.I |VirTool:Win32/Injector.AX |
MicroWorld-eScan | Trojan.Dropper.WYO |Gen:Variant.Ser.Razy.7042 |Gen:Variant.Mikey.66498 |
NANO-Antivirus | Trojan.Win32.Zbot.cywsnj |Virus.Win32.Gen.ccmw |Trojan.Win32.Zbot.ssygo |
Paloalto | generic.ml |generic.ml |null |
Panda | Generic Malware |Trj/CI.A |Trj/Genetic.gen |
Qihoo-360 | Win32/Trojan.f8e |Win32/Backdoor.Androm.HgIASOYA |HEUR/Malware.QVM08.Gen |
Rising | Trojan.Spy.Win32.Zbot.hli (CLOUD) |Worm.Win32.Gamarue.b (C64:YzY0OkPVd5YI2RWQ) |null |
Sangfor | Trojan.Win32.Save.a |PUP.Win32.Ulise.52016 |Trojan.Win32.Save.a |
SentinelOne | Static AI - Malicious PE |Static AI - Suspicious SFX |Static AI - Suspicious PE |
Sophos | Mal/Generic-R + Troj/Zbot-IIB |Mal/Generic-R |Mal/Generic-R + Troj/Agent-VQC |
SUPERAntiSpyware | Trojan.Agent/Gen-Zbot |Trojan.Agent/Gen-Flooder |Trojan.Agent/Gen-Injector |
Symantec | ML.Attribute.HighConfidence |Trojan.Gen.MBT |ML.Attribute.HighConfidence |
TACHYON | Trojan-Spy/W32.ZBot.700416.O |Backdoor/W32.Androm.135747 |Trojan-Spy/W32.ZBot.231424.P |
Tencent | Malware.Win32.Gencirc.10c6b119 |Win32.Worm.Gamarue.Ug |Malware.Win32.Gencirc.11492793 |
TotalDefense | Win32/Zbot.TFUCQRB |null |null |
TrendMicro | TSPY_ZBOT.SM52 |BKDR_ANDROM.SMV1 |TROJ_AGENT_033805.TOMB |
TrendMicro-HouseCall | TSPY_ZBOT.SM52 |BKDR_ANDROM.SMV1 |TROJ_AGENT_033805.TOMB |
VBA32 | TrojanSpy.Zbot |BScope.Backdoor.Androm |TrojanPSW.Panda |
VIPRE | Win32.Malware!Drop |Trojan.Win32.Generic!BT |Trojan.Win32.Generic!BT |
ViRobot | Trojan.Win32.Agent.700416.U |null |Trojan.Win32.A.Zbot.231424.I |
Webroot | null |null |W32.Bot.Gen |
Yandex | Trojan.PWS.Panda!fyfIciXTHF8 |Backdoor.Androm!5muhMm7wRfA |Trojan.GenAsa!p4YQ1wCChqw |
Zillya | Trojan.Zbot.Win32.154544 |Backdoor.Androm.Win32.25444 |Trojan.Zbot.Win32.60799 |
ZoneAlarm | Trojan-Spy.Win32.Zbot.sbch |Backdoor.Win32.Androm.a |HEUR:Trojan.Win32.Generic |
Zoner | Trojan.Win32.23330 |null |null |

## Materials and Methods

This paper proposes a database aiming at the classification of 32-bit benign and malware executables. There are 12,540 malicious executables, and 3,135 other benign executables. Therefore, our dataset is suitable for learning with artificial intelligence, since both classes of executables have the same amount.

Virtual plagues were extracted from databases provided by enthusiastic study groups as VirusShare. As for benign executables, the acquisition came from benign applications repositories such as sourceforge, github and sysinternals. It should be noted that all benign executables were submitted to VirusTotal and all were its benign attested by the main commercial antivirus worldwide. The diagnostics, provided by VirusTotal, corresponding to the benign and malware executables are available in the virtual address of our database.

The purpose of the creation of the database is to give full possibility of the proposed methodology being replicated by third parties in future works. Therefore, the proposed article, by making its database freely available, enables transparency and impartiality to research, as well as demonstrating the veracity of the results achieved. Therefore, it is hoped that the methodology will serve as a basis for the creation of new scientific works.

## Executable Feature Extraction

The extraction of features of executables employs the process of disassembling. Then, the algorithm, referring to the executable, can be studied and later classified by the neural networks described in the next section. In total, 568 features of each executable are extracted, referring to the groups mentioned above. The pescanner tool are employed in order to extract the features of executables. Next, the groups of features extracted from the executables investigated are detailed.
######	Histogram of instructions, in assembly, referring to the mnemonic.
######	Number of subroutines invoking TLS (Transport Layer Security).
######	Number of subroutines responsible for exporting data (exports).  
######	APIs (Application Programming Interface) used by the executable.
######	Features related to clues that the computer has suffered fragmentation on its hard disk, as well as accumulated invalid boot attempts.  
######	Application execution mode. There are two options:
-	software with a graphical interface (GUI);
-	software running on the console.
######	Features related to the Operating System. Our digital forensics examines if the tested file tries to:
-	identify the current operating system user name;
-	access APIs in order to create and manage current OS user profiles;
-	detect the number of milliseconds since the system was initialized;
-	execute an operation in a specific file;
-	identify the version of the Windows Operating System in use;
-	monitor internal message traffic among system processes;
-	alter the Windows startup settings and contents (STARTUPINFO);  
-	allow applications to access functionality provided by shell of the operating system, as well as alter it; 
-	change the logon messages at Windows OS startup; 
-	change native applications linked to standard dialog boxes in order to open and save files, choosing color and font, among other customizations;
-	configure Windows Server licensing ; 
-	configure Windows Server 2003;
-	change the system's power settings;
-	open a process, service, or native library of the Operating System; 
-	exclude the context of certificates linked to the Operating System; 
-	copy an existing file to a new file; 
-	create, open, delete, or alter a file;
-	create and execute new process(s); 
-	create new directory(s); 
-	search for specific file(s);  
-	create a service object and add it to the control manager database for a certain service; 
-	encrypt data. It is a typical strategy of ransomwares which sequester the victim's data through cryptography. To decrypt the data, the invader asks the user for a monetary amount so that he victim can have all his data back;
-	access file systems, devices, processes, threads and error handling of the system;
-	change the sound and audio device properties of the system;
-	access graphical content information for monitors, printers, and other Windows OS output devices; 
-	use and/or monitor the USB port;
-	control a driver of a particular device; 
-	investigate if a disk drive is a removable, fixed, CD / DVD-ROM, RAM or network drive;
######	Features related to Windows Registry (Regedit). It is worth noting that the victim may not be free from malware infection even after its detection and elimination. The persistence of malefactions, even after malware exclusion, occurs due to the insertion of malicious entries (keys) in Regedit. Then, when the operating system boots, the cyber-attack restarts because of the malicious key invoking the vulnerability exploited by malware (eg: redirect Internet Explorer home page). Then, our antivirus audits if the suspicious application tries to:
-	detect the NetBIOS name of the local computer. This name is established at system startup, when the system reads it in the registry (Regedit);
-	terminate a key of a specific registry; 
-	create a key from in a specific registry. If the key already exists in Regedit, then it will be read; 
-	delete a key and its values in Regedit; 
-	enumerate and   open subkeys of a specific open registry. 
######	Features related to spywares such as keyloggers (capture of keyboard information in order to theft of passwords and logins) and screenloggers (screen shot of the victim). Our antivirus audits if the analyzed file tries to:
-	detect in which part of the victim's screen there was an update;
-	identify the screen update region by copying it to a particular region;
-	capture AVI movies and videos from web cameras and other video hardware; 
-	capture information on electronic voting, specifically from the company Optical Vote-Trakker;
-	copy an array of keyboard key states. Such strategy is typical of keyloggers
-	monitor user's Internet activity and private information;
-	collect online bank passwords and other confidential information and to send the data to invader creator;
-	access a computer from remote locations, stealing passwords, Internet banking and personal data; 
-	create a BHO (Browser Helper Object) which is executed automatically every time when the web browser is started. It fits to emphasize that BHOs are not impeded by personal firewalls because they are identified as part of the browser. In a distorted way, BHOs are often used by adware and spyware in order to record keyboard and mouse entries
-	locate passwords stored on a computer.
######	Features related to Anti-forensic Digital which are techniques of removal, occultation and subversion of evidences with the goal of reducing the consequences of the results of forensic analyzes. Our antivirus investigates if the file tries to:
-	Suspend its own execution until a certain timeout interval has elapsed. A typical malware strategy that maintains itself inactive until the end of commercial antivirus quarantine;
-	Disable the victim's defense mechanisms, including Firewall and Antivirus;
-	disable automatic Windows updates;
-	detect if the own file is being scanned by an debugger of the Operating System;   
-	retrieve information about the first and next process found in an Operating System snapshot. Such strategy is typical of malwares that aim to corrupt backups and restore points of the Operating System;
-	hide one file in another. This strategy is named, technically, steganography which aims to hide malware in a benign program in the Task Manager;
-	disguise its own name in the Task Manager;
-	make use of libraries associated with Hackers Encyclopedia 2002;
-	Create a ZeroAcess cyber-attack type through firmware updates of hardware devices (eg, hard drive controlled).
######	Features related to the creation of GUI (Graphical User Interface) of the suspicious program. Our antivirus audits if the suspect file tries to: 
-	create a GUI at runtime; 
-	use DirectX which allows multimedia applications to draw 2D graphics; 
-	create a module that contains bitmap compression and decompression routines used for Microsoft Video for Windows;
-	create 3D graphics related to utilitarian functions used by OpenGL; 
-	detect shapes through computer vision and digital image processing;
-	access functionalities in order to create and to manage screen windows and more basic controls such as buttons and scrollbars, receive mouse and keyboard input, and other functionalities associated with the Windows GUI. This includes widgets like status bars, progress bars, toolbars, and guides; 
######	Features related to the illicit forensic of the RAM (main memory) of the local system. Our antivirus investigates if the suspicious application tries to:
-	access information in specific regions of main memory;
-	read data from an area of memory occupied by a specific process;
-	write data to a memory area in a specific process;
-	reserve, confirm or alter the status of a page region in the virtual address space of a process.
######	Features related to network traffic. It is checked if the suspect file tries to:
-	query DNS servers;
-	send request to an HTTP server; 
-	monitor information of the headers of computer data packets associated with an HTTP request;
-	send an ICMP IPv4 echo request; 
-	send an SNMP request used to monitor LAN equipment;
-	terminate the Internet connection;
-	create an FTP or HTTP session at runtime; 
-	fragment a URL at runtime; 
-	query a server in order to determine the amount of traffic data available; 
-	identify the connection state of the local system in relation to the Internet; 
-	initialize the use of an application of the WinINet functions (Windows API for creating and using the application using the Internet); 
-	read data from network packets made from previous local system requests (typical behavior of sniffers); 
-	overwrite data in a local system network packet; 
-	manage local and remote network systems; 
-	create a network socket on the local system. In a conventional application, the server sends data to the client (s). In an opposite way, in malware, the victim sends the data (images, digits) to the server. Therefore, malware can create sockets on the local system waiting (listen) for a remote malicious computer to request a connection and, then, receive the victim's private information;
-	receive data of a socket. Typical strategy of backdoors when the victim starts receiving remote commands; 
-	send data to a socket. Typical strategies of spywares which, after capturing innermost information, they send them to a malicious remote computer; 
######	Features related to utility applications programs. Our created antivirus checks if the suspicious file tries to:
-	reproduce videos/audios through Windows Media Player; 
-	change the shortcut icon and Internet default settings exhibited in the Explorer toolbar address bar; 
-	alter the Wordpad configurations;
-	alter the configurations of sockets, specifically, managed by Internet Explorer; 
-	alter Outlook Express configurations and to access the victim’s  e-mail list; 
-	access information linked to the Microsof Office; 
-	alter the configurations of the Adobe System’s suite;
-	change the system's disk cleanup configurations; 
-	alter the settings of native digital electronic games and others linked to companies Tycoon and Electronic Arts;
-	change Google Inc updates settings; 
-	use Visual Basic. Such strategy is typical of macro viruses that are intended to infect applications that support macro language such as web browsers, Microsoft Office, and Adobe Systems.
-	alter the access settings to Wikipedia.
