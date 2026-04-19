# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/roshanak-kh/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "rkh" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2026-04-17T22:59:19.7259964Z`. These events began at `2026-04-17T22:58:43.0249564Z`.

**Query used to locate events:**

```kql
DeviceFileEvents
|where FileName contains "tor"
|where DeviceName =="roshi-kh-threat"
|where RequestAccountName =="rkh"
|where TimeGenerated >= datetime('2026-04-17T22:58:43.0249564Z')
|project  TimeGenerated, DeviceName,FolderPath,SHA256, Account=InitiatingProcessAccountName, ActionType, FileName
|order by TimeGenerated
```
<img width="1354" height="421" alt="image" src="https://github.com/user-attachments/assets/5538da76-11fb-4c2f-a393-d4c2cc3b633b" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned,on April 17, 2026, at approximately 11:02 PM, a user named "rkh" ran an installer for the Tor Browser from their "Downloads" folder on the device named "roshi-kh-threat" by using a command that triggers silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
|where DeviceName =="roshi-kh-threat"
|where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-15.0.9.exe"
|project TimeGenerated, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine,FolderPath,SHA256
```
                                     
<img width="1438" height="107" alt="image" src="https://github.com/user-attachments/assets/b95359f1-fb56-4cd0-8adf-4d789a95121f" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents
|where DeviceName =="roshi-kh-threat"
|where FileName has_any ("tor.exe","firefox.exe","tor-browser.exe")
|project TimeGenerated, DeviceName, AccountName, ActionType, FileName, ProcessCommandLine,FolderPath,SHA256
|order by TimeGenerated desc

```

<img width="1361" height="522" alt="image" src="https://github.com/user-attachments/assets/961a4119-d026-4974-a07d-5285893616e1" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

I searched the DeviceNetworkEvents table for any indication that Tor browser was used to establish a connection using any of known Tor ports. The logs show on April 17, 2026, around 11:04 PM (UTC), a user account named rkh on the device roshi-kh-threat successfully established two network connections related to the Tor Browser.
First, the Firefox browser (running from the Tor Browser folder) connected locally to 127.0.0.1 on port 9151, which is typically used by Tor as a local proxy service.
A few seconds later, the tor.exe process connected externally to the IP address 185.162.251.94 on port 9001, which is commonly associated with Tor relay or node communication. 
There were a couple of other connections to sites over port 443 as well.
In short: the Tor Browser was launched and functioning normally—Firefox connected to the local Tor service, and Tor itself connected out to the Tor network.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName =="roshi-kh-threat"
|where InitiatingProcessAccountName =="rkh"
|where RemotePort in ("9001","9030","9050","9051","9150","9151")
|project TimeGenerated,DeviceName, InitiatingProcessFileName,ActionType, AccountName=InitiatingProcessAccountName,RemotePort,RemoteUrl,RemoteIP,InitiatingProcessFolderPath
|order by TimeGenerated desc

```
<img width="1429" height="461" alt="image" src="https://github.com/user-attachments/assets/8cb2823a-f26f-40db-849c-93ce967bd92e" />

---

## Chronological Event Timeline 

### 1. File Download - TOR Installer
- ** (Initial File Activity)
- **Timestamp:** 2026-04-17
- **Event:** The user "rkh" downloaded a file named `tor-browser-windows-x86_64-portable-15.0.9.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\rkh\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `22026-04-17T23:02:18.5106057Z`
- **Event:** The user "rkh" executed the file `tor-browser-windows-x86_64-portable-15.0.9.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-15.0.9.exe /S`
- **File Path:** `C:\Users\rkh\Downloads\tor-browser-windows-x86_64-portable-15.0.9.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2026-04-17T23:04:34.9853554Z`
- **Event:** User "rkh" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\rkh\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2026-04-17T23:04:52.2990218Z`
- **Event:** A network connection to IP `185.162.251.94` on port `9001` by user "rkh" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\rkh\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2026-04-17T23:05:01.3480286ZZ` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "rkh" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2026-04-17T23:05:50.3480286Z`
- **Event:** The user "rkh" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\rkh\Desktop\tor-shopping-list.txt`

---

## Summary

The user "rkh" on the "roshi-kh-threat" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `roshi-kh-threat` by the user `rkh`. The device was isolated, and the user's direct manager was notified.

---# threat-hunting-scenario-tor
