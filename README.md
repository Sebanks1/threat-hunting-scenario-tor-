#<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/Sebanks1/threat-hunting-scenario-tor-/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
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

Searched the DeviceFileName table for any file containing the string "tor" and found that the user "Sebanks304" appeared to have downloaded a Tor installer. Subsequent activity resulted in multiple Tor-related files being copied to the desktop and the creation of a file named "tor-shopping-list.txt" on the desktop at 2025-02-10T16:51:11.7978015Z. These events began on 2025-02-06T20:04:29.055919Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "se-threat-lab"
| where FileName contains "tor"
| where Timestamp >= datetime(2025-02-06T20:04:29.055919Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, SHA256, Account = InitiatingProcessAccountName

```
![image](https://github.com/user-attachments/assets/014f08a3-a344-4605-aa4e-6db2c2ef3647)



---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine containing the string "tor-browser-windows-x86_64-portable-14.0.4.exe". According to the logs, on February 6, 2025, at 2:59 PM, a process was created on the device "se-threat-lab" under the user account "sebanks304." The process involved executing the Tor Browser portable version (14.0.4), a privacy-focused web browser that routes traffic through the Tor network.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "se-threat-lab"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.4.exe"
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
![image](https://github.com/user-attachments/assets/739c8e2c-8789-4ca6-b94a-e0e9acc558ea)


---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for any ProcessCommandLine containing the string "tor-browser-windows-x86_64-portable-14.0.4.exe". According to the logs, on February 6, 2025, at 2:59 PM, a process was created on the device "se-threat-lab" under the user account "sebanks304." The process involved executing the Tor Browser portable version (14.0.4), a privacy-focused web browser that routes traffic through the Tor network.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "se-threat-lab"
| where FileName has_any ("tor.exe", "firefox", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/6e9d2d9c-bcce-4108-a780-94e2f69fa1e3)


---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication that the Tor browser was used to establish a connection through known Tor ports. The logs show that at 2025-02-06T20:04:30.8535616Z, a user on the device "se-threat-lab" successfully connected to the remote IP address 188.192.183.75 on port 9001. This connection was initiated by the Tor executable (tor.exe), located in C:\Users\Sebanks304\Desktop\Tor Browser\Browser\firefox.exe. Additionally, there were a few other connections made to sites over port 443.

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "se-threat-lab"
| where tolower(InitiatingProcessAccountName) != tolower("sebanks304")
| where RemotePort in (9001, 9030, 9050, 9051, 9150, 9151, 9152, 80, 443)
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath
| order by Timestamp desc
```
![image](https://github.com/user-attachments/assets/0f1c62f2-f779-4e0b-b723-cc7362afb005)


---

## Chronological Event Timeline 

### 1. File Download - TOR Installer

- **Timestamp:** `2024-11-08T22:14:48.6065231Z`
- **Event:** The user "employee" downloaded a file named `tor-browser-windows-x86_64-portable-14.0.1.exe` to the Downloads folder.
- **Action:** File download detected.
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 2. Process Execution - TOR Browser Installation

- **Timestamp:** `2024-11-08T22:16:47.4484567Z`
- **Event:** The user "employee" executed the file `tor-browser-windows-x86_64-portable-14.0.1.exe` in silent mode, initiating a background installation of the TOR Browser.
- **Action:** Process creation detected.
- **Command:** `tor-browser-windows-x86_64-portable-14.0.1.exe /S`
- **File Path:** `C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

### 3. Process Execution - TOR Browser Launch

- **Timestamp:** `2024-11-08T22:17:21.6357935Z`
- **Event:** User "employee" opened the TOR browser. Subsequent processes associated with TOR browser, such as `firefox.exe` and `tor.exe`, were also created, indicating that the browser launched successfully.
- **Action:** Process creation of TOR browser-related executables detected.
- **File Path:** `C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

### 4. Network Connection - TOR Network

- **Timestamp:** `2024-11-08T22:18:01.1246358Z`
- **Event:** A network connection to IP `176.198.159.33` on port `9001` by user "employee" was established using `tor.exe`, confirming TOR browser network activity.
- **Action:** Connection success.
- **Process:** `tor.exe`
- **File Path:** `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`

### 5. Additional Network Connections - TOR Browser Activity

- **Timestamps:**
  - `2024-11-08T22:18:08Z` - Connected to `194.164.169.85` on port `443`.
  - `2024-11-08T22:18:16Z` - Local connection to `127.0.0.1` on port `9150`.
- **Event:** Additional TOR network connections were established, indicating ongoing activity by user "employee" through the TOR browser.
- **Action:** Multiple successful connections detected.

### 6. File Creation - TOR Shopping List

- **Timestamp:** `2024-11-08T22:27:19.7259964Z`
- **Event:** The user "employee" created a file named `tor-shopping-list.txt` on the desktop, potentially indicating a list or notes related to their TOR browser activities.
- **Action:** File creation detected.
- **File Path:** `C:\Users\employee\Desktop\tor-shopping-list.txt`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

--- threat-hunting-scenario-tor-
