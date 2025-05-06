# 🕵️ Threat Hunting Case Study: Insider Exfiltration via Steganography

This project showcases a real-world style **behavioral threat hunting investigation** using **Microsoft Defender for Endpoint** and **Kusto Query Language (KQL)**. I analyzed telemetry data to uncover an insider threat involving **unauthorized document access**, **steganography**, and **data exfiltration** via removable media.

> 📁 Full case write-up: [case-study.md](./case-study.md)

---

## 🧠 Scenario Summary

A simulated insider (user `bmontgomery`) accessed sensitive corporate documents, used `steghide.exe` to hide the data inside BMP images, and compressed them into `secure_files.zip` before exfiltrating via removable media.

I used hash tracking, command-line analysis, and behavior-based hunting to reconstruct the full attack chain.

---

## 🛠️ Tools & Techniques

- **Microsoft Defender for Endpoint**
- **KQL (Kusto Query Language)**
- **File hash tracking**
- **Process behavior analysis**
- **Steganography detection**
- **MITRE ATT&CK Mapping (T1027, T1005, T1041, T1074)**

---

## 📸 Sample Screenshots

> 

- `screenshots/document_access.png`  
- `screenshots/steghide_usage.png`  
- `screenshots/zip_creation.png`  
- `screenshots/file_renamed_evidence.png`

---

## ✅ Skills Demonstrated

- Threat hunting & behavioral analysis
- Endpoint telemetry investigation
- KQL query design & refinement
- Realistic incident report documentation
- Mapping findings to MITRE ATT&CK techniques

---

## 📂 Repo Contents

