# 🕵️ Threat Hunting Case Study: Insider Exfiltration via Steganography

This project documents a full threat hunting investigation using **Microsoft Defender for Endpoint** and **Kusto Query Language (KQL)** to uncover a simulated insider threat. It traces the attacker's actions from accessing sensitive documents to hiding them within image files and staging them for exfiltration via removable media.

> 📁 Full case write-up: [case-study.md](./case-study.md)

---

## 📌 Scenario Summary

An internal user (`bmontgomery`) accessed confidential PDF and Excel documents, used **`steghide.exe`** to embed them into `.bmp` images, and then compressed the images into an encrypted archive using **`7z.exe`**. The archive was staged and later renamed for stealth.

Through endpoint telemetry and file hash correlation, this case study reconstructs the entire exfiltration chain.

---

## 🧠 Tools & Techniques

* **Microsoft Defender for Endpoint**
* **Kusto Query Language (KQL)**
* **File hash correlation & timeline reconstruction**
* **Behavioral analysis & steganography detection**
* **MITRE ATT\&CK Mapping**:

  * T1005 (Data from Local System)
  * T1027 (Obfuscated Files or Information)
  * T1074.001 (Local Data Staging)
  * T1052 (Exfiltration over Removable Media)

---

## ✅ Skills Demonstrated

* Threat hunting methodology
* Endpoint visibility and investigative workflows
* KQL query creation and refinement
* Real-world reporting and documentation


**This project is for educational demonstration purposes and simulates a realistic insider threat workflow.**
