# El Diff — quick introduction and user guide

**El Diff** is a lightweight web interface for rapidly analyzing Microsoft Patch Tuesday updates at the binary and function pseudocode level. The database includes data for Windows 11 22H2/23H2. Vulnerability information is available for the entire lifecycle of this OS version, while binary-level data is partially available from December 2024 to June 2025. You can also use the database to build your own applications with global search and other features that are not included in this version. El Diff was created for anyone interested in patch diffing and looking to save time by skipping the manual binary analysis step and diving directly into the patches. The large binary database also helps you learn what real Microsoft patches look like.

**The story about how the database were collected - Microsoft quirks and other stuff will be published soon here**. Also you can find me on [X](https://x.com/varwar1337).

---

## Features

- View all CVE's from a selected Microsoft update
- Analyze binaries with function-level changes
- View added, removed, and modified functions
- Decompiled diffs for changed functions
- Partial component-to-binary and CVE mapping

---

## Installation Guide

```sh
git clone https://github.com/varwara/eldiff.git
cd eldiff
python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

export FLASK_APP=eldiff_minimal.py
flask run --debug
```

---

## Workflow

### 1. CVE Table

- Displays CVE's from the latest update
- Dropdown menu allows selecting another update (e.g., `2024-Jun`)
- Click the **Info** button to open a modal with details about the selected CVE  
![1.png](./doc/1.png)

---

### 2. KB View

- Shows most of the binaries affected in the selected update  
![2.png](./doc/2.png)  
Open the binary list window by double-clicking any row in the CVE table

---

### 3. Function Changes View

- Displays all functions in a table:
  - Modified
  - Added/Deleted and Imported

To open a function view tab, click the **View** button. You can open as many tabs as needed for convenience

![3.png](./doc/3.png)

---

### 4. Decompiled Diff View

- Displays a unified diff for the selected function

Click the **View** button to open the diff modal.  
![4.png](./doc/4.png)

---

### 5. View Added/Deleted Functions

- Syntax highlighting is enabled for these views

![5.png](./doc/5.png)

---

### 6. Mapping

- Partial mapping is implemented between vulnerabilities and binaries, allowing fast navigation from the CVE list to the patched binary and its functions.

![7.png](./doc/7.png)

---

## Simple Reports

- Update reports include 4 statistical tables
    - TOP-10 CWE's
    - High-Risk CVE's
    - Known Component → Binary → CVE mappings
    - Binary Function Stats

These can be expanded or customized. Reports are available via the **Report** tab.

![6](./doc/6.png)

---

**Credentials**
guest:xss.is
