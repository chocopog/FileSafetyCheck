from hashing import GetFileHash
from sigcheck import checksig
from virustotalcheck import checkVirusTotal
from extensioncheck import CheckDoubleExtension, isDangerExt

import os
def RiskAnalyzer(is_danger_ext, is_double_ext, sig_status, vt_status):
    score = 0
    if is_danger_ext:
        if sig_status=="Valid":
            pass
        else:
            score += 1
    if is_double_ext:
        score += 2
    if sig_status.startswith("N/A"):
        pass
    elif "Valid" not in sig_status:
        score+= 2
    if "Flagged" in vt_status:
        score+=3
    elif "Unknown file" in vt_status:
        score+=1
    
    if score==0:
        return "Low"
    if score<=2:
        return "Medium"
    if score<=5:
        return "High"
    if score>5:
        return "Extreme"


def analyzeFile(filepath):
    print("\n--- File Analyzer ---")

    if not os.path.exists(filepath):
        print("Error, file not found")
        return
    if not os.path.isfile(filepath):
        print("Error, path is not a file")
    filename = os.path.basename(filepath)
    isDoubleExt = CheckDoubleExtension(filename)

    print("\n Scanning...")
    print(f"File: {filename}")
    print(f"Size: {os.path.getsize(filepath)} bytes")
    print(f"Double extension: {'DETECTED!!' if isDoubleExt else "None"}")
    print(f"Dangerous file type: {'Yes'if isDangerExt(filename) else "No"}")
    

    file_hash = GetFileHash(filepath)
    print(f"SHA-256 hash: {file_hash if file_hash else "Could not compute!"}")

    sig_status = checksig(filepath)
    print(f"Digital signature status: {sig_status}")

    if file_hash:
        vt_status = checkVirusTotal(file_hash, 2)
    else: 
        vt_status = "Skipped, no hash available"
    print(f"Global threat DB: {vt_status}")

    risk_level = RiskAnalyzer(isDangerExt(filename), isDoubleExt, sig_status, vt_status)
    print(f"\nOverall Risk Level: {risk_level}")

    print("\nDone. This tool only reads and reports; no files were changed.")

path = input("Please enter file path:   ").strip().strip('"')
analyzeFile(path)