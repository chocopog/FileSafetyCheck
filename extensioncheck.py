dangerous_ext = ['.exe', '.bat', '.dll', '.cmd', '.sh', '.js', '.vbs', '.scr', '.ps1', '.msi']
disguise_ext = ['.pdf', '.doc', '.docx', '.jpg', '.jpeg', '.png', '.txt', '.xls', '.xlsx']

def CheckDoubleExtension(filename):
    parts = filename.lower().split('.')
    if len(parts)<3:
        return False
    penultimateExt = f".{parts[-2]}"
    ultimateExt = f".{parts[-1]}"
    return penultimateExt in disguise_ext and ultimateExt in dangerous_ext

def getFinalExt(filename):
    parts = filename.lower().split('.')
    return f".{parts[-1]}" if len(parts)>1 else ""

def isDangerExt(filename):
    return getFinalExt(filename) in dangerous_ext

