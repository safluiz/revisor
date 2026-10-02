' Roda o vigia sem abrir janela (chamado pelo Agendador de Tarefas a cada 2 minutos)
Set sh = CreateObject("WScript.Shell")
pasta = CreateObject("Scripting.FileSystemObject").GetParentFolderName(WScript.ScriptFullName)
sh.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -File """ & pasta & "\vigia.ps1""", 0, False
