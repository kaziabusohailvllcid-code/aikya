Option Explicit

Dim shell, fileSystem, appFile
Set shell = CreateObject("WScript.Shell")
Set fileSystem = CreateObject("Scripting.FileSystemObject")
appFile = fileSystem.BuildPath(fileSystem.GetParentFolderName(WScript.ScriptFullName), "index.html")

If Not fileSystem.FileExists(appFile) Then
    MsgBox "AiKya index.html was not found." & vbCrLf & appFile, vbExclamation, "AiKya"
    WScript.Quit 1
End If

shell.Run Chr(34) & appFile & Chr(34), 1, False