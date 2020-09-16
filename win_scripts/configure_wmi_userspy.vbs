' ==================================================================
'   VBScript Source File
'   Name: configure_wmi_userspy.vbs
'   Description: This script configures access for Userspy via WMI
'   Author: shmakovpn <shmakovpn@yandex.ru>
'   version: 1.1
'   Created:  2020-09-01
' ==================================================================


' You need to have privileges of Administrator to perform this script,
' WmiSecurity.exe requires Microsoft .NET Framework 2.0


On Error Resume Next

' ====================== Settings =======================
' Domain username
Const DOMAIN_USER_NAME = "userspy"
' ==================================================================

' Hostname and domain name
Set wshNetwork = WScript.CreateObject( "WScript.Network" )
strComputer = wshNetwork.ComputerName
domainNameShort = wshNetwork.UserDomain


' checking Windows Management Instrumentation
Set objWMIService = GetObject("winmgmts:" _
    & "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")

Set colServiceList = objWMIService.ExecQuery _
    ("Select * from Win32_Service where Name = 'Winmgmt'")    


For Each objService in colServiceList
    ' is service enabled
    errReturnCode = -700
    If objService.StartMode <> "Auto" Then
      errReturnCode = objService.Change( , , , , "Automatic")
      If errReturnCode <> 0 Then
        	Call WriteLogFile(now & " ERROR - enabling of Windows Management Instrumentation failed")
      End If      
    End If 
    
    ' checking service status
    errReturnCode = -700
    If (objService.Started = False) Then
      errReturnCode = objService.StartService
      If errReturnCode <> 0 Then
      		Call WriteLogFile(now & " ERROR - starting Windows Management Instrumentation failed")
	  End If          
    End If   
Next

' Checking OS type
Set objWMIService = GetObject("winmgmts:" _
& "{impersonationLevel=impersonate}!\\" & strComputer & "\root\cimv2")
Set colOperatingSystems = objWMIService.ExecQuery _
("SELECT * FROM Win32_OperatingSystem")

For Each objOperatingSystem in colOperatingSystems
  VerOS = objOperatingSystem.Caption
Next 

VerOS=UCase(VerOS)

Set WshShell = CreateObject("WScript.Shell")

' There are no a the DCOM Users in Windows 2000 (performs adding user into group if the version of the OS does not contain '2000')
If (InStr(VerOS, UCase("2000")) = 0) Then
	' Получить имя группы "Distributed COM Users" по SID
	strDistrCOMUsersGroup = GetNameLocalGroupBySID("S-1-5-32-562")
	
	' Добавление учетной записи в группу Distributed COM Users
	Set objGroup = GetObject("WinNT://" & strComputer & _
		   "/" & strDistrCOMUsersGroup & ",group")
	If Not DomainUserExistInLocalGroup(DOMAIN_USER_NAME, strDistrCOMUsersGroup) Then
	    objGroup.Add("WinNT://" & domainNameShort & "/" & DOMAIN_USER_NAME)
	End If	   
End If


' In WMI enable privilege for user Remote Enable for namespace ROOT\CIMV2
' then disable Execute Methods (Permits the user to execute methods defined on WMI classes)
Set objfso = CreateObject("Scripting.FileSystemObject")
CurDir = objfso.GetParentFolderName(Wscript.ScriptFullName)

ResultWMISec = WshShell.Run(Chr(34) & CurDir & "\WmiSecurity.exe" & Chr(34) & " /C=""" & strComputer & """ /A /N=Root/CIMV2 /M=""" & domainNameShort & "\" & DOMAIN_USER_NAME & ":REMOTEACCESS"" /R", 0, True)
ResultWMIMESec = WshShell.Run(Chr(34) & CurDir & "\WmiSecurity.exe" & Chr(34) & " /C=""" & strComputer & """ /D /N=Root/CIMV2 /M=""" & domainNameShort & "\" & DOMAIN_USER_NAME & ":ONLYMETHODEXECUTE"" /R", 0, True)


If ResultWMISec <> 0 Then
	Call WriteLogFile(now & " ERROR - enabling Remote Enable for namespace ROOT\CIMV2 failed. Username: " & DOMAIN_USER_NAME)
End If

If ResultWMIMESec <> 0 Then
	Call WriteLogFile(now & " ERROR - disabling Execute Methods for namespace ROOT\CIMV2 failed. Username: " & DOMAIN_USER_NAME)
End If

If Err.Number <> 0 Then
	Call WriteLogFile(now & " ERROR - this script failed: " & Err.Number)
Else
	Call WriteLogFile(now & " INFO - this script success")
End If

WScript.Quit Err


' Get local group by SID
Function GetNameLocalGroupBySID(strSID)
	strComputer = "."
	Set objWMIServ = GetObject("winmgmts:\\" & strComputer & "\root\cimv2")
	Set colItems = objWMIServ.ExecQuery _
		("SELECT * FROM Win32_Group WHERE DOMAIN = '" & strComputer & "' AND SID='" & strSID & "'") 		     
 	For Each objCol In colItems
	  GetNameLocalGroupBySID = objCol.Name
	  Exit For
	Next
End Function


' Checking are user in group
Function UserExistInLocalGroup(strUName, strGroup)
    UserExistInLocalGroup = False
	Set objNet = CreateObject("WScript.Network")
	strComputer = objNet.ComputerName	
	Set objGroup = GetObject("WinNT://" & strComputer & "/" & strGroup & ",group")	
	For Each objMember In objGroup.Members	  
	  If (UCase(objMember.Name) = UCase(strUName)) And _
	     (InStr(UCase(objMember.AdsPath), UCase(strComputer)) <> 0) Then
	    UserExistInLocalGroup = True
	    Exit For
	  End If	  
	Next
End Function

' Checking are domain user in group
Function DomainUserExistInLocalGroup(strDomainUName, strGroup)
    DomainUserExistInLocalGroup = False
	Set objNet = CreateObject("WScript.Network")
	strComputer = objNet.ComputerName	
	Set objGroup = GetObject("WinNT://" & strComputer & "/" & strGroup & ",group")	
	For Each objMember In objGroup.Members	    
	  If (UCase(objMember.Name) = UCase(strDomainUName)) And _
	     (InStr(UCase(objMember.AdsPath), UCase(strComputer)) = 0) Then	      
	    DomainUserExistInLocalGroup = True
	    Exit For
	  End If	  
	Next
End Function

Sub WriteLogFile(msg)
	Dim EnvObj
	Dim LogObj
	Dim LogDirPath
	Dim LogFilePath
	Dim LogFile

	Set EnvObj = CreateObject("WScript.Shell")
	Set LogObj = CreateObject("Scripting.FileSystemObject")
	LogDirPath = EnvObj.ExpandEnvironmentStrings("%WINDIR%") & "\CCMPkgLogs\"
	LogFilePath = LogDirPath & "WMIuserAct.log"

	If Not LogObj.FolderExists(LogDirPath) Then
		LogObj.CreateFolder(LogDirPath)
	End If

	Set LogFile = LogObj.OpenTextFile(LogFilePath, 8, True)
	LogFile.WriteLine msg
	LogFile.Close
End Sub
