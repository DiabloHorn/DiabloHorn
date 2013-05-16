'DiabloHorn http://diablohorn.wordpress.com
'Interactive registry viewer
'Resources
'   http://technet.microsoft.com/en-us/library/ee176786.aspx
'   http://technet.microsoft.com/en-us/library/ee176769.aspx
'   http://kryogenix.org/days/2004/04/01/interactivevbscript

'This reminds us of undefined vars ...i hope
Option Explicit

'############################################
' global vars
'############################################
Dim objRegistry
Dim rootkeys(5)
Dim chosenkey
Dim chosenkeypath
Dim promptpath
Dim ln

'current computer cause of the '.'
Set objRegistry = GetObject("winmgmts:\\.\root\default:StdRegProv")

'############################################
' constants declaration
'############################################
const HKEY_CLASSES_ROOT = &H80000000
const HKEY_CURRENT_USER = &H80000001
const HKEY_LOCAL_MACHINE = &H80000002
const HKEY_USERS = &H80000003
const HKEY_CURRENT_CONFIG = &H80000005
Const REG_SZ = 1
Const REG_EXPAND_SZ = 2
Const REG_BINARY = 3
Const REG_DWORD = 4
Const REG_MULTI_SZ = 7

'############################################
' init some vars, we are lazy
'############################################
chosenkey = ""
chosenkeypath = ""
promptpath = ""

rootkeys(0) = "HKEY_CLASSES_ROOT"
rootkeys(1) = "HKEY_CURRENT_USER"
rootkeys(2) = "HKEY_LOCAL_MACHINE"
rootkeys(3) = "HKEY_USERS"
rootkeys(4) = "HKEY_CURRENT_CONFIG"

'############################################
' convert key name to number
'############################################
function keyname2number(keyname)
    if keyname = "HKEY_CLASSES_ROOT" Then
        keyname2number = HKEY_CLASSES_ROOT
    elseif keyname = "HKEY_CURRENT_USER" Then
        keyname2number = HKEY_CURRENT_USER
    elseif keyname = "HKEY_LOCAL_MACHINE" Then
        keyname2number = HKEY_LOCAL_MACHINE
    elseif keyname = "HKEY_USERS" Then
        keyname2number = HKEY_USERS
    elseif keyname = "HKEY_CURRENT_CONFIG" Then
        keyname2number = HKEY_CURRENT_CONFIG
    end if
end function

'############################################
' Get the last generated error
'############################################
function geterror()
    If Err.Number <> 0 Then
      wscript.echo "Error: " & Err.Description
      Err.Clear
    End If
end function

'############################################
' list subkeys only, no values
'############################################
function list(path)
    on error resume next
    Dim arrSubkeys, strSubkey
    objRegistry.EnumKey keyname2number(chosenkey),path, arrSubkeys
    If IsNull(arrSubKeys) Then
        wscript.echo "Key does not exist"
    else
        If IsArray(arrSubkeys) Then 
            For Each strSubkey In arrSubkeys 
                wscript.Echo strSubkey
            Next
        else
            wscript.echo VarType(arrSubkeys)
            wscript.echo "not an array"
            geterror()
        End If
    end if
    
end function

'############################################
' list values only
'############################################
function listv(strKeyPath)
    Dim arrEntryNames,arrValueTypes,ii,dwValue,arrValue,strValue,byteValue,arrValues
    objRegistry.EnumValues keyname2number(chosenkey),strKeyPath,arrEntryNames,arrValueTypes
    For ii=0 To UBound(arrEntryNames)
         Wscript.Echo "Entry Name: " & arrEntryNames(ii)
         Select Case arrValueTypes(ii)
        Case REG_SZ
            Wscript.Echo vbTab & "Data Type: String"
            objRegistry.GetStringValue keyname2number(chosenkey), strKeyPath, arrEntryNames(ii),strValue
            Wscript.Echo vbTab & "Value: " & strValue
         Case REG_EXPAND_SZ
            Wscript.Echo vbTab & "Data Type: Expanded String"
            objRegistry.GetExpandedStringValue keyname2number(chosenkey), strKeyPath, arrEntryNames(ii),estrValue
            Wscript.Echo vbTab & "Value: " & estrValue
         Case REG_BINARY
            Wscript.Echo vbTab & "Data Type: Binary"
            objRegistry.GetBinaryValue keyname2number(chosenkey), strKeyPath, arrEntryNames(ii),arrValue
            WScript.StdOut.Write "Value: "
            For Each byteValue in arrValue
                WScript.StdOut.Write byteValue & " "
            Next
            WScript.StdOut.Write vbCRLF
         Case REG_DWORD
            Wscript.Echo vbTab & "Data Type: DWORD"
            objRegistry.GetDWORDValue keyname2number(chosenkey), strKeyPath, arrEntryNames(ii),dwValue
            Wscript.Echo vbTab & "Value: " & dwValue
         Case REG_MULTI_SZ
            Wscript.Echo vbTab & "Data Type: Multi String"
            objRegistry.GetMultiStringValue keyname2number(chosenkey), strKeyPath, arrEntryNames(ii),arrValues
            For Each strValue in arrValues
                Wscript.Echo vbTab & strValue
            Next
        End Select
    Next    
    geterror()
end function

'############################################
' Display the help
'############################################
function help()
    wscript.stdout.write(vbCrLf)
    wscript.stdout.write("help - displays this help" & vbCrLf)
    wscript.stdout.write("cd <keyname> - change to that key" & vbCrLf)
    wscript.stdout.write("cd .. - go to parent/previous key" & vbCrLf)    
    wscript.stdout.write("back - go to parent/previous key" & vbCrLf)
    wscript.stdout.write("ls - list current subkeys" & vbCrLf)
    wscript.stdout.write("lsv - list current key values" & vbCrLf)
    wscript.stdout.write("use <number> - root key number to use" & vbCrLf)    
    wscript.stdout.write(vbTab & "0 - HKEY_CLASSES_ROOT" & vbCrLf)
    wscript.stdout.write(vbTab & "1 - HKEY_CURRENT_USER" & vbCrLf)
    wscript.stdout.write(vbTab & "2 - HKEY_LOCAL_MACHINE" & vbCrLf)
    wscript.stdout.write(vbTab & "3 - HKEY_USERS" & vbCrLf)
    wscript.stdout.write(vbTab & "4 - HKEY_CURRENT_CONFIG" & vbCrLf)    
    wscript.stdout.write(vbCrLf)
end function

'############################################
' Our prompt
'############################################
function displayprompt(promptdata)
    Dim promptstart,promptend
    promptstart = "["
    promptend = "] "
    wscript.stdout.write(promptstart & promptdata & promptend)
end function

'############################################
' go to parent key
'############################################
function pathgoback(currentpath)
        Dim splittedpath, i
        splittedpath = split(currentpath,"\")
        chosenkeypath = ""
        For i = 0 to (ubound(splittedpath)-1)
            if chosenkeypath = "" then
                chosenkeypath = splittedpath(i)
            else
                chosenkeypath = chosenkeypath & "\" & splittedpath(i)
            end if
        Next
        promptpath = chosenkey & "\" & chosenkeypath
end function
'############################################
' Main logic
'############################################
do while true
    Dim command
    displayprompt(promptpath)
    ln = trim(wscript.stdin.readline)
    if ln = "exit" Then 
        exit do
    elseif InStr(ln,"use") = 1 Then
        chosenkeypath = ""
        command = split(ln)
        if ubound(command) = 1 then
            if IsNumeric(command(1)) Then
                chosenkey = rootkeys(trim(command(1)))
                promptpath = chosenkey & "\"
            else 
                wscript.Echo "That was not a number"
            end if   
        else
            wscript.stdout.write("Please Choose: " & vbCrLf)
            wscript.stdout.write(vbTab & "0 - HKEY_CLASSES_ROOT" & vbCrLf)
            wscript.stdout.write(vbTab & "1 - HKEY_CURRENT_USER" & vbCrLf)
            wscript.stdout.write(vbTab & "2 - HKEY_LOCAL_MACHINE" & vbCrLf)
            wscript.stdout.write(vbTab & "3 - HKEY_USERS" & vbCrLf)
            wscript.stdout.write(vbTab & "4 - HKEY_CURRENT_CONFIG" & vbCrLf)        
            wscript.stdout.write("key number: ")
            ln = wscript.stdin.readline
            if IsNumeric(ln) Then
                chosenkey = rootkeys(trim(ln))
                promptpath = chosenkey & "\"
            else 
                wscript.Echo "That was not a number"
            end if             
        end if
    elseif InStr(ln,"cd") = 1 Then
        Dim count, spacestring
        spacestring = ""
        command = split(ln)
        if ubound(command) > 0 then
            if trim(command(1)) = ".." then
                pathgoback(chosenkeypath)
            else
                For count = 1 to ubound(command) 
                    if spacestring = "" Then
                        spacestring = trim(command(count))
                    else
                        spacestring = spacestring & " " & trim(command(count))
                    end if
                Next
                if chosenkeypath = "" Then
                    chosenkeypath = spacestring
                else
                    chosenkeypath = chosenkeypath & "\" & spacestring
                end if
                promptpath = chosenkey & "\" & chosenkeypath
            end if
        end if
    elseif ln = "back" Then
        pathgoback(chosenkeypath)
    elseif ln = "ls" Then
        list(chosenkeypath)
    elseif ln = "lsv" Then
        listv(chosenkeypath)
    elseif ln = "help" Then
        help()
    end if    
    'maybe remove so it displays more errors?
    on error resume next
    err.clear
loop