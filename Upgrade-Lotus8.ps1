#################################################################
#                    Upgrade Lotus 8                            # 
#                                                               #
#  mathieu chot-plassot    09/02/2016                           #
#################################################################


<#
    Ce script doit être executé depuis les sources
    L'outil nice.exe est utilisé donc il doit être présent dans les sources au meme niveau que le script

    Pour déployer et éxecuter ce script avec ses sources:
    "PowerShell.exe -ExecutionPolicy Bypass -File ./nom-du-script.ps1"
    
    '-ExecutionPolicy Bypass' permet d'executer le script sans restrictions 
    et ne modifie pas la politique d'execution des scripts powershell
    LANDESK doit fournir ce genre d'option
#>


#continue sans output si erreurs rencontrés 
$ErrorActionPreference = "SilentlyContinue"

Function Test-CurrentAdminRights() {  
        <#
            Check si le script est lancé avec les droits admin 
        #>  
    $user = [System.Security.Principal.WindowsIdentity]::GetCurrent()  
    $Role = [System.Security.Principal.WindowsBuiltinRole]::Administrator
    return (New-Object Security.Principal.WindowsPrincipal $User).IsInRole($Role)  
} 

Function WriteLogFile(){
        <#
            Permet de logger des informations dans un fichier de log
            Ce fichier peut être visualisé en live lors de l'install avec des outil comme trace32
        #>
    Param(
    	[Parameter(Mandatory=$false)]
       	[String]$strOutput=""

    ,	[Parameter(Mandatory=$false)]
    	[Int]$flagAppend=1
    )

    #met a jour le fichier de log
    If ($strOutput -ne "")
    {
    	$date_Now = Get-Date
        #convertie la date en string, affichage fr
    	[String]$text = $date_Now.ToString("dd/MM/yyyy HH:mm:ss")
    	$text = "$text : $strOutput"
    }
    else {[String]$text = ""}
    If ([Int]$flagAppend -eq 1){$text | Out-File $Global:strLogFile -append}
    Else {$text | Out-File $Global:strLogFile}
}

Function Create-Backup($bak){
        <#
            Cree le repertoire de backup ou les fichiers de conf lotus seront placés
        #>
    If (!(Test-Path $bak)){
        Try{
            #creation du dossier backup                                       
            $_ = [System.IO.Directory]::CreateDirectory($bak)
            WriteLogFile "creation du dossier de backup $bak"
            return $True  
            }
        Catch [Exception]{
            $ErrorMsg = $_.Exception.Message
            WriteLogFile "Erreur lors de la création du dossier de backup $bak : $ErrorMsg"
            return $False   
            }
        }
    else{
        return $True
        }
}

Function Show-SystrayNotif {   
        <#
            permet d'afficher une notification depuis la barre de notification  
        #>
             
    [cmdletbinding()]            
    param(            
     [parameter(Mandatory=$true)] #param a fournir             
     [string]$Title,            
     [ValidateSet("Info","Warning","Error")]             
     [string]$MessageType = "Info",            
     [parameter(Mandatory=$true)]            
     [string]$Message,            
     [string]$Duration=10000            
    )            

    [system.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms') | Out-Null     
    #bulle de notification        
    $balloon = New-Object System.Windows.Forms.NotifyIcon 
    #attribue l'icone powershell           
    $path = Get-Process -id $pid | Select-Object -ExpandProperty Path            
    $icon = [System.Drawing.Icon]::ExtractAssociatedIcon($path)            
    $balloon.Icon = $icon            
    $balloon.BalloonTipIcon = $MessageType            
    $balloon.BalloonTipText = $Message            
    $balloon.BalloonTipTitle = $Title            
    $balloon.Visible = $true            
    $balloon.ShowBalloonTip($Duration)            
}

Function NICE(){
        <#
            execute l'outil nice.exe d'IBM afin de supprimer les installations de Lotus Notes  
        #>
    Try{
        #afficher notification systray
        Show-SystrayNotif -Title “MIS A JOUR de Lotus Note” -MessageType Warning `
        -Message “Votre version de Lotus va être mise à jour dans 1 minute, veuillez sauvegarder votre travail” `
        -Duration 15000 
        start-sleep('60')
        if ($balloon -ne $null){
            $balloon.Dispose() #enleve l'icone systray dans la barre de notification
            }
        }
    Catch{
        $ErrorMsg = $_.Exception.Message
        WriteLogFile "[Info] Une erreur est survenue lors de l'affichage de la notification d'installation, l'utilisateur n'a pas été prévenu: $ErrorMsg "     
        }
    WriteLogFile "Désinstallation de Lotus en cours..."
    #liste de proces a stopper avant de lancer nice.exe
    $lprocess = "notes2", "ntmulti", "SUService", "ntaskldr", "notes", "nlnotes", "sametime75", "nminder", "soffice"
    foreach ( $p in $lprocess){
        Try{
            #arret des process
            Stop-Process -name $p -Force
            }
        Catch [Exception]{
            $ErrorMsg = $_.Exception.Message
            WriteLogFile "[Critique] Impossible d'arreter tous les processus de Lotus, interruption du script:  $ErrorMsg"
            exit -2
            }
    }
    Try{
        #execution de nice.exe 
        $args = "-rp -rd -wipe -qn"
        $p = Start-Process $NICE_path -ArgumentList $args -Wait -PassThru
        #attend un retour du process 
        $p.ExitCode 
        if ($p.ExitCode -eq 0){
            WriteLogFile "Lotus a été correctement désinstallé"
            }
        else{
            WriteLogFile "[Critique] La desinstallation de Lotus ne s'est pas passé comme prévu, interruption du script"
            exit -2
            }
        }
    Catch [Exception]{
        $ErrorMsg = $_.Exception.Message
        WriteLogFile "[Critique] Un problème est survenue lors de l'execution de nice.exe, interruption du script: $ErrorMsg "
        exit -2
        }
}

Function Restore-Backup($multi){
        <#
            Cette fonction restaure les fichiers de configurations 
            Pour les installations 'un seul user' les fichiers de configurations 
            vont être copiés dans tous les profils utilisateurs existants
        #>
    if($multi -eq 0){
        foreach ($user in $dict_users.GetEnumerator()){ 
            $username = $user.Name
            foreach($item in $backuplist){
                Try{
                    #si profils existants sur la machine on copie les fichiers de conf pour chaque users
                    if (Test-Path "$env:SystemDrive\Users\$username"){
                        if (Test-Path "$backupfolder\$item"){
                            Copy-Item "$backupfolder\$item" "$env:SystemDrive\Users\$username\AppData\Local\IBM\Notes\Data" -Recurse -Force        
                            WriteLogFile "[Restore] $backupfolder\$item a été restauré dans $env:SystemDrive\Users\$username\AppData\Local\IBM\Notes\Data"                           
                        }
                    }
					}
                Catch{
                    $ErrorMsg = $_.Exception.Message
                    WriteLogFile "[Critique] Impossible de restaurer les fichiers de Lotus8, Lotus 9 va tout de même être installé:  $ErrorMsg"
                    WriteLogFile "[Info] les fichiers dans $backupfolder devront être restaurés dans le profil utilisateur qui utilise lotus note"
                    }
            }
			}
		}  
    Elseif($multi -eq 1){
        foreach ($j in $Lotus_users.GetEnumerator()){
            $username = $j.Name
            $backupfolder = "$env:SystemDrive\Users\$username\AppData\Local\Temp\backup_lotus8"
            foreach($item in $backuplist){
                Try{
                    $newfolder = "$env:SystemDrive\Users\$username\AppData\Local\IBM\Notes\Data" #x64 lotus9
                    Copy-Item "$backupfolder\$item" "$newfolder" -Recurse -Force
                    WriteLogFile "[Restore] $backupfolder\$item a été restauré dans $newfolder"
                    }
                Catch{
                    $ErrorMsg = $_.Exception.Message
                    WriteLogFile "[Critique] Impossible de restaurer les fichiers de Lotus8, Lotus 9 va tout de même être installé:  $ErrorMsg"
                    WriteLogFile "[Info] les fichiers dans $backupfolder devront être restaurés dans $newfolder"
                    }
            }
        }
    }

}

Function Install-Lotus9(){
        <#
            execute le msi d'installation de Lotus9 et previens l'user 
        #>
    Try{
        WriteLogFile "Installation de Lotus 9 en cours depuis > $Lotus9msi_path"
        #$exitcode = (Start-Process msiexec -ArgumentList '/i' $Lotus9msi_path 'SETMULTIUSER=1' '/qn' '/norestart' '/l*v' $loginstall_Lotus9 -Wait -Passthru).ExitCode
        #execute le msi d'installation et attend un retour du process 
        $params = "/i $Lotus9msi_path SETMULTIUSER=1 /qn /norestart /l*v $loginstall_Lotus9"
        $installmsi = [System.Diagnostics.Process]::Start( "msiexec", $params ) 
        $installmsi.WaitForExit()
        if ($installmsi.ExitCode -eq 0){
            WriteLogFile "Lotus 9 a été correctement installé"
            Show-SystrayNotif -Title “mise a jour de Lotus Note” -MessageType Info `
            -Message “Votre version de Lotus a été mise a jour” `
            -Duration 25000 
            }
        else{
            Show-SystrayNotif -Title “mise a jour de Lotus Note” -MessageType Error `
            -Message “Une erreur s est produite lors de la mise a jour de Lotus” `
            -Duration 25000 
            WriteLogFile "Erreur lors de l installation de Lotus 9, exit code: $ec"
            }
        }
    Catch{
        $ErrorMsg = $_.Exception.Message
        WriteLogFile "[Critique] Impossible de restaurer les fichiers de Lotus8, Lotus 9 va tout de même être installé:  $ErrorMsg"
        WriteLogFile "[Info] les fichiers dans $backupfolder devront être restaurés dans $Lotus_progpath\$item"
        }
}

Function Report-a-completer{
        <#
            Si LANDESK ne permet pas d'avoir un suivi d'installation sur tous les postes comme SCCM
            Il est possible d'uploader le fichier de log d'installation du msi et du script dans un share
            sur lequel la machine a accès.
            Copy-item peut etre utilisé, mais il faut que le fqdn du share soit rajouté dans la zone intranet ou zone de confiance 
        #>
}

[String]$PackageName = "$env:COMPUTERNAME - Upgrade_Lotus8"
[String]$Global:strLogFile = "$env:TEMP\$PackageName.Log" #dosier de log, à remplacer par le repertoire de votre choix si le script est executé par 'system'
$arch = $ENV:PROCESSOR_ARCHITECTURE
$WindowsBuild = [System.Environment]::OSVersion.Version.Build
$Windowsver = (Get-WmiObject -class Win32_OperatingSystem).Caption | Out-String
$servercheck = $Windowsver.Contains("Microsoft Windows Server") 
$Global:scriptPath = split-path -parent $MyInvocation.MyCommand.Definition #path repertoire du script
$Global:ScriptFullName = $MyInvocation.Mycommand.Path #path complet du script 
If ($Global:ScriptFullName -ne $null){
	# Resolution du path UNC si script lancé depuis un share
	If ($Global:ScriptFullName.StartsWith("\\") -eq $false)
	{
		$obj_DriveInfo = new-object System.IO.DriveInfo($Global:ScriptFullName)
		If ($obj_DriveInfo.DriveType -eq [System.IO.DriveType]::Network)
		{
			$currentDrive = Split-Path -qualifier $obj_DriveInfo.Name
			$logicalDisk = Gwmi Win32_LogicalDisk -filter "DriveType = 4 AND DeviceID = '$currentDrive'"
			$Global:ScriptFullName = $Global:ScriptFullName.Replace($currentDrive, $logicalDisk.ProviderName)
		}
	}
	$Global:str_Path = [System.IO.Path]::GetDirectoryName($Global:ScriptFullName)
}

#execute le script uniquement sur Windows7 7601 ou '7600.16385'RTM 
if (($servercheck -eq $True) -or (!(($WindowsBuild -eq '7600.16385') -or ($WindowsBuild -eq '7601')))) {
    exit -1
}


WriteLogFile "-*-- Execution du script Upgrade-Lotus8 --*-"

#test les droits admin
If (!(Test-CurrentAdminRights))
{
	WriteLogFile "Le script n'a pas pu être executé correctement, Role administrateur : False"
    exit -1
}

#architecture x86 ou AMD64
if ($arch -eq 'AMD64'){
    $HKLMLotus = 'HKLM:\SOFTWARE\Wow6432Node\Lotus\Notes\8.0'
    $HKLMLotus9 = 'HKLM:\SOFTWARE\Wow6432Node\Lotus\Notes\9.0'
    }
else{
    $HKLMLotus = 'HKLM:\SOFTWARE\Lotus\Notes\8.0'
    $HKLMLotus9 = 'HKLM:\SOFTWARE\Lotus\Notes\9.0'
    }

if (Test-Path $HKLMLotus9){
    WriteLogFile "L'execution du script a été interrompu, une version 9.0 de Lotus Note est installé sur le poste"
    exit -1   
}

#main
if (Test-Path $HKLMLotus){
    $Lotusversion = (Get-ItemProperty -Path $HKLMLotus).Version
    $Lotus_multiuser = (Get-ItemProperty -Path $HKLMLotus).Multiuser 
    $Lotus_progpath = (Get-ItemProperty -Path $HKLMLotus).Path
    $NICE_path = "$scriptpath\nice.exe"
    $loginstall_Lotus9 = "$env:TEMP\$env:COMPUTERNAME-Lotus9_Install.Log" #dosier de log, à remplacer par le repertoire de votre choix si le script est executé par 'system'
    $Lotus9msi_path = "$Global:scriptPath\IBM-Notes-9.0.1-Social-Edition.msi" #"$scriptpath\IBM Notes 9.0.1 Social Edition.msi"
    $usersSID = Get-ChildItem 'hklm:\software\microsoft\windows NT\currentversion\ProfileList\' -Name | ? { $_.length -gt 15} #recupere la liste des SID des utilisateurs qui se sont déjà connectés
    $dict_users = @{} #dictionnaire qui va stocker l'username/SID de chaque utilisateur
    if ($Lotusversion -like "08*"){
        #recupere la liste des users/SID
        ForEach ($sid in $usersSID ) { 
            Try{
                #convertion SID --> username
                $objSID = New-Object System.Security.Principal.SecurityIdentifier `
                ($sid)
                $objUser = $objSID.Translate( [System.Security.Principal.NTAccount])
                $userdom = $objUser.Value  #string
                #resultat sous cette forme: DOMAIN\username
                #on parse la string pour ne garder que l'username
                if ($userdom -like "*\*"){
                    $username = $userdom.Split("\\")[1]
                    $dict_users.Add($username, $sid) #ajout des utilisateurs/SID au dictionnaire
                    }
                }
            Catch [Exception]{
                #echo $_.Exception
                }
        }
        ### cas installation multiuser ###
        if ($Lotus_multiuser -eq '1'){
            WriteLogFile "Installation multiuser détecté"   
            #$Lotus_users = New-Object System.Collections.ArrayList #@()
            $Lotus_users = @{} #dictionnaire qui va stocker uniquement tous les users qui utilise lotus
            New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS  >$null 2>&1 #car HKU pas disponible en alias par defaut  >$null 2>&1 redirige stdout et stderr dans null = pas d'output console
            foreach ($i in $dict_users.GetEnumerator()){ 
                $iusername = $i.Name ; $isid = $i.Value 
                $HKUnotes = "HKU:\$isid\Software\Lotus\Notes\8.0" 
                $notesini_path = (Get-ItemProperty -Path $HKUnotes).NotesIniPath #verifie le chemin par defaut du fichier notes.ini dans la ruche de l'user actuel
                $notes_datadir = ($notesini_path -split '\\')[0..(($notesini_path -split '\\').count -2)] -join '\' #repertoire du fichier notes.ini
                if ((Test-Path "$env:SystemDrive\Users\$iusername\AppData\Local\Lotus\Notes\Data") -or (Test-Path $notes_datadir)){
                    $Lotus_users.Add($iusername, $isid)
                    $backupfolder = "$env:SystemDrive\Users\$iusername\AppData\Local\Temp\backup_lotus8" #dossier de backup ou sera situé les fichiers a sauvegarder puis a restaurer
                    if (Create-Backup($backupfolder)){
                        #fichiers a sauvegarder
                        $backuplist = "archives", "names.nsf", "notes.ini", "*.id" #user.id 
                        foreach ($item in $backuplist){
                            #verifie la presences des fichiers dans les repertoires ci dessous et copie les fichier dans le dossier de backup s'ils existent
                            Try{
                                if(Test-Path "$env:SystemDrive\Users\$iusername\AppData\Local\Lotus\Notes\Data\$item"){
                                    Copy-Item "$env:SystemDrive\Users\$iusername\AppData\Local\Lotus\Notes\Data\$item" "$backupfolder" -Recurse -Force
                                    WriteLogFile "[backup] $item sauvegardé dans $backupfolder pour l'utilisateur $iusername"   
                                    }
                                Elseif(Test-Path "$env:SystemDrive\Users\$iusername\AppData\Local\IBM\Notes\Data\$item"){
                                    Copy-Item "$env:SystemDrive\Users\$iusername\AppData\Local\IBM\Notes\Data\$item" "$backupfolder" -Recurse -Force
                                    WriteLogFile "[backup]$item sauvegardé dans $backupfolder pour l'utilisateur $iusername"   
                                    }
                                Elseif(Test-Path "$notes_datadir\$item"){
                                    Copy-Item "$notes_datadir\$item" "$backupfolder" -Recurse -Force 
                                    WriteLogFile "[backup] $item sauvegardé dans $backupfolder pour l'utilisateur $iusername"   
                                    }
                                }
                            Catch [Exception]{
                                $ErrorMsg = $_.Exception.Message
                                WriteLogFile "Erreur lors de la sauvegarde de $item pour l'utilisateur $iusername : $ErrorMsg"   
                                exit -1
                                }
                        }
                    }
                    else{exit -1}
                 }
            }
            #desinstallation de lotus
            NICE
            #racourcis à supprimmer
            $shortc = @("$env:SystemDrive\ProgramData\Microsoft\Windows\Start Menu\Programs\*IBM",`
                        "$env:SystemDrive\ProgramData\Microsoft\Windows\Start Menu\Programs\*Lotus")
            Foreach($shortcut in $shortc){
                If (Test-Path $shortcut){
	                Remove-Item $shortcut -Force -Recurse
                    }
                }
            #restauration des fichiers
            Restore-Backup(1)
            #installation de Lotus 9
            Install-Lotus9
        }
        ### un seul user ###
        if ($Lotus_multiuser -eq '0'){
            WriteLogFile "Installation un seul user détecté"   
            if (Test-Path $Lotus_progpath){
                $backupfolder = "$env:TEMP\backup_lotus8"    
                if (Create-Backup($backupfolder)){
                    $backuplist = "Data\archives","Data\*.id", "Data\names.nsf", "notes.ini" 
                    Try{
                        foreach ($item in $backuplist){
                            #Pour une install 'un seul user', les fichiers pour tous les users sont situés dans $Lotus_progpath
                            if(Test-Path "$Lotus_progpath\$item"){                       
                                Copy-Item "$Lotus_progpath\$item" "$backupfolder" -Recurse -Force
                                WriteLogFile "$item sauvegardé dans $backupfolder"   
                                }
                            }
                        }
                    Catch [Exception]{
                        $ErrorMsg = $_.Exception.Message
                        WriteLogFile "Erreur lors de la sauvegarde de $item : $ErrorMsg"
                        exit -1   
                        }
                    #desinstallation de lotus
                    NICE
                    #racourcis à supprimmer
                    $shortc = @("$env:SystemDrive\ProgramData\Microsoft\Windows\Start Menu\Programs\*IBM",`
                                "$env:SystemDrive\ProgramData\Microsoft\Windows\Start Menu\Programs\*Lotus")
                    Foreach($shortcut in $shortc){
                        If (Test-Path $shortcut){
	                       Remove-Item $shortcut -Force -Recurse
                            }
                        }
                    #restauration des fichiers 
                    Restore-Backup(0)
                    #installation de Lotus 9
                    Install-Lotus9
                }
            }
        }
        
    }
} 
