[Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
$webClient = new-object System.Net.WebClient

function Disable-InternetExplorerESC {
    # From https://stackoverflow.com/questions/9368305/disable-ie-security-on-windows-server-via-powershell
    $AdminKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}"
    $UserKey = "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A8-37EF-4b3f-8CFC-4F3A74704073}"
    Set-ItemProperty -Path $AdminKey -Name "IsInstalled" -Value 0 -Force
    Set-ItemProperty -Path $UserKey -Name "IsInstalled" -Value 0 -Force
    Stop-Process -Name Explorer -Force
    Write-Output "IE Enhanced Security Configuration (ESC) has been disabled." -ForegroundColor Green
}

function Update-Windows {
    $url = "https://gallery.technet.microsoft.com/scriptcenter/Execute-Windows-Update-fc6acb16/file/144365/1/PS_WinUpdate.zip"
    $compressed_file = "PS_WinUpdate.zip"
    $update_script = "PS_WinUpdate.ps1"

    Write-Output "Downloading Windows Update Powershell Script from $url"
    $webClient.DownloadFile($url, "$PSScriptRoot\$compressed_file")
    Unblock-File -Path "$PSScriptRoot\$compressed_file"

    Write-Output "Extracting Windows Update Powershell Script"
    Expand-Archive "$PSScriptRoot\$compressed_file" -DestinationPath "$PSScriptRoot\" -Force

    Write-Output "Running Windows Update"
    Invoke-Expression $PSScriptRoot\$update_script
}

function Update-Firewall {
    Write-Output "Enable ICMP Ping in Firewall."
    Set-NetFirewallRule -DisplayName "File and Printer Sharing (Echo Request - ICMPv4-In)" -Enabled True
}

function Disable-Defender {
    Write-Output "Disable Windows Defender real-time protection."
    Set-MpPreference -DisableRealtimeMonitoring $true
}

function Disable-ScheduledTasks {
    Write-Output "Disable unnecessary scheduled tasks"
    Disable-ScheduledTask -TaskName 'ScheduledDefrag' -TaskPath '\Microsoft\Windows\Defrag'
    Disable-ScheduledTask -TaskName 'ProactiveScan' -TaskPath '\Microsoft\Windows\Chkdsk'
    Disable-ScheduledTask -TaskName 'Scheduled' -TaskPath '\Microsoft\Windows\Diagnosis'
    Disable-ScheduledTask -TaskName 'SilentCleanup' -TaskPath '\Microsoft\Windows\DiskCleanup'
    Disable-ScheduledTask -TaskName 'WinSAT' -TaskPath '\Microsoft\Windows\Maintenance'
    Disable-ScheduledTask -TaskName 'Windows Defender Cache Maintenance' -TaskPath '\Microsoft\Windows\Windows Defender'
    Disable-ScheduledTask -TaskName 'Windows Defender Cleanup' -TaskPath '\Microsoft\Windows\Windows Defender'
    Disable-ScheduledTask -TaskName 'Windows Defender Scheduled Scan' -TaskPath '\Microsoft\Windows\Windows Defender'
    Disable-ScheduledTask -TaskName 'Windows Defender Verification' -TaskPath '\Microsoft\Windows\Windows Defender'
}

function Edit-VisualEffectsRegistry {
    Write-Output "Adjust performance options in registry"
    New-Item -Path "Registry::\HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects"
    Set-ItemProperty -Path "Registry::\HKEY_USERS\.DEFAULT\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -Value 2
}

function Disable-Devices {
    $url = "https://gallery.technet.microsoft.com/PowerShell-Device-60d73bb0/file/147248/2/DeviceManagement.zip"
    $compressed_file = "DeviceManagement.zip"
    $extract_folder = "DeviceManagement"

    Write-Output "Downloading Device Management Powershell Script from $url"
    $webClient.DownloadFile($url, "$PSScriptRoot\$compressed_file")
    Unblock-File -Path "$PSScriptRoot\$compressed_file"

    Write-Output "Extracting Device Management Powershell Script"
    Expand-Archive "$PSScriptRoot\$compressed_file" -DestinationPath "$PSScriptRoot\$extract_folder" -Force

    Write-Output "Disabling Hyper-V Video"
    Import-Module "$PSScriptRoot\$extract_folder\DeviceManagement.psd1"
    Get-Device | Where-Object -Property Name -Like "Microsoft Hyper-V Video" | Disable-Device -Confirm:$false
}

function Disable-TCC {
    $nvsmi = "C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"
    $gpu = & $nvsmi --format=csv,noheader --query-gpu=pci.bus_id
    & $nvsmi -g $gpu -fdm 0
}

function Install-VirtualAudio {
    $compressed_file = "vbcable.zip"
    Write-Output "Downloading Virtual Audio Driver"
    $webClient.DownloadFile("https://download.vb-audio.com/Download_CABLE/VBCABLE_Driver_Pack43.zip", "$PSScriptRoot\$compressed_file")
    Unblock-File -Path "$PSScriptRoot\$compressed_file"

    Write-Host "Installing VBCABLE..."
    Expand-Archive -Path "$PSScriptRoot\$compressed_file" -DestinationPath "$PSScriptRoot\vbcable"
    Start-Process -FilePath "$PSScriptRoot\vbcable\VBCABLE_Setup_x64.exe" -ArgumentList "-i","-h" -NoNewWindow -Wait

    $osType = Get-CimInstance -ClassName Win32_OperatingSystem

    if($osType.ProductType -eq 3) {
        Write-Host "Applying Audio service fix for Windows Server..."
        New-ItemProperty "hklm:\SYSTEM\CurrentControlSet\Control" -Name "ServicesPipeTimeout" -Value 600000 -PropertyType "DWord" | Out-Null
        Set-Service -Name Audiosrv -StartupType Automatic | Out-Null
    }

}

function Install-Chocolatey {
    Write-Output "Installing Chocolatey"
    Invoke-Expression ($webClient.DownloadString('https://chocolatey.org/install.ps1'))
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
    chocolatey feature enable -n allowGlobalConfirmation
}

function Disable-IPv6To4 {
    Set-Net6to4Configuration -State disabled
    Set-NetTeredoConfiguration -Type disabled
    Set-NetIsatapConfiguration -State disabled
}

function Install-VPN {
    $cert = "zerotier_cert.cer"
    $url = "https://github.com/ecalder6/azure-gaming/raw/master/$cert"

    Write-Output "Downloading zero tier certificate from $url"
    $webClient.DownloadFile($url, "$PSScriptRoot\$cert")

    Write-Output "Importing zero tier certificate"
    Import-Certificate -FilePath "$PSScriptRoot\$cert" -CertStoreLocation "cert:\LocalMachine\TrustedPublisher"

    Write-Output "Installing ZeroTier"
    choco install zerotier-one --force
    $env:Path = [System.Environment]::GetEnvironmentVariable("Path","Machine")
}

function Join-Network ($network) {
    Write-Output "Joining network $network"
    zerotier-cli join $network
}

function Install-NSSM {
    Write-Output "Installing NSSM for launching services that run apps at startup"
    choco install nssm --force
}

function Set-ScheduleWorkflow ($admin_username, $admin_password, $manual_install) {
    $script_name = "setup2.ps1"
    $url = "https://raw.githubusercontent.com/ecalder6/azure-gaming/master/$script_name"

    Write-Output "Downloading second stage setup script from $url"
    $webClient.DownloadFile($url, "C:\$script_name")

    $powershell = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
    $service_name = "SetupSecondStage"
    Write-Output "Creating a service $service_name to finish setting up"
    $cmd = "-ExecutionPolicy Unrestricted -NoProfile -File C:\$script_name -admin_username `"$admin_username`" -admin_password `"$admin_password`""
    if ($manual_install) {
        $cmd = -join ($cmd, " -manual_install")
    }

    nssm install $service_name $powershell $cmd
    nssm set $service_name Start SERVICE_AUTO_START
    nssm set $service_name AppExit 0 Exit
}

function Disable-ScheduleWorkflow {
    $service_name = "SetupSecondStage"
    nssm remove $service_name confirm
}

function Add-AutoLogin ($admin_username, $admin_password) {
    Write-Output "Make the password and account of admin user never expire."
    Set-LocalUser -Name $admin_username -PasswordNeverExpires $true -AccountNeverExpires

    Write-Output "Make the admin login at startup."
    $registry = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
    Set-ItemProperty $registry "AutoAdminLogon" -Value "1" -type String
    Set-ItemProperty $registry "DefaultDomainName" -Value "$env:computername" -type String
    Set-ItemProperty $registry "DefaultUsername" -Value $admin_username -type String
    Set-ItemProperty $registry "DefaultPassword" -Value $admin_password -type String
}

# Custom Stuff!

function Install-GFE {
    $webClient.DownloadFile("https://us.download.nvidia.com/GFE/GFEClient/3.13.0.85/GeForce_Experience_Beta_v3.13.0.85.exe", "$PSScriptRoot\GFE.exe")
    $ExitCode = (Start-Process -FilePath "$PSScriptRoot\GFE.exe" -ArgumentList "-s" -NoNewWindow -Wait -Passthru).ExitCode
    if($ExitCode -eq 0) { Write-Host "Installed." -ForegroundColor Green }
    else {  
        throw "GeForce Experience installation failed (Error: $ExitCode)."
    }
}

function Install-VCRedist {
    $webClient.DownloadFile("https://download.microsoft.com/download/9/3/F/93FCF1E7-E6A4-478B-96E7-D4B285925B00/vc_redist.x86.exe", "$PSScriptRoot\redist.exe")

    $ExitCode = (Start-Process -FilePath "$PSScriptRoot\redist.exe" -ArgumentList "/install","/quiet","/norestart" -NoNewWindow -Wait -Passthru).ExitCode
    if($ExitCode -eq 0) { Write-Host "Installed." -ForegroundColor Green }
    elseif($ExitCode -eq 1638) { Write-Host "Newer version already installed." -ForegroundColor Green }
    else { 
        throw "Visual C++ Redist 2015 x86 installation failed (Error: $ExitCode)."
    }
}

function Install-GPUDrivers {
    $webClient.DownloadFile("https://download.microsoft.com/download/b/8/f/b8f5ecec-b8f9-47de-b007-ac40adc88dc8/442.06_grid_win10_64bit_international_whql.exe", "$PSScriptRoot\Drivers.exe")
    $ExitCode = (Start-Process -FilePath "$PSScriptRoot\Drivers.exe" -ArgumentList "/s","/clean" -NoNewWindow -Wait -PassThru).ExitCode
    if($ExitCode -eq 0) {
        Write-Host "NVIDIA GRID GPU drivers installed." -ForegroundColor Green 
    }
}

function Install-GFEPatches {
    Write-Host "Enabling NVIDIA FrameBufferCopy..."
    $ExitCode = (Start-Process -FilePath "$PSScriptRoot\NvFBCEnable.exe" -ArgumentList "-enable" -NoNewWindow -Wait -PassThru).ExitCode
    if($ExitCode -ne 0) {
        throw "Failed to enable NvFBC. (Error: $ExitCode)"
    } else {
        Write-Host "Enabled NvFBC successfully." -ForegroundColor DarkGreen
    }

    Write-Host "Patching GFE to allow the GPU's Device ID..."
    Stop-Service -Name NvContainerLocalSystem | Out-Null
    $TargetDevice = (Get-WmiObject Win32_VideoController | select PNPDeviceID,Name | where Name -match "nvidia" | Select-Object -First 1) 
    if(!$TargetDevice) {
        throw "Failed to find an NVIDIA GPU."
    }
    if(!($TargetDevice.PNPDeviceID -match "DEV_(\w*)")) {
        throw "Regex failed to extract device ID."
    }
    & $PSScriptRoot\Patcher.ps1 -DeviceID $matches[1] -TargetFile "C:\Program Files\NVIDIA Corporation\NvContainer\plugins\LocalSystem\GameStream\Main\_NvStreamControl.dll";

    Write-Host "Adding hosts file rules to block updates..."
    $BlockedHosts = @("telemetry.gfe.nvidia.com", "ls.dtrace.nvidia.com", "ota.nvidia.com", "ota-downloads.nvidia.com", "rds-assets.nvidia.com", "nvidia.tt.omtrdc.net", "api.commune.ly")
    $HostsFile = "$env:SystemRoot\System32\Drivers\etc\hosts"
    $HostsContent = [String](Get-Content -Path $HostsFile)
    $Appended = ""

    foreach($Entry in $BlockedHosts) {
        if($HostsContent -notmatch $Entry) {
            $Appended += "0.0.0.0 $Entry`r`n"
        }
    }

    if($Appended.Length -gt 0) {
        $Appended = $Appended.Substring(0,$Appended.length-2)
        Write-Host "Added hosts:`r`n$Appended"
        Add-Content -Path $HostsFile -Value $Appended
    }

    Write-Host "Adding a GameStream rule to the Windows Firewall..."
    New-NetFirewallRule -DisplayName "NVIDIA GameStream TCP" -Direction inbound -LocalPort 47984,47989,48010 -Protocol TCP -Action Allow | Out-Null
    New-NetFirewallRule -DisplayName "NVIDIA GameStream UDP" -Direction inbound -LocalPort 47998,47999,48000,48010 -Protocol UDP -Action Allow | Out-Null
}

function Disable-OtherGPUs {
    Write-Host "Disabling HyperV Monitor and non-NVIDIA GPUs..."
    displayswitch.exe /internal
    Get-PnpDevice -Class "Display" -Status OK | where { $_.Name -notmatch "nvidia" } | Disable-PnpDevice -confirm:$false
}

function Install-WiFi {
    $osType = Get-CimInstance -ClassName Win32_OperatingSystem

    if($osType.ProductType -eq 3) {
        Write-Host "Installing Wireless Networking."
        Install-WindowsFeature -Name Wireless-Networking | Out-Null
    }
}

function Install-ResolutionFix {
    Write-Host "Applying resolution fix..."
    $Status = @("NvAPI failed to initialize", "Failed to query GPUs", "Failed to get display count", "Failed to query displays", "Failed to set EDID")

    $ExitCode = (Start-Process -FilePath "$WorkDir\ResolutionFix.exe" -WorkingDirectory "$WorkDir" -Argument "-a","-g 0","-d 0" -NoNewWindow -Wait -PassThru).ExitCode
    if($ExitCode -ne 0) {
        $Message = $Status[$($ExitCode - 1)]
        throw "Adding EDID failed: $Message($ExitCode)"
    }
}

function Install-Chrome {
}

function Install-Apps {
    $steam_exe = "steam.exe"
    $epic_exe = "epic.exe"
    Write-Output "Downloading steam into path $PSScriptRoot\$steam_exe"
    $webClient.DownloadFile("https://steamcdn-a.akamaihd.net/client/installer/SteamSetup.exe", "$PSScriptRoot\$steam_exe")
    Write-Output "Installing steam"
    Start-Process -FilePath "$PSScriptRoot\$steam_exe" -ArgumentList "/S" -Wait

    Write-Output "Cleaning up steam installation file"
    Remove-Item -Path $PSScriptRoot\$steam_exe -Confirm:$false

    choco install googlechrome --force
    choco install uplay
    choco install 7zip
    choco install notepadplusplus
    $webClient.DownloadFile("https://launcher-public-service-prod06.ol.epicgames.com/launcher/api/installer/download/EpicGamesLauncherInstaller.msi", "$PSScriptRoot\$epic_exe")
    Start-Process -FilePath "$PSScriptRoot\$epic_exe" -ArgumentList "/qn /norestart ALLUSERS=2" -Wait
}