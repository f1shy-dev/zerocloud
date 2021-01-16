param (
    [string]$network = "565799d8f6ad4a55",
    [string]$admin_username = "Elka",
    [string]$admin_password = "Elka123@0hakim"
)

function Get-Script ($script_name) {
    $url = "https://raw.githubusercontent.com/vishy-dev/zerocloud/master/$script_name"
    Write-Host "Downloading script from $url"
    [Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12

    $webClient = new-object System.Net.WebClient
    $webClient.DownloadFile($url, "$PSScriptRoot\$script_name")
}

if(!$RebootSkip) {
    Get-Script "utils.psm1"
    Import-Module "$PSScriptRoot\utils.psm1"
    Get-Script "Patcher.ps1"
    Update-Firewall
    Disable-Defender
    Disable-IPv6To4
    Disable-InternetExplorerESC
    Edit-VisualEffectsRegistry
    Install-Chocolatey
    Install-VPN
    Join-Network $network

    Disable-ScheduledTasks
    Install-VirtualAudio
    Install-GFE
    Install-VCRedist
    Install-GPUDrivers
    $script = "powershell -ExecutionPolicy Bypass -File `"'$PSScriptRoot\setup.ps1'`" -RebootSkip";
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument $script
    $trigger = New-ScheduledTaskTrigger -AtLogon -RandomDelay "00:00:30"
    $principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators" -RunLevel Highest
    Register-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -TaskName "ZCSetup" -Description "ZCSetup" | Out-Null
} else {
    Import-Module "$PSScriptRoot\utils.psm1"
    if(Get-ScheduledTask | Where-Object {$_.TaskName -like "ZCSetup" }) {
        Unregister-ScheduledTask -TaskName "ZCSetup" -Confirm:$false
    }
    Disable-TCC
    Install-GFEPatches
    Disable-OtherGPUs
    Install-WiFi
    Install-ResolutionFix
    Install-Apps
    Add-AutoLogin $admin_username $admin_password
    Restart-Computer
}