<#
.SYNOPSIS
    MacroDetector
.DESCRIPTION
    A comprehensive forensic mouse device and macro software configuration analysis tool.
.NOTES
    Compatible with Windows 10 and Windows 11. Requires Administrative privileges for full registry and Prefetch analysis.
    v2.5 - Fixed explicit macro file pointing and wording.
#>

# --- BRAND DETECTION ENGINE ---
 $BrandMap = @(
    @{ Keyword = "attack shark";  Brand = "Attack Shark" }
    @{ Keyword = "attackshark";   Brand = "Attack Shark" }
    @{ Keyword = "logitech";      Brand = "Logitech" }
    @{ Keyword = "logi";          Brand = "Logitech" }
    @{ Keyword = "razer";         Brand = "Razer" }
    @{ Keyword = "steelseries";   Brand = "SteelSeries" }
    @{ Keyword = "corsair";       Brand = "Corsair" }
    @{ Keyword = "roccat";        Brand = "ROCCAT" }
    @{ Keyword = "glorious";      Brand = "Glorious" }
    @{ Keyword = "zowie";         Brand = "ZOWIE" }
    @{ Keyword = "benq";          Brand = "ZOWIE" }
    @{ Keyword = "hyperx";        Brand = "HyperX" }
    @{ Keyword = "asus";          Brand = "ASUS" }
    @{ Keyword = "msi";           Brand = "MSI" }
    @{ Keyword = "pulsar";        Brand = "Pulsar" }
    @{ Keyword = "finalmouse";    Brand = "Finalmouse" }
    @{ Keyword = "endgame gear";  Brand = "Endgame Gear" }
    @{ Keyword = "endgamegear";   Brand = "Endgame Gear" }
    @{ Keyword = "viper";         Brand = "Razer" }
    @{ Keyword = "deathadder";    Brand = "Razer" }
    @{ Keyword = "basilisk";      Brand = "Razer" }
    @{ Keyword = "g502";          Brand = "Logitech" }
    @{ Keyword = "g pro";         Brand = "Logitech" }
    @{ Keyword = "bloody";        Brand = "Bloody" }
    @{ Keyword = "a4tech";        Brand = "Bloody" }
    @{ Keyword = "redragon";      Brand = "Redragon" }
    @{ Keyword = "coolermaster";  Brand = "CoolerMaster" }
    @{ Keyword = "cooler master"; Brand = "CoolerMaster" }
    @{ Keyword = "alienware";     Brand = "Alienware" }
    @{ Keyword = "kensington";    Brand = "Kensington" }
    @{ Keyword = "cougar";        Brand = "Cougar" }
    @{ Keyword = "fantech";       Brand = "Fantech" }
    @{ Keyword = "marvo";         Brand = "Marvo" }
    @{ Keyword = "ajazz";         Brand = "Ajazz" }
    @{ Keyword = "marsgaming";    Brand = "Marsgaming" }
    @{ Keyword = "mars gaming";   Brand = "Marsgaming" }
    @{ Keyword = "motospeed";     Brand = "Motospeed" }
    @{ Keyword = "xtrfy";         Brand = "Xtrfy" }
    @{ Keyword = "fnatic";        Brand = "Fnatic" }
    @{ Keyword = "vaxee";         Brand = "Vaxee" }
    @{ Keyword = "ninjutso";      Brand = "Ninjutso" }
    @{ Keyword = "pulsar";        Brand = "Pulsar" }
    @{ Keyword = "spc gear";      Brand = "SPC Gear" }
)

function Detect-Brand {
    param([string]$text)
    if ([string]::IsNullOrEmpty($text)) { return "Unknown" }
    foreach ($entry in $BrandMap) {
        if ($text.IndexOf($entry.Keyword, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            return $entry.Brand
        }
    }
    return "Unknown"
}

function Get-InstallDate {
    param([string]$regPath, [string]$valueName = "0065")
    try {
        $targetPath = "HKLM:\$regPath\Properties\{83da6326-97a6-4088-9453-a1923f573b29}"
        if (Test-Path $targetPath) {
            $regKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("$regPath\Properties\{83da6326-97a6-4088-9453-a1923f573b29}")
            if ($regKey) {
                $bytes = $regKey.GetValue($valueName)
                $regKey.Close()
                if ($bytes -and $bytes.Count -ge 8) {
                    $ft = [BitConverter]::ToInt64($bytes, 0)
                    if ($ft -gt 0) { return [DateTime]::FromFileTimeUtc($ft).ToLocalTime() }
                }
            }
        }
    } catch {}
    return $null
}

function Guess-ConnectionType {
    param([string]$deviceIdStr)
    if ([string]::IsNullOrEmpty($deviceIdStr)) { return "Unknown" }
    $p = $deviceIdStr.ToUpper()
    if ($p.StartsWith("BTH") -or $p.Contains("BTHLE")) { return "Bluetooth" }
    if ($p.StartsWith("USB") -or $p.Contains("HID"))   { return "USB" }
    return "Unknown"
}

function Get-ConnectedMice {
    $results = @()
    try {
        $wmiDevices = Get-CimInstance -Query "SELECT * FROM Win32_PointingDevice" -ErrorAction SilentlyContinue
        foreach ($obj in $wmiDevices) {
            $name = if ($obj.Name)         { $obj.Name.Trim() }         else { "" }
            $mfr  = if ($obj.Manufacturer) { $obj.Manufacturer.Trim() } else { "" }
            $id   = if ($obj.PNPDeviceID)  { $obj.PNPDeviceID }         else { "" }
            $results += [PSCustomObject]@{
                Name = $name; Manufacturer = $mfr; DeviceId = $id; IsConnected = $true
                Brand = Detect-Brand -text "$name $mfr $id"; ConnectionType = Guess-ConnectionType -deviceIdStr $id
                ConnectedAt = Get-InstallDate -regPath "SYSTEM\CurrentControlSet\Enum\$id"; DisconnectedAt = $null; Source = "WMI"
            }
        }
    } catch {}
    return $results
}

function Scan-EnumKey {
    param([string]$regPath)
    $results = @()
    $rootSubKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($regPath)
    if (-not $rootSubKey) { return @() }
    foreach ($vid in $rootSubKey.GetSubKeyNames()) {
        $vidSubKey = $rootSubKey.OpenSubKey($vid)
        if (-not $vidSubKey) { continue }
        foreach ($instance in $vidSubKey.GetSubKeyNames()) {
            $instSubKey = $vidSubKey.OpenSubKey($instance)
            if (-not $instSubKey) { continue }
            $friendly = if ($instSubKey.GetValue("FriendlyName")) { $instSubKey.GetValue("FriendlyName").ToString() } else { "" }
            $desc     = if ($instSubKey.GetValue("DeviceDesc"))   { $instSubKey.GetValue("DeviceDesc").ToString()   } else { "" }
            $instSubKey.Close()
            $combined = "$friendly $desc $vid $instance"
            $brand    = Detect-Brand -text $combined
            if ($brand -eq "Unknown") { continue }
            $finalName = if (-not [string]::IsNullOrEmpty($friendly)) { $friendly } else { $desc }
            $fullId    = "$regPath\$vid\$instance"
            $results += [PSCustomObject]@{
                Name = $finalName; Manufacturer = ""; DeviceId = $fullId; Brand = $brand
                ConnectionType = if ($regPath.Contains("HID")) { "USB HID" } else { "USB" }
                IsConnected = $false; ConnectedAt = Get-InstallDate -regPath $fullId; DisconnectedAt = $null; Source = "Registry"
            }
        }
        $vidSubKey.Close()
    }
    $rootSubKey.Close()
    return $results
}

function Get-RegistryHistory {
    $results = @()
    $results += Scan-EnumKey -regPath "SYSTEM\CurrentControlSet\Enum\HID"
    $results += Scan-EnumKey -regPath "SYSTEM\CurrentControlSet\Enum\USB"
    return $results
}

function Get-BluetoothDevices {
    $results = @()
    $btKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\BTHPORT\Parameters\Devices")
    if ($btKey) {
        foreach ($key in $btKey.GetSubKeyNames()) {
            $devSubKey = $btKey.OpenSubKey($key)
            if (-not $devSubKey) { continue }
            $nameRaw = $devSubKey.GetValue("Name")
            $name    = if ($nameRaw) { [System.Text.Encoding]::UTF8.GetString($nameRaw).TrimEnd("`0") } else { "" }
            $brand   = Detect-Brand -text $name
            $lastSeen = $null
            $lastSeenRaw = $devSubKey.GetValue("LastSeen")
            if ($lastSeenRaw) { try { $ft = [BitConverter]::ToInt64($lastSeenRaw, 0); $lastSeen = [DateTime]::FromFileTimeUtc($ft).ToLocalTime() } catch {} }
            $devSubKey.Close()
            if ($brand -eq "Unknown") { continue }
            $results += [PSCustomObject]@{ Name = $name; Manufacturer = ""; DeviceId = $key; Brand = $brand; ConnectionType = "Bluetooth"; IsConnected = $false; ConnectedAt = $lastSeen; DisconnectedAt = $null; Source = "Bluetooth Registry" }
        }
        $btKey.Close()
    }
    $bleKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Enum\BTHLE")
    if ($bleKey) {
        foreach ($cls in $bleKey.GetSubKeyNames()) {
            $clsSubKey = $bleKey.OpenSubKey($cls)
            if (-not $clsSubKey) { continue }
            foreach ($inst in $clsSubKey.GetSubKeyNames()) {
                $instSubKey = $clsSubKey.OpenSubKey($inst)
                if (-not $instSubKey) { continue }
                $friendly = if ($instSubKey.GetValue("FriendlyName")) { $instSubKey.GetValue("FriendlyName").ToString() } else { "" }
                $brand = Detect-Brand -text $friendly; $instSubKey.Close()
                if ($brand -eq "Unknown") { continue }
                $results += [PSCustomObject]@{ Name = $friendly; Manufacturer = ""; DeviceId = "BTHLE\$cls\$inst"; Brand = $brand; ConnectionType = "Bluetooth LE"; IsConnected = $false; ConnectedAt = $null; DisconnectedAt = $null; Source = "BLE Registry" }
            }
            $clsSubKey.Close()
        }
        $bleKey.Close()
    }
    $btEnumKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Enum\BTH")
    if ($btEnumKey) {
        foreach ($cls in $btEnumKey.GetSubKeyNames()) {
            $clsSubKey = $btEnumKey.OpenSubKey($cls)
            if (-not $clsSubKey) { continue }
            foreach ($inst in $clsSubKey.GetSubKeyNames()) {
                $instSubKey = $clsSubKey.OpenSubKey($inst)
                if (-not $instSubKey) { continue }
                $friendly = if ($instSubKey.GetValue("FriendlyName")) { $instSubKey.GetValue("FriendlyName").ToString() } else { "" }
                $desc = if ($instSubKey.GetValue("DeviceDesc")) { $instSubKey.GetValue("DeviceDesc").ToString() } else { "" }
                $brand = Detect-Brand -text "$friendly $desc $cls"; $instSubKey.Close()
                if ($brand -eq "Unknown") { continue }
                $finalName = if (-not [string]::IsNullOrEmpty($friendly)) { $friendly } else { $desc }
                $results += [PSCustomObject]@{ Name = $finalName; Manufacturer = ""; DeviceId = "BTH\$cls\$inst"; Brand = $brand; ConnectionType = "Bluetooth"; IsConnected = $false; ConnectedAt = $null; DisconnectedAt = $null; Source = "BTH Registry" }
            }
            $clsSubKey.Close()
        }
        $btEnumKey.Close()
    }
    return $results
}

 $KnownSoftware = @(
    @{ Keyword = "logi options+";             Brand = "Logitech";     Name = "Logitech Options+" }
    @{ Keyword = "logi options";              Brand = "Logitech";     Name = "Logitech Options" }
    @{ Keyword = "lghub";                     Brand = "Logitech";     Name = "Logitech G HUB" }
    @{ Keyword = "logitech g hub";            Brand = "Logitech";     Name = "Logitech G HUB" }
    @{ Keyword = "logitech gaming software";  Brand = "Logitech";     Name = "Logitech Gaming Software" }
    @{ Keyword = "razer synapse";             Brand = "Razer";        Name = "Razer Synapse" }
    @{ Keyword = "razer cortex";              Brand = "Razer";        Name = "Razer Cortex" }
    @{ Keyword = "steelseries gg";            Brand = "SteelSeries";  Name = "SteelSeries GG" }
    @{ Keyword = "steelseries engine";        Brand = "SteelSeries";  Name = "SteelSeries Engine" }
    @{ Keyword = "icue";                      Brand = "Corsair";      Name = "Corsair iCUE" }
    @{ Keyword = "corsair utility engine";    Brand = "Corsair";      Name = "Corsair iCUE" }
    @{ Keyword = "roccat swarm";              Brand = "ROCCAT";       Name = "ROCCAT Swarm" }
    @{ Keyword = "glorious core";             Brand = "Glorious";     Name = "Glorious CORE" }
    @{ Keyword = "attack shark";              Brand = "Attack Shark"; Name = "Attack Shark Software" }
    @{ Keyword = "armoury crate";             Brand = "ASUS";         Name = "ASUS Armoury Crate" }
    @{ Keyword = "msi dragon center";         Brand = "MSI";          Name = "MSI Dragon Center" }
    @{ Keyword = "msi center";                Brand = "MSI";          Name = "MSI Center" }
    @{ Keyword = "hyperx ngenuity";           Brand = "HyperX";       Name = "HyperX NGENUITY" }
    @{ Keyword = "bloody";                    Brand = "Bloody";       Name = "Bloody Software" }
    @{ Keyword = "a4tech";                    Brand = "Bloody";       Name = "A4Tech Software" }
    @{ Keyword = "redragon";                  Brand = "Redragon";     Name = "Redragon Software" }
    @{ Keyword = "coolermaster";              Brand = "CoolerMaster"; Name = "CoolerMaster MasterPlus" }
    @{ Keyword = "cooler master";             Brand = "CoolerMaster"; Name = "CoolerMaster MasterPlus" }
    @{ Keyword = "alienware command center";  Brand = "Alienware";    Name = "Alienware Command Center" }
    @{ Keyword = "kensington works";          Brand = "Kensington";   Name = "Kensington Works" }
    @{ Keyword = "cougar uix";                Brand = "Cougar";       Name = "Cougar UIX" }
    @{ Keyword = "fantech";                   Brand = "Fantech";      Name = "Fantech Software" }
    @{ Keyword = "marvo";                     Brand = "Marvo";        Name = "Marvo Software" }
    @{ Keyword = "ajazz";                     Brand = "Ajazz";        Name = "Ajazz Software" }
    @{ Keyword = "marsgaming";                Brand = "Marsgaming";   Name = "Marsgaming MMGX" }
    @{ Keyword = "motospeed";                 Brand = "Motospeed";    Name = "Motospeed Gaming Mouse" }
    @{ Keyword = "finalmouse";                Brand = "Finalmouse";   Name = "Finalmouse Software" }
    @{ Keyword = "zowie";                     Brand = "ZOWIE";        Name = "ZOWIE Mouse Config" }
    @{ Keyword = "endgame gear";              Brand = "Endgame Gear"; Name = "Endgame Gear Software" }
    @{ Keyword = "pulsar";                    Brand = "Pulsar";       Name = "Pulsar Software" }
)

function Scan-InstalledSoftware {
    $results = @()
    $seen = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    $hives = @(
        @{ Root = "LocalMachine"; Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" }
        @{ Root = "LocalMachine"; Path = "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" }
        @{ Root = "CurrentUser";  Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" }
    )
    foreach ($hive in $hives) {
        $regRoot = if ($hive.Root -eq "LocalMachine") { [Microsoft.Win32.Registry]::LocalMachine } else { [Microsoft.Win32.Registry]::CurrentUser }
        $baseSubKey = $regRoot.OpenSubKey($hive.Path)
        if (-not $baseSubKey) { continue }
        foreach ($appName in $baseSubKey.GetSubKeyNames()) {
            $appSubKey = $baseSubKey.OpenSubKey($appName)
            if (-not $appSubKey) { continue }
            $displayRaw = $appSubKey.GetValue("DisplayName")
            if (-not $displayRaw) { $appSubKey.Close(); continue }
            $display = $displayRaw.ToString()
            $lower = $display.ToLowerInvariant()
            foreach ($known in $KnownSoftware) {
                if (-not $lower.Contains($known.Keyword)) { continue }
                $dedupeKey = "$($known.Brand)|$($known.Name)"
                if (-not $seen.Add($dedupeKey)) { continue }
                $version = if ($appSubKey.GetValue("DisplayVersion")) { $appSubKey.GetValue("DisplayVersion").ToString() } else { "" }
                $results += [PSCustomObject]@{ Brand = $known.Brand; SoftwareName = $known.Name; Version = $version }
                break
            }
            $appSubKey.Close()
        }
        $baseSubKey.Close()
    }
    return $results
}

 $ConfigEntries = @(
    @{ Brand = "Logitech";    Name = "G HUB - settings.db";              Path = "$env:LOCALAPPDATA\LGHUB\settings.db";                                          IsMacro = $true  }
    @{ Brand = "Logitech";    Name = "G HUB - Macros folder";            Path = "$env:LOCALAPPDATA\LGHUB";                                                      IsMacro = $true  }
    @{ Brand = "Logitech";    Name = "Options+ - options_plus.db";       Path = "$env:LOCALAPPDATA\Logi\LogiOptionsPlus\data\options_plus.db";                   IsMacro = $false }
    @{ Brand = "Logitech";    Name = "Gaming Software - settings";       Path = "$env:LOCALAPPDATA\Logitech\Logitech Gaming Software\settings.json";             IsMacro = $true  }
    @{ Brand = "Logitech";    Name = "G HUB - ProgramData applications"; Path = "C:\ProgramData\LGHUBData\applications";                                       IsMacro = $true  }
    @{ Brand = "Logitech";    Name = "G HUB - Roaming Backup";          Path = "$env:APPDATA\LGHUB_BKP";                                                     IsMacro = $true  }
    @{ Brand = "Razer";       Name = "Synapse 3 - Settings";            Path = "$env:APPDATA\Razer\Synapse3\Settings";                                         IsMacro = $true  }
    @{ Brand = "Razer";       Name = "Synapse 3 - MacroData";           Path = "$env:APPDATA\Razer\Synapse3\MacroData";                                        IsMacro = $true  }
    @{ Brand = "Razer";       Name = "Synapse 3 - Accounts";            Path = "$env:APPDATA\Razer\Synapse3\Accounts";                                         IsMacro = $true  }
    @{ Brand = "Razer";       Name = "RazerAppEngine - User Data";      Path = "$env:LOCALAPPDATA\Razer\RazerAppEngine\User Data";                             IsMacro = $true  }
    @{ Brand = "Razer";       Name = "RazerAppEngine - Logs";           Path = "$env:LOCALAPPDATA\Razer\RazerAppEngine\User Data\Logs";                         IsMacro = $true  }
    @{ Brand = "Razer";       Name = "RazerAppEngine - Products";       Path = "$env:LOCALAPPDATA\Razer\RazerAppEngine\User Data\Products";                     IsMacro = $true  }
    @{ Brand = "Razer";       Name = "Synapse 3 - ProgramData";         Path = "$env:PROGRAMDATA\Razer\Synapse3";                                              IsMacro = $true  }
    @{ Brand = "Razer";       Name = "Razer Central - ProgramData";     Path = "$env:PROGRAMDATA\Razer\Razer Central";                                         IsMacro = $true  }
    @{ Brand = "SteelSeries"; Name = "GG - gg.db";                      Path = "$env:APPDATA\SteelSeries\GG\db\gg.db";                                        IsMacro = $true  }
    @{ Brand = "Corsair";     Name = "iCUE 5 - config.db";              Path = "$env:APPDATA\Corsair\CUE5\config.db";                                         IsMacro = $true  }
    @{ Brand = "Corsair";     Name = "iCUE 4 - config.db";              Path = "$env:APPDATA\Corsair\CUE4\config.db";                                         IsMacro = $true  }
    @{ Brand = "ROCCAT";      Name = "Swarm - macro folder";             Path = "$env:APPDATA\ROCCAT\SWARM\macro";                                             IsMacro = $true  }
    @{ Brand = "Glorious";    Name = "CORE - settings.db";               Path = "$env:LOCALAPPDATA\GloriousCore\settings.db";                                  IsMacro = $true  }
    @{ Brand = "Bloody";      Name = "Bloody7 - GunLib Macros";          Path = "C:\Program Files (x86)\Bloody7\Bloody7\Data\Mouse\English\ScriptsMacros\GunLib"; IsMacro = $true  }
    @{ Brand = "ASUS";        Name = "Armoury Crate - settings.db";      Path = "$env:LOCALAPPDATA\ASUS\ArmouryCrate\settings.db";                            IsMacro = $true  }
    @{ Brand = "Redragon";    Name = "GamingMouse - Macro folder";       Path = "$env:APPDATA\REDRAGON\GamingMouse\Macro";                                    IsMacro = $true  }
)

function Scan-ConfigFiles {
    $results = @()
    foreach ($entry in $ConfigEntries) {
        $exists = Test-Path $entry.Path
        $lastMod = $null; $size = $null; $isDir = $false
        if ($exists) {
            $item = Get-Item $entry.Path -ErrorAction SilentlyContinue
            if ($item) { $lastMod = $item.LastWriteTime; $isDir = $item.PSIsContainer; if (-not $isDir) { $size = $item.Length } }
        }
        $results += [PSCustomObject]@{ Brand = $entry.Brand; SoftwareName = $entry.Name; FilePath = $entry.Path; Exists = $exists; LastModified = $lastMod; IsMacro = $entry.IsMacro; IsDirectory = $isDir; SizeBytes = $size }
    }
    return $results
}

function Show-Separator { param([char]$ch = [char]0x2500, [int]$width = 72) Write-Host "  $(New-Object string ($ch, $width))" -ForegroundColor DarkGray }
function Show-Section { param([string]$title) Write-Host ""; Show-Separator; Write-Host "  " -NoNewline; Write-Host ([char]0x258C + " ") -ForegroundColor DarkMagenta -NoNewline; Write-Host $title.ToUpperInvariant() -ForegroundColor White; Show-Separator }
function Show-Field { param([string]$key, [string]$value, $col = "Gray") Write-Host "    $($key.PadRight(22))" -ForegroundColor DarkGray -NoNewline; Write-Host $value -ForegroundColor $col }
function Show-Good  { param([string]$text) Write-Host "  + $text" -ForegroundColor Green }
function Show-Alert { param([string]$text) Write-Host "  ! $text" -ForegroundColor Yellow }
function Show-Warn  { param([string]$text) Write-Host "  [!] $text" -ForegroundColor Red }

function Format-Bytes { param([long]$bytes) if ($bytes -ge 1MB) { return "{0:N1} MB" -f ($bytes / 1MB) } if ($bytes -ge 1KB) { return "{0:N1} KB" -f ($bytes / 1KB) } return "$bytes B" }

 $IgnorePaths = @("\Cache\", "\GPUCache\", "\Code Cache\", "\Session Storage\", "\IndexedDB\", "\Dictionaries\", "\Crashpad\", "\GrpcChann", "\CrashReports\", "\Service Worker\")
function Test-IsNoise { param([string]$Path) $upper = $Path.ToUpper(); foreach ($n in $IgnorePaths) { if ($upper.Contains($n.ToUpper())) { return $true } } return $false }

function Get-FileContentFast { param([string]$Path) try { return [System.IO.File]::ReadAllText($Path) } catch { return $null } }

# STRIPPED DOWN DIRECT MACRO FINDER - Looks directly for macro strings
function Find-ExplicitMacrosInFile {
    param([string]$FilePath)
    $txt = Get-FileContentFast -Path $FilePath
    if (-not $txt) { return $false }
    
    $low = $txt.ToLower()
    # Direct definitions of macros
    if ($low.Contains('"macro"') -or $low.Contains('"macros"') -or $low.Contains('"macromanager"') -or $low.Contains('"macrodata"')) { return $true }
    # G HUB specific
    if ($low.Contains('"assignments"') -and ($low.Contains('"delay"') -or $low.Contains('"script"'))) { return $true }
    # Razer / Generic specific
    if ($low.Contains('"sequence"') -and $low.Contains('"delay"')) { return $true }
    if ($low.Contains('"script"') -and $low.Contains('"delay"')) { return $true }
    
    return $false
}

# Scans directory and returns ONLY files that actually contain macro definitions
function Get-ExplicitMacroFiles {
    param([string]$DirectoryPath, [datetime]$Cutoff)
    $found = [System.Collections.Generic.List[PSCustomObject]]::new()
    $safeExts = @(".json", ".xml", ".txt", ".cfg", ".ini", ".lua", ".log", ".dat", ".db")
    
    try {
        $dirFiles = Get-ChildItem -Path $DirectoryPath -Recurse -File -ErrorAction SilentlyContinue | 
                    Where-Object { $_.LastWriteTime -ge $Cutoff -and $safeExts -contains $_.Extension.ToLower() -and -not (Test-IsNoise -Path $_.FullName) }
        
        foreach ($file in $dirFiles) {
            if (Find-ExplicitMacrosInFile -FilePath $file.FullName) {
                $found.Add([PSCustomObject]@{
                    Name = $file.Name
                    FullPath = $file.FullName
                    SizeBytes = $file.Length
                    LastModified = $file.LastWriteTime
                })
            }
        }
    } catch {}
    return $found
}

 $SoftwareProfiles = @(
    @{ Name="Logitech G HUB";           Paths=@("$env:LOCALAPPDATA\LGHUB","$env:APPDATA\LGHUB","$env:PROGRAMDATA\LGHUB","$env:APPDATA\LGHUB_BKP","C:\ProgramData\LGHUBData\applications"); Ext=@("*.json", "*.db");       Keys=@("macros","assignments","commands"); Proc=@("LGHUB","LGHUB Agent") }
    @{ Name="Logitech Gaming Software (Legacy)"; Paths=@("$env:APPDATA\Logitech\Logitech Gaming Software","$env:LOCALAPPDATA\Logitech"); Ext=@("*.json","*.xml"); Keys=@("macro","assignment","script"); Proc=@("LCore") }
    @{ Name="Razer Synapse";            Paths=@("$env:APPDATA\Razer\Synapse3","$env:LOCALAPPDATA\Razer\Synapse3","$env:PROGRAMDATA\Razer\Synapse3","$env:LOCALAPPDATA\Razer\RazerAppEngine"); Ext=@("*.json","*.xml","*.ldb","*.log", "*.db"); Keys=@("macro","Macro","action","Action","Script"); Proc=@("Razer Synapse","RazerCentralService","RazerStats") }
    @{ Name="SteelSeries GG";           Paths=@("$env:APPDATA\SteelSeries\SteelSeries GG","$env:LOCALAPPDATA\SteelSeries"); Ext=@("*.json", "*.db"); Keys=@("macro","action","binding"); Proc=@("SteelSeriesGG","SteelSeriesEngine") }
    @{ Name="Corsair iCUE";             Paths=@("$env:APPDATA\Corsair\CUE5","$env:APPDATA\Corsair\CUE4","$env:APPDATA\Corsair"); Ext=@("*.cueprofile","*.json", "*.db"); Keys=@("macro","action","command"); Proc=@("iCUE","CorsairService") }
    @{ Name="ASUS Armoury Crate";       Paths=@("$env:LOCALAPPDATA\ASUS\ArmouryCrate","$env:PROGRAMDATA\ASUS\ArmouryCrate"); Ext=@("*.json","*.xml"); Keys=@("macro","key","action"); Proc=@("ArmouryCrate") }
    @{ Name="Glorious CORE";            Paths=@("$env:LOCALAPPDATA\Glorious\Glorious CORE","$env:APPDATA\Glorious","$env:LOCALAPPDATA\Glorious"); Ext=@("*.json"); Keys=@("macro","key","assignment","sequence"); Proc=@("GloriousCORE") }
    @{ Name="Bloody / A4Tech";          Paths=@("$env:LOCALAPPDATA\Bloody","$env:PROGRAMDATA\Bloody"); Ext=@("*.dat","*.json","*.xml","*.bin"); Keys=@("macro","script","shot"); Proc=@("Bloody7","A4Tech") }
)

function Invoke-ContentScan {
    param([int]$RecentMins = 20)
    $cutoff = (Get-Date).AddMinutes(-$RecentMins)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($sw in $SoftwareProfiles) {
        foreach ($bp in $sw.Paths) {
            if (-not (Test-Path $bp)) { continue }
            foreach ($ext in $sw.Ext) {
                try {
                    $files = [System.IO.Directory]::GetFiles($bp, $ext, [System.IO.SearchOption]::AllDirectories)
                    foreach ($f in $files) {
                        if (Test-IsNoise -Path $f) { continue }
                        $item = [System.IO.FileInfo]::new($f)
                        if ($item.LastWriteTime -lt $cutoff) { continue }
                        
                        $hasMacro = Find-ExplicitMacrosInFile -FilePath $f
                        $results.Add([PSCustomObject]@{
                            Software = $sw.Name; FilePath = $f; LastModified = $item.LastWriteTime
                            SizeBytes = $item.Length; HasMacro = $hasMacro; Processes = $sw.Proc
                        })
                    }
                } catch {}
            }
        }
    }
    return $results.ToArray()
}

function Get-ProcessStatus {
    param([string[]]$Names)
    $running = [System.Collections.Generic.List[string]]::new()
    foreach ($n in $Names) { if (Get-Process -Name $n -ErrorAction SilentlyContinue) { $running.Add($n) } }
    return $running.ToArray()
}

function Invoke-PrefetchScan {
    param([datetime]$Cutoff)
    $results = [System.Collections.Generic.List[PSCustomObject]]::new()
    $prefetchDir = "C:\Windows\Prefetch"
    if (-not (Test-Path $prefetchDir)) { return $results.ToArray() }
    $execs = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
    foreach ($sw in $SoftwareProfiles) { foreach ($p in $sw.Proc) { if (-not [string]::IsNullOrEmpty($p)) { $execs.Add("$p.EXE") | Out-Null } } }
    foreach ($exe in $execs) {
        try {
            $pfFiles = Get-ChildItem -Path $prefetchDir -Filter "$exe-*.pf" -ErrorAction SilentlyContinue
            foreach ($pf in $pfFiles) { if ($pf.LastWriteTime -ge $Cutoff) { $results.Add([PSCustomObject]@{ Executable = $exe; FileName = $pf.Name; SizeBytes = $pf.Length; LastModified = $pf.LastWriteTime }) } }
        } catch {}
    }
    return $results.ToArray()
}

function Main {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $Host.UI.RawUI.WindowTitle = "MacroDetector v2.5"
    $cutoff = (Get-Date).AddMinutes(-20)
    $pcOwner = $env:USERNAME

    Write-Host @"
  ▄▄▄     ▄▄▄
   ███▄ ▄███
   ██ ▀█▀ ██               ▄
   ██     ██   ▄▀▀█▄ ▄███▀ ████▄▄███▄
   ██     ██   ▄█▀██ ██    ██   ██ ██
 ▀██▀     ▀██▄▄▀█▄██▄▀███▄▄█▀  ▄▀███▀
"@ -ForegroundColor Magenta

    Write-Host "  MacroDetector v2.5" -ForegroundColor Magenta -NoNewline
    Write-Host "  |  " -ForegroundColor DarkGray -NoNewline
    Write-Host "@imnicc.dll" -ForegroundColor Cyan
    Write-Host "  PC Owner: " -ForegroundColor DarkGray -NoNewline
    Write-Host "$pcOwner" -ForegroundColor White
    Write-Host ""

    # 1. HARDWARE
    $wmiMice = Get-ConnectedMice
    $regMice = Get-RegistryHistory
    $btMice  = Get-BluetoothDevices
    $allMice = New-Object System.Collections.Generic.List[PSCustomObject]
    foreach ($m in $wmiMice) { $allMice.Add($m) }
    foreach ($m in ($regMice + $btMice)) {
        $dupe = $false
        foreach ($x in $allMice) { if (-not [string]::IsNullOrEmpty($x.DeviceId) -and -not [string]::IsNullOrEmpty($m.DeviceId) -and $x.DeviceId.Equals($m.DeviceId, [StringComparison]::OrdinalIgnoreCase)) { $dupe = $true; break } }
        if (-not $dupe) { $allMice.Add($m) }
    }
    $recentMice = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($m in $allMice) { if ($m.IsConnected) { $recentMice.Add($m); continue } if ($m.ConnectedAt -and $m.ConnectedAt -ge $cutoff) { $recentMice.Add($m) } }

    if ($recentMice.Count -gt 0) {
        Write-Host "  Detected Mice (recent):" -ForegroundColor Cyan
        foreach ($m in $recentMice) {
            $tag = if ($m.IsConnected) { "connected" } else { "history" }
            Write-Host "    " -NoNewline
            if ($m.IsConnected) { Write-Host "$tag" -ForegroundColor Green -NoNewline } else { Write-Host "$tag" -ForegroundColor DarkGray -NoNewline }
            Write-Host "  " -NoNewline; Write-Host "$($m.Name)" -ForegroundColor White -NoNewline
            if ($m.Brand -ne "Unknown") { Write-Host "  [$($m.Brand)]" -ForegroundColor DarkMagenta -NoNewline }
            Write-Host ""
        }
    }

    # 2. SOFTWARE
    $installed = Scan-InstalledSoftware
    if ($installed.Count -gt 0) {
        Write-Host "`n  Installed Software:" -ForegroundColor Cyan
        foreach ($s in ($installed | Sort-Object Brand)) {
            Write-Host "    " -NoNewline; Write-Host "$($s.SoftwareName)" -ForegroundColor White -NoNewline
            Write-Host "  [$($s.Brand)]" -ForegroundColor DarkMagenta -NoNewline
            if ($s.Version) { Write-Host " v$($s.Version)" -ForegroundColor DarkGray -NoNewline }
            Write-Host ""
        }
    }

    # 3. EXACT MACRO FILE SCANNER (The main feature requested)
    Show-Section "Macro File Detection (Last 20 Mins)"
    $scanResults = Invoke-ContentScan -RecentMins 20
    $macroFiles = $scanResults | Where-Object { $_.HasMacro }
    $otherFiles = $scanResults | Where-Object { -not $_.HasMacro }

    if ($macroFiles.Count -gt 0) {
        foreach ($f in ($macroFiles | Sort-Object LastModified -Descending)) {
            Write-Host "    [!] MACROS DETECTED & MODIFIED IN: " -NoNewline -ForegroundColor Red -BackgroundColor DarkRed
            Write-Host "$($f.Software)" -ForegroundColor Yellow
            Write-Host "        FILE: " -NoNewline -ForegroundColor White
            Write-Host "$($f.FilePath)" -ForegroundColor Yellow
            Write-Host "        MODIFIED: " -NoNewline -ForegroundColor DarkGray
            Write-Host "$($f.LastModified)" -ForegroundColor White
            Write-Host "        SIZE: " -NoNewline -ForegroundColor DarkGray
            Write-Host "$(Format-Bytes -bytes $f.SizeBytes)" -ForegroundColor White
            
            $procs = Get-ProcessStatus -Names $f.Processes
            if ($procs.Count -gt 0) {
                Write-Host "        STATUS: " -NoNewline -ForegroundColor DarkGray
                Write-Host "SOFTWARE IS ACTIVELY RUNNING ($($procs -join ', '))" -ForegroundColor Red -BackgroundColor DarkRed
            }
            Write-Host ""
        }
    } else {
        Write-Host "    No macro strings detected in recently modified files." -ForegroundColor DarkGray
    }

    # 4. CONFIG MAP DEEP SCAN (If a folder was modified, find the EXACT file inside with macros)
    $configs = Scan-ConfigFiles
    $foundConfigs = $configs | Where-Object { $_.Exists -and $_.LastModified -and $_.LastModified -ge $cutoff -and $_.IsMacro }
    
    if ($foundConfigs.Count -gt 0) {
        Show-Section "Deep Directory Trace (Last 20 Mins)"
        
        foreach ($c in $foundConfigs) {
            Write-Host "    Scanning: " -NoNewline -ForegroundColor DarkGray
            Write-Host "$($c.Brand) - $($c.SoftwareName)" -ForegroundColor White
            
            if ($c.IsDirectory) {
                $exactFiles = Get-ExplicitMacroFiles -DirectoryPath $c.FilePath -Cutoff $cutoff
                
                if ($exactFiles.Count -gt 0) {
                    foreach ($mf in $exactFiles) {
                        Write-Host "        [!] MACROS MODIFIED IN FILE: " -NoNewline -ForegroundColor Red
                        Write-Host "$($mf.Name)" -ForegroundColor Yellow
                        Write-Host "            FULL PATH: " -NoNewline -ForegroundColor DarkGray
                        Write-Host "$($mf.FullPath)" -ForegroundColor Yellow
                        Write-Host "            MODIFIED: " -NoNewline -ForegroundColor DarkGray
                        Write-Host "$($mf.LastModified)" -ForegroundColor White
                    }
                } else {
                    Write-Host "        -> Folder was modified, but exact macro file not changed in <20m." -ForegroundColor DarkGray
                }
            } else {
                # It's a single file that was modified
                if (Find-ExplicitMacrosInFile -FilePath $c.FilePath) {
                    Write-Host "        [!] MACROS MODIFIED IN FILE: " -NoNewline -ForegroundColor Red
                    Write-Host "$(Split-Path $c.FilePath -Leaf)" -ForegroundColor Yellow
                    Write-Host "            FULL PATH: " -NoNewline -ForegroundColor DarkGray
                    Write-Host "$($c.FilePath)" -ForegroundColor Yellow
                    Write-Host "            MODIFIED: " -NoNewline -ForegroundColor DarkGray
                    Write-Host "$($c.LastModified)" -ForegroundColor White
                } else {
                    Write-Host "        -> File was modified, but contains no macro strings." -ForegroundColor DarkGray
                }
            }
            Write-Host ""
        }
    }

    # 5. RUNNING PROCESSES
    Show-Section "Running Macro Software Processes"
    $allProcNames = @()
    foreach ($sw in $SoftwareProfiles) { foreach ($p in $sw.Proc) { $allProcNames += $p } }
    $allProcNames = $allProcNames | Sort-Object -Unique
    $foundRunning = $false
    foreach ($pn in $allProcNames) {
        $procs = Get-Process -Name $pn -ErrorAction SilentlyContinue
        if ($procs) {
            $foundRunning = $true
            foreach ($p in $procs) {
                Write-Host "    [RUNNING] " -NoNewline -ForegroundColor Red -BackgroundColor DarkRed
                Write-Host "$($p.ProcessName)" -ForegroundColor White -NoNewline
                Write-Host "  PID: $($p.Id)  Memory: $(Format-Bytes -bytes $p.WorkingSet64)" -ForegroundColor DarkGray
            }
        }
    }
    if (-not $foundRunning) { Write-Host "    No macro software processes detected." -ForegroundColor DarkGray }

    # 6. PREFETCH
    Show-Section "Prefetch Artifacts (Last 20 Mins)"
    $prefetchResults = Invoke-PrefetchScan -Cutoff $cutoff
    if ($prefetchResults.Count -gt 0) {
        foreach ($pf in ($prefetchResults | Sort-Object LastModified -Descending)) {
            Write-Host "    [PREFETCH] " -NoNewline -ForegroundColor Yellow
            Write-Host "$($pf.FileName)" -ForegroundColor White
            Write-Host "        Modified: $($pf.LastModified) | Size: $(Format-Bytes -bytes $pf.SizeBytes)" -ForegroundColor DarkGray
        }
    } else { Write-Host "    No macro software prefetch artifacts modified in the last 20 minutes." -ForegroundColor DarkGray }

    # 7. SUMMARY
    Show-Section "Summary"
    $runningCount = 0
    foreach ($pn in $allProcNames) { $runningCount += (Get-Process -Name $pn -ErrorAction SilentlyContinue).Count }

    Show-Field "Mice detected"       "$($recentMice.Count) recent" "White"
    Show-Field "Software installed"  "$($installed.Count) packages" "White"
    Show-Field "Macro files modified" "$($macroFiles.Count)"          $(if ($macroFiles.Count -gt 0) { "Red" } else { "Green" })
    Show-Field "Running processes"   "$runningCount"                 $(if ($runningCount -gt 0) { "Red" } else { "Green" })
    Show-Field "Prefetch artifacts"  "$($prefetchResults.Count)"     $(if ($prefetchResults.Count -gt 0) { "Yellow" } else { "Green" })

    Write-Host ""
    if ($macroFiles.Count -gt 0 -or $runningCount -gt 0) {
        Show-Warn "Macro software activity detected on this system."
    } elseif ($foundConfigs.Count -gt 0) {
        Show-Alert "Macro software traces found but no direct macro strings modified in <20m."
    } else {
        Show-Good "No macro software traces detected."
    }

    Write-Host ""
    Show-Separator
    Write-Host ""
}

Main
