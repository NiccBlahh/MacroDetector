<#
.SYNOPSIS
    MacroDetector
.DESCRIPTION
    A comprehensive forensic mouse device and macro software configuration analysis tool.
.NOTES
    Compatible with Windows 10 and Windows 11. Requires Administrative privileges for full registry analysis.
    v2.0 - Expanded Razer LocalAppData detection, BLE/Bluetooth improvements, richer config coverage.
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

# --- WINDOWS FILE TIME CONVERTER ---
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

# --- CONNECTION TYPE GUESSER ---
function Guess-ConnectionType {
    param([string]$deviceIdStr)
    if ([string]::IsNullOrEmpty($deviceIdStr)) { return "Unknown" }
    $p = $deviceIdStr.ToUpper()
    if ($p.StartsWith("BTH") -or $p.Contains("BTHLE")) { return "Bluetooth" }
    if ($p.StartsWith("USB") -or $p.Contains("HID"))   { return "USB" }
    return "Unknown"
}

# --- 1. HARDWARE DETECTORS ---
function Get-ConnectedMice {
    $results = @()
    try {
        $wmiDevices = Get-CimInstance -Query "SELECT * FROM Win32_PointingDevice" -ErrorAction SilentlyContinue
        foreach ($obj in $wmiDevices) {
            $name = if ($obj.Name)         { $obj.Name.Trim() }         else { "" }
            $mfr  = if ($obj.Manufacturer) { $obj.Manufacturer.Trim() } else { "" }
            $id   = if ($obj.PNPDeviceID)  { $obj.PNPDeviceID }         else { "" }

            $results += [PSCustomObject]@{
                Name           = $name
                Manufacturer   = $mfr
                DeviceId       = $id
                IsConnected    = $true
                Brand          = Detect-Brand -text "$name $mfr $id"
                ConnectionType = Guess-ConnectionType -deviceIdStr $id
                ConnectedAt    = Get-InstallDate -regPath "SYSTEM\CurrentControlSet\Enum\$id"
                DisconnectedAt = $null
                Source         = "WMI"
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
                Name           = $finalName
                Manufacturer   = ""
                DeviceId       = $fullId
                Brand          = $brand
                ConnectionType = if ($regPath.Contains("HID")) { "USB HID" } else { "USB" }
                IsConnected    = $false
                ConnectedAt    = Get-InstallDate -regPath $fullId
                DisconnectedAt = $null
                Source         = "Registry"
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

    # Classic Bluetooth
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
            if ($lastSeenRaw) {
                try {
                    $ft = [BitConverter]::ToInt64($lastSeenRaw, 0)
                    $lastSeen = [DateTime]::FromFileTimeUtc($ft).ToLocalTime()
                } catch {}
            }
            $devSubKey.Close()

            if ($brand -eq "Unknown") { continue }

            $results += [PSCustomObject]@{
                Name           = $name
                Manufacturer   = ""
                DeviceId       = $key
                Brand          = $brand
                ConnectionType = "Bluetooth"
                IsConnected    = $false
                ConnectedAt    = $lastSeen
                DisconnectedAt = $null
                Source         = "Bluetooth Registry"
            }
        }
        $btKey.Close()
    }

    # Bluetooth LE
    $bleKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Enum\BTHLE")
    if ($bleKey) {
        foreach ($cls in $bleKey.GetSubKeyNames()) {
            $clsSubKey = $bleKey.OpenSubKey($cls)
            if (-not $clsSubKey) { continue }

            foreach ($inst in $clsSubKey.GetSubKeyNames()) {
                $instSubKey = $clsSubKey.OpenSubKey($inst)
                if (-not $instSubKey) { continue }

                $friendly = if ($instSubKey.GetValue("FriendlyName")) { $instSubKey.GetValue("FriendlyName").ToString() } else { "" }
                $brand    = Detect-Brand -text $friendly
                $instSubKey.Close()

                if ($brand -eq "Unknown") { continue }

                $results += [PSCustomObject]@{
                    Name           = $friendly
                    Manufacturer   = ""
                    DeviceId       = "BTHLE\$cls\$inst"
                    Brand          = $brand
                    ConnectionType = "Bluetooth LE"
                    IsConnected    = $false
                    ConnectedAt    = $null
                    DisconnectedAt = $null
                    Source         = "BLE Registry"
                }
            }
            $clsSubKey.Close()
        }
        $bleKey.Close()
    }

    # Bluetooth ENUM (additional scan path)
    $btEnumKey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Enum\BTH")
    if ($btEnumKey) {
        foreach ($cls in $btEnumKey.GetSubKeyNames()) {
            $clsSubKey = $btEnumKey.OpenSubKey($cls)
            if (-not $clsSubKey) { continue }

            foreach ($inst in $clsSubKey.GetSubKeyNames()) {
                $instSubKey = $clsSubKey.OpenSubKey($inst)
                if (-not $instSubKey) { continue }

                $friendly = if ($instSubKey.GetValue("FriendlyName")) { $instSubKey.GetValue("FriendlyName").ToString() } else { "" }
                $desc     = if ($instSubKey.GetValue("DeviceDesc"))   { $instSubKey.GetValue("DeviceDesc").ToString()   } else { "" }
                $brand    = Detect-Brand -text "$friendly $desc $cls"
                $instSubKey.Close()

                if ($brand -eq "Unknown") { continue }

                $finalName = if (-not [string]::IsNullOrEmpty($friendly)) { $friendly } else { $desc }

                $results += [PSCustomObject]@{
                    Name           = $finalName
                    Manufacturer   = ""
                    DeviceId       = "BTH\$cls\$inst"
                    Brand          = $brand
                    ConnectionType = "Bluetooth"
                    IsConnected    = $false
                    ConnectedAt    = $null
                    DisconnectedAt = $null
                    Source         = "BTH Registry"
                }
            }
            $clsSubKey.Close()
        }
        $btEnumKey.Close()
    }

    return $results
}

# --- 2. SOFTWARE REGISTRY SCANNER ---
$KnownSoftware = @(
    @{ Keyword = "logi options+";             Brand = "Logitech";     Name = "Logitech Options+" }
    @{ Keyword = "logi options";              Brand = "Logitech";     Name = "Logitech Options" }
    @{ Keyword = "lghub";                     Brand = "Logitech";     Name = "Logitech G HUB" }
    @{ Keyword = "logitech g hub";            Brand = "Logitech";     Name = "Logitech G HUB" }
    @{ Keyword = "logitech gaming software";  Brand = "Logitech";     Name = "Logitech Gaming Software" }
    @{ Keyword = "logitech unifying";         Brand = "Logitech";     Name = "Logitech Unifying Software" }
    @{ Keyword = "logitech bolt";             Brand = "Logitech";     Name = "Logitech Bolt Receiver" }
    @{ Keyword = "razer synapse";             Brand = "Razer";        Name = "Razer Synapse" }
    @{ Keyword = "razer cortex";              Brand = "Razer";        Name = "Razer Cortex" }
    @{ Keyword = "razer central";             Brand = "Razer";        Name = "Razer Central" }
    @{ Keyword = "steelseries gg";            Brand = "SteelSeries";  Name = "SteelSeries GG" }
    @{ Keyword = "steelseries engine";        Brand = "SteelSeries";  Name = "SteelSeries Engine" }
    @{ Keyword = "steelseries";               Brand = "SteelSeries";  Name = "SteelSeries Software" }
    @{ Keyword = "icue";                      Brand = "Corsair";      Name = "Corsair iCUE" }
    @{ Keyword = "corsair utility engine";    Brand = "Corsair";      Name = "Corsair iCUE" }
    @{ Keyword = "corsair";                   Brand = "Corsair";      Name = "Corsair Software" }
    @{ Keyword = "roccat swarm";              Brand = "ROCCAT";       Name = "ROCCAT Swarm" }
    @{ Keyword = "roccat connect";            Brand = "ROCCAT";       Name = "ROCCAT Connect" }
    @{ Keyword = "roccat";                    Brand = "ROCCAT";       Name = "ROCCAT Software" }
    @{ Keyword = "glorious core";             Brand = "Glorious";     Name = "Glorious CORE" }
    @{ Keyword = "glorious";                  Brand = "Glorious";     Name = "Glorious Software" }
    @{ Keyword = "attack shark";              Brand = "Attack Shark"; Name = "Attack Shark Software" }
    @{ Keyword = "attackshark";               Brand = "Attack Shark"; Name = "Attack Shark Software" }
    @{ Keyword = "armoury crate";             Brand = "ASUS";         Name = "ASUS Armoury Crate" }
    @{ Keyword = "asus armoury";              Brand = "ASUS";         Name = "ASUS Armoury Crate" }
    @{ Keyword = "msi dragon center";         Brand = "MSI";          Name = "MSI Dragon Center" }
    @{ Keyword = "msi center";                Brand = "MSI";          Name = "MSI Center" }
    @{ Keyword = "hyperx ngenuity";           Brand = "HyperX";       Name = "HyperX NGENUITY" }
    @{ Keyword = "hp omen gaming hub";        Brand = "HyperX";       Name = "HP OMEN Gaming Hub" }
    @{ Keyword = "pulsar";                    Brand = "Pulsar";       Name = "Pulsar Software" }
    @{ Keyword = "finalmouse";                Brand = "Finalmouse";   Name = "Finalmouse Software" }
    @{ Keyword = "zowie";                     Brand = "ZOWIE";        Name = "ZOWIE Mouse Config" }
    @{ Keyword = "endgame gear";              Brand = "Endgame Gear"; Name = "Endgame Gear Software" }
    @{ Keyword = "bloody";                    Brand = "Bloody";       Name = "Bloody Software" }
    @{ Keyword = "a4tech";                    Brand = "Bloody";       Name = "A4Tech Software" }
    @{ Keyword = "cougar uix";                Brand = "Cougar";       Name = "Cougar UIX" }
    @{ Keyword = "cougar";                    Brand = "Cougar";       Name = "Cougar Software" }
    @{ Keyword = "alienware command center";  Brand = "Alienware";    Name = "Alienware Command Center" }
    @{ Keyword = "dell peripheral manager";   Brand = "Alienware";    Name = "Dell Peripheral Manager" }
    @{ Keyword = "turtle beach";              Brand = "Turtle Beach"; Name = "Turtle Beach Software" }
    @{ Keyword = "kensington works";          Brand = "Kensington";   Name = "Kensington Works" }
    @{ Keyword = "kensingtontrackerworks";    Brand = "Kensington";   Name = "Kensington Works" }
    @{ Keyword = "redragon";                  Brand = "Redragon";     Name = "Redragon Software" }
    @{ Keyword = "xtrfy";                     Brand = "Xtrfy";        Name = "Xtrfy Software" }
    @{ Keyword = "fnatic";                    Brand = "Fnatic";       Name = "Fnatic Bolt" }
    @{ Keyword = "vaxee";                     Brand = "Vaxee";        Name = "Vaxee Software" }
    @{ Keyword = "ninjutso";                  Brand = "Ninjutso";     Name = "Ninjutso Software" }
    @{ Keyword = "fantech";                   Brand = "Fantech";      Name = "Fantech Software" }
    @{ Keyword = "marsgaming";                Brand = "Marsgaming";   Name = "Marsgaming MMGX" }
    @{ Keyword = "mars gaming";               Brand = "Marsgaming";   Name = "Marsgaming MMGX" }
    @{ Keyword = "motospeed";                 Brand = "Motospeed";    Name = "Motospeed Gaming Mouse" }
    @{ Keyword = "marvo";                     Brand = "Marvo";        Name = "Marvo Software" }
    @{ Keyword = "coolermaster";              Brand = "CoolerMaster"; Name = "CoolerMaster MasterPlus" }
    @{ Keyword = "cooler master";             Brand = "CoolerMaster"; Name = "CoolerMaster MasterPlus" }
    @{ Keyword = "ajazz";                     Brand = "Ajazz";        Name = "Ajazz Software" }
    @{ Keyword = "blackweb";                  Brand = "Blackweb";     Name = "Blackweb Gaming" }
    @{ Keyword = "spc gear";                  Brand = "SPC Gear";     Name = "SPC Gear LIX" }
    @{ Keyword = "ayax";                      Brand = "Ayax";         Name = "AYAX Gaming Mouse" }
    @{ Keyword = "noganet";                   Brand = "Noganet";      Name = "Noganet Ayax" }
)

function Scan-InstalledSoftware {
    $results = @()
    $seen    = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)

    $hives = @(
        @{ Root = "LocalMachine"; Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" }
        @{ Root = "LocalMachine"; Path = "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall" }
        @{ Root = "CurrentUser";  Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" }
    )

    foreach ($hive in $hives) {
        $regRoot    = if ($hive.Root -eq "LocalMachine") { [Microsoft.Win32.Registry]::LocalMachine } else { [Microsoft.Win32.Registry]::CurrentUser }
        $baseSubKey = $regRoot.OpenSubKey($hive.Path)
        if (-not $baseSubKey) { continue }

        foreach ($appName in $baseSubKey.GetSubKeyNames()) {
            $appSubKey = $baseSubKey.OpenSubKey($appName)
            if (-not $appSubKey) { continue }

            $displayRaw = $appSubKey.GetValue("DisplayName")
            if (-not $displayRaw) { $appSubKey.Close(); continue }
            $display = $displayRaw.ToString()
            $lower   = $display.ToLowerInvariant()

            foreach ($known in $KnownSoftware) {
                if (-not $lower.Contains($known.Keyword)) { continue }

                $dedupeKey = "$($known.Brand)|$($known.Name)"
                if (-not $seen.Add($dedupeKey)) { continue }

                $version     = if ($appSubKey.GetValue("DisplayVersion"))  { $appSubKey.GetValue("DisplayVersion").ToString()                  } else { "" }
                $location    = if ($appSubKey.GetValue("InstallLocation")) { $appSubKey.GetValue("InstallLocation").ToString().TrimEnd('\')    } else { "" }
                $dateStr     = if ($appSubKey.GetValue("InstallDate"))     { $appSubKey.GetValue("InstallDate").ToString()                     } else { "" }

                $installDate = $null
                if ($dateStr.Length -eq 8) {
                    try {
                        $installDate = [DateTime]::new([int]$dateStr.Substring(0,4), [int]$dateStr.Substring(4,2), [int]$dateStr.Substring(6,2))
                    } catch {}
                }

                $results += [PSCustomObject]@{
                    Brand           = $known.Brand
                    SoftwareName    = $known.Name
                    Version         = $version
                    InstallLocation = $location
                    InstallDate     = $installDate
                    RegistryKey     = "$($hive.Path)\$appName"
                }
                break
            }
            $appSubKey.Close()
        }
        $baseSubKey.Close()
    }
    return $results
}

# --- 3. CONFIG FILE ENTRIES ---
$ConfigEntries = @(

    # -- LOGITECH --
    @{ Brand = "Logitech";    Name = "G HUB - settings.db";       Path = "$env:LOCALAPPDATA\LGHUB\settings.db";                                          IsMacro = $true  }
    @{ Brand = "Logitech";    Name = "G HUB - Macros folder";      Path = "$env:LOCALAPPDATA\LGHUB";                                                      IsMacro = $true  }
    @{ Brand = "Logitech";    Name = "Options+ - options_plus.db"; Path = "$env:LOCALAPPDATA\Logi\LogiOptionsPlus\data\options_plus.db";                   IsMacro = $false }
    @{ Brand = "Logitech";    Name = "Gaming Software - settings"; Path = "$env:LOCALAPPDATA\Logitech\Logitech Gaming Software\settings.json";             IsMacro = $true  }

    # -- RAZER - ROAMING APPDATA --
    @{ Brand = "Razer";       Name = "Synapse 3 - Settings";       Path = "$env:APPDATA\Razer\Synapse3\Settings";                                         IsMacro = $true  }
    @{ Brand = "Razer";       Name = "Synapse 3 - MacroData";      Path = "$env:APPDATA\Razer\Synapse3\MacroData";                                        IsMacro = $true  }
    @{ Brand = "Razer";       Name = "Synapse 3 - StaticDevConf";  Path = "$env:APPDATA\Razer\Synapse3\StaticDeviceConf.json";                            IsMacro = $false }
    @{ Brand = "Razer";       Name = "Synapse 3 - Accounts";       Path = "$env:APPDATA\Razer\Synapse3\Accounts";                                         IsMacro = $true  }
    @{ Brand = "Razer";       Name = "Razer Central - Accounts";   Path = "$env:APPDATA\Razer\Razer Central\Accounts";                                    IsMacro = $false }

    # -- RAZER - LOCAL APPDATA (primary new detections) --
    @{ Brand = "Razer";       Name = "Razer - LocalAppData root";  Path = "$env:LOCALAPPDATA\Razer";                                                      IsMacro = $false }
    @{ Brand = "Razer";       Name = "RazerAppEngine - root";      Path = "$env:LOCALAPPDATA\Razer\RazerAppEngine";                                       IsMacro = $false }
    @{ Brand = "Razer";       Name = "RazerAppEngine - Cache";     Path = "$env:LOCALAPPDATA\Razer\RazerAppEngine\Cache";                                  IsMacro = $false }
    @{ Brand = "Razer";       Name = "RazerAppEngine - User Data"; Path = "$env:LOCALAPPDATA\Razer\RazerAppEngine\User Data";                             IsMacro = $true  }
    @{ Brand = "Razer";       Name = "RazerAppEngine - Local State";Path = "$env:LOCALAPPDATA\Razer\RazerAppEngine\User Data\Local State";                IsMacro = $false }
    @{ Brand = "Razer";       Name = "Razer Cortex - LocalAppData";Path = "$env:LOCALAPPDATA\Razer\Razer Cortex";                                         IsMacro = $false }
    @{ Brand = "Razer";       Name = "Razer Cortex - DB";          Path = "$env:LOCALAPPDATA\Razer\Razer Cortex\data.db";                                 IsMacro = $false }
    @{ Brand = "Razer";       Name = "Razer Cortex - config.json"; Path = "$env:LOCALAPPDATA\Razer\Razer Cortex\config.json";                             IsMacro = $false }
    @{ Brand = "Razer";       Name = "Razer Central - LocalAppData";Path = "$env:LOCALAPPDATA\Razer\Razer Central";                                       IsMacro = $false }
    @{ Brand = "Razer";       Name = "Razer Central - settings.db";Path = "$env:LOCALAPPDATA\Razer\Razer Central\settings.db";                            IsMacro = $false }
    @{ Brand = "Razer";       Name = "Synapse 3 - Accounts";       Path = "$env:LOCALAPPDATA\Razer\Synapse3\Accounts";                                    IsMacro = $true  }
    @{ Brand = "Razer";       Name = "Synapse 3 - Cloud Cache";    Path = "$env:LOCALAPPDATA\Razer\Synapse3\Data";                                        IsMacro = $true  }
    @{ Brand = "Razer";       Name = "Synapse 3 - Local DB";       Path = "$env:LOCALAPPDATA\Razer\Synapse3\Devices.db";                                  IsMacro = $true  }
    @{ Brand = "Razer";       Name = "Synapse 3 - UpdateService";  Path = "$env:LOCALAPPDATA\Razer\UpdateService";                                        IsMacro = $false }
    @{ Brand = "Razer";       Name = "Synapse 3 - Installer";      Path = "$env:LOCALAPPDATA\Razer\Installer";                                            IsMacro = $false }
    @{ Brand = "Razer";       Name = "RazerAppEngine - Logs";      Path = "$env:LOCALAPPDATA\Razer\RazerAppEngine\User Data\Logs";                         IsMacro = $true  }
    @{ Brand = "Razer";       Name = "RazerAppEngine - Products";  Path = "$env:LOCALAPPDATA\Razer\RazerAppEngine\User Data\Products";                     IsMacro = $true  }

    # -- RAZER - PROGRAMDATA --
    @{ Brand = "Razer";       Name = "Synapse 3 - Service Log";    Path = "$env:PROGRAMDATA\Razer\Synapse3\Log\SynapseService.log";                       IsMacro = $true  }
    @{ Brand = "Razer";       Name = "Synapse 3 - ProgramData";    Path = "$env:PROGRAMDATA\Razer\Synapse3";                                              IsMacro = $true  }
    @{ Brand = "Razer";       Name = "Razer Central - ProgramData";Path = "$env:PROGRAMDATA\Razer\Razer Central";                                         IsMacro = $true  }

    # -- STEELSERIES --
    @{ Brand = "SteelSeries"; Name = "GG - gg.db";                 Path = "$env:APPDATA\SteelSeries\GG\db\gg.db";                                        IsMacro = $true  }

    # -- CORSAIR --
    @{ Brand = "Corsair";     Name = "iCUE 5 - config.db";         Path = "$env:APPDATA\Corsair\CUE5\config.db";                                         IsMacro = $true  }
    @{ Brand = "Corsair";     Name = "iCUE 4 - config.db";         Path = "$env:APPDATA\Corsair\CUE4\config.db";                                         IsMacro = $true  }
    @{ Brand = "Corsair";     Name = "iCUE - Config.cuecfg";       Path = "$env:APPDATA\corsair\CUE\Config.cuecfg";                                       IsMacro = $true  }

    # -- ROCCAT --
    @{ Brand = "ROCCAT";      Name = "Swarm - settings.xml";        Path = "$env:APPDATA\ROCCAT\ROCCAT Swarm\settings.xml";                               IsMacro = $false }
    @{ Brand = "ROCCAT";      Name = "Swarm - macro folder";        Path = "$env:APPDATA\ROCCAT\SWARM\macro";                                             IsMacro = $true  }
    @{ Brand = "ROCCAT";      Name = "Swarm - preset macros";       Path = "$env:APPDATA\ROCCAT\SWARM\preset_macro";                                      IsMacro = $true  }
    @{ Brand = "ROCCAT";      Name = "Connect - settings.db";       Path = "$env:APPDATA\ROCCAT\ROCCAT Connect\settings.db";                              IsMacro = $false }

    # -- GLORIOUS --
    @{ Brand = "Glorious";    Name = "CORE - config.json";          Path = "$env:APPDATA\glorious-core-app\config.json";                                  IsMacro = $false }
    @{ Brand = "Glorious";    Name = "CORE - settings.db";          Path = "$env:LOCALAPPDATA\GloriousCore\settings.db";                                  IsMacro = $true  }
    @{ Brand = "Glorious";    Name = "BYCOMBO-2 - Macros";          Path = "$env:APPDATA\BYCOMBO-2\Mac";                                                  IsMacro = $true  }

    # -- ATTACK SHARK --
    @{ Brand = "Attack Shark"; Name = "Software - config.json";     Path = "$env:APPDATA\AttackShark\config.json";                                        IsMacro = $false }
    @{ Brand = "Attack Shark"; Name = "Software - settings.db";     Path = "$env:LOCALAPPDATA\AttackShark\settings.db";                                   IsMacro = $true  }
    @{ Brand = "Attack Shark"; Name = "ProgramData config";         Path = "$env:PROGRAMDATA\AttackShark\config.json";                                    IsMacro = $false }

    # -- ASUS --
    @{ Brand = "ASUS";        Name = "Armoury Crate - settings.db"; Path = "$env:LOCALAPPDATA\ASUS\ArmouryCrate\settings.db";                            IsMacro = $true  }
    @{ Brand = "ASUS";        Name = "ROG Armoury - Macros";        Path = "$env:USERPROFILE\Documents\ASUS\ROG\ROG Armoury\common";                     IsMacro = $true  }

    # -- MSI --
    @{ Brand = "MSI";         Name = "Dragon Center - settings";    Path = "$env:APPDATA\MSI\Dragon Center\settings.json";                               IsMacro = $false }
    @{ Brand = "MSI";         Name = "MSI Center - settings.db";    Path = "$env:APPDATA\MSI\MSI Center\settings.db";                                    IsMacro = $true  }

    # -- HYPERX --
    @{ Brand = "HyperX";      Name = "NGENUITY - settings.db";      Path = "$env:APPDATA\HyperX\NGENUITY\settings.db";                                   IsMacro = $true  }
    @{ Brand = "HyperX";      Name = "NGENUITY - Store DB";         Path = "$env:LOCALAPPDATA\Packages\33C30B79.HyperXNGenuity_0a78dr3hq0pvt\LocalState\Settings\setting.db"; IsMacro = $true }

    # -- PULSAR --
    @{ Brand = "Pulsar";      Name = "Fusion - config.json";        Path = "$env:APPDATA\Pulsar\config.json";                                            IsMacro = $false }

    # -- FINALMOUSE --
    @{ Brand = "Finalmouse";  Name = "Software - settings.db";      Path = "$env:APPDATA\Finalmouse\settings.db";                                        IsMacro = $false }

    # -- ZOWIE --
    @{ Brand = "ZOWIE";       Name = "Mouse Config - config.json";  Path = "$env:APPDATA\ZOWIE\config.json";                                             IsMacro = $false }

    # -- ENDGAME GEAR --
    @{ Brand = "Endgame Gear"; Name = "Software - settings.db";     Path = "$env:APPDATA\Endgame Gear\settings.db";                                      IsMacro = $false }

    # -- BLOODY --
    @{ Brand = "Bloody";      Name = "Bloody7 - GunLib Macros";     Path = "C:\Program Files (x86)\Bloody7\Bloody7\Data\Mouse\English\ScriptsMacros\GunLib"; IsMacro = $true }
    @{ Brand = "Bloody";      Name = "Software - config.json";      Path = "$env:APPDATA\Bloody\config.json";                                            IsMacro = $false }
    @{ Brand = "Bloody";      Name = "Software - settings.db";      Path = "$env:LOCALAPPDATA\Bloody\settings.db";                                       IsMacro = $true  }

    # -- ALIENWARE --
    @{ Brand = "Alienware";   Name = "CC - fxmetadata";             Path = "C:\ProgramData\Alienware\AlienWare Command Center\fxmetadata";               IsMacro = $false }
    @{ Brand = "Alienware";   Name = "CC - config.json";            Path = "$env:PROGRAMDATA\Alienware\AWCCService\config.json";                         IsMacro = $false }

    # -- KENSINGTON --
    @{ Brand = "Kensington";  Name = "Works - settings.db";         Path = "$env:APPDATA\Kensington\KensingtonWorks\settings.db";                        IsMacro = $false }

    # -- COUGAR --
    @{ Brand = "Cougar";      Name = "UIX - config.json";           Path = "$env:APPDATA\Cougar\UIX\config.json";                                        IsMacro = $false }

    # -- REDRAGON --
    @{ Brand = "Redragon";    Name = "GamingMouse - Macro folder";  Path = "$env:APPDATA\REDRAGON\GamingMouse\Macro";                                    IsMacro = $true  }
    @{ Brand = "Redragon";    Name = "GamingMouse - config.ini";    Path = "$env:APPDATA\REDRAGON\GamingMouse\config.ini";                               IsMacro = $false }
    @{ Brand = "Redragon";    Name = "Software - config.json";      Path = "$env:APPDATA\Redragon\config.json";                                          IsMacro = $false }

    # -- XENON200 --
    @{ Brand = "Xenon200";    Name = "Configs folder";              Path = "C:\Program Files (x86)\Xenon200\configs";                                    IsMacro = $false }

    # -- T16 / BYCOMBO --
    @{ Brand = "T16";         Name = "BY-COMBO - curid.dct";        Path = "$env:LOCALAPPDATA\BY-COMBO\curid.dct";                                       IsMacro = $false }
    @{ Brand = "T16";         Name = "BY-COMBO - pro.dct";          Path = "$env:LOCALAPPDATA\BY-COMBO\pro.dct";                                         IsMacro = $false }

    # -- MARVO --
    @{ Brand = "Marvo";       Name = "BY-8801 - curid.dct";         Path = "$env:LOCALAPPDATA\BY-8801-GM917-v108\curid.dct";                             IsMacro = $false }
    @{ Brand = "Marvo";       Name = "BY-8801 - pro.dct";           Path = "$env:LOCALAPPDATA\BY-8801-GM917-v108\pro.dct";                               IsMacro = $false }

    # -- AJAZZ --
    @{ Brand = "Ajazz";       Name = "BYCOMBO-2 - Macros (Local)";  Path = "$env:LOCALAPPDATA\BYCOMBO-2\Mac";                                            IsMacro = $true  }
    @{ Brand = "Ajazz";       Name = "BYCOMBO-2 - Macros (Roam)";   Path = "$env:APPDATA\BYCOMBO-2\Mac";                                                 IsMacro = $true  }

    # -- KROM KOLT --
    @{ Brand = "Krom Kolt";   Name = "KROM KOLT - sequence.dat";    Path = "$env:LOCALAPPDATA\VirtualStore\Program Files (x86)\KROM KOLT\Config\sequence.dat"; IsMacro = $true }

    # -- BLACKWEB --
    @{ Brand = "Blackweb";    Name = "Gaming AP - config";          Path = "C:\Blackweb Gaming AP\config";                                               IsMacro = $false }

    # -- SPC GEAR --
    @{ Brand = "SPC Gear";    Name = "LIX - install folder";        Path = "C:\Program Files (x86)\SPC Gear";                                            IsMacro = $false }

    # -- AYAX --
    @{ Brand = "Ayax";        Name = "GamingMouse - record.ini";    Path = "C:\Program Files\AYAX GamingMouse\record.ini";                               IsMacro = $true  }

    # -- MARSGAMING --
    @{ Brand = "Marsgaming";  Name = "MMGX - macro module";         Path = "C:\Program Files (x86)\MARSGAMING\MMGX\modules\macro";                       IsMacro = $true  }

    # -- MOTOSPEED --
    @{ Brand = "Motospeed";   Name = "Gaming Mouse - modules";      Path = "C:\Program Files (x86)\MotoSpeed Gaming Mouse\V60\modules";                  IsMacro = $false }

    # -- COOLERMASTER --
    @{ Brand = "CoolerMaster"; Name = "MasterPlus - folder";        Path = "C:\Program Files (x86)\CoolerMaster\MasterPlus";                             IsMacro = $false }

    # -- FANTECH --
    @{ Brand = "Fantech";     Name = "VX7 - config.ini";            Path = "C:\Program Files (x86)\FANTECH VX7 Gaming Mouse\config.ini";                 IsMacro = $false }

    # -- AJ390R --
    @{ Brand = "AJ390R";      Name = "AJ390R - data folder";        Path = "C:\Program Files (x86)\AJ390R Gaming Mouse\data";                            IsMacro = $false }
)

function Scan-ConfigFiles {
    $results = @()
    foreach ($entry in $ConfigEntries) {
        $exists  = Test-Path $entry.Path
        $lastMod = $null
        $size    = $null
        $isDir   = $false

        if ($exists) {
            $item = Get-Item $entry.Path -ErrorAction SilentlyContinue
            if ($item) {
                $lastMod = $item.LastWriteTime
                $isDir   = $item.PSIsContainer
                if (-not $isDir) {
                    $size = $item.Length
                }
            }
        }

        $results += [PSCustomObject]@{
            Brand        = $entry.Brand
            SoftwareName = $entry.Name
            FilePath     = $entry.Path
            Exists       = $exists
            LastModified = $lastMod
            IsMacro      = $entry.IsMacro
            IsDirectory  = $isDir
            SizeBytes    = $size
        }
    }
    return $results
}

# -- RAZER DIRECTORY DEEP SCAN --
function Scan-RazerDirs {
    $results = @()
    $paths = @("$env:LOCALAPPDATA\Razer", "$env:APPDATA\Razer", "$env:PROGRAMDATA\Razer")
    foreach ($root in $paths) {
        if (-not (Test-Path $root)) { continue }
        try {
            $items = Get-ChildItem -Path $root -Recurse -ErrorAction SilentlyContinue
            foreach ($item in $items) {
                $results += [PSCustomObject]@{
                    FullPath     = $item.FullName
                    Name         = $item.Name
                    IsDirectory  = $item.PSIsContainer
                    LastModified = $item.LastWriteTime
                    SizeBytes    = if ($item.PSIsContainer) { $null } else { $item.Length }
                }
            }
        } catch {}
    }
    return $results
}

# --- 4. RENDERING ENGINE ---
function Show-Separator {
    param([char]$ch = [char]0x2500, [int]$width = 72)
    Write-Host "  $(New-Object string ($ch, $width))" -ForegroundColor DarkGray
}

function Show-Section {
    param([string]$title)
    Write-Host ""
    Show-Separator
    Write-Host "  " -NoNewline
    Write-Host ([char]0x258C + " ") -ForegroundColor DarkMagenta -NoNewline
    Write-Host $title.ToUpperInvariant() -ForegroundColor White
    Show-Separator
}

function Show-Field {
    param([string]$key, [string]$value, $col = "Gray")
    Write-Host "    $($key.PadRight(22))" -ForegroundColor DarkGray -NoNewline
    Write-Host $value -ForegroundColor $col
}

function Show-Info  { param([string]$text) Write-Host "  $text"      -ForegroundColor DarkGray }
function Show-Good  { param([string]$text) Write-Host "  + $text"    -ForegroundColor Green    }
function Show-Alert { param([string]$text) Write-Host "  ! $text"    -ForegroundColor Yellow   }
function Show-Warn  { param([string]$text) Write-Host "  [!] $text"  -ForegroundColor Red      }

function Format-Bytes {
    param([long]$bytes)
    if ($bytes -ge 1MB) { return "{0:N1} MB" -f ($bytes / 1MB) }
    if ($bytes -ge 1KB) { return "{0:N1} KB" -f ($bytes / 1KB) }
    return "$bytes B"
}

# --- 5. NOISE FILTER ---
$IgnorePaths = @(
    "\Cache\", "\GPUCache\", "\Code Cache\",
    "\Session Storage\", "\IndexedDB\", "\Dictionaries\",
    "\Crashpad\", "\GrpcChann", "\CrashReports\",
    "\Service Worker\"
)
function Test-IsNoise {
    param([string]$Path)
    $upper = $Path.ToUpper()
    foreach ($n in $IgnorePaths) { if ($upper.Contains($n.ToUpper())) { return $true } }
    return $false
}

# --- 6. MACRO CONTENT DETECTION ---
$RxMacroTiming = [regex]::new('"delay"\s*:\s*\d+', 'Compiled')
$RxRepeat      = [regex]::new('"repeat"', 'Compiled')
$RxSequence    = [regex]::new('"sequence"', 'Compiled')

$Script:FileCache = @{}

function Get-FileContentFast {
    param([string]$Path)
    try { return [System.IO.File]::ReadAllText($Path) } catch { return $null }
}

function Test-MacroStrings {
    param([string]$Text, [string[]]$Keys)
    $hits = [System.Collections.Generic.List[string]]::new()
    foreach ($k in $Keys) {
        if ($Text.Contains($k)) { $hits.Add("key:'$k'") }
    }
    if ($RxMacroTiming.IsMatch($Text)) { $hits.Add("timed delays") }
    if ($RxRepeat.IsMatch($Text))      { $hits.Add("repeat/loop") }
    if ($RxSequence.IsMatch($Text))    { $hits.Add("key sequence") }
    return ,$hits
}

function Parse-ContentForMacros {
    param([string]$FilePath, [string[]]$MacroKeys)
    $text = Get-FileContentFast -Path $FilePath
    if (-not $text) { return @() }
    return ,(Test-MacroStrings -Text $text -Keys $MacroKeys)
}

# --- 7. SOFTWARE PROFILES ---
$SoftwareProfiles = @(
    @{ Name="Logitech G HUB";           Paths=@("$env:LOCALAPPDATA\LGHUB","$env:APPDATA\LGHUB","$env:PROGRAMDATA\LGHUB");           Ext=@("*.json");       Keys=@("macros","assignments","commands"); Proc=@("LGHUB","LGHUB Agent") }
    @{ Name="Logitech Gaming Software (Legacy)"; Paths=@("$env:APPDATA\Logitech\Logitech Gaming Software","$env:LOCALAPPDATA\Logitech"); Ext=@("*.json","*.xml"); Keys=@("macro","assignment","script"); Proc=@("LCore") }
    @{ Name="Razer Synapse";            Paths=@("$env:APPDATA\Razer\Synapse3","$env:APPDATA\Razer\Synapse","$env:LOCALAPPDATA\Razer\Synapse3","$env:PROGRAMDATA\Razer\Synapse3","$env:LOCALAPPDATA\Razer\RazerAppEngine","$env:PROGRAMDATA\Razer\RazerAppEngine"); Ext=@("*.json","*.xml","*.ldb","*.log"); Keys=@("macro","Macro","action","Action","Script"); Proc=@("Razer Synapse","RazerCentralService","RazerStats") }
    @{ Name="SteelSeries GG";           Paths=@("$env:APPDATA\SteelSeries\SteelSeries GG","$env:LOCALAPPDATA\SteelSeries\SteelSeries GG","$env:LOCALAPPDATA\SteelSeries"); Ext=@("*.json"); Keys=@("macro","action","binding"); Proc=@("SteelSeriesGG","SteelSeriesEngine") }
    @{ Name="SteelSeries Engine 3 (Legacy)"; Paths=@("$env:APPDATA\SteelSeries Engine 3"); Ext=@("*.json"); Keys=@("macro","action","binding"); Proc=@("SteelSeriesEngine3") }
    @{ Name="Corsair iCUE";             Paths=@("$env:APPDATA\Corsair\CUE5","$env:APPDATA\Corsair\CUE4","$env:APPDATA\Corsair","$env:LOCALAPPDATA\Corsair"); Ext=@("*.cueprofile","*.json"); Keys=@("macro","action","command"); Proc=@("iCUE","CorsairService") }
    @{ Name="ASUS Armoury Crate";       Paths=@("$env:LOCALAPPDATA\ASUS\ArmouryCrate","$env:LOCALAPPDATA\ASUS\AURA","$env:APPDATA\ASUS\ArmouryCrate","$env:PROGRAMDATA\ASUS\ArmouryCrate"); Ext=@("*.json","*.xml"); Keys=@("macro","key","action"); Proc=@("ArmouryCrate","ASUSOptimization") }
    @{ Name="HyperX NGENUITY";          Paths=@("$env:LOCALAPPDATA\HyperX NGENUITY","$env:APPDATA\HyperX NGENUITY","$env:LOCALAPPDATA\HyperX"); Ext=@("*.json"); Keys=@("macro","action","binding"); Proc=@("NGENUITY") }
    @{ Name="Wooting";                  Paths=@("$env:LOCALAPPDATA\Wooting","$env:APPDATA\Wooting"); Ext=@("*.json"); Keys=@("macro","analog","action"); Proc=@("WootingUACHelper","Wooting") }
    @{ Name="Glorious CORE";            Paths=@("$env:LOCALAPPDATA\Glorious\Glorious CORE","$env:APPDATA\Glorious","$env:LOCALAPPDATA\Glorious"); Ext=@("*.json"); Keys=@("macro","key","assignment","sequence"); Proc=@("GloriousCORE") }
    @{ Name="Bloody / A4Tech";          Paths=@("$env:LOCALAPPDATA\Bloody","$env:PROGRAMDATA\Bloody","$env:LOCALAPPDATA\A4Tech","$env:PROGRAMDATA\A4Tech"); Ext=@("*.dat","*.json","*.xml","*.bin"); Keys=@("macro","Macro","script","Script","shot"); Proc=@("Bloody7","A4Tech") }
    @{ Name="Cooler Master MasterPlus+";Paths=@("$env:LOCALAPPDATA\Cooler Master","$env:APPDATA\Cooler Master"); Ext=@("*.json","*.xml"); Keys=@("macro","assignment","action"); Proc=@("MasterPlus") }
    @{ Name="Roccat Swarm / Titan";     Paths=@("$env:APPDATA\Roccat","$env:LOCALAPPDATA\Roccat"); Ext=@("*.xml","*.json"); Keys=@("macro","Macro","sequence","command"); Proc=@("Roccat Swarm","Titan") }
    @{ Name="Redragon";                 Paths=@("$env:APPDATA\REDRAGON\GamingMouse","$env:APPDATA\Redragon","$env:LOCALAPPDATA\Redragon"); Ext=@("*.ini","*.json"); Keys=@("macro","Macro"); Proc=@("Redragon") }
    @{ Name="Marvo / BY-COMBO";         Paths=@("$env:LOCALAPPDATA\BY-8801-GM917-v108","$env:LOCALAPPDATA\BY-COMBO","$env:LOCALAPPDATA\BYCOMBO-2"); Ext=@("*.dct","*.json"); Keys=@("macro"); Proc=@() }
    @{ Name="Ajazz";                    Paths=@("$env:LOCALAPPDATA\BYCOMBO-2","$env:APPDATA\BYCOMBO-2"); Ext=@("*.json"); Keys=@("macro"); Proc=@() }
)

# --- 8. CONTENT SCAN ---
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
                        $hits = Parse-ContentForMacros -FilePath $f -MacroKeys $sw.Keys
                        $results.Add([PSCustomObject]@{
                            Software = $sw.Name
                            FilePath = $f
                            LastModified = $item.LastWriteTime
                            SizeBytes = $item.Length
                            MacroHits = $hits
                            HasMacro  = $hits.Count -gt 0
                            Processes = $sw.Proc
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
    foreach ($n in $Names) {
        if (Get-Process -Name $n -ErrorAction SilentlyContinue) { $running.Add($n) }
    }
    return $running.ToArray()
}
function Main {
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    $Host.UI.RawUI.WindowTitle = "MacroDetector v2.0"
    $cutoff = (Get-Date).AddMinutes(-20)
    $pcOwner = $env:USERNAME

    Write-Host @"

  ▄▄▄     ▄▄▄
   ███▄ ▄███
   ██ ▀█▀ ██               ▄
   ██     ██   ▄▀▀█▄ ▄███▀ ████▄▄███▄
   ██     ██   ▄█▀██ ██    ██   ██ ██
 ▀██▀     ▀██▄▄▀█▄██▄▀███▄▄█▀  ▄▀███▀

                ▄▄▄▄▄▄
               █▀██▀▀██        █▄             █▄
                 ██   ██      ▄██▄           ▄██▄      ▄
                 ██   ██ ▄█▀█▄ ██ ▄█▀█▄ ▄███▀ ██ ▄███▄ ████▄
               ▄ ██   ██ ██▄█▀ ██ ██▄█▀ ██    ██ ██ ██ ██
               ▀██▀███▀ ▄▀█▄▄▄▄██▄▀█▄▄▄▄▀███▄▄██▄▀███▀▄█▀
"@ -ForegroundColor Magenta

    Write-Host "  MacroDetector" -ForegroundColor Magenta -NoNewline
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
        foreach ($x in $allMice) {
            if (-not [string]::IsNullOrEmpty($x.DeviceId) -and -not [string]::IsNullOrEmpty($m.DeviceId) -and $x.DeviceId.Equals($m.DeviceId, [StringComparison]::OrdinalIgnoreCase)) { $dupe = $true; break }
        }
        if (-not $dupe) { $allMice.Add($m) }
    }

    $recentMice = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($m in $allMice) {
        if ($m.IsConnected) { $recentMice.Add($m); continue }
        if ($m.ConnectedAt -and $m.ConnectedAt -ge $cutoff) { $recentMice.Add($m) }
    }

    if ($recentMice.Count -gt 0) {
        Write-Host "  Detected Mice (recent):" -ForegroundColor Cyan
        foreach ($m in $recentMice) {
            $tag = if ($m.IsConnected) { "connected" } else { "history" }
            Write-Host "    " -NoNewline
            if ($m.IsConnected) { Write-Host "$tag" -ForegroundColor Green -NoNewline } else { Write-Host "$tag" -ForegroundColor DarkGray -NoNewline }
            Write-Host "  " -NoNewline
            Write-Host "$($m.Name)" -ForegroundColor White -NoNewline
            if ($m.Brand -ne "Unknown") { Write-Host "  [$($m.Brand)]" -ForegroundColor DarkMagenta -NoNewline }
            Write-Host ""
        }
    }

    # 2. SOFTWARE
    $installed = Scan-InstalledSoftware
    if ($installed.Count -gt 0) {
        Write-Host "`n  Installed Software:" -ForegroundColor Cyan
        foreach ($s in ($installed | Sort-Object Brand)) {
            Write-Host "    " -NoNewline
            Write-Host "$($s.SoftwareName)" -ForegroundColor White -NoNewline
            Write-Host "  [$($s.Brand)]" -ForegroundColor DarkMagenta -NoNewline
            if ($s.Version) { Write-Host " v$($s.Version)" -ForegroundColor DarkGray -NoNewline }
            Write-Host ""
        }
    }

    # 3. SOFTWARE DIRECTORIES (profiles with found paths)
    $liveSw = @()
    foreach ($sw in $SoftwareProfiles) {
        foreach ($p in $sw.Paths) {
            if (Test-Path $p) { $liveSw += $sw.Name; break }
        }
    }
    if ($liveSw.Count -gt 0) {
        Write-Host "`n  Software Directories:" -ForegroundColor Cyan
        foreach ($name in ($liveSw | Sort-Object -Unique)) {
            Write-Host "    $name" -ForegroundColor White
        }
    }

    # 4. CONTENT SCAN (macro file contents, last 20 min)
    $scanResults = Invoke-ContentScan -RecentMins 20
    $macroFiles = $scanResults | Where-Object { $_.HasMacro }
    $otherFiles = $scanResults | Where-Object { -not $_.HasMacro }

    if ($scanResults.Count -gt 0) {
        Write-Host "`n  Scanned Files (modified <20min):" -ForegroundColor Cyan
    }

    if ($macroFiles.Count -gt 0) {
        Write-Host "`n  Macro Content Detected:" -ForegroundColor Cyan
        foreach ($f in ($macroFiles | Sort-Object LastModified -Descending)) {
            $sw = $f.Software
            Write-Host "    " -NoNewline; Write-Host "!" -ForegroundColor Red -NoNewline
            Write-Host " $sw" -ForegroundColor DarkMagenta -NoNewline
            Write-Host " | $(Split-Path $f.FilePath -Leaf)" -ForegroundColor Yellow
            Write-Host "        $($f.FilePath)" -ForegroundColor DarkGray
            $phits = $f.MacroHits -join ", "
            Write-Host "        [" -ForegroundColor DarkGray -NoNewline; Write-Host "$phits" -ForegroundColor Yellow -NoNewline; Write-Host "]" -ForegroundColor DarkGray
            $proc = Get-ProcessStatus -Names $f.Processes
            if ($proc.Count -gt 0) {
                Write-Host "        Process: $($proc -join ', ')" -ForegroundColor DarkMagenta
            }
        }
    }

    # 5. SUMMARY
    $totalMacro = $macroFiles.Count
    if ($totalMacro -gt 0) {
        Write-Host "`n  Macro Found:" -ForegroundColor Cyan
        foreach ($f in ($macroFiles | Sort-Object LastModified -Descending)) {
            Write-Host "    " -NoNewline; Write-Host "!" -ForegroundColor Red -NoNewline
            Write-Host " $($f.Software)" -ForegroundColor DarkMagenta -NoNewline
            Write-Host " | $($f.FilePath)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "`n  No recent macro activity" -ForegroundColor DarkGray
    }

    Write-Host ""
}

Main
