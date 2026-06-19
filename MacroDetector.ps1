<#
.SYNOPSIS
    MacroDetector
.DESCRIPTION
    A comprehensive forensic mouse device and macro software configuration analysis tool.
.NOTES
    Compatible with Windows 10 and Windows 11. Requires Administrative privileges for full registry and Prefetch analysis.
    v3.0 - Added generic macro tools, AutoHotkey, X-Mouse, and expanded paths.
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
    @{ Keyword = "spc gear";      Brand = "SPC Gear" }
    # Additional generic tools
    @{ Keyword = "autohotkey";    Brand = "Generic Software" }
    @{ Keyword = "ahk";           Brand = "Generic Software" }
    @{ Keyword = "x-mouse";       Brand = "Generic Software" }
    @{ Keyword = "macrogamer";    Brand = "Generic Software" }
    @{ Keyword = "tinytask";      Brand = "Generic Software" }
    @{ Keyword = "speedautoclicker";          Brand = "Generic Software" }
    @{ Keyword = "jitbit";                    Brand = "Generic Software" }
    @{ Keyword = "pulover";                   Brand = "Generic Software" }
    @{ Keyword = "murgee";                    Brand = "Generic Software" }
    @{ Keyword = "ptfb pro";                  Brand = "Generic Software" }
    @{ Keyword = "fastclicker";               Brand = "Generic Software" }
    @{ Keyword = "free mouse auto clicker";   Brand = "Generic Software" }
    @{ Keyword = "auto keyboard presser";     Brand = "Generic Software" }
    @{ Keyword = "perfect automation";        Brand = "Generic Software" }
    @{ Keyword = "easy macro recorder";       Brand = "Generic Software" }
    @{ Keyword = "keypresser";                Brand = "Generic Software" }
    @{ Keyword = "autotyper";                 Brand = "Generic Software" }
    @{ Keyword = "clickey";                   Brand = "Generic Software" }
    @{ Keyword = "ghostmouse";                Brand = "Generic Software" }
    @{ Keyword = "mini mouse macro";          Brand = "Generic Software" }
    @{ Keyword = "macro toolworks";           Brand = "Generic Software" }
    @{ Keyword = "auto click typer";          Brand = "Generic Software" }
    @{ Keyword = "keyman";                    Brand = "Generic Software" }
    @{ Keyword = "shocker";                   Brand = "Generic Software" }
    @{ Keyword = "ds4windows";                Brand = "Generic Software" }
    @{ Keyword = "inputmapper";               Brand = "Generic Software" }
    @{ Keyword = "ucr";                       Brand = "Generic Software" }
    @{ Keyword = "rewasd";                    Brand = "Generic Software" }
    @{ Keyword = "antimicro";                 Brand = "Generic Software" }
    @{ Keyword = "keyscrambler";              Brand = "Generic Software" }
    @{ Keyword = "tgmacro";                   Brand = "Generic Software" }
    @{ Keyword = "lamzu";                     Brand = "LAMZU" }
    @{ Keyword = "pwnage";                    Brand = "Pwnage" }
    @{ Keyword = "g-wolves";                  Brand = "G-Wolves" }
    @{ Keyword = "gwolves";                   Brand = "G-Wolves" }
    @{ Keyword = "vgn";                       Brand = "VGN" }
    @{ Keyword = "vxe";                       Brand = "VXE" }
    @{ Keyword = "zaopin";                    Brand = "Zaopin" }
    @{ Keyword = "darmoshark";                Brand = "Darmoshark" }
    @{ Keyword = "waizowl";                   Brand = "Waizowl" }
    @{ Keyword = "wlmouse";                   Brand = "WLmouse" }
    @{ Keyword = "arbiter studio";            Brand = "Arbiter Studio" }
    @{ Keyword = "incott";                    Brand = "Incott" }
    @{ Keyword = "sprime";                    Brand = "Sprime" }
    @{ Keyword = "machenike";                 Brand = "Machenike" }
    @{ Keyword = "thunderobot";               Brand = "Thunderobot" }
    @{ Keyword = "delux";                     Brand = "Delux" }
    @{ Keyword = "rapoo";                     Brand = "Rapoo" }
    @{ Keyword = "e-dra";                     Brand = "E-Dra" }
    @{ Keyword = "trust gaming";              Brand = "Trust" }
    @{ Keyword = "mad catz";                  Brand = "Mad Catz" }
    @{ Keyword = "madcatz";                   Brand = "Mad Catz" }
    @{ Keyword = "swiftpoint";                Brand = "Swiftpoint" }
    @{ Keyword = "ragnok";                    Brand = "Ragnok" }
    @{ Keyword = "gembird";                   Brand = "Gembird" }
    @{ Keyword = "hama";                      Brand = "Hama" }
    @{ Keyword = "zelotes";                   Brand = "Zelotes" }
    @{ Keyword = "havit";                     Brand = "HAVIT" }
    @{ Keyword = "pictek";                    Brand = "Pictek" }
    @{ Keyword = "victsing";                  Brand = "VictSing" }
    @{ Keyword = "utechsmart";                Brand = "UtechSmart" }
    @{ Keyword = "roccat kone";               Brand = "ROCCAT" }
    @{ Keyword = "roccat burst";              Brand = "ROCCAT" }
    @{ Keyword = "ducky";                     Brand = "Ducky" }
    @{ Keyword = "cherry";                    Brand = "Cherry" }
    @{ Keyword = "keychron";                  Brand = "Keychron" }
    @{ Keyword = "ironcat";                   Brand = "Ironcat" }
    @{ Keyword = "x-trike";                   Brand = "Xtrike Me" }
    @{ Keyword = "onexplayer";                Brand = "OneXPlayer" }
    @{ Keyword = "ayaneo";                    Brand = "AYANEO" }
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
    # Added generic
    @{ Keyword = "autohotkey";                Brand = "Generic";      Name = "AutoHotkey" }
    @{ Keyword = "x-mouse";                   Brand = "Generic";      Name = "X-Mouse Button Control" }
    @{ Keyword = "macrogamer";                Brand = "Generic";      Name = "MacroGamer" }
    @{ Keyword = "tinytask";                  Brand = "Generic";      Name = "TinyTask" }
    @{ Keyword = "speedautoclicker";          Brand = "Generic";      Name = "SpeedAutoClicker" }
    @{ Keyword = "jitbit";                    Brand = "Generic";      Name = "Jitbit Macro Recorder" }
    @{ Keyword = "pulover";                   Brand = "Generic";      Name = "Pulover's Macro Creator" }
    @{ Keyword = "murgee";                    Brand = "Generic";      Name = "Murgee Auto Clicker" }
    @{ Keyword = "ptfb pro";                  Brand = "Generic";      Name = "PTFB Pro" }
    @{ Keyword = "fastclicker";               Brand = "Generic";      Name = "FastClicker" }
    @{ Keyword = "ghostmouse";                Brand = "Generic";      Name = "GhostMouse" }
    @{ Keyword = "minimousemacro";            Brand = "Generic";      Name = "Mini Mouse Macro" }
    @{ Keyword = "macro toolworks";           Brand = "Generic";      Name = "Macro Toolworks" }
    @{ Keyword = "ds4windows";                Brand = "Generic";      Name = "DS4Windows" }
    @{ Keyword = "inputmapper";               Brand = "Generic";      Name = "InputMapper" }
    @{ Keyword = "ucr";                       Brand = "Generic";      Name = "Universal Control Remapper" }
    @{ Keyword = "rewasd";                    Brand = "Generic";      Name = "reWASD" }
    @{ Keyword = "antimicro";                 Brand = "Generic";      Name = "AntiMicro / AntiMicroX" }
    @{ Keyword = "tgmacro";                   Brand = "Generic";      Name = "TGMacro" }
    @{ Keyword = "lamzu";                     Brand = "LAMZU";        Name = "LAMZU Software" }
    @{ Keyword = "pwnage";                    Brand = "Pwnage";       Name = "Pwnage Software" }
    @{ Keyword = "g-wolves";                  Brand = "G-Wolves";     Name = "G-Wolves Software" }
    @{ Keyword = "vgn";                       Brand = "VGN";          Name = "VGN Hub" }
    @{ Keyword = "vxe";                       Brand = "VXE";          Name = "VXE Hub" }
    @{ Keyword = "zaopin";                    Brand = "Zaopin";       Name = "Zaopin Software" }
    @{ Keyword = "darmoshark";                Brand = "Darmoshark";   Name = "Darmoshark Software" }
    @{ Keyword = "waizowl";                   Brand = "Waizowl";      Name = "Waizowl Software" }
    @{ Keyword = "wlmouse";                   Brand = "WLmouse";      Name = "WLmouse Software" }
    @{ Keyword = "machenike";                 Brand = "Machenike";    Name = "Machenike Control Center" }
    @{ Keyword = "delux";                     Brand = "Delux";        Name = "Delux Gaming Mouse" }
    @{ Keyword = "rapoo";                     Brand = "Rapoo";        Name = "Rapoo Driver" }
    @{ Keyword = "mad catz";                  Brand = "Mad Catz";     Name = "Mad Catz Software" }
    @{ Keyword = "swiftpoint";                Brand = "Swiftpoint";   Name = "Swiftpoint X1 Control Panel" }
    @{ Keyword = "utechsmart";                Brand = "UtechSmart";   Name = "UtechSmart Venus Software" }
    @{ Keyword = "havit";                     Brand = "HAVIT";        Name = "HAVIT Gaming Software" }
    @{ Keyword = "zelotes";                   Brand = "Zelotes";      Name = "Zelotes Gaming Mouse Software" }
    @{ Keyword = "keychron";                  Brand = "Keychron";     Name = "VIA/Keychron Software" }
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
    # -- LOGITECH --
    @{ Brand = "Logitech";    Name = "G HUB - settings.db";              Path = "$env:LOCALAPPDATA\LGHUB\settings.db";                                          IsMacro = $true  }
    @{ Brand = "Logitech";    Name = "G HUB - Macros folder";            Path = "$env:LOCALAPPDATA\LGHUB";                                                      IsMacro = $true  }
    @{ Brand = "Logitech";    Name = "Options+ - options_plus.db";       Path = "$env:LOCALAPPDATA\Logi\LogiOptionsPlus\data\options_plus.db";                   IsMacro = $false }
    @{ Brand = "Logitech";    Name = "Gaming Software - settings";       Path = "$env:LOCALAPPDATA\Logitech\Logitech Gaming Software\settings.json";             IsMacro = $true  }

    # -- LOGITECH (extended) --
    @{ Brand = "Logitech";    Name = "G HUB - ProgramData applications"; Path = "C:\ProgramData\LGHUBData\applications";                                       IsMacro = $true  }
    @{ Brand = "Logitech";    Name = "G HUB - Roaming Backup";          Path = "$env:APPDATA\LGHUB_BKP";                                                     IsMacro = $true  }
    @{ Brand = "Logitech";    Name = "G HUB - Prefetch (LGHUB.EXE)";    Path = "C:\Windows\Prefetch\LGHUB.EXE-1A9EA8C0.pf";                                 IsMacro = $false }

    # -- RAZER - ROAMING APPDATA --
    @{ Brand = "Razer";       Name = "Synapse 3 - Settings";            Path = "$env:APPDATA\Razer\Synapse3\Settings";                                         IsMacro = $true  }
    @{ Brand = "Razer";       Name = "Synapse 3 - MacroData";           Path = "$env:APPDATA\Razer\Synapse3\MacroData";                                        IsMacro = $true  }
    @{ Brand = "Razer";       Name = "Synapse 3 - StaticDevConf";       Path = "$env:APPDATA\Razer\Synapse3\StaticDeviceConf.json";                            IsMacro = $false }
    @{ Brand = "Razer";       Name = "Synapse 3 - Accounts";            Path = "$env:APPDATA\Razer\Synapse3\Accounts";                                         IsMacro = $true  }
    @{ Brand = "Razer";       Name = "Razer Central - Accounts";        Path = "$env:APPDATA\Razer\Razer Central\Accounts";                                    IsMacro = $false }

    # -- RAZER - LOCAL APPDATA (primary new detections) --
    @{ Brand = "Razer";       Name = "Razer - LocalAppData root";       Path = "$env:LOCALAPPDATA\Razer";                                                      IsMacro = $false }
    @{ Brand = "Razer";       Name = "RazerAppEngine - root";           Path = "$env:LOCALAPPDATA\Razer\RazerAppEngine";                                       IsMacro = $false }
    @{ Brand = "Razer";       Name = "RazerAppEngine - Cache";          Path = "$env:LOCALAPPDATA\Razer\RazerAppEngine\Cache";                                  IsMacro = $false }
    @{ Brand = "Razer";       Name = "RazerAppEngine - User Data";      Path = "$env:LOCALAPPDATA\Razer\RazerAppEngine\User Data";                             IsMacro = $true  }
    @{ Brand = "Razer";       Name = "RazerAppEngine - Local State";    Path = "$env:LOCALAPPDATA\Razer\RazerAppEngine\User Data\Local State";                IsMacro = $false }
    @{ Brand = "Razer";       Name = "Razer Cortex - LocalAppData";     Path = "$env:LOCALAPPDATA\Razer\Razer Cortex";                                         IsMacro = $false }
    @{ Brand = "Razer";       Name = "Razer Cortex - DB";               Path = "$env:LOCALAPPDATA\Razer\Razer Cortex\data.db";                                 IsMacro = $false }
    @{ Brand = "Razer";       Name = "Razer Cortex - config.json";      Path = "$env:LOCALAPPDATA\Razer\Razer Cortex\config.json";                             IsMacro = $false }
    @{ Brand = "Razer";       Name = "Razer Central - LocalAppData";    Path = "$env:LOCALAPPDATA\Razer\Razer Central";                                       IsMacro = $false }
    @{ Brand = "Razer";       Name = "Razer Central - settings.db";     Path = "$env:LOCALAPPDATA\Razer\Razer Central\settings.db";                            IsMacro = $false }
    @{ Brand = "Razer";       Name = "Synapse 3 - Accounts (Local)";    Path = "$env:LOCALAPPDATA\Razer\Synapse3\Accounts";                                    IsMacro = $true  }
    @{ Brand = "Razer";       Name = "Synapse 3 - Cloud Cache";         Path = "$env:LOCALAPPDATA\Razer\Synapse3\Data";                                        IsMacro = $true  }
    @{ Brand = "Razer";       Name = "Synapse 3 - Local DB";            Path = "$env:LOCALAPPDATA\Razer\Synapse3\Devices.db";                                  IsMacro = $true  }
    @{ Brand = "Razer";       Name = "Synapse 3 - UpdateService";       Path = "$env:LOCALAPPDATA\Razer\UpdateService";                                        IsMacro = $false }
    @{ Brand = "Razer";       Name = "Synapse 3 - Installer";           Path = "$env:LOCALAPPDATA\Razer\Installer";                                            IsMacro = $false }
    @{ Brand = "Razer";       Name = "RazerAppEngine - Logs";           Path = "$env:LOCALAPPDATA\Razer\RazerAppEngine\User Data\Logs";                         IsMacro = $true  }
    @{ Brand = "Razer";       Name = "RazerAppEngine - Products";       Path = "$env:LOCALAPPDATA\Razer\RazerAppEngine\User Data\Products";                     IsMacro = $true  }

    # -- RAZER - PROGRAMDATA --
    @{ Brand = "Razer";       Name = "Synapse 3 - Service Log";         Path = "$env:PROGRAMDATA\Razer\Synapse3\Log\SynapseService.log";                       IsMacro = $true  }
    @{ Brand = "Razer";       Name = "Synapse 3 - ProgramData";         Path = "$env:PROGRAMDATA\Razer\Synapse3";                                              IsMacro = $true  }
    @{ Brand = "Razer";       Name = "Razer Central - ProgramData";     Path = "$env:PROGRAMDATA\Razer\Razer Central";                                         IsMacro = $true  }

    # -- STEELSERIES --
    @{ Brand = "SteelSeries"; Name = "GG - gg.db";                      Path = "$env:APPDATA\SteelSeries\GG\db\gg.db";                                        IsMacro = $true  }

    # -- CORSAIR --
    @{ Brand = "Corsair";     Name = "iCUE 5 - config.db";              Path = "$env:APPDATA\Corsair\CUE5\config.db";                                         IsMacro = $true  }
    @{ Brand = "Corsair";     Name = "iCUE 4 - config.db";              Path = "$env:APPDATA\Corsair\CUE4\config.db";                                         IsMacro = $true  }
    @{ Brand = "Corsair";     Name = "iCUE - Config.cuecfg";            Path = "$env:APPDATA\corsair\CUE\Config.cuecfg";                                       IsMacro = $true  }

    # -- ROCCAT --
    @{ Brand = "ROCCAT";      Name = "Swarm - settings.xml";             Path = "$env:APPDATA\ROCCAT\ROCCAT Swarm\settings.xml";                               IsMacro = $false }
    @{ Brand = "ROCCAT";      Name = "Swarm - macro folder";             Path = "$env:APPDATA\ROCCAT\SWARM\macro";                                             IsMacro = $true  }
    @{ Brand = "ROCCAT";      Name = "Swarm - preset macros";            Path = "$env:APPDATA\ROCCAT\SWARM\preset_macro";                                      IsMacro = $true  }
    @{ Brand = "ROCCAT";      Name = "Connect - settings.db";            Path = "$env:APPDATA\ROCCAT\ROCCAT Connect\settings.db";                              IsMacro = $false }

    # -- GLORIOUS --
    @{ Brand = "Glorious";    Name = "CORE - config.json";               Path = "$env:APPDATA\glorious-core-app\config.json";                                  IsMacro = $false }
    @{ Brand = "Glorious";    Name = "CORE - settings.db";               Path = "$env:LOCALAPPDATA\GloriousCore\settings.db";                                  IsMacro = $true  }
    @{ Brand = "Glorious";    Name = "BYCOMBO-2 - Macros";               Path = "$env:APPDATA\BYCOMBO-2\Mac";                                                  IsMacro = $true  }

    # -- ATTACK SHARK --
    @{ Brand = "Attack Shark"; Name = "Software - config.json";          Path = "$env:APPDATA\AttackShark\config.json";                                        IsMacro = $false }
    @{ Brand = "Attack Shark"; Name = "Software - settings.db";          Path = "$env:LOCALAPPDATA\AttackShark\settings.db";                                   IsMacro = $true  }
    @{ Brand = "Attack Shark"; Name = "ProgramData config";              Path = "$env:PROGRAMDATA\AttackShark\config.json";                                    IsMacro = $false }

    # -- ASUS --
    @{ Brand = "ASUS";        Name = "Armoury Crate - settings.db";      Path = "$env:LOCALAPPDATA\ASUS\ArmouryCrate\settings.db";                            IsMacro = $true  }
    @{ Brand = "ASUS";        Name = "ROG Armoury - Macros";             Path = "$env:USERPROFILE\Documents\ASUS\ROG\ROG Armoury\common";                     IsMacro = $true  }

    # -- MSI --
    @{ Brand = "MSI";         Name = "Dragon Center - settings";         Path = "$env:APPDATA\MSI\Dragon Center\settings.json";                               IsMacro = $false }
    @{ Brand = "MSI";         Name = "MSI Center - settings.db";         Path = "$env:APPDATA\MSI\MSI Center\settings.db";                                    IsMacro = $true  }

    # -- HYPERX --
    @{ Brand = "HyperX";      Name = "NGENUITY - settings.db";           Path = "$env:APPDATA\HyperX\NGENUITY\settings.db";                                   IsMacro = $true  }
    @{ Brand = "HyperX";      Name = "NGENUITY - Store DB";              Path = "$env:LOCALAPPDATA\Packages\33C30B79.HyperXNGenuity_0a78dr3hq0pvt\LocalState\Settings\setting.db"; IsMacro = $true }

    # -- PULSAR --
    @{ Brand = "Pulsar";      Name = "Fusion - config.json";             Path = "$env:APPDATA\Pulsar\config.json";                                            IsMacro = $false }

    # -- FINALMOUSE --
    @{ Brand = "Finalmouse";  Name = "Software - settings.db";           Path = "$env:APPDATA\Finalmouse\settings.db";                                        IsMacro = $false }

    # -- ZOWIE --
    @{ Brand = "ZOWIE";       Name = "Mouse Config - config.json";       Path = "$env:APPDATA\ZOWIE\config.json";                                             IsMacro = $false }

    # -- ENDGAME GEAR --
    @{ Brand = "Endgame Gear"; Name = "Software - settings.db";          Path = "$env:APPDATA\Endgame Gear\settings.db";                                      IsMacro = $false }

    # -- BLOODY --
    @{ Brand = "Bloody";      Name = "Bloody7 - GunLib Macros";          Path = "C:\Program Files (x86)\Bloody7\Bloody7\Data\Mouse\English\ScriptsMacros\GunLib"; IsMacro = $true }
    @{ Brand = "Bloody";      Name = "Software - config.json";           Path = "$env:APPDATA\Bloody\config.json";                                            IsMacro = $false }
    @{ Brand = "Bloody";      Name = "Software - settings.db";           Path = "$env:LOCALAPPDATA\Bloody\settings.db";                                       IsMacro = $true  }

    # -- ALIENWARE --
    @{ Brand = "Alienware";   Name = "CC - fxmetadata";                  Path = "C:\ProgramData\Alienware\AlienWare Command Center\fxmetadata";               IsMacro = $false }
    @{ Brand = "Alienware";   Name = "CC - config.json";                 Path = "$env:PROGRAMDATA\Alienware\AWCCService\config.json";                         IsMacro = $false }

    # -- KENSINGTON --
    @{ Brand = "Kensington";  Name = "Works - settings.db";              Path = "$env:APPDATA\Kensington\KensingtonWorks\settings.db";                        IsMacro = $false }

    # -- COUGAR --
    @{ Brand = "Cougar";      Name = "UIX - config.json";                Path = "$env:APPDATA\Cougar\UIX\config.json";                                        IsMacro = $false }

    # -- REDRAGON --
    @{ Brand = "Redragon";    Name = "GamingMouse - Macro folder";       Path = "$env:APPDATA\REDRAGON\GamingMouse\Macro";                                    IsMacro = $true  }
    @{ Brand = "Redragon";    Name = "GamingMouse - config.ini";         Path = "$env:APPDATA\REDRAGON\GamingMouse\config.ini";                               IsMacro = $false }
    @{ Brand = "Redragon";    Name = "Software - config.json";           Path = "$env:APPDATA\Redragon\config.json";                                          IsMacro = $false }

    # -- XENON200 --
    @{ Brand = "Xenon200";    Name = "Configs folder";                   Path = "C:\Program Files (x86)\Xenon200\configs";                                    IsMacro = $false }

    # -- T16 / BYCOMBO --
    @{ Brand = "T16";         Name = "BY-COMBO - curid.dct";             Path = "$env:LOCALAPPDATA\BY-COMBO\curid.dct";                                       IsMacro = $false }
    @{ Brand = "T16";         Name = "BY-COMBO - pro.dct";               Path = "$env:LOCALAPPDATA\BY-COMBO\pro.dct";                                         IsMacro = $false }

    # -- MARVO --
    @{ Brand = "Marvo";       Name = "BY-8801 - curid.dct";              Path = "$env:LOCALAPPDATA\BY-8801-GM917-v108\curid.dct";                             IsMacro = $false }
    @{ Brand = "Marvo";       Name = "BY-8801 - pro.dct";                Path = "$env:LOCALAPPDATA\BY-8801-GM917-v108\pro.dct";                               IsMacro = $false }

    # -- AJAZZ --
    @{ Brand = "Ajazz";       Name = "BYCOMBO-2 - Macros (Local)";       Path = "$env:LOCALAPPDATA\BYCOMBO-2\Mac";                                            IsMacro = $true  }
    @{ Brand = "Ajazz";       Name = "BYCOMBO-2 - Macros (Roam)";        Path = "$env:APPDATA\BYCOMBO-2\Mac";                                                 IsMacro = $true  }

    # -- KROM KOLT --
    @{ Brand = "Krom Kolt";   Name = "KROM KOLT - sequence.dat";         Path = "$env:LOCALAPPDATA\VirtualStore\Program Files (x86)\KROM KOLT\Config\sequence.dat"; IsMacro = $true }

    # -- BLACKWEB --
    @{ Brand = "Blackweb";    Name = "Gaming AP - config";               Path = "C:\Blackweb Gaming AP\config";                                               IsMacro = $false }

    # -- SPC GEAR --
    @{ Brand = "SPC Gear";    Name = "LIX - install folder";             Path = "C:\Program Files (x86)\SPC Gear";                                            IsMacro = $false }

    # -- AYAX --
    @{ Brand = "Ayax";        Name = "GamingMouse - record.ini";         Path = "C:\Program Files\AYAX GamingMouse\record.ini";                               IsMacro = $true  }

    # -- MARSGAMING --
    @{ Brand = "Marsgaming";  Name = "MMGX - macro module";              Path = "C:\Program Files (x86)\MARSGAMING\MMGX\modules\macro";                       IsMacro = $true  }

    # -- MOTOSPEED --
    @{ Brand = "Motospeed";   Name = "Gaming Mouse - modules";            Path = "C:\Program Files (x86)\MotoSpeed Gaming Mouse\V60\modules";                  IsMacro = $false }

    # -- COOLERMASTER --
    @{ Brand = "CoolerMaster"; Name = "MasterPlus - folder";             Path = "C:\Program Files (x86)\CoolerMaster\MasterPlus";                             IsMacro = $false }

    # -- FANTECH --
    @{ Brand = "Fantech";     Name = "VX7 - config.ini";                 Path = "C:\Program Files (x86)\FANTECH VX7 Gaming Mouse\config.ini";                 IsMacro = $false }

    # Added explicit path checks for generic macro tools
    @{ Brand = "Generic";     Name = "AutoHotkey - Documents";           Path = "$env:USERPROFILE\Documents\AutoHotkey.ahk";                                  IsMacro = $true  }
    @{ Brand = "Generic";     Name = "X-Mouse Button Control settings";  Path = "$env:APPDATA\Highresolution Enterprises\XMouseButtonControl\XMBCSettings.xml"; IsMacro = $true  }
    @{ Brand = "Generic";     Name = "MacroGamer - Profiles";            Path = "$env:APPDATA\MacroGamer";                                                    IsMacro = $true  }
    @{ Brand = "Generic";     Name = "OP AutoClicker";                   Path = "$env:APPDATA\OPAutoClicker";                                                 IsMacro = $true  }
    @{ Brand = "Generic";     Name = "GS Auto Clicker";                  Path = "$env:APPDATA\GSAutoClicker";                                                 IsMacro = $true  }
    @{ Brand = "Generic";     Name = "SpeedAutoClicker";                 Path = "$env:APPDATA\SpeedAutoClicker";                                              IsMacro = $true  }
    @{ Brand = "Generic";     Name = "TinyTask";                         Path = "$env:APPDATA\TinyTask";                                                      IsMacro = $true  }
    @{ Brand = "Logitech";    Name = "SetPoint - legacy";                Path = "$env:APPDATA\Logitech\SetPoint";                                             IsMacro = $true  }
    @{ Brand = "Generic";     Name = "reWASD";                           Path = "$env:PROGRAMDATA\Disc Soft\reWASD";                                          IsMacro = $true  }
    @{ Brand = "Generic";     Name = "Wootility";                        Path = "$env:APPDATA\wootility";                                                     IsMacro = $true  }
    @{ Brand = "Generic";     Name = "VIA Keyboard Config";              Path = "$env:APPDATA\VIA";                                                           IsMacro = $true  }
    @{ Brand = "Generic";     Name = "JoyToKey";                         Path = "$env:USERPROFILE\Documents\JoyToKey";                                        IsMacro = $true  }
    @{ Brand = "Generic";     Name = "AntiMicroX";                       Path = "$env:LOCALAPPDATA\antimicrox";                                               IsMacro = $true  }
    @{ Brand = "Generic";     Name = "Jitbit Macro Recorder";            Path = "$env:APPDATA\Jitbit\MacroRecorder";                                          IsMacro = $true  }
    @{ Brand = "Generic";     Name = "Pulover Macro Creator";            Path = "$env:APPDATA\MacroCreator";                                                  IsMacro = $true  }
    @{ Brand = "Generic";     Name = "Murgee Auto Clicker";              Path = "$env:APPDATA\Murgee\Auto Clicker";                                           IsMacro = $true  }
    @{ Brand = "Generic";     Name = "PTFB Pro";                         Path = "$env:PROGRAMDATA\Technology Lighthouse\PTFB Pro";                            IsMacro = $true  }
    @{ Brand = "Generic";     Name = "GhostMouse";                       Path = "$env:APPDATA\GhostMouse";                                                    IsMacro = $true  }
    @{ Brand = "Generic";     Name = "DS4Windows Profiles";              Path = "$env:APPDATA\DS4Windows\Profiles";                                           IsMacro = $true  }
    @{ Brand = "Generic";     Name = "InputMapper";                      Path = "$env:APPDATA\InputMapper";                                                   IsMacro = $true  }
    @{ Brand = "Generic";     Name = "TGMacro";                          Path = "$env:APPDATA\TGMacro";                                                       IsMacro = $true  }
    @{ Brand = "Generic";     Name = "Mini Mouse Macro";                 Path = "$env:APPDATA\MiniMouseMacro";                                                IsMacro = $true  }
    @{ Brand = "Generic";     Name = "Macro Toolworks";                  Path = "$env:APPDATA\MacroToolworks";                                                IsMacro = $true  }
    @{ Brand = "Generic";     Name = "UCR settings";                     Path = "$env:APPDATA\UCR";                                                           IsMacro = $true  }
    @{ Brand = "Generic";     Name = "Perfect Automation";               Path = "$env:APPDATA\Perfect Automation";                                            IsMacro = $true  }
    @{ Brand = "Generic";     Name = "Auto Click Typer";                 Path = "$env:APPDATA\AutoClickTyper";                                                IsMacro = $true  }
    @{ Brand = "Generic";     Name = "Free Mouse Auto Clicker";          Path = "$env:APPDATA\Free Mouse Auto Clicker";                                       IsMacro = $true  }
    @{ Brand = "Generic";     Name = "Auto Keyboard Presser";            Path = "$env:APPDATA\Auto Keyboard Presser";                                         IsMacro = $true  }
    @{ Brand = "Generic";     Name = "Easy Macro Recorder";              Path = "$env:APPDATA\Easy Macro Recorder";                                           IsMacro = $true  }
    @{ Brand = "Generic";     Name = "AutoIt Scripts";                   Path = "$env:USERPROFILE\Documents\AutoIt v3 Script.au3";                            IsMacro = $true  }
    @{ Brand = "LAMZU";       Name = "LAMZU Software configs";           Path = "$env:LOCALAPPDATA\LAMZU";                                                    IsMacro = $true  }
    @{ Brand = "Pwnage";      Name = "Pwnage Software configs";          Path = "$env:LOCALAPPDATA\Pwnage";                                                   IsMacro = $true  }
    @{ Brand = "VGN";         Name = "VGN Hub / ATK Hub";                Path = "$env:APPDATA\ATK Hub";                                                       IsMacro = $true  }
    @{ Brand = "VGN";         Name = "VGN Hub (old)";                    Path = "$env:LOCALAPPDATA\VGN Hub";                                                  IsMacro = $true  }
    @{ Brand = "Darmoshark";  Name = "Darmoshark Config";                Path = "$env:LOCALAPPDATA\Darmoshark";                                               IsMacro = $true  }
    @{ Brand = "WLmouse";     Name = "WLmouse Config";                   Path = "$env:APPDATA\WLmouse";                                                       IsMacro = $true  }
    @{ Brand = "Machenike";   Name = "Machenike Settings";               Path = "$env:APPDATA\Machenike";                                                     IsMacro = $true  }
    @{ Brand = "Delux";       Name = "Delux Gaming Software";            Path = "$env:LOCALAPPDATA\Delux";                                                    IsMacro = $true  }
    @{ Brand = "Mad Catz";    Name = "Mad Catz Profiles";                Path = "$env:PUBLIC\Documents\Mad Catz";                                             IsMacro = $true  }
    @{ Brand = "Swiftpoint";  Name = "Swiftpoint X1 Config";             Path = "$env:LOCALAPPDATA\Swiftpoint";                                               IsMacro = $true  }
    @{ Brand = "UtechSmart";  Name = "UtechSmart Macro";                 Path = "$env:APPDATA\UtechSmart";                                                    IsMacro = $true  }
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
    if ($low.Contains('<macro') -or $low.Contains('<macros') -or $low.Contains('<action') -or $low.Contains('<delay')) { return $true }
    if ($low.Contains('[macro') -or $low.Contains('macro=')) { return $true }
    
    # G HUB specific
    if ($low.Contains('"assignments"') -and ($low.Contains('"delay"') -or $low.Contains('"script"'))) { return $true }
    
    # Razer / Generic specific
    if ($low.Contains('sequence') -and $low.Contains('delay')) { return $true }
    if ($low.Contains('script') -and $low.Contains('delay')) { return $true }
    if ($low.Contains('macro') -and $low.Contains('delay')) { return $true }
    if ($low.Contains('macro') -and $low.Contains('action')) { return $true }
    
    # Basic AHK/Script heuristics
    if ($low.Contains('::') -and $low.Contains('send')) { return $true }
    if ($low.Contains('click') -and $low.Contains('sleep')) { return $true }
    
    return $false
}

# Scans directory and returns ONLY files that actually contain macro definitions
function Get-ExplicitMacroFiles {
    param([string]$DirectoryPath, [datetime]$Cutoff)
    $found = [System.Collections.Generic.List[PSCustomObject]]::new()
    $safeExts = @(".json", ".xml", ".txt", ".cfg", ".ini", ".lua", ".log", ".dat", ".db", ".ahk")
    
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
    # Major Brands
    @{ Name="Logitech G HUB";           Paths=@("$env:LOCALAPPDATA\LGHUB","$env:APPDATA\LGHUB","$env:PROGRAMDATA\LGHUB","$env:APPDATA\LGHUB_BKP","C:\ProgramData\LGHUBData\applications"); Ext=@("*.json", "*.db");       Keys=@("macros","assignments","commands"); Proc=@("LGHUB","LGHUB Agent") }
    @{ Name="Logitech Gaming Software (Legacy)"; Paths=@("$env:APPDATA\Logitech\Logitech Gaming Software","$env:LOCALAPPDATA\Logitech"); Ext=@("*.json","*.xml"); Keys=@("macro","assignment","script"); Proc=@("LCore") }
    @{ Name="Razer Synapse";            Paths=@("$env:APPDATA\Razer\Synapse3","$env:LOCALAPPDATA\Razer\Synapse3","$env:PROGRAMDATA\Razer\Synapse3","$env:LOCALAPPDATA\Razer\RazerAppEngine"); Ext=@("*.json","*.xml","*.ldb","*.log", "*.db"); Keys=@("macro","Macro","action","Action","Script"); Proc=@("Razer Synapse","RazerCentralService","RazerStats") }
    @{ Name="Razer Cortex/Central";     Paths=@("$env:LOCALAPPDATA\Razer\Razer Cortex","$env:LOCALAPPDATA\Razer\Razer Central"); Ext=@("*.json", "*.db"); Keys=@("macro","shortcut"); Proc=@("RazerCortex") }
    @{ Name="SteelSeries GG";           Paths=@("$env:APPDATA\SteelSeries\SteelSeries GG","$env:LOCALAPPDATA\SteelSeries"); Ext=@("*.json", "*.db"); Keys=@("macro","action","binding"); Proc=@("SteelSeriesGG","SteelSeriesEngine") }
    @{ Name="Corsair iCUE";             Paths=@("$env:APPDATA\Corsair\CUE5","$env:APPDATA\Corsair\CUE4","$env:APPDATA\Corsair"); Ext=@("*.cueprofile","*.json", "*.db"); Keys=@("macro","action","command"); Proc=@("iCUE","CorsairService") }
    @{ Name="ROCCAT Swarm";             Paths=@("$env:APPDATA\ROCCAT\SWARM","$env:APPDATA\ROCCAT\ROCCAT Swarm"); Ext=@("*.dat","*.xml"); Keys=@("macro","preset"); Proc=@("ROCCAT_Swarm_Monitor") }
    @{ Name="Glorious CORE";            Paths=@("$env:LOCALAPPDATA\Glorious\Glorious CORE","$env:APPDATA\Glorious","$env:LOCALAPPDATA\Glorious"); Ext=@("*.json"); Keys=@("macro","key","assignment","sequence"); Proc=@("GloriousCORE") }
    @{ Name="ASUS Armoury Crate";       Paths=@("$env:LOCALAPPDATA\ASUS\ArmouryCrate","$env:PROGRAMDATA\ASUS\ArmouryCrate"); Ext=@("*.json","*.xml"); Keys=@("macro","key","action"); Proc=@("ArmouryCrate") }
    @{ Name="Bloody / A4Tech";          Paths=@("$env:LOCALAPPDATA\Bloody","$env:PROGRAMDATA\Bloody"); Ext=@("*.dat","*.json","*.xml","*.bin"); Keys=@("macro","script","shot"); Proc=@("Bloody7","A4Tech") }
    @{ Name="MSI Center/Dragon";        Paths=@("$env:APPDATA\MSI\MSI Center","$env:APPDATA\MSI\Dragon Center"); Ext=@("*.json","*.db"); Keys=@("macro"); Proc=@("MSICenter","DragonCenter") }
    @{ Name="HyperX NGENUITY";          Paths=@("$env:APPDATA\HyperX\NGENUITY","$env:LOCALAPPDATA\Packages\33C30B79.HyperXNGenuity_0a78dr3hq0pvt"); Ext=@("*.db","*.json"); Keys=@("macro"); Proc=@("NGENUITY") }
    @{ Name="Pulsar Fusion";            Paths=@("$env:APPDATA\Pulsar"); Ext=@("*.json"); Keys=@("macro"); Proc=@("Pulsar") }
    @{ Name="Finalmouse";               Paths=@("$env:APPDATA\Finalmouse"); Ext=@("*.db"); Keys=@("macro"); Proc=@("Finalmouse") }
    @{ Name="ZOWIE";                    Paths=@("$env:APPDATA\ZOWIE"); Ext=@("*.json"); Keys=@("macro"); Proc=@("ZOWIE") }
    @{ Name="Endgame Gear";             Paths=@("$env:APPDATA\Endgame Gear"); Ext=@("*.db"); Keys=@("macro"); Proc=@("EndgameGear") }
    @{ Name="Alienware CC";             Paths=@("C:\ProgramData\Alienware\AlienWare Command Center","$env:PROGRAMDATA\Alienware\AWCCService"); Ext=@("*.json","*.xml"); Keys=@("macro"); Proc=@("AWCC") }
    @{ Name="Cougar UIX";               Paths=@("$env:APPDATA\Cougar\UIX"); Ext=@("*.json"); Keys=@("macro"); Proc=@("UIX") }
    @{ Name="Redragon";                 Paths=@("$env:APPDATA\REDRAGON\GamingMouse","$env:APPDATA\Redragon"); Ext=@("*.json","*.ini"); Keys=@("macro"); Proc=@("Redragon") }

    # Enthusiast Brands
    @{ Name="LAMZU Software";           Paths=@("$env:LOCALAPPDATA\LAMZU"); Ext=@("*.json", "*.cfg"); Keys=@("macro", "delay"); Proc=@("LAMZU") }
    @{ Name="Pwnage Software";          Paths=@("$env:LOCALAPPDATA\Pwnage"); Ext=@("*.json", "*.ini"); Keys=@("macro"); Proc=@("Pwnage") }
    @{ Name="VGN/ATK Hub";              Paths=@("$env:APPDATA\ATK Hub", "$env:LOCALAPPDATA\VGN Hub"); Ext=@("*.json"); Keys=@("macro", "action"); Proc=@("VGN", "ATK") }
    @{ Name="Darmoshark Software";      Paths=@("$env:LOCALAPPDATA\Darmoshark"); Ext=@("*.json", "*.cfg"); Keys=@("macro"); Proc=@("Darmoshark") }
    @{ Name="WLmouse Software";         Paths=@("$env:APPDATA\WLmouse"); Ext=@("*.json", "*.cfg"); Keys=@("macro"); Proc=@("WLmouse") }
    @{ Name="Mad Catz";                 Paths=@("$env:PUBLIC\Documents\Mad Catz"); Ext=@("*.pr0"); Keys=@("macro", "command"); Proc=@("MadCatz") }
    @{ Name="Machenike";                Paths=@("$env:APPDATA\Machenike"); Ext=@("*.json"); Keys=@("macro"); Proc=@("Machenike") }
    @{ Name="Delux";                    Paths=@("$env:LOCALAPPDATA\Delux"); Ext=@("*.json"); Keys=@("macro"); Proc=@("Delux") }
    @{ Name="Swiftpoint";               Paths=@("$env:LOCALAPPDATA\Swiftpoint"); Ext=@("*.cfg"); Keys=@("macro"); Proc=@("Swiftpoint") }
    @{ Name="UtechSmart";               Paths=@("$env:APPDATA\UtechSmart"); Ext=@("*.json"); Keys=@("macro"); Proc=@("UtechSmart") }

    # Generic
    @{ Name="AutoHotkey";               Paths=@("$env:USERPROFILE\Documents"); Ext=@("*.ahk"); Keys=@("Send","Sleep","Click"); Proc=@("AutoHotkey", "AutoHotkeyUX") }
    @{ Name="X-Mouse Button Control";   Paths=@("$env:APPDATA\Highresolution Enterprises\XMouseButtonControl"); Ext=@("*.xml"); Keys=@("button", "simulated", "macro"); Proc=@("XMouseButtonControl") }
    @{ Name="DS4Windows";               Paths=@("$env:APPDATA\DS4Windows"); Ext=@("*.xml", "*.json"); Keys=@("macro", "action"); Proc=@("DS4Windows") }
    @{ Name="Jitbit Macro Recorder";    Paths=@("$env:APPDATA\Jitbit\MacroRecorder"); Ext=@("*.mcr"); Keys=@(); Proc=@("MacroRecorder") }
    @{ Name="Pulover Macro Creator";    Paths=@("$env:APPDATA\MacroCreator"); Ext=@("*.pmc"); Keys=@(); Proc=@("MacroCreator") }
    @{ Name="TGMacro";                  Paths=@("$env:APPDATA\TGMacro"); Ext=@("*.tkm"); Keys=@(); Proc=@("TGMacro") }
    @{ Name="reWASD";                   Paths=@("$env:PROGRAMDATA\Disc Soft\reWASD"); Ext=@("*.rewasd"); Keys=@("macro", "combo"); Proc=@("reWASD") }
    @{ Name="MacroGamer";               Paths=@("$env:APPDATA\MacroGamer"); Ext=@("*.mg"); Keys=@(); Proc=@("MacroGamer") }
    @{ Name="OP AutoClicker";           Paths=@("$env:APPDATA\OPAutoClicker"); Ext=@("*.ini"); Keys=@(); Proc=@("OPAutoClicker") }
    @{ Name="GS Auto Clicker";          Paths=@("$env:APPDATA\GSAutoClicker"); Ext=@("*.ini"); Keys=@(); Proc=@("GSAutoClicker") }
    @{ Name="SpeedAutoClicker";         Paths=@("$env:APPDATA\SpeedAutoClicker"); Ext=@("*.cfg"); Keys=@(); Proc=@("SpeedAutoClicker") }
    @{ Name="TinyTask";                 Paths=@("$env:APPDATA\TinyTask"); Ext=@("*.rec"); Keys=@(); Proc=@("TinyTask") }
    @{ Name="Wootility";                Paths=@("$env:APPDATA\wootility"); Ext=@("*.json"); Keys=@("macro"); Proc=@("Wootility") }
    @{ Name="VIA Config";               Paths=@("$env:APPDATA\VIA"); Ext=@("*.json"); Keys=@("macro"); Proc=@("VIA") }
    @{ Name="JoyToKey";                 Paths=@("$env:USERPROFILE\Documents\JoyToKey"); Ext=@("*.cfg"); Keys=@("macro"); Proc=@("JoyToKey") }
    @{ Name="AntiMicroX";               Paths=@("$env:LOCALAPPDATA\antimicrox"); Ext=@("*.xml"); Keys=@("macro"); Proc=@("antimicrox") }
    @{ Name="Murgee Auto Clicker";      Paths=@("$env:APPDATA\Murgee\Auto Clicker"); Ext=@("*.mac"); Keys=@(); Proc=@("AutoClicker") }
    @{ Name="PTFB Pro";                 Paths=@("$env:PROGRAMDATA\Technology Lighthouse\PTFB Pro"); Ext=@("*.cfg"); Keys=@(); Proc=@("PTFBPro") }
    @{ Name="GhostMouse";               Paths=@("$env:APPDATA\GhostMouse"); Ext=@("*.rms"); Keys=@(); Proc=@("GhostMouse") }
    @{ Name="InputMapper";              Paths=@("$env:APPDATA\InputMapper"); Ext=@("*.xml"); Keys=@(); Proc=@("InputMapper") }
    @{ Name="Mini Mouse Macro";         Paths=@("$env:APPDATA\MiniMouseMacro"); Ext=@("*.mmmac"); Keys=@(); Proc=@("MiniMouseMacro") }
    @{ Name="Macro Toolworks";          Paths=@("$env:APPDATA\MacroToolworks"); Ext=@("*.tw"); Keys=@(); Proc=@("MacroToolworks") }
    @{ Name="UCR";                      Paths=@("$env:APPDATA\UCR"); Ext=@("*.xml"); Keys=@(); Proc=@("UCR") }
    @{ Name="Perfect Automation";       Paths=@("$env:APPDATA\Perfect Automation"); Ext=@("*.pam"); Keys=@(); Proc=@("PerfectAutomation") }
    @{ Name="Auto Click Typer";         Paths=@("$env:APPDATA\AutoClickTyper"); Ext=@("*.act"); Keys=@(); Proc=@("AutoClickTyper") }
    @{ Name="Free Mouse Auto Clicker";  Paths=@("$env:APPDATA\Free Mouse Auto Clicker"); Ext=@("*.fac"); Keys=@(); Proc=@("FreeMouseAutoClicker") }
    @{ Name="Auto Keyboard Presser";    Paths=@("$env:APPDATA\Auto Keyboard Presser"); Ext=@("*.akp"); Keys=@(); Proc=@("AutoKeyboardPresser") }
    @{ Name="Easy Macro Recorder";      Paths=@("$env:APPDATA\Easy Macro Recorder"); Ext=@("*.emr"); Keys=@(); Proc=@("EasyMacroRecorder") }
    @{ Name="AutoIt";                   Paths=@("$env:USERPROFILE\Documents"); Ext=@("*.au3"); Keys=@("MouseClick","Send"); Proc=@("AutoIt3") }
    
    # Rare / Niche
    @{ Name="Xenon200";                 Paths=@("C:\Program Files (x86)\Xenon200"); Ext=@("*.ini","*.cfg"); Keys=@("macro"); Proc=@("Xenon200") }
    @{ Name="T16 / BY-COMBO";           Paths=@("$env:LOCALAPPDATA\BY-COMBO","$env:APPDATA\BYCOMBO-2"); Ext=@("*.dct","*.Mac"); Keys=@("macro"); Proc=@("BYCOMBO") }
    @{ Name="Marvo BY-8801";            Paths=@("$env:LOCALAPPDATA\BY-8801-GM917-v108"); Ext=@("*.dct"); Keys=@("macro"); Proc=@("Marvo") }
    @{ Name="Ajazz";                    Paths=@("$env:LOCALAPPDATA\BYCOMBO-2\Mac","$env:APPDATA\BYCOMBO-2\Mac"); Ext=@("*.Mac"); Keys=@("macro"); Proc=@("Ajazz") }
    @{ Name="KROM KOLT";                Paths=@("$env:LOCALAPPDATA\VirtualStore\Program Files (x86)\KROM KOLT\Config"); Ext=@("*.dat"); Keys=@("macro"); Proc=@("Krom") }
    @{ Name="Blackweb";                 Paths=@("C:\Blackweb Gaming AP\config"); Ext=@("*.ini"); Keys=@("macro"); Proc=@("Blackweb") }
    @{ Name="SPC Gear";                 Paths=@("C:\Program Files (x86)\SPC Gear"); Ext=@("*.cfg","*.ini"); Keys=@("macro"); Proc=@("SPCGear") }
    @{ Name="Ayax";                     Paths=@("C:\Program Files\AYAX GamingMouse"); Ext=@("*.ini"); Keys=@("macro"); Proc=@("Ayax") }
    @{ Name="Marsgaming MMGX";          Paths=@("C:\Program Files (x86)\MARSGAMING\MMGX"); Ext=@("*.ini","*.macro"); Keys=@("macro"); Proc=@("MMGX") }
    @{ Name="Motospeed";                Paths=@("C:\Program Files (x86)\MotoSpeed Gaming Mouse"); Ext=@("*.ini"); Keys=@("macro"); Proc=@("Motospeed") }
    @{ Name="CoolerMaster MasterPlus";  Paths=@("C:\Program Files (x86)\CoolerMaster\MasterPlus"); Ext=@("*.json"); Keys=@("macro"); Proc=@("MasterPlus") }
    @{ Name="Fantech VX7";              Paths=@("C:\Program Files (x86)\FANTECH VX7 Gaming Mouse"); Ext=@("*.ini"); Keys=@("macro"); Proc=@("Fantech") }
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
    $Host.UI.RawUI.WindowTitle = "MacroDetector v6.0"
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

    Write-Host "  MacroDetector v6.0" -ForegroundColor Magenta -NoNewline
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
                    $allModFiles = Get-ChildItem -Path $c.FilePath -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $cutoff }
                    if ($allModFiles.Count -gt 0) {
                        Write-Host "        [?] FOLDER ACTIVITY DETECTED (NO EXPLICIT MACRO STRINGS FOUND IN FILES):" -ForegroundColor Yellow
                        foreach ($mdf in $allModFiles) {
                            Write-Host "            - $($mdf.Name)  (Modified: $($mdf.LastWriteTime))" -ForegroundColor DarkGray
                        }
                    } else {
                        Write-Host "        -> Folder timestamp changed, but no specific files inside were modified." -ForegroundColor DarkGray
                    }
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
                    Write-Host "        [?] CONFIG FILE MODIFIED (NO EXPLICIT MACRO STRINGS FOUND): " -NoNewline -ForegroundColor Yellow
                    Write-Host "$(Split-Path $c.FilePath -Leaf)" -ForegroundColor White
                    Write-Host "            FULL PATH: " -NoNewline -ForegroundColor DarkGray
                    Write-Host "$($c.FilePath)" -ForegroundColor DarkGray
                    Write-Host "            MODIFIED: " -NoNewline -ForegroundColor DarkGray
                    Write-Host "$($c.LastModified)" -ForegroundColor White
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
