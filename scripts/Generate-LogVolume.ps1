<#
  Generate-LogVolume.ps1

  Generates realistic Windows Event Log traffic across System, Application,
  Security and a custom "WinLogGen" channel, targeting ~100GB/day with
  diurnal load shaping and random volume spikes.

  MUST be run as Administrator (writes to System/Application logs, manages
  audit policy, creates a local test account, reconfigures log retention).

  Intended for lab / SIEM-ingestion / log-pipeline capacity testing only.
  Run on a disposable/test machine — this deliberately disables account
  lockout for one dedicated test account and grows event log files large.

  Usage:
    .\Generate-LogVolume.ps1 -Setup            # one-time provisioning
    .\Generate-LogVolume.ps1 -Run               # start generating (foreground)
    .\Generate-LogVolume.ps1 -Run -AsTask       # register as a Scheduled Task so it survives logoff/reboot
    .\Generate-LogVolume.ps1 -Stop              # signal a running instance to stop
#>

[CmdletBinding()]
param(
    [switch]$Setup,
    [switch]$Run,
    [switch]$Stop,
    [switch]$AsTask,
    [double]$TargetGBPerDay = 100,
    [string]$RootPath = 'C:\LogSim'
)

$ErrorActionPreference = 'Stop'
$ArchivePath = Join-Path $RootPath 'Archive'
$StateFile   = Join-Path $RootPath 'state.json'
$StopFlag    = Join-Path $RootPath 'STOP'
$WinLogGenChannel = 'WinLogGen'
$TestUser    = 'svc_logsim'

# ---------------------------------------------------------------------------
# SETUP
# ---------------------------------------------------------------------------
function Invoke-Setup {
    if (-not ([Security.Principal.WindowsIdentity]::GetCurrent()).Groups -contains 'S-1-5-32-544') {
        Write-Warning "Run this from an elevated (Administrator) PowerShell session."
    }

    New-Item -ItemType Directory -Force -Path $RootPath, $ArchivePath | Out-Null

    # --- Custom channel: WinLogGen -----------------------------------------
    if (-not [System.Diagnostics.EventLog]::Exists($WinLogGenChannel)) {
        New-EventLog -LogName $WinLogGenChannel -Source 'OrderService'
        New-EventLog -LogName $WinLogGenChannel -Source 'PaymentGateway'
        New-EventLog -LogName $WinLogGenChannel -Source 'ApiGateway'
        Write-Host "Created custom event log channel: $WinLogGenChannel"
    }

    # --- Make sure normal-app sources exist for System/Application --------
    foreach ($src in 'AppSimSvc') {
        if (-not [System.Diagnostics.EventLog]::SourceExists($src)) {
            New-EventLog -LogName Application -Source $src
        }
    }

    # --- Grow log file sizes so they can absorb sustained volume -----------
    # 4GB is the practical ceiling for classic .evtx; we rely on a periodic
    # export+clear job (Start-Archiver) to keep the live file from filling up
    # while still accumulating the full day's volume on disk under Archive\.
    foreach ($chan in 'System','Application','Security',$WinLogGenChannel) {
        wevtutil sl $chan /ms:4294967296 /rt:false   # 4GB max, overwrite-as-needed
    }

    # --- Audit policy: make real logon/logoff/privilege events fire --------
    auditpol /set /subcategory:"Logon" /success:enable /failure:enable
    auditpol /set /subcategory:"Logoff" /success:enable /failure:enable
    auditpol /set /subcategory:"Special Logon" /success:enable
    auditpol /set /subcategory:"Account Lockout" /success:enable /failure:enable

    # --- Disposable test account used purely to generate real Security events
    if (-not (Get-LocalUser -Name $TestUser -ErrorAction SilentlyContinue)) {
        $pwd = ConvertTo-SecureString 'L0gSim-Temp!2024' -AsPlainText -Force
        New-LocalUser -Name $TestUser -Password $pwd -PasswordNeverExpires `
            -Description "Disposable log-sim test account" | Out-Null
        Add-LocalGroupMember -Group 'Users' -Member $TestUser -ErrorAction SilentlyContinue
    }
    # Disable lockout machine-wide is intrusive; instead just keep the threshold
    # generous enough that the simulator's deliberate failed logons don't lock
    # the box's real accounts. We only ever target $TestUser for failures.
    net accounts /lockoutthreshold:0 | Out-Null

    Write-Host "Setup complete. Channels widened, audit policy enabled, test account '$TestUser' ready."
}

# ---------------------------------------------------------------------------
# REALISTIC CONTENT TEMPLATES (real Windows provider/event-id shapes)
# ---------------------------------------------------------------------------
$Script:SystemTemplates = @(
    @{ Source='Service Control Manager'; Id=7036; Type='Information';
       Msg={ param($svc,$state) "The $svc service entered the $state state." } ;
       Args={ @(('wuauserv','BITS','Schedule','EventLog','Dnscache','LanmanWorkstation' | Get-Random), ('running','stopped' | Get-Random)) } }
    @{ Source='Disk'; Id=51; Type='Warning';
       Msg={ param($dev) "An error was detected on device \Device\Harddisk0\DR$dev during a paging operation." } ;
       Args={ @((0..3 | Get-Random)) } }
    @{ Source='Kernel-General'; Id=16; Type='Information';
       Msg={ param($delta) "The system time has changed to (Local) by $delta seconds from the previous time." } ;
       Args={ @((1..30 | Get-Random)) } }
)

$Script:AppTemplates = @(
    @{ Source='Application Error'; Id=1000; Type='Error';
       Msg={ param($proc,$ver,$mod,$offset) "Faulting application name: $proc, version: $ver, time stamp: 0x5f3a1c20`nFaulting module name: $mod, version: $ver, time stamp: 0x5f3a1c20`nException code: 0xc0000005`nFault offset: $offset" } ;
       Args={ @((('contoso-app.exe','billing-svc.exe','reportgen.exe') | Get-Random), '10.0.19041.1', (('ntdll.dll','kernel32.dll','msvcrt.dll') | Get-Random), ('0x{0:x8}' -f (Get-Random -Maximum 0xFFFFFF))) } }
    @{ Source='MsiInstaller'; Id=1033; Type='Information';
       Msg={ param($prod) "Windows Installer installed the product. Product Name: $prod. Installation success or error status: 0." } ;
       Args={ @((('Contoso Agent','Reporting Module','Update Package 24.06') | Get-Random)) } }
    @{ Source='ESENT'; Id=102; Type='Information';
       Msg={ param($db) "svchost ($PID) Instance: The database engine started a new instance for database $db." } ;
       Args={ @((('SoftwareDistribution.db','WindowsUpdate.db') | Get-Random)) } }
)

$Script:WinLogGenTemplates = @(
    @{ Source='OrderService'; Id=2001; Type='Information';
       Msg={ param($orderId,$amount,$ms) "<Order id='$orderId' amount='$amount' currency='USD' latencyMs='$ms' status='Completed'/>" } ;
       Args={ @(("ORD-{0}" -f (Get-Random -Maximum 999999)), [math]::Round((Get-Random -Minimum 5 -Maximum 500.0),2), (Get-Random -Minimum 10 -Maximum 800)) } }
    @{ Source='PaymentGateway'; Id=3002; Type='Warning';
       Msg={ param($txn,$code) "<Payment txn='$txn' result='Declined' code='$code'/>" } ;
       Args={ @(("TXN-{0}" -f (Get-Random -Maximum 999999)), (('51','05','61') | Get-Random)) } }
    @{ Source='ApiGateway'; Id=4003; Type='Information';
       Msg={ param($route,$status,$ms) "<Request route='$route' statusCode='$status' durationMs='$ms'/>" } ;
       Args={ @((('/api/v1/orders','/api/v1/users','/api/v1/payments') | Get-Random), (200,200,200,404,500 | Get-Random), (Get-Random -Minimum 1 -Maximum 2000)) } }
)

function Write-TemplatedEvent {
    param([hashtable]$Template)
    $argv = & $Template.Args
    $message = & $Template.Msg @argv
    Write-EventLog -LogName $(if ($Template.Source -in 'OrderService','PaymentGateway','ApiGateway') { $WinLogGenChannel }
                               elseif ($Template.Source -in 'Service Control Manager','Disk','Kernel-General') { 'System' }
                               else { 'Application' }) `
                    -Source $Template.Source -EventId $Template.Id -EntryType $Template.Type -Message $message
    return [System.Text.Encoding]::Unicode.GetByteCount($message) + 512   # + approx XML/header overhead
}

function Invoke-SecurityLogonCycle {
    # Real 4624/4625/4634 events generated by genuine authentication, not fabricated XML.
    $bytesWritten = 0
    $goodCred = New-Object System.Management.Automation.PSCredential($TestUser, (ConvertTo-SecureString 'L0gSim-Temp!2024' -AsPlainText -Force))
    $badCred  = New-Object System.Management.Automation.PSCredential($TestUser, (ConvertTo-SecureString ("bad{0}" -f (Get-Random)) -AsPlainText -Force))
    try {
        if ((Get-Random -Maximum 4) -eq 0) {
            Start-Process -FilePath 'cmd.exe' -ArgumentList '/c exit' -Credential $badCred -WindowStyle Hidden -ErrorAction SilentlyContinue
        } else {
            $p = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c exit' -Credential $goodCred -WindowStyle Hidden -PassThru -ErrorAction SilentlyContinue
            $p | Wait-Process -Timeout 5 -ErrorAction SilentlyContinue
        }
    } catch { }
    $bytesWritten = 1800   # typical 4624/4625 event size on disk
    return $bytesWritten
}

# ---------------------------------------------------------------------------
# LOAD SHAPE: diurnal baseline + random spikes
# ---------------------------------------------------------------------------
function Get-RateMultiplier {
    $hour = (Get-Date).TimeOfDay.TotalHours
    $diurnal = 0.4 + 0.6 * [math]::Sin([math]::PI * ($hour - 6) / 14)   # business-hours bump
    if ($diurnal -lt 0.15) { $diurnal = 0.15 }

    $stateFile = Join-Path $RootPath 'spike.json'
    $now = Get-Date
    $spike = 1.0
    if (Test-Path $stateFile) {
        $s = Get-Content $stateFile -Raw | ConvertFrom-Json
        if ($now -lt [datetime]$s.Until) { $spike = $s.Mult }
    }
    if ($spike -eq 1.0 -and (Get-Random -Maximum 600) -eq 0) {
        $spike = Get-Random -Minimum 3.0 -Maximum 9.0
        $until = $now.AddMinutes((Get-Random -Minimum 5 -Maximum 20))
        @{ Until = $until; Mult = $spike } | ConvertTo-Json | Set-Content $stateFile
        Write-Host "[$now] VOLUME SPIKE x$([math]::Round($spike,1)) until $until"
    }
    return [math]::Max(0.1, $diurnal) * $spike
}

# ---------------------------------------------------------------------------
# ARCHIVER: keeps live .evtx from filling up while preserving total volume
# ---------------------------------------------------------------------------
function Start-Archiver {
    $job = Start-Job -Name 'LogSimArchiver' -ScriptBlock {
        param($ArchivePath, $StopFlag)
        while (-not (Test-Path $StopFlag)) {
            foreach ($chan in 'System','Application','Security','WinLogGen') {
                try {
                    $stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
                    $safeChan = $chan -replace '[\\/]','-'
                    $dest = Join-Path $ArchivePath "$safeChan-$stamp.evtx"
                    wevtutil epl $chan $dest /ow:true
                    wevtutil cl $chan
                } catch { }
            }
            Start-Sleep -Seconds 1800   # archive every 30 min
        }
    } -ArgumentList $ArchivePath, $StopFlag
    return $job
}

# ---------------------------------------------------------------------------
# MAIN GENERATION LOOP
# ---------------------------------------------------------------------------
function Invoke-Run {
    if (Test-Path $StopFlag) { Remove-Item $StopFlag -Force }
    $archiverJob = Start-Archiver

    $targetBytesPerDay = $TargetGBPerDay * 1GB
    $weights = @{ System = 0.20; Application = 0.30; Security = 0.30; WinLogGen = 0.20 }
    $avgEventBytes = 1700
    $baseEventsPerSec = ($targetBytesPerDay / 86400) / $avgEventBytes

    Write-Host "Target: $TargetGBPerDay GB/day  ~baseline $([math]::Round($baseEventsPerSec,1)) events/sec (pre-shaping)"

    $totalBytesToday = 0
    $dayStamp = (Get-Date).Date

    while ($true) {
        if (Test-Path $StopFlag) { break }
        if ((Get-Date).Date -ne $dayStamp) { $totalBytesToday = 0; $dayStamp = (Get-Date).Date }

        $mult = Get-RateMultiplier
        $eventsThisTick = [math]::Max(1, [int]($baseEventsPerSec * $mult))

        for ($i = 0; $i -lt $eventsThisTick; $i++) {
            $r = Get-Random -Minimum 0.0 -Maximum 1.0
            $bytes = 0
            if     ($r -lt $weights.System)                                            { $bytes = Write-TemplatedEvent -Template (Get-Random $Script:SystemTemplates) }
            elseif ($r -lt $weights.System + $weights.Application)                     { $bytes = Write-TemplatedEvent -Template (Get-Random $Script:AppTemplates) }
            elseif ($r -lt $weights.System + $weights.Application + $weights.Security) { $bytes = Invoke-SecurityLogonCycle }
            else                                                                        { $bytes = Write-TemplatedEvent -Template (Get-Random $Script:WinLogGenTemplates) }
            $totalBytesToday += $bytes
        }

        if ((Get-Random -Maximum 20) -eq 0) {
            Write-Host "[$(Get-Date -Format T)] mult=$([math]::Round($mult,2)) todaySoFar=$([math]::Round($totalBytesToday/1GB,2))GB"
        }
        Start-Sleep -Milliseconds 1000
    }

    Stop-Job $archiverJob -ErrorAction SilentlyContinue
    Remove-Job $archiverJob -ErrorAction SilentlyContinue
    Remove-Item $StopFlag -Force -ErrorAction SilentlyContinue
}

function Invoke-Stop {
    New-Item -ItemType Directory -Force -Path $RootPath | Out-Null
    New-Item -ItemType File -Force -Path $StopFlag | Out-Null
    Write-Host "Stop signal written. The running loop will exit within ~1s; archiver within ~30min poll (also stops on next check)."
}

function Register-AsTask {
    $action  = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" -Run -TargetGBPerDay $TargetGBPerDay"
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    Register-ScheduledTask -TaskName 'LogSimGenerator' -Action $action -Trigger $trigger -Principal $principal -Force | Out-Null
    Start-ScheduledTask -TaskName 'LogSimGenerator'
    Write-Host "Registered and started Scheduled Task 'LogSimGenerator'."
}

# ---------------------------------------------------------------------------
if ($Setup) { Invoke-Setup }
if ($Stop)  { Invoke-Stop }
if ($Run) {
    if ($AsTask) { Register-AsTask } else { Invoke-Run }
}
if (-not ($Setup -or $Run -or $Stop)) {
    Write-Host "Usage: .\Generate-LogVolume.ps1 -Setup | -Run [-AsTask] | -Stop"
}
