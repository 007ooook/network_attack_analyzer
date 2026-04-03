<#
.SYNOPSIS
    Windows 10 系统日志采集脚本
    用于收集系统、安全、应用程序等日志，支持自定义参数

.DESCRIPTION
    此脚本以管理员权限运行，可收集指定类型的Windows事件日志，并导出为CSV或EVTX格式
    支持设置时间范围、日志类型、导出路径等参数

.PARAMETER LogNames
    指定要收集的日志名称，多个日志用逗号分隔
    默认值: 'System', 'Security', 'Application'

.PARAMETER ExportPath
    指定导出文件的保存路径
    默认值: 当前用户桌面\WindowsLogs

.PARAMETER ExportFormat
    指定导出格式，支持 CSV 或 EVTX
    默认值: CSV

.PARAMETER Days
    指定收集最近几天的日志
    默认值: 7

.PARAMETER IncludeAll
    收集所有可用的Windows事件日志

.EXAMPLE
    # 收集默认日志（系统、安全、应用程序），保存到桌面
    .\windows_log_collector.ps1

.EXAMPLE
    # 收集系统和安全日志，保存到D盘，格式为EVTX
    .\windows_log_collector.ps1 -LogNames 'System','Security' -ExportPath 'D:\Logs' -ExportFormat 'EVTX'

.EXAMPLE
    # 收集最近3天的所有日志
    .\windows_log_collector.ps1 -IncludeAll -Days 3

.NOTES
    作者: Network Attack Analyzer Team
    版本: 1.0
    日期: 2026-03-31
    要求: 以管理员权限运行
#>

[CmdletBinding()]
param (
    [string[]]$LogNames = @('System', 'Security', 'Application'),
    [string]$ExportPath = "$env:USERPROFILE\Desktop\WindowsLogs",
    [ValidateSet('CSV', 'EVTX')]
    [string]$ExportFormat = 'CSV',
    [int]$Days = 7,
    [switch]$IncludeAll
)

# 检查是否以管理员权限运行
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "错误: 请以管理员权限运行此脚本!" -ForegroundColor Red
    Start-Sleep -Seconds 3
    exit 1
}

# 创建导出目录
if (-not (Test-Path $ExportPath)) {
    try {
        New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null
        Write-Host "创建导出目录: $ExportPath" -ForegroundColor Green
    } catch {
        Write-Host "错误: 无法创建导出目录: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# 如果指定了IncludeAll，获取所有可用日志
if ($IncludeAll) {
    try {
        $LogNames = (Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | Where-Object {$_.IsEnabled} | Select-Object -ExpandProperty LogName)
        Write-Host "已获取所有可用日志，共 $($LogNames.Count) 个" -ForegroundColor Green
    } catch {
        Write-Host "错误: 无法获取日志列表: $($_.Exception.Message)" -ForegroundColor Red
        exit 1
    }
}

# 计算时间范围
$StartTime = (Get-Date).AddDays(-$Days)
Write-Host "收集从 $($StartTime.ToString('yyyy-MM-dd HH:mm:ss')) 到现在的日志" -ForegroundColor Yellow

# 处理每个日志
foreach ($LogName in $LogNames) {
    Write-Host "\n正在处理日志: $LogName" -ForegroundColor Cyan
    
    try {
        # 检查日志是否存在
        if (-not (Get-WinEvent -ListLog $LogName -ErrorAction SilentlyContinue)) {
            Write-Host "警告: 日志 $LogName 不存在或未启用" -ForegroundColor Yellow
            continue
        }
        
        # 生成文件名
        $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
        if ($ExportFormat -eq 'CSV') {
            $fileName = "$ExportPath\$LogName`_$timestamp.csv"
            # 导出为CSV
            Get-WinEvent -LogName $LogName -StartTime $StartTime -ErrorAction SilentlyContinue | 
            Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message | 
            Export-Csv -Path $fileName -Encoding UTF8 -NoTypeInformation
        } else {
            $fileName = "$ExportPath\$LogName`_$timestamp.evtx"
            # 导出为EVTX
            wevtutil epl $LogName $fileName /q:"*[System[TimeCreated[timediff(@SystemTime) <= $($Days * 86400000)]]"
        }
        
        if (Test-Path $fileName) {
            $fileSize = (Get-Item $fileName).Length / 1MB
            Write-Host "成功导出: $fileName (大小: $($fileSize.ToString('0.00')) MB)" -ForegroundColor Green
        } else {
            Write-Host "警告: 导出文件不存在，可能没有符合条件的日志" -ForegroundColor Yellow
        }
        
    } catch {
        Write-Host "错误处理日志 $LogName: $($_.Exception.Message)" -ForegroundColor Red
        continue
    }
}

# 生成汇总报告
$reportFile = "$ExportPath\LogCollection_Report_$timestamp.txt"
$reportContent = @"
Windows 10 日志采集报告
======================
采集时间: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
采集范围: 最近 $Days 天
导出格式: $ExportFormat
导出路径: $ExportPath
采集的日志:
$($LogNames | ForEach-Object { "- $_" } | Out-String)

文件列表:
$((Get-ChildItem -Path $ExportPath -Name | Where-Object { $_ -like "*$timestamp*" } | ForEach-Object { "- $_" } | Out-String))

脚本执行完成！
"@

$reportContent | Out-File -FilePath $reportFile -Encoding UTF8
Write-Host "\n生成报告: $reportFile" -ForegroundColor Green
Write-Host "\n日志采集完成！" -ForegroundColor Green
Write-Host "\n按任意键退出..." -ForegroundColor Gray
$null = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
