Install-Module Invoke-SqlCmd2 -Scope CurrentUser -Force -ErrorAction SilentlyContinue

function ExportEventToNewRelic ($eventType, $event, $APIKey, $AccountId) {
    $headers = @{
        "X-Insert-Key" = $APIKey
    }
    $event | Add-Member -NotePropertyName eventType -NotePropertyValue $eventType
    $eventJson = ConvertTo-Json -InputObject $event
    $response = Invoke-RestMethod -Uri "https://insights-collector.newrelic.com/v1/accounts/$AccountId/events" -Method Post -Body $eventJson -ContentType "application/json" -Headers $headers
    return $response.success
}

if ($(Test-Path config.json) -eq $false) {
    Get-Content .\config.json.template | Out-File config.json
    Write-Warning "Created config.json from template file. Edit config.json and run the script again"
    exit
}
$configuration = Get-Content config.json | ConvertFrom-Json

if ($(Test-Path $configuration.ScriptFileName) -eq $false) {
    "SELECT 'Edit this query file' AS [Message]" | Out-File $configuration.ScriptFileName
    Write-Warning "Created $($configuration.ScriptFileName) script file. Edit $($configuration.ScriptFileName) and run the script again"
    exit
}
Invoke-Sqlcmd2 -ServerInstance $configuration.ServerName -InputFile $configuration.ScriptFileName | Select-Object * -ExcludeProperty ItemArray, Table, RowError, RowState, HasErrors | ConvertTo-Json | Out-File -FilePath $configuration.OutputFileName

$md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
$utf8 = new-object -TypeName System.Text.UTF8Encoding
$currentHistory = Get-Content $configuration.OutputFileName | ConvertFrom-Json 
if (Test-Path $configuration.ExportHistoryFileName) {
    $exportHistory = Get-Content $configuration.ExportHistoryFileName
} else {
    $exportHistory = $()
}

foreach ($item in $currentHistory) {
    $itemJson = ConvertTo-Json -InputObject $item
    $hash = [System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($itemJson)))
    if ($item.RunStatus -eq 0 -and $exportHistory -notcontains $hash) {
        $success = ExportEventToNewRelic -eventType $configuration.EventType -event $item -AccountId $configuration.NewRelicAccountId -APIKey $configuration.NewRelicAPIKey 
        if ($success) {
            Out-File -FilePath $configuration.ExportHistoryFileName -InputObject $hash -Append
        } else {
            Write-Error "Failed to post event to New Relic API"
        }
    }
}