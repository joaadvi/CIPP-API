function Invoke-ListSecureScoreReport {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Tenant.Administration.Read
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $TenantFilter = $Request.Query.tenantFilter
    $Results = [System.Collections.Generic.List[object]]::new()

    try {
        if ($TenantFilter -eq 'AllTenants' -or [string]::IsNullOrWhiteSpace($TenantFilter)) {
            $AllScoreItems = Get-CIPPDbItem -TenantFilter 'allTenants' -Type 'SecureScore'
            $ScoresByTenant = $AllScoreItems | Where-Object { $_.RowKey -ne 'SecureScore-Count' } | Group-Object -Property PartitionKey
            $TenantList = Get-Tenants -IncludeErrors

            foreach ($TenantGroup in $ScoresByTenant) {
                $TenantDomain = $TenantGroup.Name
                $TenantInfo = $TenantList | Where-Object { $_.defaultDomainName -eq $TenantDomain } | Select-Object -First 1
                if (-not $TenantInfo) { continue }

                try {
                    $Scores = $TenantGroup.Group | ForEach-Object { $_.Data | ConvertFrom-Json -ErrorAction SilentlyContinue } | Where-Object { $_ }
                    $Latest = $Scores | Sort-Object -Property createdDateTime -Descending | Select-Object -First 1
                    if (-not $Latest) { continue }

                    $Result = Get-SecureScoreResult -Latest $Latest -TenantName ($TenantInfo.displayName ?? $TenantDomain)
                    $Results.Add($Result)
                } catch {
                    Write-LogMessage -API 'ListSecureScoreReport' -tenant $TenantDomain -message "Failed to process cached secure score: $($_.Exception.Message)" -Sev 'Warning'
                }
            }

            if ($Results.Count -eq 0) {
                $Results.Add([PSCustomObject]@{
                    Tenant         = 'No cached data. Enable Secure Score cache under CIPP Settings > Backend > Cache Management.'
                    CurrentScore   = 'N/A'
                    MaxScore       = 'N/A'
                    Percentage     = 'N/A'
                    VsAllTenants   = 'N/A'
                    VsSimilarSize  = 'N/A'
                    LicensedUsers  = 'N/A'
                    Identity       = 'N/A'
                    Data           = 'N/A'
                    Device         = 'N/A'
                    Apps           = 'N/A'
                    Infrastructure = 'N/A'
                })
            }
        } else {
            try {
                $Scores = New-CIPPDbRequest -TenantFilter $TenantFilter -Type 'SecureScore'

                if (-not $Scores) {
                    $Scores = New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/security/secureScores?$top=1' -tenantid $TenantFilter -noPagination $true
                }

                $Latest = $Scores | Sort-Object -Property createdDateTime -Descending | Select-Object -First 1

                if ($Latest) {
                    $TenantInfo = Get-Tenants -TenantFilter $TenantFilter | Select-Object -First 1
                    $Result = Get-SecureScoreResult -Latest $Latest -TenantName ($TenantInfo.displayName ?? $TenantFilter)
                    $Results.Add($Result)
                }
            } catch {
                $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
                Write-LogMessage -API 'ListSecureScoreReport' -tenant $TenantFilter -message "Failed to get secure score: $ErrorMessage" -Sev 'Warning'
                $Results.Add([PSCustomObject]@{
                    Tenant         = $TenantFilter
                    CurrentScore   = 'Error'
                    MaxScore       = 'Error'
                    Percentage     = 'Error'
                    VsAllTenants   = 'Error'
                    VsSimilarSize  = 'Error'
                    LicensedUsers  = 'Error'
                    Identity       = 'Error'
                    Data           = 'Error'
                    Device         = 'Error'
                    Apps           = 'Error'
                    Infrastructure = 'Error'
                })
            }
        }
    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        Write-LogMessage -API 'ListSecureScoreReport' -message "Secure Score Report failed: $ErrorMessage" -Sev 'Error'
        return ([HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::InternalServerError
                Body       = "Failed to generate report: $ErrorMessage"
            })
    }

    return ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = @($Results)
        })
}

function Get-SecureScoreResult {
    param($Latest, $TenantName)

    $CategoryScores = @{}
    foreach ($Control in $Latest.controlScores) {
        $Cat = $Control.controlCategory
        if (-not $CategoryScores.ContainsKey($Cat)) {
            $CategoryScores[$Cat] = 0
        }
        $CategoryScores[$Cat] += [double]$Control.score
    }

    $VsAllTenants = ($Latest.averageComparativeScores | Where-Object { $_.basis -eq 'AllTenants' }).averageScore
    $VsSimilar = ($Latest.averageComparativeScores | Where-Object { $_.basis -eq 'TotalSeats' }).averageScore
    $Percentage = if ($Latest.maxScore -gt 0) { [math]::Round(($Latest.currentScore / $Latest.maxScore) * 100, 1) } else { 0 }
    $UserCount = $Latest.licensedUserCount ?? $Latest.LicensedUserCount ?? $Latest.activeUserCount ?? 0

    return [PSCustomObject]@{
        Tenant         = $TenantName
        CurrentScore   = [math]::Round($Latest.currentScore, 1)
        MaxScore       = [math]::Round($Latest.maxScore, 1)
        Percentage     = $Percentage
        VsAllTenants   = if ($VsAllTenants) { [math]::Round([double]$VsAllTenants, 1) } else { 'N/A' }
        VsSimilarSize  = if ($VsSimilar) { [math]::Round([double]$VsSimilar, 1) } else { 'N/A' }
        LicensedUsers  = if ($UserCount -gt 0) { $UserCount } else { 'N/A' }
        Identity       = [math]::Round($CategoryScores['Identity'] ?? 0, 1)
        Data           = [math]::Round($CategoryScores['Data'] ?? 0, 1)
        Device         = [math]::Round($CategoryScores['Device'] ?? 0, 1)
        Apps           = [math]::Round($CategoryScores['Apps'] ?? 0, 1)
        Infrastructure = [math]::Round($CategoryScores['Infrastructure'] ?? 0, 1)
    }
}
