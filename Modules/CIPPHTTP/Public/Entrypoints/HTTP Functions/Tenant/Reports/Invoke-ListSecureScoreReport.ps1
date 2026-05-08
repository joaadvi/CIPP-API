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
            $AllProfileItems = Get-CIPPDbItem -TenantFilter 'allTenants' -Type 'SecureScoreControlProfiles'

            $ScoresByTenant = $AllScoreItems | Where-Object { $_.RowKey -ne 'SecureScore-Count' } | Group-Object -Property PartitionKey
            $ProfilesByTenant = @{}
            $AllProfileItems | Where-Object { $_.RowKey -ne 'SecureScoreControlProfiles-Count' } | ForEach-Object {
                if (-not $ProfilesByTenant.ContainsKey($_.PartitionKey)) {
                    $ProfilesByTenant[$_.PartitionKey] = [System.Collections.Generic.List[object]]::new()
                }
                $ProfilesByTenant[$_.PartitionKey].Add($_)
            }

            $TenantList = Get-Tenants -IncludeErrors

            foreach ($TenantGroup in $ScoresByTenant) {
                $TenantDomain = $TenantGroup.Name
                $TenantInfo = $TenantList | Where-Object { $_.defaultDomainName -eq $TenantDomain } | Select-Object -First 1
                if (-not $TenantInfo) { continue }

                try {
                    $Scores = $TenantGroup.Group | ForEach-Object { $_.Data | ConvertFrom-Json -ErrorAction SilentlyContinue } | Where-Object { $_ }
                    $Latest = $Scores | Sort-Object -Property createdDateTime -Descending | Select-Object -First 1
                    if (-not $Latest) { continue }

                    $ProfileMap = @{}
                    $TenantProfiles = $ProfilesByTenant[$TenantDomain]
                    if ($TenantProfiles) {
                        foreach ($ProfileItem in $TenantProfiles) {
                            $Profile = $ProfileItem.Data | ConvertFrom-Json -ErrorAction SilentlyContinue
                            if ($Profile) { $ProfileMap[$Profile.id] = $Profile }
                        }
                    }

                    $Result = Get-SecureScoreResult -Latest $Latest -ProfileMap $ProfileMap -TenantName ($TenantInfo.displayName ?? $TenantDomain)
                    $Results.Add($Result)
                } catch {
                    Write-LogMessage -API 'ListSecureScoreReport' -tenant $TenantDomain -message "Failed to process cached secure score: $($_.Exception.Message)" -Sev 'Warning'
                }
            }

            if ($Results.Count -eq 0) {
                $Results.Add([PSCustomObject]@{
                    Tenant         = 'No cached data available. Ensure the Secure Score cache is enabled in CIPP Settings > Backend > Cache Management.'
                    CurrentScore   = '-'
                    MaxScore       = '-'
                    Percentage     = '-'
                    VsAllTenants   = '-'
                    VsSimilarSize  = '-'
                    LicensedUsers  = '-'
                    Identity       = '-'
                    Data           = '-'
                    Device         = '-'
                    Apps           = '-'
                    Infrastructure = '-'
                })
            }
        } else {
            try {
                $Scores = New-CIPPDbRequest -TenantFilter $TenantFilter -Type 'SecureScore'
                $Profiles = New-CIPPDbRequest -TenantFilter $TenantFilter -Type 'SecureScoreControlProfiles'

                if (-not $Scores) {
                    $Scores = New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/security/secureScores?$top=1' -tenantid $TenantFilter -noPagination $true
                    $Profiles = New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/security/secureScoreControlProfiles' -tenantid $TenantFilter
                }

                $Latest = $Scores | Sort-Object -Property createdDateTime -Descending | Select-Object -First 1

                if ($Latest) {
                    $ProfileMap = @{}
                    foreach ($Profile in $Profiles) { $ProfileMap[$Profile.id] = $Profile }

                    $TenantInfo = Get-Tenants -TenantFilter $TenantFilter | Select-Object -First 1
                    $Result = Get-SecureScoreResult -Latest $Latest -ProfileMap $ProfileMap -TenantName ($TenantInfo.displayName ?? $TenantFilter)
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
    param($Latest, $ProfileMap, $TenantName)

    $Categories = @{}
    foreach ($Control in $Latest.controlScores) {
        $Cat = $Control.controlCategory
        if (-not $Categories.ContainsKey($Cat)) {
            $Categories[$Cat] = @{ score = 0; maxScore = 0 }
        }
        $Categories[$Cat].score += [double]$Control.score
        $MatchingProfile = $ProfileMap[$Control.controlName]
        if ($MatchingProfile) {
            $Categories[$Cat].maxScore += [double]$MatchingProfile.maxScore
        }
    }

    $CategoryPct = @{}
    foreach ($Cat in $Categories.Keys) {
        $CatData = $Categories[$Cat]
        if ($CatData.maxScore -gt 0) {
            $CategoryPct[$Cat] = [math]::Round(($CatData.score / $CatData.maxScore) * 100, 1)
        } else {
            $CategoryPct[$Cat] = 0
        }
    }

    $VsAllTenants = ($Latest.averageComparativeScores | Where-Object { $_.basis -eq 'AllTenants' }).averageScore
    $VsSimilar = ($Latest.averageComparativeScores | Where-Object { $_.basis -eq 'TotalSeats' }).averageScore
    $Percentage = if ($Latest.maxScore -gt 0) { [math]::Round(($Latest.currentScore / $Latest.maxScore) * 100, 1) } else { 0 }

    return [PSCustomObject]@{
        Tenant         = $TenantName
        CurrentScore   = [math]::Round($Latest.currentScore, 1)
        MaxScore       = [math]::Round($Latest.maxScore, 1)
        Percentage     = $Percentage
        VsAllTenants   = if ($VsAllTenants) { [math]::Round([double]$VsAllTenants, 1) } else { 'N/A' }
        VsSimilarSize  = if ($VsSimilar) { [math]::Round([double]$VsSimilar, 1) } else { 'N/A' }
        LicensedUsers  = $Latest.licensedUserCount
        Identity       = $CategoryPct['Identity'] ?? 0
        Data           = $CategoryPct['Data'] ?? 0
        Device         = $CategoryPct['Device'] ?? 0
        Apps           = $CategoryPct['Apps'] ?? 0
        Infrastructure = $CategoryPct['Infrastructure'] ?? 0
    }
}
