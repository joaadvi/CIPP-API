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

    if ($TenantFilter -eq 'AllTenants' -or [string]::IsNullOrWhiteSpace($TenantFilter)) {
        $Tenants = Get-Tenants -IncludeErrors
    } else {
        $Tenants = @(@{ defaultDomainName = $TenantFilter; displayName = $TenantFilter })
    }

    $Results = [System.Collections.Generic.List[object]]::new()

    foreach ($Tenant in $Tenants) {
        try {
            $TenantName = $Tenant.defaultDomainName
            $Score = New-GraphGetRequest -uri "https://graph.microsoft.com/beta/security/secureScores?`$top=1" -tenantid $TenantName -noPagination $true -ErrorAction Stop

            if (-not $Score -or -not $Score[0]) { continue }

            $Latest = $Score[0]

            $Profiles = New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/security/secureScoreControlProfiles' -tenantid $TenantName -ErrorAction Stop

            $ProfileMap = @{}
            foreach ($Profile in $Profiles) {
                $ProfileMap[$Profile.id] = $Profile
            }

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

            $Results.Add([PSCustomObject]@{
                Tenant          = $Tenant.displayName ?? $TenantName
                CurrentScore    = [math]::Round($Latest.currentScore, 1)
                MaxScore        = [math]::Round($Latest.maxScore, 1)
                Percentage      = $Percentage
                VsAllTenants    = if ($VsAllTenants) { [math]::Round($VsAllTenants, 1) } else { 'N/A' }
                VsSimilarSize   = if ($VsSimilar) { [math]::Round($VsSimilar, 1) } else { 'N/A' }
                LicensedUsers   = $Latest.licensedUserCount
                Identity        = $CategoryPct['Identity'] ?? 0
                Data            = $CategoryPct['Data'] ?? 0
                Device          = $CategoryPct['Device'] ?? 0
                Apps            = $CategoryPct['Apps'] ?? 0
                Infrastructure  = $CategoryPct['Infrastructure'] ?? 0
            })
        } catch {
            $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
            Write-LogMessage -API 'ListSecureScoreReport' -tenant $Tenant.defaultDomainName -message "Failed to get secure score: $ErrorMessage" -Sev 'Warning'
            $Results.Add([PSCustomObject]@{
                Tenant          = $Tenant.displayName ?? $Tenant.defaultDomainName
                CurrentScore    = 'Error'
                MaxScore        = 'Error'
                Percentage      = 'Error'
                VsAllTenants    = 'Error'
                VsSimilarSize   = 'Error'
                LicensedUsers   = 'Error'
                Identity        = 'Error'
                Data            = 'Error'
                Device          = 'Error'
                Apps            = 'Error'
                Infrastructure  = 'Error'
            })
        }
    }

    return ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = @($Results)
        })
}
