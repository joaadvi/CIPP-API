function Invoke-CIPPStandardNudgeMFA {
    <#
    .FUNCTIONALITY
        Internal
    .COMPONENT
        (APIName) NudgeMFA
    .SYNOPSIS
        (Label) Sets the state for the request to setup Authenticator
    .DESCRIPTION
        (Helptext) Sets the state of the registration campaign for the tenant
        (DocsDescription) Sets the state of the registration campaign for the tenant. If enabled nudges users to set up the Microsoft Authenticator during sign-in.
    .NOTES
        CAT
            Entra (AAD) Standards
        TAG
            "ZTNA21889"
        EXECUTIVETEXT
            Prompts employees to set up multi-factor authentication during login, gradually improving the organization's security posture by encouraging adoption of stronger authentication methods. This helps achieve better security compliance without forcing immediate mandatory changes.
        ADDEDCOMPONENT
            {"type":"autoComplete","multiple":false,"creatable":false,"label":"Select value","name":"standards.NudgeMFA.state","options":[{"label":"Enabled","value":"enabled"},{"label":"Disabled","value":"disabled"}]}
            {"type":"number","name":"standards.NudgeMFA.snoozeDurationInDays","label":"Number of days to allow users to skip registering Authenticator (0-14, default is 1)","defaultValue":1,"validators":{"min":{"value":0,"message":"Minimum value is 0"},"max":{"value":14,"message":"Maximum value is 14"}}}
            {"type":"input","name":"standards.NudgeMFA.excludeGroupName","label":"Exclude group display name (e.g. CIPP-JIT-MFA-Exclude)"}
            {"type":"switch","name":"standards.NudgeMFA.CreateGroups","label":"Create exclude group if it does not exist"}
        IMPACT
            Low Impact
        ADDEDDATE
            2022-12-08
        POWERSHELLEQUIVALENT
            Update-MgPolicyAuthenticationMethodPolicy
        RECOMMENDEDBY
        UPDATECOMMENTBLOCK
            Run the Tools\Update-StandardsComments.ps1 script to update this comment block
    .LINK
        https://docs.cipp.app/user-documentation/tenant/standards/list-standards
    #>

    param($Tenant, $Settings)

    # Get state value using null-coalescing operator
    $State = $Settings.state.value ?? $Settings.state

    # Resolve exclude group if configured
    $ExcludeGroupId = $null
    $ExcludeGroupName = $Settings.excludeGroupName.value ?? $Settings.excludeGroupName
    if (![string]::IsNullOrWhiteSpace($ExcludeGroupName)) {
        try {
            $ExcludeGroupIds = Convert-CIPPGroupNameToId -TenantFilter $Tenant -GroupNames @($ExcludeGroupName) -CreateGroups:([bool]$Settings.CreateGroups) -APIName 'Standards'
            $ExcludeGroupId = $ExcludeGroupIds | Select-Object -First 1
        } catch {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "Failed to resolve MFA exclude group '$ExcludeGroupName': $($_.Exception.Message)" -sev 'Warning'
        }
    }

    try {
        $CurrentState = New-GraphGetRequest -Uri 'https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy' -tenantid $Tenant

        $ExcludeGroupCorrect = if ($ExcludeGroupId) {
            $CurrentState.registrationEnforcement.authenticationMethodsRegistrationCampaign.excludeTargets.id -contains $ExcludeGroupId
        } else { $true }

        $StateIsCorrect = ($CurrentState.registrationEnforcement.authenticationMethodsRegistrationCampaign.state -eq $State) -and
        ($CurrentState.registrationEnforcement.authenticationMethodsRegistrationCampaign.snoozeDurationInDays -eq $Settings.snoozeDurationInDays) -and
        ($CurrentState.registrationEnforcement.authenticationMethodsRegistrationCampaign.enforceRegistrationAfterAllowedSnoozes -eq $true) -and
        $ExcludeGroupCorrect
    } catch {
        Write-LogMessage -API 'Standards' -tenant $Tenant -message 'Failed to get Authenticator App Nudge state, check your permissions and try again' -sev Error -LogData (Get-CippException -Exception $_)
        return
    }

    if ($Settings.remediate -eq $true) {
        $StateName = $State.Substring(0, 1).ToUpper() + $State.Substring(1)
        if ($StateIsCorrect -eq $true) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "Authenticator App Nudge is already set to $State with a snooze duration of $($Settings.snoozeDurationInDays)." -sev Info
        } else {
            try {
                # Merge exclude group into existing excludeTargets
                $MergedExcludeTargets = [System.Collections.Generic.List[object]]::new()
                $CurrentExcludeTargets = $CurrentState.registrationEnforcement.authenticationMethodsRegistrationCampaign.excludeTargets
                if ($CurrentExcludeTargets) {
                    $CurrentExcludeTargets | ForEach-Object { $MergedExcludeTargets.Add($_) }
                }
                if ($ExcludeGroupId -and ($MergedExcludeTargets.id -notcontains $ExcludeGroupId)) {
                    $MergedExcludeTargets.Add(@{ id = $ExcludeGroupId; targetType = 'group' })
                }

                $GraphRequest = @{
                    tenantid    = $Tenant
                    uri         = 'https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy'
                    AsApp       = $false
                    Type        = 'PATCH'
                    ContentType = 'application/json'
                    Body        = @{
                        registrationEnforcement = @{
                            authenticationMethodsRegistrationCampaign = @{
                                state                                  = $State
                                snoozeDurationInDays                   = $Settings.snoozeDurationInDays
                                enforceRegistrationAfterAllowedSnoozes = $true
                                includeTargets                         = $CurrentState.registrationEnforcement.authenticationMethodsRegistrationCampaign.includeTargets
                                excludeTargets                         = @($MergedExcludeTargets)
                            }
                        }
                    } | ConvertTo-Json -Depth 10 -Compress
                }
                New-GraphPostRequest @GraphRequest
                $ExcludeMessage = if ($ExcludeGroupId) { " with exclude group '$ExcludeGroupName'" } else { '' }
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "$StateName Authenticator App Nudge with a snooze duration of $($Settings.snoozeDurationInDays)$ExcludeMessage" -sev Info
            } catch {
                $ErrorMessage = Get-CippException -Exception $_
                Write-LogMessage -API 'Standards' -tenant $Tenant -message "Failed to set Authenticator App Nudge to $State. Error: $($ErrorMessage.NormalizedError)" -sev Error -LogData $ErrorMessage
            }
        }
    }

    if ($Settings.alert -eq $true) {
        if ($StateIsCorrect -eq $true) {
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "Authenticator App Nudge is enabled with a snooze duration of $($CurrentState.registrationEnforcement.authenticationMethodsRegistrationCampaign.snoozeDurationInDays)" -sev Info
        } else {
            Write-StandardsAlert -message "Authenticator App Nudge is not enabled with a snooze duration of $($CurrentState.registrationEnforcement.authenticationMethodsRegistrationCampaign.snoozeDurationInDays)" -object ($CurrentState.registrationEnforcement.authenticationMethodsRegistrationCampaign | Select-Object snoozeDurationInDays, state) -tenant $Tenant -standardName 'NudgeMFA' -standardId $Settings.standardId
            Write-LogMessage -API 'Standards' -tenant $Tenant -message "Authenticator App Nudge is not enabled with a snooze duration of $($CurrentState.registrationEnforcement.authenticationMethodsRegistrationCampaign.snoozeDurationInDays)" -sev Info
        }
    }

    if ($Settings.report -eq $true) {
        $CurrentValue = @{
            snoozeDurationInDays = $CurrentState.registrationEnforcement.authenticationMethodsRegistrationCampaign.snoozeDurationInDays
            state                = $CurrentState.registrationEnforcement.authenticationMethodsRegistrationCampaign.state
            excludeGroupPresent  = if ($ExcludeGroupId) { $CurrentState.registrationEnforcement.authenticationMethodsRegistrationCampaign.excludeTargets.id -contains $ExcludeGroupId } else { $true }
        }
        $ExpectedValue = @{
            snoozeDurationInDays = $Settings.snoozeDurationInDays
            state                = $State
            excludeGroupPresent  = $true
        }
        Set-CIPPStandardsCompareField -FieldName 'standards.NudgeMFA' -CurrentValue $CurrentValue -ExpectedValue $ExpectedValue -TenantFilter $Tenant
        Add-CIPPBPAField -FieldName 'NudgeMFA' -FieldValue $StateIsCorrect -StoreAs bool -Tenant $Tenant
    }
}
