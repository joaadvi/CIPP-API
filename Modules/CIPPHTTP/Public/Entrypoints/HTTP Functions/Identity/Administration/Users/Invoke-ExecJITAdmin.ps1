function Invoke-ExecJITAdmin {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Identity.Role.ReadWrite

    .DESCRIPTION
        Just-in-time admin management API endpoint. This function can create users, add roles, remove roles, delete, or disable a user.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $TenantFilter = $Request.Body.tenantFilter.value ? $Request.Body.tenantFilter.value : $Request.Body.tenantFilter


    $Start = ([System.DateTimeOffset]::FromUnixTimeSeconds($Request.Body.StartDate)).DateTime.ToLocalTime()
    $Expiration = ([System.DateTimeOffset]::FromUnixTimeSeconds($Request.Body.EndDate)).DateTime.ToLocalTime()
    $Results = [System.Collections.Generic.List[object]]::new()

    # Check maximum duration setting
    try {
        $ConfigTable = Get-CIPPTable -TableName Config
        $Filter = "PartitionKey eq 'JITAdminSettings' and RowKey eq 'JITAdminSettings'"
        $JITAdminConfig = Get-CIPPAzDataTableEntity @ConfigTable -Filter $Filter

        if ($JITAdminConfig -and ![string]::IsNullOrWhiteSpace($JITAdminConfig.MaxDuration)) {
            $RequestedDuration = $Expiration - $Start
            try {
                $MaxDurationTimeSpan = [System.Xml.XmlConvert]::ToTimeSpan($JITAdminConfig.MaxDuration)
                if ($RequestedDuration -gt $MaxDurationTimeSpan) {
                    $RequestedDays = $RequestedDuration.TotalDays.ToString('0.00')
                    $MaxDays = $MaxDurationTimeSpan.TotalDays.ToString('0.00')
                    $ErrorMessage = "Requested JIT Admin duration ($RequestedDays days) exceeds the maximum allowed duration of $($JITAdminConfig.MaxDuration) ($MaxDays days)"
                    Write-LogMessage -headers $Headers -API $APIName -message $ErrorMessage -Sev 'Error'
                    return ([HttpResponseContext]@{
                            StatusCode = [HttpStatusCode]::BadRequest
                            Body       = @{'Results' = @($ErrorMessage) }
                        })
                }
            } catch {
                Write-Warning "Failed to parse MaxDuration setting: $($_.Exception.Message)"
            }
        }
    } catch {
        Write-Warning "Failed to check JIT Admin settings: $($_.Exception.Message)"
    }

    # Resolve MFA exclude group from request (template-driven)
    $MfaExcludeGroupId = $null
    if ($Request.Body.mfaExcludeEnabled -and ![string]::IsNullOrWhiteSpace($Request.Body.mfaExcludeGroupName)) {
        try {
            $MfaExcludeGroupIds = Convert-CIPPGroupNameToId -TenantFilter $TenantFilter -GroupNames @($Request.Body.mfaExcludeGroupName) -CreateGroups -APIName $APIName -Headers $Headers
            $MfaExcludeGroupId = $MfaExcludeGroupIds | Select-Object -First 1
        } catch {
            Write-Warning "Failed to resolve MFA exclude group '$($Request.Body.mfaExcludeGroupName)': $($_.Exception.Message)"
        }
    }

    if ($Request.Body.userAction -eq 'create') {
        $Domain = $Request.Body.Domain.value ? $Request.Body.Domain.value : $Request.Body.Domain
        $Username = "$($Request.Body.Username)@$($Domain)"
        Write-Information "Creating JIT Admin user: $($Request.Body.username)"

        $JITAdmin = @{
            User         = @{
                'FirstName'         = $Request.Body.FirstName
                'LastName'          = $Request.Body.LastName
                'UserPrincipalName' = $Username
                'UsageLocation'     = $Request.Body.usageLocation.value ?? $Request.Body.usageLocation
            }
            Expiration   = $Expiration
            StartDate    = $Start
            Reason       = $Request.Body.reason
            Action       = 'Create'
            TenantFilter = $TenantFilter
            Headers      = $Headers
            APIName      = $APIName
        }
        try {
            $CreateResult = Set-CIPPUserJITAdmin @JITAdmin
        } catch {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = @{'Results' = @("Failed to create JIT Admin user: $($_.Exception.Message)") }
                })
        }
        $Results.Add(@{
                resultText = "Created User: $Username"
                copyField  = $Username
                state      = 'success'
            })
        if (!$Request.Body.UseTAP) {
            $Results.Add(@{
                    resultText = "Password: $($CreateResult.password)"
                    copyField  = $CreateResult.password
                    state      = 'success'
                })
        }
        $Results.Add("JIT Admin Expires: $($Expiration)")
        Start-Sleep -Seconds 1
    } else {

        $Username = $Request.Body.existingUser.value
        if ($Username -match '^[a-f0-9]{8}-([a-f0-9]{4}-){3}[a-f0-9]{12}$') {
            Write-Information "Resolving UserPrincipalName from ObjectId: $($Request.Body.existingUser.value)"
            $Username = (New-GraphGetRequest -uri "https://graph.microsoft.com/v1.0/users/$($Request.Body.existingUser.value)" -tenantid $TenantFilter).userPrincipalName

            # If the resolved username is a guest user, we need to use the id instead of the UPN
            if ($Username -clike '*#EXT#*') {
                $Username = $Request.Body.existingUser.value
            }
        }

        # Validate we have a username
        if ([string]::IsNullOrWhiteSpace($Username)) {
            return [HttpResponseContext]@{
                StatusCode = [HttpStatusCode]::BadRequest
                Body       = @{ 'Results' = @("Could not resolve username from existingUser value: $($Request.Body.existingUser.value)") }
            }
        }

        # Add username result for existing user
        $Results.Add(@{
                resultText = "User: $Username"
                copyField  = $Username
                state      = 'success'
            })
    }



    #Region TAP creation
    if ($Request.Body.UseTAP) {
        try {
            $LifetimeMinutes = $null
            $RequestedMinutes = $null
            $ParsedRequestLifetime = $false
            if (![string]::IsNullOrWhiteSpace($Request.Body.tapLifetimeInMinutes)) {
                try {
                    $RequestedMinutes = [int]$Request.Body.tapLifetimeInMinutes
                    $ParsedRequestLifetime = $true
                } catch {
                    Write-Warning "Failed to parse TAP lifetime from request: $($_.Exception.Message)"
                }
            }

            if ($null -eq $RequestedMinutes) {
                $RequestedMinutes = [int](($Expiration - $Start).TotalMinutes)
            }

            try {
                $Policy = New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/TemporaryAccessPass' -tenantid $TenantFilter
                $PolicyMax = [int]($Policy.maximumLifetimeInMinutes ?? 1440)
                $PolicyMin = [Math]::Min([int]($Policy.minimumLifetimeInMinutes ?? 1), $PolicyMax)
                $LifetimeMinutes = [Math]::Min([Math]::Max($RequestedMinutes, $PolicyMin), $PolicyMax)
            } catch {
                Write-Warning "Failed to determine TAP lifetime from policy: $($_.Exception.Message)"
                if ($ParsedRequestLifetime) {
                    $LifetimeMinutes = $RequestedMinutes
                }
            }

            $TapParams = @{}
            if ($Start -gt (Get-Date)) {
                $TapParams.startDateTime = [System.DateTimeOffset]::FromUnixTimeSeconds($Request.Body.StartDate).DateTime
            }
            if ($LifetimeMinutes -gt 0) {
                $TapParams.lifetimeInMinutes = [int]$LifetimeMinutes
            }
            $TapBody = if ($TapParams.Count) { ConvertTo-Json -Depth 5 -InputObject $TapParams } else { '{}' }
            # Retry creating the TAP up to 10 times, since it can fail due to the user not being fully created yet. Sometimes it takes 2 reties, sometimes it takes 8+. Very annoying. -Bobby
            $Retries = 0
            $MAX_TAP_RETRIES = 10
            do {
                try {
                    $TapRequest = New-GraphPostRequest -uri "https://graph.microsoft.com/beta/users/$($Username)/authentication/temporaryAccessPassMethods" -tenantid $TenantFilter -type POST -body $TapBody
                } catch {
                    Start-Sleep -Seconds 2
                    Write-Information "ERROR: Run $Retries of $MAX_TAP_RETRIES : Failed to create TAP, retrying"
                }
                $Retries++
            } while ( $null -eq $TapRequest.temporaryAccessPass -and $Retries -le $MAX_TAP_RETRIES )

            $TempPass = $TapRequest.temporaryAccessPass
            $PasswordExpiration = $TapRequest.LifetimeInMinutes

            $PasswordLink = New-PwPushLink -Payload $TempPass
            $Password = $PasswordLink ? $PasswordLink : $TempPass

            $Results.Add(@{
                    resultText = "Temporary Access Pass: $Password"
                    copyField  = $Password
                    state      = 'success'
                })
            $Results.Add("This TAP is usable starting at $($TapRequest.startDateTime) UTC for the next $PasswordExpiration minutes")
        } catch {
            $Results.Add('Failed to create TAP, if this is not yet enabled, use the Standards to push the settings to the tenant.')
            Write-Information (Get-CippException -Exception $_ | ConvertTo-Json -Depth 5)
            if ($Password) {
                $Results.Add(@{
                        resultText = "Password: $Password"
                        copyField  = $Password
                        state      = 'success'
                    })
            }
        }
    }
    #EndRegion TAP creation

    # Merge MFA exclude group into group memberships
    $UserGroups = @($Request.Body.GroupMemberships.value)
    if ($MfaExcludeGroupId -and $MfaExcludeGroupId -notin $UserGroups) {
        $UserGroups = $UserGroups + @($MfaExcludeGroupId)
    }

    $Parameters = @{
        TenantFilter = $TenantFilter
        User         = @{
            'UserPrincipalName' = $Username
        }
        Roles        = $Request.Body.AdminRoles.value
        Groups       = $UserGroups
        Action       = if ($Request.Body.AdminRoles.value -and $UserGroups) {
            'AddRolesAndGroups'
        } elseif ($UserGroups) {
            'AddGroups'
        } else {
            'AddRoles'
        }
        Reason       = $Request.Body.Reason
        Expiration   = $Expiration
        StartDate    = $Start
        Headers      = $Headers
        APIName      = $APIName
    }
    if ($Start -gt (Get-Date)) {
        $TaskBody = @{
            TenantFilter  = $TenantFilter
            Name          = "JIT Admin (enable): $Username"
            AlertComment  = if (![string]::IsNullOrWhiteSpace($Request.Body.Reason)) { "JIT Reason: $($Request.Body.Reason)" } else { $null }
            Command       = @{
                value = 'Set-CIPPUserJITAdmin'
                label = 'Set-CIPPUserJITAdmin'
            }
            Parameters    = [pscustomobject]$Parameters
            ScheduledTime = $Request.Body.StartDate
            PostExecution = @{
                Webhook = [bool]($Request.Body.PostExecution | Where-Object -Property value -EQ 'webhook')
                Email   = [bool]($Request.Body.PostExecution | Where-Object -Property value -EQ 'email')
                PSA     = [bool]($Request.Body.PostExecution | Where-Object -Property value -EQ 'PSA')
            }
        }
        Add-CIPPScheduledTask -Task $TaskBody -hidden $false
        if ($Request.Body.userAction -ne 'create') {
            Set-CIPPUserJITAdminProperties -TenantFilter $TenantFilter -UserId $Request.Body.existingUser.value -Expiration $Expiration -StartDate $Start -Reason $Request.Body.Reason -CreatedBy (([System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($Headers.'x-ms-client-principal')) | ConvertFrom-Json).userDetails)
        }
        $Results.Add("Scheduling JIT Admin enable task for $Username")
    } else {
        try {
            $Results.Add("Executing JIT Admin enable task for $Username")
            Set-CIPPUserJITAdmin @Parameters
        } catch {
            return ([HttpResponseContext]@{
                    StatusCode = [HttpStatusCode]::BadRequest
                    Body       = @{'Results' = @("Failed to execute JIT Admin enable task: $($_.Exception.Message)") }
                })
        }
    }

    # Determine expire action and groups for the disable task
    $ExpireAction = $Request.Body.ExpireAction.value
    $ExpireGroups = @($Request.Body.GroupMemberships.value)
    if ($MfaExcludeGroupId) {
        if ($MfaExcludeGroupId -notin $ExpireGroups) {
            $ExpireGroups = $ExpireGroups + @($MfaExcludeGroupId)
        }
        switch ($ExpireAction) {
            'RemoveRoles' {
                $ExpireAction = 'RemoveRolesAndGroups'
            }
            'DisableUser' {
                # Schedule separate hidden task to remove from MFA exclude group
                $CleanupTask = [pscustomobject]@{
                    TenantFilter  = $TenantFilter
                    Name          = "JIT Admin (MFA exclude cleanup): $Username"
                    Command       = @{
                        value = 'Set-CIPPUserJITAdmin'
                        label = 'Set-CIPPUserJITAdmin'
                    }
                    Parameters    = [pscustomobject]@{
                        TenantFilter = $TenantFilter
                        User         = @{
                            'UserPrincipalName' = $Username
                        }
                        Groups       = @($MfaExcludeGroupId)
                        Action       = 'RemoveGroups'
                    }
                    ScheduledTime = $Request.Body.EndDate
                }
                Add-CIPPScheduledTask -Task $CleanupTask -hidden $true
            }
        }
    }

    $DisableTaskBody = [pscustomobject]@{
        TenantFilter  = $TenantFilter
        Name          = "JIT Admin ($($ExpireAction)): $Username"
        AlertComment  = if (![string]::IsNullOrWhiteSpace($Request.Body.Reason)) { "JIT Reason: $($Request.Body.Reason)" } else { $null }
        Command       = @{
            value = 'Set-CIPPUserJITAdmin'
            label = 'Set-CIPPUserJITAdmin'
        }
        Parameters    = [pscustomobject]@{
            TenantFilter = $TenantFilter
            User         = @{
                'UserPrincipalName' = $Username
            }
            Roles        = $Request.Body.AdminRoles.value
            Groups       = $ExpireGroups
            Reason       = $Request.Body.Reason
            Action       = $ExpireAction
        }
        PostExecution = @{
            Webhook = [bool]($Request.Body.PostExecution | Where-Object -Property value -EQ 'webhook')
            Email   = [bool]($Request.Body.PostExecution | Where-Object -Property value -EQ 'email')
            PSA     = [bool]($Request.Body.PostExecution | Where-Object -Property value -EQ 'PSA')
        }
        ScheduledTime = $Request.Body.EndDate
    }
    $null = Add-CIPPScheduledTask -Task $DisableTaskBody -hidden $false
    $Results.Add("Scheduling JIT Admin $($ExpireAction) task for $Username")

    return ([HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = @{'Results' = @($Results) }
        })

}
