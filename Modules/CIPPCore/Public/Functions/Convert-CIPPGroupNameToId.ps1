function Convert-CIPPGroupNameToId {
    <#
    .SYNOPSIS
    Resolves group display names to GUIDs in a tenant

    .DESCRIPTION
    Standalone version of the group name resolution logic from New-CIPPCAPolicy.
    Resolves group display names to their object IDs in a specific tenant.
    If CreateGroups is enabled and a group is not found, it will be created
    from a matching Group Template or as a basic security group.

    .PARAMETER TenantFilter
    Tenant to resolve groups in

    .PARAMETER GroupNames
    One or more group display names or GUIDs to resolve

    .PARAMETER CreateGroups
    Create groups if they do not exist

    .PARAMETER PreloadedGroups
    Optional pre-loaded groups array to avoid additional Graph queries

    .PARAMETER APIName
    API name for logging

    .PARAMETER Headers
    Headers for logging
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$TenantFilter,
        [Parameter(Mandatory = $true)]
        [string[]]$GroupNames,
        [switch]$CreateGroups,
        [array]$PreloadedGroups,
        [string]$APIName = 'Convert-CIPPGroupNameToId',
        $Headers
    )

    if (-not $PreloadedGroups) {
        $PreloadedGroups = New-GraphGETRequest -uri 'https://graph.microsoft.com/beta/groups?$select=id,displayName&$top=999' -tenantid $TenantFilter -asApp $true
    }

    $GroupTemplates = $null

    $GroupIds = [System.Collections.Generic.List[string]]::new()
    $GroupNames | ForEach-Object {
        if (Test-IsGuid -String $_) {
            Write-LogMessage -Headers $Headers -API $APIName -message "Already GUID, no need to replace: $_" -Sev 'Debug'
            $GroupIds.Add($_)
        } else {
            $matchedGroups = @($PreloadedGroups | Where-Object -Property displayName -EQ $_)
            $groupId = $matchedGroups.id
            if ($groupId) {
                if ($matchedGroups.Count -gt 1) {
                    Write-Warning "Multiple groups found with display name '$_'. Using the first match: $($matchedGroups[0].id). IDs found: $($groupId -join ', ')"
                    $null = Write-LogMessage -Headers $Headers -API $APIName -message "Multiple groups found with display name '$_'. Using first match: $($matchedGroups[0].id)" -Sev 'Warning'
                    $groupId = @($matchedGroups[0].id)
                }
                foreach ($gid in $groupId) {
                    Write-Warning "Replaced group name $_ with ID $gid"
                    $null = Write-LogMessage -Headers $Headers -API $APIName -message "Replaced group name $_ with ID $gid" -Sev 'Debug'
                    $GroupIds.Add($gid)
                }
            } elseif ($CreateGroups) {
                Write-Warning "Creating group $_ as it does not exist in the tenant"
                if ($null -eq $GroupTemplates) {
                    $TemplatesTable = Get-CIPPTable -tablename 'templates'
                    $GroupTemplates = @(Get-CIPPAzDataTableEntity @TemplatesTable -filter "PartitionKey eq 'GroupTemplate'" | ForEach-Object {
                        if ($_.JSON -and (Test-Json -Json $_.JSON -ErrorAction SilentlyContinue)) {
                            $_.JSON | ConvertFrom-Json
                        }
                    })
                }
                if ($GroupTemplates.displayName -eq $_) {
                    Write-Information "Creating group from template for $_"
                    $GroupTemplate = $GroupTemplates | Where-Object -Property displayName -EQ $_
                    $NewGroup = New-CIPPGroup -GroupObject $GroupTemplate -TenantFilter $TenantFilter -APIName $APIName
                    $GroupIds.Add($NewGroup.GroupId)
                } else {
                    Write-Information "No template found, creating security group for $_"
                    $username = $_ -replace '[^a-zA-Z0-9]', ''
                    if ($username.Length -gt 64) {
                        $username = $username.Substring(0, 64)
                    }
                    $GroupObject = @{
                        groupType       = 'generic'
                        displayName     = $_
                        username        = $username
                        securityEnabled = $true
                    }
                    $NewGroup = New-CIPPGroup -GroupObject $GroupObject -TenantFilter $TenantFilter -APIName $APIName
                    $GroupIds.Add($NewGroup.GroupId)
                }
            } else {
                Write-Warning "Group $_ not found in the tenant and CreateGroups is disabled"
                throw "Group '$_' not found in tenant $TenantFilter. Enable 'Create groups if they do not exist' or create the group manually."
            }
        }
    }
    return $GroupIds
}
