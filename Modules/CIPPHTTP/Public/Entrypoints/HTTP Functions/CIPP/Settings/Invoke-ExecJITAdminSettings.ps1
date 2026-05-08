function Invoke-ExecJITAdminSettings {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        CIPP.AppSettings.ReadWrite
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    $StatusCode = [HttpStatusCode]::OK

    try {
        $Table = Get-CIPPTable -TableName Config
        $Filter = "PartitionKey eq 'JITAdminSettings' and RowKey eq 'JITAdminSettings'"
        $JITAdminConfig = Get-CIPPAzDataTableEntity @Table -Filter $Filter

        if (-not $JITAdminConfig) {
            $JITAdminConfig = @{
                PartitionKey        = 'JITAdminSettings'
                RowKey              = 'JITAdminSettings'
                MaxDuration         = $null
                MfaExcludeGroupName = $null
            }
        }

        $Action = if ($Request.Body.Action) { $Request.Body.Action } else { $Request.Query.Action }

        $Results = switch ($Action) {
            'Get' {
                @{
                    MaxDuration         = $JITAdminConfig.MaxDuration
                    MfaExcludeGroupName = $JITAdminConfig.MfaExcludeGroupName
                }
            }
            'Set' {
                $MaxDuration = $Request.Body.MaxDuration.value
                if (![string]::IsNullOrWhiteSpace($MaxDuration)) {
                    try {
                        $null = [System.Xml.XmlConvert]::ToTimeSpan($MaxDuration)
                        $JITAdminConfig | Add-Member -NotePropertyName MaxDuration -NotePropertyValue $MaxDuration -Force
                    } catch {
                        $StatusCode = [HttpStatusCode]::BadRequest
                        @{
                            Results = 'Error: Invalid ISO 8601 duration format. Expected format like PT4H, P1D, P4W, etc.'
                        }
                        break
                    }
                } else {
                    $JITAdminConfig | Add-Member -NotePropertyName MaxDuration -NotePropertyValue $null -Force
                }

                $MfaExcludeGroupName = $Request.Body.MfaExcludeGroupName
                if (![string]::IsNullOrWhiteSpace($MfaExcludeGroupName)) {
                    $JITAdminConfig | Add-Member -NotePropertyName MfaExcludeGroupName -NotePropertyValue $MfaExcludeGroupName -Force
                } else {
                    $JITAdminConfig | Add-Member -NotePropertyName MfaExcludeGroupName -NotePropertyValue $null -Force
                }

                $JITAdminConfig.PartitionKey = 'JITAdminSettings'
                $JITAdminConfig.RowKey = 'JITAdminSettings'

                Add-CIPPAzDataTableEntity @Table -Entity $JITAdminConfig -Force | Out-Null

                $MessageParts = [System.Collections.Generic.List[string]]::new()
                if ($JITAdminConfig.MaxDuration) {
                    $MessageParts.Add("maximum duration to $($JITAdminConfig.MaxDuration)")
                }
                if ($JITAdminConfig.MfaExcludeGroupName) {
                    $MessageParts.Add("MFA exclude group to '$($JITAdminConfig.MfaExcludeGroupName)'")
                }

                $Message = if ($MessageParts.Count -gt 0) {
                    "Successfully set JIT Admin $($MessageParts -join ' and ')"
                } else {
                    'Successfully cleared all JIT Admin settings'
                }

                Write-LogMessage -headers $Headers -API $APIName -message $Message -Sev 'Info'

                @{
                    Results = $Message
                }
            }
            default {
                $StatusCode = [HttpStatusCode]::BadRequest
                @{
                    Results = 'Error: Invalid action. Use Get or Set.'
                }
            }
        }
    } catch {
        $ErrorMessage = Get-CippException -Exception $_
        $StatusCode = [HttpStatusCode]::InternalServerError
        $Results = @{
            Results = "Error: $($ErrorMessage.NormalizedError)"
        }
        Write-LogMessage -headers $Headers -API $APIName -message "Failed to process JIT Admin settings: $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage
    }

    return ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = $Results
        })
}
