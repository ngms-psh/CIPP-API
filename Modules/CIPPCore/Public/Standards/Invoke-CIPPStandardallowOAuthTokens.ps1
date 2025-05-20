function Invoke-CIPPStandardallowOAuthTokens {
    <#
    .FUNCTIONALITY
        Internal
    .COMPONENT
        (APIName) allowOAuthTokens
    .SYNOPSIS
        (Label) Enable OTP Software OAuth tokens
    .DESCRIPTION
        (Helptext) Allows you to use any software OAuth token generator
        (DocsDescription) Enables OTP Software OAuth tokens for the tenant. This allows users to use OTP codes generated via software, like a password manager to be used as an authentication method.
    .NOTES
        CAT
            Entra (AAD) Standards
        TAG
        ADDEDCOMPONENT
        IMPACT
            Low Impact
        ADDEDDATE
            2022-12-18
        POWERSHELLEQUIVALENT
            Update-MgBetaPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration
        RECOMMENDEDBY
        UPDATECOMMENTBLOCK
            Run the Tools\Update-StandardsComments.ps1 script to update this comment block
    .LINK
        https://docs.cipp.app/user-documentation/tenant/standards/list-standards/entra-aad-standards#low-impact
    #>

    param($Tenant, $Settings)
    #$Rerun -Type Standard -Tenant $Tenant -API 'AddDKIM' -Settings $Settings

    Function Get-CIPPTenantGroupId {
        param (
            $GroupNames,
            $tenantid
        )
        $GroupNames = $GroupNames | Where-Object { $null -ne $_ }

        $GroupResults = New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/groups?$select=id,displayName&$top=999' -tenantid $tenantid |
            ForEach-Object {
                foreach ($SingleName in $GroupNames) {
                    if ($_.displayName -like $SingleName) {
                        [PSCustomObject]@{
                            displayName = $SingleName
                            id = $_.id
                        }
                    }
                }
            }
        if ($GroupResults.Count -ne $GroupNames.Count) {
            throw "Unable to find group(s) '$($GroupNames -join ', ')' in tenant $tenantid"
        }
        elseif ($duplicate = $GroupResults | Group-Object -Property displayName | Where-Object {$_.count -gt 1}){
            throw "Duplicate group(s) '$($duplicate.Name -join ', ')' found in tenant $tenantid"
        }
        else {
            return $GroupResults
        }
    }

    $State = $Settings.state.value
    $IncludeTargets = $Settings.includeTargets.value
    $ExcludeTargets = $Settings.excludeTargets.value


    if ($null -ne ($IncludeTargets+$ExcludeTargets)) {
        try {
            $GroupLookup = (@(@($IncludeTargets)+@($ExcludeTargets)) | Where-Object {$_ -NE 'all_users'})
            $Groups = Get-CIPPTenantGroupId -GroupNames $GroupLookup -tenantid $Tenant

            if ('all_users' -in $IncludeTargets) {
                $IncludeTargets = 'all_users'
            }
            else {
                $IncludeTargets = ($Groups | Where-Object {$_.displayName -in $IncludeTargets}).id
            }

            $ExcludeTargets = ($Groups | Where-Object {$_.displayName -in $ExcludeTargets}).id
        }
        catch {
            Write-Host "Unable to find group(s) for Software OTP/oAuth tokens: $($_)"
            Write-LogMessage -API 'Standards' -tenant $tenant -message "Unable to find group(s) for Software OTP/oAuth tokens: $($_)" -sev Error
            return
        }
    }

    $CurrentState = New-GraphGetRequest -uri 'https://graph.microsoft.com/beta/policies/authenticationMethodsPolicy/authenticationMethodConfigurations/softwareOath' -tenantid $Tenant
    $StateIsCorrect = ($State ? $CurrentState.state -eq $State : $CurrentState.state -eq 'enabled') -and
        ($IncludeTargets ? [bool]($IncludeTargets | Compare-Object $CurrentState.IncludeTargets.id -ExcludeDifferent -ErrorAction SilentlyContinue)  : $true) -and
        ([bool]($ExcludeTargets | Compare-Object $CurrentState.ExcludeTargets.id -ExcludeDifferent -ErrorAction SilentlyContinue))


    If ($Settings.remediate -eq $true) {
        if ($StateIsCorrect -eq $true) {
            Write-LogMessage -API 'Standards' -tenant $tenant -message 'AuthenticationMethod Software OTP/oAuth tokens is already configured correct.' -sev Info
        } else {
            try {
                Set-CIPPAuthenticationPolicy -Tenant $tenant -APIName 'Standards' -AuthenticationMethodId 'softwareOath' -Enabled ($State -eq "enabled" ? $true : $false) -IncludeTargets $IncludeTargets -ExcludeTargets $ExcludeTargets -OverWriteTargets $true
            } catch {
                Write-LogMessage -API 'Standards' -tenant $tenant -message "Failed to set Software OTP/oAuth tokens: $($_)" -sev Error
            }
        }
    }

    if ($Settings.alert -eq $true) {
        if ($StateIsCorrect -eq $true) {
            Write-LogMessage -API 'Standards' -tenant $tenant -message 'AuthenticationMethod Software OTP/oAuth tokens is already configured correct' -sev Info
        } else {
            Write-StandardsAlert -message 'AuthenticationMethod Software OTP/oAuth tokens is not configured correct' -object $CurrentState -tenant $tenant -standardName 'allowOAuthTokens' -standardId $Settings.standardId
            Write-LogMessage -API 'Standards' -tenant $tenant -message 'AuthenticationMethod Software OTP/oAuth tokens is not configured correct' -sev Info
        }
    }

    if ($Settings.report -eq $true) {
        Add-CIPPBPAField -FieldName 'softwareOath' -FieldValue $StateIsCorrect -StoreAs bool -Tenant $tenant
        Set-CIPPStandardsCompareField -FieldName 'standards.allowOAuthTokens' -FieldValue $StateIsCorrect -TenantFilter $tenant
    }
}
