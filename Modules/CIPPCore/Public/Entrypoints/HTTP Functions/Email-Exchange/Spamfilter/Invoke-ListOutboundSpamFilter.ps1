using namespace System.Net

Function Invoke-ListOutboundSpamFilter {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Exchange.SpamFilter.Read
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers
    Write-LogMessage -headers $Headers -API $APIName -message 'Accessed this API' -Sev 'Debug'
    $Tenantfilter = $request.Query.tenantfilter

    try {
        $Policies = New-ExoRequest -tenantid $Tenantfilter -cmdlet 'Get-HostedOutboundSpamFilterPolicy' | Select-Object * -ExcludeProperty *odata*, *data.type*
        $RuleState = New-ExoRequest -tenantid $Tenantfilter -cmdlet 'Get-HostedOutboundSpamFilterRule' | Select-Object * -ExcludeProperty *odata*, *data.type*

        $GraphRequest = $Policies | Select-Object *,
            @{l = 'ruleState'; e = { $name = $_.name; $_.IsDefault -eq $true ? 'Always on' : ($RuleState | Where-Object name -EQ $name).State } },
            @{l = 'rulePrio'; e = { $name = $_.name; $_.IsDefault -eq $true ? 'Lowest' : ($RuleState | Where-Object name -EQ $name).Priority } },
            # @{l = 'Include'; e = { $name = $_.name; $match = ($RuleState | Where-Object name -EQ $name); [pscustomobject]@{ Users = $match.From; Groups = $match.FromMemberOf; Domains = $match.SenderDomainIs } } },
            # @{l = 'Exclude'; e = { $name = $_.name; $match = ($RuleState | Where-Object name -EQ $name); [pscustomobject]@{ Users = $match.ExceptIfFrom; Groups = $match.ExceptIfFromMemberOf; Domains = $match.ExceptIfSenderDomainIs } } }
            @{l = 'From'; e = { $name = $_.name; ($RuleState | Where-Object name -EQ $name).From } },
            @{l = 'FromMemberOf'; e = { $name = $_.name; ($RuleState | Where-Object name -EQ $name).FromMemberOf } },
            @{l = 'SenderDomainIs'; e = { $name = $_.name; ($RuleState | Where-Object name -EQ $name).SenderDomainIs } },
            @{l = 'ExceptIfFrom'; e = { $name = $_.name; ($RuleState | Where-Object name -EQ $name).ExceptIfFrom } },
            @{l = 'ExceptIfFromMemberOf'; e = { $name = $_.name; ($RuleState | Where-Object name -EQ $name).ExceptIfFromMemberOf } },
            @{l = 'ExceptIfSenderDomainIs'; e = { $name = $_.name; ($RuleState | Where-Object name -EQ $name).ExceptIfSenderDomainIs } }

        $StatusCode = [HttpStatusCode]::OK
    } catch {
        $ErrorMessage = Get-NormalizedError -Message $_.Exception.Message
        $StatusCode = [HttpStatusCode]::Forbidden
        $GraphRequest = $ErrorMessage
    }

    # Associate values to output bindings by calling 'Push-OutputBinding'.
    Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
            StatusCode = $StatusCode
            Body       = @($GraphRequest)
        })

}
