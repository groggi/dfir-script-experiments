function Get-Now {
    $now = Get-Date
    Write-Output "Local:`t$($now.ToLocalTime().ToString('o'))"
    Write-Output "UTC:`t$($now.ToUniversalTime().ToString('o'))"
}

<#
 .Synopsis
  Retrieves VirusTotal report for given file hash.

 .Parameter Hash
  MD5, SHA1 or SHA256 hash of the file to check on VirusTotal.

 .Parameter Path
  Filepath for documentation, not necessary.

 .Parameter ApiKey
  Personal VirusTotal API key

 .Example
   # Find all .exe files and check their reputation on VirusTotal
   Get-ChildItem -Path '.' -Recurse | Get-FileHash | Get-VirusTotalReport -ApiKey <YOUR API KEY> | Format-List

 .Example
   # Find, hash and export to a CSV
   Get-ChildItem -Path '.' --Recurse | Get-FileHash | Export-Csv -Path out.csv
   # Transfer to other machine
   Import-Csv -Path out.csv | Get-VirusTotalReport -ApiKey <YOUR API KEY>
#>
function Get-VirusTotalReport {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory, ValueFromPipelineByPropertyName)][string]$Hash,
        [Parameter(ValueFromPipelineByPropertyName)][string]$Path,
        [Parameter(Mandatory)]$ApiKey
    )
    
    BEGIN {
        Get-Now

        Write-Output "Host (DNS):`t$([System.Net.Dns]::GetHostName())"
        Write-Output "Host (ENV):`t$($env:ComputerName)"
        Write-Output "User:`t$([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)"

        $requestParams = @{
            apikey   = $ApiKey
            resource = $null
        }
    }

    PROCESS {
        $requestParams.resource = $Hash

        $tries = 0
        do {
            $tries++

            $response = Invoke-WebRequest -Uri "https://www.virustotal.com/vtapi/v2/file/report" -Method Post -Body $requestParams

            switch($response.StatusCode) {
                200 {$tries = [int]::MaxValue}
                204 {
                    Start-Sleep -Seconds 60
                }
                403 {
                    Write-Error "Unauthorized"
                    exit
                }
            }
        } while($tries -lt 4)

        $result = [ordered]@{
            Status = $null
            Filepath = $Path
            Malicious = $null
            Permalink = $null
            Hash = $Hash
        }

        $responseData = ConvertFrom-Json -InputObject $response.Content
        switch ($responseData.response_code) {
            -2 {
                $result['Status'] = "Hash queued for analysis"
            }
            0 {
                $result['Status'] = "Hash unknown"
            }
            1 {
                if ($responseData.positives -gt 0) {
                    $result['Status'] = "Potentially malicious"
                }
                else {
                    $result['Status'] = "Clean"
                }

                $result['Malicious'] = "{0}/{1}" -f $responseData.positives, $responseData.total
                $result['Permalink'] = $responseData.permalink
            }
        }

        Write-Output (New-Object -TypeName PSCustomObject -Property $result)
    }

    END {
        Get-Now
    }
}

Export-ModuleMember -Function Get-VirusTotalReport