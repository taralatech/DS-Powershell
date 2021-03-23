﻿param (
    [Parameter(Mandatory=$true)][string]$manager,
    [Parameter(Mandatory=$true)][string]$user,
    [Parameter(Mandatory=$false)][string]$tenant
)


$passwordinput = Read-host "Password for Deep Security Manager" -AsSecureString
$password = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($passwordinput))
[System.Net.ServicePointManager]::ServerCertificateValidationCallback={$true}
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Global:DSMSoapService = New-WebServiceProxy -uri "https://$manager/webservice/Manager?WSDL" -Namespace "DSSOAP" -ErrorAction Stop
$Global:DSM = New-Object DSSOAP.ManagerService
$Global:SID
try {
    if (!$tenant) {
        $Global:SID = $DSM.authenticate($user, $password)
        }
    else {
        $Global:SID = $DSM.authenticateTenant($tenant, $user, $password)
        }
}
catch {
    echo "An error occurred during authentication. Verify username and password and try again. `nError returned was: $($_.Exception.Message)"
    exit
}


try {
    $timestamp = Get-Date -Format yyyyMMddhhmmss        
    $filename = "ipsReport$($timestamp).csv"
    $hts = $dsm.hostRetrieveAll($SID)
    foreach ($ht in $hts)
    {
        
        $hs = $DSM.hostGetStatus($ht.ID, $SID)
        if ($hs.overallStatus -like 'Unmanaged*' -Or $hs.overallDpiStatus -like '*OFF*' -Or $hs.overallDpiStatus -like 'Not Activated')
            {
                continue
            }
        Write-Host "Checking details for hostID: $($ht.ID) $($ht.name)"
        $assignedrules=$hs.overallDpiStatus
        $recommended = $DSM.hostRecommendationRuleIDsRetrieve($ht.ID, 2, $false, $SID)
      
        foreach ($reecruleid in $recommended)
        {
              $reecruletps = $DSM.DPIRuleRetrieve($reecruleid,$SID)

              $recrulecve = $reecruletps.cveNumbers -split ", "

               foreach ($cve in $recrulecve)
               {
                if ($cve -ne $null)
                    {
                        $csvline = New-Object PSObject;
                        $csvline | Add-Member -MemberType NoteProperty -Name DisplayName -Value $ht.DisplayName;
                        $csvline | Add-Member -MemberType NoteProperty -Name HostName -Value $ht.name;
                        $csvline | Add-Member -MemberType NoteProperty -Name HostID -Value $ht.id;
                        $csvline | Add-Member -MemberType NoteProperty -Name OverallStatus -Value $hs.overallStatus
                        $csvline | Add-Member -MemberType NoteProperty -Name TotalAssignedRules -Value $hs.overallDpiStatus.Split(",")[2]
                        $csvline | Add-Member -MemberType NoteProperty -Name RulesRecommendedTotal -Value $recommended.count
                        $csvline | Add-Member -MemberType NoteProperty -Name SecurityPolicy -Value $SecurityPolicy.name
                        $csvline | Add-Member -MemberType NoteProperty -Name RecruleID -Value $reecruleid
                        $csvline | Add-Member -MemberType NoteProperty -Name RecruleName -Value $reecruletps.name
                        $csvline | Add-Member -MemberType NoteProperty -Name CVENumber -Value $cve
                        $csvline | Add-Member -MemberType NoteProperty -Name Severity -Value $reecruletps.severity
                        $csvline | export-csv $filename -Append
                    }
                }
         }

    }

}
catch {
    echo "An error occurred while pulling records. 'nError returned was: $($_.Exception.Message)"
}
finally {
    $DSM.endSession($SID)
}

$DSM.endSession($SID)