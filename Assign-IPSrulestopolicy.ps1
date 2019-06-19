<#
Run this script as .\Assign-IPSrulestopolicy "secretkey" "<full path to csv file>"
Example: .\Assign-IPSrulestopolicy "31:Aab1254fgjkdfgkhdfg=" "c:\scripts\mycsvfile.csv"
The script file location is not mandatory.  It can be specified below instead.
#>
param (
    [Parameter(Mandatory=$true)][string]$secretkey,
    [Parameter(Mandatory=$false)][string]$csvfile
)

#Alternatively enter the csv file location here
#$csvfile = "c:\scripts\csv\machinetoPolicy.csv"
#enter the timeout for REST queries here
$resttimeout = 30
#Enter the full path to the logfile here without the slash at the end
$logfilepath = "C:\scripts\log"
#URL must include HTTPS:// and finish with a /
#e.g. $DSmanager = "https://app.deepsecurity.trendmicro.com/"
$DSmanager = "https://sr-dse1.home.tarala.me.uk/"
$date = ( get-date ).ToString('yyyyMMddhhmmss')
$logfile = New-Item -type file "$logfilepath\Assign-IPSrules-$date.txt"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$headers = @{
            'Content-Type' = 'application/json'
            'API-Secret-Key' = $secretkey
            'API-Version' = 'v1'
            }
Add-Content $logfile "Assignment of IPS rules started - DS manager URL - $DSmanager"

$Hostpolicies = Import-CSV $csvfile
ForEach ( $hostline in $Hostpolicies ) 
    {
    $compsearchuri = $dsmanager + 'api/computers/search/'
    $policysearchuri = $DSmanager + 'api/policies/search/'
    if ($hostline.ComputerIDyes -eq 0)
        {
        $hostname = $hostline.ComputerNameID
        $json = @{
                    "maxItems" = 2
                    "searchCriteria" = @{
                                        "fieldName" = "displayName"
                                        "stringTest" = "equal"
                                        "stringValue" = $hostname
                                        }
                    "sortByObjectID" = "true"
                  } | ConvertTo-Json
        $computerdetails = Invoke-RestMethod -Headers $headers -method Post -Uri $compsearchuri -body $json -TimeoutSec $resttimeout
        $hostID = $computerdetails.computers.ID
        $displayname = $computerdetails.computers.Displayname
        Add-Content $logfile "Hostname - $hostname - Returned Display name - $displayname - Host ID: $hostID"
        write-host "Hostname - $hostname - Returned Display name - $displayname - Host ID: $hostID"
        }
    else
        {
        $hostID = $hostline.ComputerNameID
        $json = @{
         "maxItems" = 1
         "searchCriteria" = @{
                               "idValue" =  $hostID
                             }
         "sortByObjectID" =  "true"
         } | ConvertTo-Json
         $computerdetails = Invoke-RestMethod -Headers $headers -method Post -Uri $compsearchuri -body $json -TimeoutSec $resttimeout
         $displayname = $computerdetails.computers.Displayname
         Add-Content $logfile "Hostname - $hostname - Returned Display name - $displayname - Host ID: $hostID"
         write-host "Hostname - $hostname - Returned Display name - $displayname - Host ID: $hostID"
        }

    if ($computerdetails.computers.Count -gt 1)
        {write-host "more than 1"
        write-host $computerdetails.computers.Count
        Add-Content $logfile "More than 1 Computer object returned for Computer search $hostname $hostID"
        }
    else
        {

        $ipsuri = $dsmanager + 'api/computers/' + $hostID + '/intrusionprevention/assignments'
        $rulesassigned = Invoke-RestMethod -Headers $headers -Uri $ipsuri -TimeoutSec $resttimeout
        $rulenumbersassigned = $rulesassigned.assignedRuleIDs
        $recoscanstatus = $rulesassigned.recommendationScanStatus
        $recoscandateinmilliseconds = $rulesassigned.lastRecommendationScanDate
        $rulestoassign = $rulesassigned.recommendedToAssignRuleIDs
        $rulestoremove = $rulesassigned.recommendedToUnassignRuleIDs
        Add-Content $logfile "IPS Rules Assigned: $rulenumbersassigned"
        Add-Content $logfile "Recommendation Scan Status: $recoscanstatus"
        Add-Content $logfile "Recommendation Scan date in milliseconds since epoch: $recoscandateinmilliseconds"
        Add-Content $logfile "Rules recommended to Assign to computer: $rulestoassign"
        Add-Content $logfile "Rules Recommended to remove from computer: $rulestoremove"
        $fullruleset = $rulenumbersassigned + $rulestoassign | where {$rulestoremove -notcontains $_}
        Add-Content $logfile "Fullruleset: $fullruleset"
        write-host $rulenumbersassigned
        if ($hostline.PolicyIDYes -eq 0)
            {
            $policyname = $hostline.PolicynameID
            $json = @{
                    "maxItems" = 2
                    "searchCriteria" = @{
                                        "fieldName" = "name"
                                        "stringTest" = "equal"
                                        "stringValue" = $policyname
                                        }
                    "sortByObjectID" = "true"
                  } | ConvertTo-Json
            $policydetails = Invoke-RestMethod -Headers $headers -method Post -Uri $policysearchuri -body $json -TimeoutSec $resttimeout
            $policydisplayname = $policydetails.computers.name
            $policyID = $policydetails.policies.ID
            Add-Content $logfile "Policy name - $policyname - Returned Display name - $policydisplayname - Policy ID: $policyID"
            write-host "Policy name - $policyname - Returned Display name - $policydisplayname - Policy ID: $policyID"

            }
        else
            {
            $policyID = $hostline.PolicynameID
            $json = @{
             "maxItems" = 1
             "searchCriteria" = @{
                               "idValue" =  $policyID
                             }
             "sortByObjectID" =  "true"
             } | ConvertTo-Json
             $policydetails = Invoke-RestMethod -Headers $headers -method Post -Uri $policysearchuri -body $json -TimeoutSec $resttimeout
             $policydisplayname = $policydetails.computers.name
             Add-Content $logfile "Policy name - $policyname - Returned Display name - $policydisplayname - Policy ID: $policyID"
             write-host "Policy name - $policyname - Returned Display name - $policydisplayname - Policy ID: $policyID"
        }
        if ($policydetails.policies.Count -gt 1)
            {write-host "more than 1"
            write-host $policydetails.policies.Count
            Add-Content $logfile "More than 1 Computer object returned for Computer search $policyname $policyID"
            }
        else
            {
            Add-Content $logfile "Policy $policydisplayname parameters before rule assignment"
            $policyipsuri = $dsmanager + 'api/policies/' + $policyID + '/intrusionprevention/assignments'
            $policyrulesassigned = Invoke-RestMethod -Headers $headers -Uri $policyipsuri -TimeoutSec $resttimeout
            $policyrulenumbersassigned = $policyrulesassigned.assignedRuleIDs
            $policyrulestoassign = $policyrulesassigned.recommendedToAssignRuleIDs
            $policyrulestoremove = $policyrulesassigned.recommendedToUnassignRuleIDs
            Add-Content $logfile "Policy IPS Rules Assigned: $policyrulenumbersassigned"
            Add-Content $logfile "Rules recommended to Assign to policy: $policyrulestoassign"
            Add-Content $logfile "Rules Recommended to remove from policy: $policyrulestoremove"
            $fullpolicyruleset = $policyrulenumbersassigned + $policyrulestoassign | where {$policyrulestoremove -notcontains $_}
            Add-Content $logfile "Fullruleset: $fullpolicyruleset"
            Add-Content $logfile "-------------------------------------------------------------------"
            write-host $policyrulenumbersassigned
            #Now change the policy rules
            $json = @{
                    "ruleIDs" = $fullruleset
                  } | ConvertTo-Json
            $policyruleset = Invoke-RestMethod -Headers $headers -method Put -Uri $policyipsuri -body $json -TimeoutSec $resttimeout
            Add-Content $logfile "Policy $policydisplayname parameters after rule assignment"
            $policyrulesassigned = Invoke-RestMethod -Headers $headers -Uri $policyipsuri -TimeoutSec $resttimeout
            $policyrulenumbersassigned = $policyrulesassigned.assignedRuleIDs
            $policyrulestoassign = $policyrulesassigned.recommendedToAssignRuleIDs
            $policyrulestoremove = $policyrulesassigned.recommendedToUnassignRuleIDs
            Add-Content $logfile "Policy IPS Rules Assigned: $policyrulenumbersassigned"
            Add-Content $logfile "Rules recommended to Assign to policy: $policyrulestoassign"
            Add-Content $logfile "Rules Recommended to remove from policy: $policyrulestoremove"
            $fullpolicyruleset = $policyrulenumbersassigned + $policyrulestoassign | where {$policyrulestoremove -notcontains $_}
            Add-Content $logfile "Fullruleset: $fullpolicyruleset"
            Add-Content $logfile " "
            }
        }
    }