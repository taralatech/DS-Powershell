<#
Run this script by typing:
.\Output-dspolicies.ps1 <API KEY> <full path to output directory> <url for DS manager> <full path to log directory>
e.g. 
.\Output-dspolicies.ps1 "shfsdajlkdajbk111444234234234" "c:\dsmanageroutput\mydsmanager\" "https://dsm.mydomain.com:4119/" "C:\logfiles\"
#>
param (
    [Parameter(Mandatory=$true)][string]$secretkey,
    [Parameter(Mandatory=$false)][string]$outputdir,
    [Parameter(Mandatory=$false)][string]$dsmanager,
    [Parameter(Mandatory=$false)][string]$logfilepath
)

#enter the timeout for REST queries here
$resttimeout = 30
#Enter the delay in seconds if there are API errors (such as "too many API requests")
$backoffdelay = 15
#URL must include HTTPS:// and finish with a /
#e.g. $DSmanager = "https://app.deepsecurity.trendmicro.com/"
#$dsmanager = "https://sr-dse1.home.tarala.me.uk/"
#$outputdir = "C:\scripts\log\export-DSM\"
#$logfilepath = "C:\scripts\log\"
$date = ( get-date ).ToString('yyyyMMddhhmmss')
$logfile = New-Item -type file "$logfilepath\Output-DSPolicies-$date.txt"
if ($outputdir -eq "")
    {
    Add-Content $logfile "Output directory not specified within script or as a parameter.  Run the script as Output-DSPolicies secretkey <full path to output directory>"
    throw "Output Directory Not specified"
    }

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$headers = @{
            'Content-Type' = 'application/json'
            'API-Secret-Key' = $secretkey
            'API-Version' = 'v1'
            }
Add-Content $logfile "Export of DS Policies started - DS manager URL - $DSmanager"

Function Get-DSConfigObject
    {
    #return DS configuration object from supplied Object ID
    [CmdletBinding()]
    Param
        (
        [Parameter(mandatory=$true)]
        [int32]$objid,
        [Parameter(mandatory=$true)]
        [string]$uripart,
        [Parameter(mandatory=$false)]
        [string]$furtheruripart
        )
    BEGIN
        {
        if ($uripart -eq 'policies')
            {
            $dsobjuri = $dsmanager + 'api/' + $uripart + '/' + $objid + '/' + $furtheruripart + '?overrides=true'
            write-host "Object is a policy - requesting overrides only"
            }
        else
            {
            $dsobjuri = $dsmanager + 'api/' + $uripart + '/' + $objid
            }
        write-host "Beginning fetch for Object ID $objid" -ForegroundColor Gray
        }
    PROCESS
        {
        $dsobject = Invoke-RestMethod -Headers $headers -method Get -Uri $dsobjuri -TimeoutSec $resttimeout
        if ($dsobject)
            {
            Write-Host "ID: $objid Connected! Get-DSConfigObject" -Foregroundcolor Green
            }
        else
            {
            Write-Host "ID: $objid Error! Assume API overload for Get-DSConfigObject" -ForegroundColor Yellow
            do
                {
                Start-Sleep -Seconds $backoffdelay
                $dsobject = Invoke-RestMethod -Headers $headers -method Get -Uri $dsobjuri -TimeoutSec $resttimeout
                }
            while (-Not $dsobject)
            $description = $dsobject.Name
            $idnumber = $dsobject.ID
            write-host "Get-DSConfigObject Error handling complete - rule to be exported is: $description" -ForegroundColor Yellow
            write-host "Get-DSConfigObject Object ID is: $idnumber" -ForegroundColor Yellow
            }
        }
    END
        {
        return $dsobject
        }

    }

Function Merge-DSobjects
    {
    #Merges two objects
    Param (
          [Parameter(mandatory=$true)]$dsobject1, 
          [Parameter(mandatory=$true)]$dsobject2,
          [Parameter(mandatory=$true)]$uripart
          )
    PROCESS
        {
        $dsmembers = [Pscustomobject]@{}
        $dsmembers | add-member -MemberType NoteProperty -Name $uripart -value @()
        $dsmembers.$uripart += $dsobject1.$uripart
        $dsmembers.$uripart += $dsobject2.$uripart
        }
    END
        {
        return $dsmembers
        }
    }

Function Get-AllObjectIDslarge
    {
    #Due to 5000 Item limit, requests need to be split.  This is used to perform multiple API calls and combine the results into one object.
    [CmdletBinding()]
    Param
        (
        [Parameter(mandatory=$true)]
        [string]$uripart
        )
    BEGIN
        {
        $geturi = $dsmanager + 'api/' + $uripart + '/search/'
        }
    PROCESS
        {
        $startid = 0
        $dsobjects = $null
        do
            {
            $json = @{
                        "maxItems" = 1000
                        "searchCriteria" = @{
                                            "fieldName" = "ID"
                                            "idValue" = $startid
                                            "idTest" = "greater-than"
                                            }
                        "sortByObjectID" = "true"
                      } | ConvertTo-Json
            if ($startid -eq 0)
                {
                $dsobjects = Invoke-RestMethod -Headers $headers -method Post -Uri $geturi -body $json -TimeoutSec $resttimeout
                $dsfullobjects = $dsobjects
                }
            else
                {
                $dsobjects = Invoke-RestMethod -Headers $headers -method Post -Uri $geturi -body $json -TimeoutSec $resttimeout
                $dsfullobjects = Merge-DSobjects $dsobjects $dsfullobjects $uripart
                }
            write-host "$startid - start id"
            $dsobjectscount = $dsobjects.$uripart.Count
            write-host "$dsobjectscount - DSobjectscount"
            $startid = $startid + 1000
            }
        until ($dsobjects.$uripart.Count -eq 0)
        }
    END
        {
        return $dsfullobjects
        }
    }

Function Get-AllObjectIDs
    {
    [CmdletBinding()]
    Param
        (
        [Parameter(mandatory=$true)]
        [string]$uripart
        )
    #Return an object containing all configurations of the specified type
    BEGIN
        {
        if ($uripart -eq 'policies')
            {
            $geturi = $dsmanager + 'api/' + $uripart + '?overrides=true'
            write-host "Object is a policy - requesting overrides only"
            }
        else
            {
            $geturi = $dsmanager + 'api/' + $uripart + '/'
            }
        }
    PROCESS
        {
        $dsobjects = Invoke-RestMethod -Headers $headers -method Get -Uri $geturi -TimeoutSec $resttimeout
        if ($dsobjects.$uripart.count -gt 4500)
            {
            $totalobjects = $dsobjects.$uripart.count
            write-host "$totalobjects returned.  This is over the 4500 object limit"
            $dsobjects = Get-AllObjectIDslarge $uripart
            }
        }
    END
        {
        $totalobjects = $dsobjects.$uripart.count
        write-host "$totalobjects returned"
        return $dsobjects
        }
    }

Function Save-DSObjectasJSON
    {
    #Take a configuration object and save it as a json file for importing later
    [CmdletBinding()]
    Param
        (
        [Parameter(mandatory=$true)]
        [pscustomobject]$saveobject,
        [Parameter(mandatory=$true)]
        [string]$file
        )
    BEGIN
        {
        write-host "Save-DSObjectasJSON"
        }
    PROCESS
        {
        $savejson = $saveobject | ConvertTo-Json -Depth 4
        $savejsonfile = New-Item -type file "$file"
        Add-Content $savejsonfile $savejson
        }
    END
        {

        }
    }

Function Export-AllDSobjectsOfType
    {
    #pass me the "unique" part of the URI for an object search/describe and I'll get all objects and export them to json
    [CmdletBinding()]
    Param
        (
        [string]$uripart
        )
    BEGIN
        {
        write-host Processing "Export-AllDSobjectsOfType - $uripart"
        }
    PROCESS
        {
        $dsobjects = Get-AllObjectIDs $uripart
        $dsobjpath = "$outputdir\$uripart"
        New-Item -ItemType directory -Path $dsobjpath
        ForEach ($dsobjectid in $dsobjects.$uripart.ID)
            {
            write-host "Object ID is: $dsobjectid (export-alldsobjectsoftype)" -ForegroundColor Cyan
            $dsobject = Get-DSConfigObject $dsobjectid $uripart
            $fullfile = "$dsobjpath\Output-DSPolicies-$uripart-$dsobjectid.json"
            Save-DSObjectasJSON $dsobject $fullfile
            $description = $dsobject.Name
            $idnumber2 = $dsobject.ID
            write-host "$description saved to disk (export-alldsobjectsoftype)"  -ForegroundColor Cyan
            write-host "Object ID is: $idnumber2 "  -ForegroundColor Cyan
            write-host "-------------------------------------------------------------------"  -ForegroundColor Cyan
            Add-Content $logfile "$description saved to disk.  $uripart $idnumber2"
            }
        }
    END
        {
        write-host "Export-AllDSobjectsOfType completed"
        }
    }

Function Export-AllDSobjectsAsSingleFile
    {
    #pass me the "unique" part of the URI for an object search/describe and I'll get all objects and export them to json
    [CmdletBinding()]
    Param
        (
        [Parameter(mandatory=$true)][string]$uripart,
        [Parameter(mandatory=$false)][string]$furtheruripart
        )
    BEGIN
        {
        write-host Processing "Export-AllDSobjectsAsSingleFile - $uripart"
        }
    PROCESS
        {
        $dsobjects = Get-AllObjectIDs $uripart
        if ($furtheruripart)
            {
            $alldsobjects = [pscustomobject]@{}
            foreach ($singleobject in $dsobjects.$uripart)
                {
                $individualobject = Get-DSConfigObject -objid $singleobject.ID -uripart $uripart -furtheruripart $furtheruripart
                $alldsobjects | Add-Member -MemberType NoteProperty -Name $singleobject.ID -Value $individualobject
                }
            $dsobjects = $alldsobjects
            }
        $subpath = $uripart + $furtheruripart
        $dsobjpath = "$outputdir\$subpath"
        New-Item -ItemType directory -Path $dsobjpath
        write-host "URIpart is is: $uripart (Export-AllDSobjectsAsSingleFile)" -ForegroundColor Cyan
        $fullfile = "$dsobjpath\Output-DSPolicies-$uripart.json"
        Save-DSObjectasJSON $dsobjects $fullfile
        write-host "$fullfile saved to disk.  $uripart" -ForegroundColor Cyan
        Add-Content $logfile "$fullfile saved to disk.  $uripart"
        }
    END
        {
        write-host "Export-AllDSobjectsOfType completed"
        }
    }

#Begin the Main body
#Check to see if the directory exists.  If not, create it
if ((Test-Path $outputdir -PathType Container) -eq $true)
    {
    Add-Content $logfile "path $outputdir exists"
    write-host "path $outputdir exists"
    }
else
    {
    Add-Content $logfile "path $outputdir does not exist"
    write-host "path $outputdir does not exist"
    New-Item -ItemType directory -Path $outputdir
    }
Export-AllDSobjectsAsSingleFile 'antimalwareconfigurations'
Start-Sleep $backoffdelay
Export-AllDSobjectsOfType 'directorylists'
Start-Sleep $backoffdelay
Export-AllDSobjectsAsSingleFile 'policies'
Start-Sleep $backoffdelay
Export-AllDSobjectsOfType 'fileextensionlists'
Start-Sleep $backoffdelay
Export-AllDSobjectsOfType 'filelists'
Start-Sleep $backoffdelay
Export-AllDSobjectsOfType 'schedules'
Start-Sleep $backoffdelay
Export-AllDSobjectsAsSingleFile 'firewallrules'
Start-Sleep $backoffdelay
Export-AllDSobjectsOfType 'iplists'
Start-Sleep $backoffdelay
Export-AllDSobjectsOfType 'maclists'
Start-Sleep $backoffdelay
Export-AllDSobjectsOfType 'portlists'
Start-Sleep $backoffdelay
Export-AllDSobjectsOfType 'contexts'
Start-Sleep $backoffdelay
Export-AllDSobjectsOfType 'statefulconfigurations'
Start-Sleep $backoffdelay
Export-AllDSobjectsAsSingleFile  'integritymonitoringrules'
Start-Sleep $backoffdelay
Export-AllDSobjectsAsSingleFile 'loginspectionrules'
Start-Sleep $backoffdelay
Export-AllDSobjectsAsSingleFile 'intrusionpreventionrules'
Start-Sleep $backoffdelay
#Export-AllDSobjectsOfType 'applicationtypes'
Export-AllDSobjectsAsSingleFile 'applicationtypes'

Export-AllDSobjectsAsSingleFile 'policies' 'firewall/rules'
Export-AllDSobjectsAsSingleFile 'policies' 'intrusionprevention/rules'
Export-AllDSobjectsAsSingleFile 'policies' 'integritymonitoring/rules'
Export-AllDSobjectsAsSingleFile 'policies' 'loginspection/rules'

pause
#Export-AllDSobjectsAsSingleFile 'policies'
<#
Missing:
antiMalwareSettingScanCacheRealTimeConfigId"
"applicationControlSettingSyslogConfigId"
SyslogConfigId
"webReputationSettingSmartProtectionWebReputationGlobalServerProxyId"
platformSettingSmartProtectionAntiMalwareGlobalServerProxyId
"logInspectionSettingSyslogConfigId"
applicationControlSettingSharedRulesetId
antiMalwareSettingScanCacheOnDemandConfigId
#>