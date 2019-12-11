<#
Description here
$masteridmappings.$uripart.Item($number)
gets the value for the key.  using $masteridmappings.$uripart.number doesn't work for first item.
#>
param (
    [Parameter(Mandatory=$true)][string]$secretkey,
    [Parameter(Mandatory=$false)][string]$inputdir,
    [Parameter(Mandatory=$false)][string]$dsmanager,
    [Parameter(Mandatory=$false)][string]$logfilepath,
    [Parameter(Mandatory=$false)][string]$prefix
)

#enter the timeout for REST queries here
$resttimeout = 30
#Enter the delay in seconds if there are API errors (such as "too many API requests")
$backoffdelay = 1
#URL must include HTTPS:// and finish with a /
#e.g. $DSmanager = "https://app.deepsecurity.trendmicro.com/"
#$dsmanager = "https://app.deepsecurity.trendmicro.com/"
$date = ( get-date ).ToString('yyyyMMddhhmmss')
$logfile = New-Item -type file "$logfilepath\Output-DSPolicies-$date.txt"

#Create a PScustomObject to store the Object ID mappings
$masteridmappings = [PSCustomObject]@{}

if ($inputdir -eq "")
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
Add-Content $logfile "Import of DS Policies started - DS manager URL - $DSmanager"

#Functions
function Get-DSfilelist
    {
    [CmdletBinding()]
    Param
        (
        [Parameter(mandatory=$true)]
        [string]$inputdir,
        [Parameter(mandatory=$true)]
        [string]$uripart
        )
    BEGIN
        {
        $importdir = $inputdir + $uripart + "\"
        write-host "Import directory = $importdir"
        Add-Content $logfile "Processing directory - $importdir"
        }
    PROCESS
        {
        $childobjects = Get-ChildItem $importdir
        }
    END
        {
        Add-Content $logfile "Output list - $childobjects"
        write-host "Output list - $childobjects"
        return $childobjects
        }
    }

function Add-Dsobjects
	{
    [CmdletBinding()]
    Param
        (
        [Parameter(mandatory=$true)]
        [string]$uripart,
        [Parameter(mandatory=$true)]
        [array]$filedirlist,
        [Parameter(mandatory=$true)]
        [string]$prefix,
        [Parameter(mandatory=$true)]
        [string]$level
        )
    BEGIN
        {
        $IDmappings = @{}
        write-host "Processing add-dsobjects URIpart =  $uripart, prefix = $prefix, level = $level"
        Add-Content $logfile "Processing add-dsobjects URIpart =  $uripart, prefix = $prefix, level = $level"
        $dsobjuri = $dsmanager + 'api/' + $uripart + '/'
        $dssearchuri = $dsmanager + 'api/' + $uripart + '/search'
        }
    PROCESS
        {
        ForEach ($filedir in $filedirlist)
            {
            $add = $true
            $dsimportfile = $filedir.VersionInfo.FileName
            write-host "ds import file: $dsimportfile"
            if ($dsimportfile)
                {
                write-host "DS Import file path = $dsimportfile"
                Add-Content $logfile "DS Import file path = $dsimportfile"
                $psobjectfromjson = Get-Content -Raw -Path $dsimportfile | ConvertFrom-Json
                $originalid = $psobjectfromjson.ID
                $psobjectfromjson.psobject.Properties.Remove('ID')
                #check if object with same name exists
                $searchname = $psobjectfromjson.name
                $searchjson = @{
                            "maxItems" = 1
                            "searchCriteria" = @{
                                                "fieldName" = "name"
                                                "stringValue" = $searchname
                                                "stringTest" = "equal"
                                                }
                            "sortByObjectID" = "true"
                          } | ConvertTo-Json
                $searchobject =  Invoke-RestMethod -Headers $headers -method Post -Body $searchjson -ContentType 'application/json' -Uri $dssearchuri -TimeoutSec $resttimeout
                if ($searchobject.$uripart.Count -eq 1)
                    {
                    write-host "Duplicate name $uripart " $psobjectfromjson.name " ID of dupe:" $searchobject.$uripart.ID
                    $logcontent = "Duplicate name $uripart " + $psobjectfromjson.name + "ID of dupe:" + $searchobject.$uripart.ID
                    Add-Content $logfile "$logcontent"
                    $psobjectfromjson.name = $prefix + "_" + $psobjectfromjson.name
                    $body = $psobjectfromjson | convertto-json
                    $dsobject = Invoke-RestMethod -Headers $headers -method Post -Body $body -ContentType 'application/json' -Uri $dsobjuri -TimeoutSec $resttimeout
                    $newID = $dsobject.ID
                    }
                else
                    {
                    $body = $psobjectfromjson | convertto-json
                    $dsobject = Invoke-RestMethod -Headers $headers -method Post -Body $body -ContentType 'application/json' -Uri $dsobjuri -TimeoutSec $resttimeout
                    $newID = $dsobject.ID
                    }
                $IDmappings.Add($originalid,$newID)
                }
            else
                {
                write-host "$filedir is not a file"
                Add-Content $logfile "$filedir is not a file"
                }
            }
        }
    END
        {
        return $IDmappings
        }
    }


#Main body
$dsimportobjects = get-dsfilelist $inputdir directorylists
$idmappings = add-dsobjects directorylists $dsimportobjects $prefix  1
$masteridmappings | Add-Member -NotePropertyName directorylists -NotePropertyValue $idmappings

$dsimportobjects = get-dsfilelist $inputdir contexts
$idmappings = add-dsobjects contexts $dsimportobjects $prefix  1
$masteridmappings | Add-Member -NotePropertyName contexts -NotePropertyValue $idmappings
