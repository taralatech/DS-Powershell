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

function compare-andcreatedsobject
    {
    #compare $importobject to $newdsmobject - if they are the same, return only the new DSM object ID.
    #If they are different, create a new object with the prefix and return the new object ID
    [CmdletBinding()]
    Param
        (
        [Parameter(mandatory=$true)]
        [pscustomobject]$importobject,
        [Parameter(mandatory=$true)]
        [pscustomobject]$newdsmobject,
        [Parameter(mandatory=$true)]
        [string]$uripart,
        [Parameter(mandatory=$true)]
        [string]$prefix
        )
    PROCESS
        {
        $newID = $newdsmobject.ID
        $newdsmobject.psobject.Properties.Remove('ID')
        $diffoutput = Compare-Object -DifferenceObject $newdsmobject -ReferenceObject $importobject
        if ($diffoutput)
            {
            #Objects do not have the same properties - this should never happen
            write-host "Something is very wrong.  Objects to be compared have different properties. New Object ID: $newID Imported Object name:" $importobject.name -ForegroundColor Red
            $logcontent = "ERROR: Something is very wrong.  Objects to be compared have different properties. New Object ID: $newID Imported Object name:" + $importobject.name
            Add-Content $logfile $logcontent
            }
        else
            {
            #We know that all of the properties are the same.  Loop through the values comparing.  Set $identical to $false if any properties differ.
            $objproperties = $newdsmobject.psobject.Properties.Name
            $identical = $true
            ForEach ($objproperty in $objproperties)
                {
                $propcompare = Compare-Object -ReferenceObject $importobject -DifferenceObject $newdsmobject -Property $objproperty
                if ($propcompare)
                    {
                    write-host "Properties $objproperty Differ. New DSM Object ID: $newID, Imported Object Name:" $importobject.name -ForegroundColor Cyan
                    $logcontent = "Properties $objproperty Differ. New DSM Object ID: $newID, Imported Object Name:" + $importobject.name
                    Add-Content $logfile $logcontent
                    $identical = $false
                    }
                else
                    {
                    write-host "Properties $objproperty are identical. New DSM Object ID: $newID, Imported Object Name:" $importobject.name -ForegroundColor Green
                    $logcontent = "Properties $objproperty are identical. New DSM Object ID: $newID, Imported Object Name:" + $importobject.name
                    Add-Content $logfile $logcontent
                    }
                }
            if ($identical -eq $false)
                {
                $importobject.name = $prefix + "_" + $importobject.name
                $body = $importobject | convertto-json
                $dsobject = Invoke-RestMethod -Headers $headers -method Post -Body $body -ContentType 'application/json' -Uri $dsobjuri -TimeoutSec $resttimeout
                if (! $dsobject)
                    {
                    write-host "Error for Object $uripart " $importobject.name -ForegroundColor Red -BackgroundColor Black
                    $logcontent = "Error for Object $uripart " + $importobject.name
                    Add-Content $logfile $logcontent
                    }
                $newID = $dsobject.ID
                write-host "New Object created - Name: "$importobject.name "Object ID: $newID" -ForegroundColor Cyan
                $logcontent = "New Object created - Name: " + $importobject.name + "Object ID: $newID"
                Add-Content $logfile $logcontent
                }
            else
                {
                write-host "Obects are identical.  Make no changes and return existing object ID - Name: "$importobject.name "Object ID: $newID" -ForegroundColor Green
                $logcontent = "Obects are identical.  Make no changes and return existing object ID - Name: " + $importobject.name + "Object ID: $newID"
                Add-Content $logfile $logcontent
                }
            }
        }
    END
        {
        return $newID
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
                    $logcontent = "Duplicate name $uripart " + $psobjectfromjson.name + " ID of dupe:" + $searchobject.$uripart.ID
                    Add-Content $logfile "$logcontent"
                    #New function here - compare objects - if the same, output just the new object ID.  If different, create new object with prefix and output new object ID
                    #Input is imported object and object from API.  Output is Object ID of unmodified/new object.
                    #This is bad.  I know but I couldn't get the array returned as a property of the pscustomobject returned into a pscustomobject with less code.
                    $newdsmjson =  $searchobject.$uripart | Convertto-Json
                    $newdsmpsobject = $newdsmjson | convertfrom-json
                    $newID = compare-andcreatedsobject $psobjectfromjson $newdsmpsobject $uripart $prefix
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
#Level One - Import objects with no links to other objects
$loneobjects = @('directorylists','contexts','fileextensionlists','filelists','iplists','maclists','portlists','schedules','statefulconfigurations')

ForEach ($uripart in $loneobjects)
    {
    $dsimportobjects = get-dsfilelist $inputdir $uripart
    if ($dsimportobjects)
        {
        $idmappings = add-dsobjects $uripart $dsimportobjects $prefix  1
        }
    else
        {
        write-host "Empty Directory for $uripart" -ForegroundColor Yellow
        Add-Content $logfile "Empty Directory for $uripart"
        }
    $masteridmappings | Add-Member -NotePropertyName $uripart -NotePropertyValue $idmappings
    }

#Level 2 - Import objects with dependencies to only level One objects

#level 3 - Import rules.  Filter "out of the box" rules out and only map them.  Optional: compare "out of box rules" and report if they are different.  Do not add them to the new DSM

#Level 4 - Import the policies