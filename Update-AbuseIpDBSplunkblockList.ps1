#requires -version 7
<#
.SYNOPSIS
  Update an ipset blocklist from a Splunk Search and corelated with AbuseIPDB information
.DESCRIPTION
  This script is intended to be launch on a Linux with an iptables and ipset blocklist set up.
  It's planned to work with a splunk search called with the API that return à list of IP and count. This list is then corallated with the AbuseIPDB database wia API calls again so that only Ip with enought confidence are added to the ipset. the script also maintains a file backuping his previous execution result so it maintains the blocklist over time.
.PARAMETER none
  All Paramaters are in the paramaters section at the start of the script.
.INPUTS
  Installation : ipset create blocklist hash:ip hashsize 4096
  iptables -I INPUT -m set --match-set blocklist src -j DROP
.OUTPUTS
  $IpsetBlockkist : the name of the ipset to update.
  $BlacklistIPJSONFile : the Json file saving the last state of te blocklist.
.NOTES
  Version:        1.0
  Author:         etienne at geekeries.org
  Creation Date:  2022-04-19
  Purpose/Change: Initial script development
  Details : https://geekeries.org/2022/04/blacklist-iptables-abuseipdb/
  Details : https://geekeries.org/2022/04/blocklist-iptable-avec-splunk-et-dabuseipdb/
.EXAMPLE
  ./Update-AbuseIpDBSplunkblockList.ps1 #in your daily crontab
#>



##PARAMETERS
$BaseUrl = "https://A.B.C.D:8089"
$Login = "user"
$Password = "password"
$APIKEY = "azerty12345678"
$INTERNAL_ALLOW_IP_LIST=@("ipv4","ipv6","ipv4=6","ipv6")
$MinConfidenceScore = 90
$MinReportsCount = 10
$MinDistinctUserscount = 5
$MinLatestReport = -7 #days
$AttemptLimitToReport = 3
$ProcessLimit = 5000
$SplunkSearch = "searchindex=logs suspicious events | stats count by src | sort -count"
$IpsetBlockkist = "blocklist"
$BlacklistIPJSONFile = "AbuseIPDBBlocklist.json"
if(-not (Test-Path $BlacklistIPJSONFile)){ConvertTo-Json @() | Out-File $BlacklistIPJSONFile }

## SPLUNK SEARCH
#Authentication
$AuthPath = "/services/auth/login"
$Response = Invoke-RestMethod -Method Post -Uri ($BaseUrl+$AuthPath) -Body @{'username'=$Login ; 'password'=$Password} -SkipCertificateCheck
$sessionkey = $Response.response.sessionKey

#Search
$searchPath = "/services/search/jobs"
$Response = Invoke-RestMethod -Method Post -Uri ($BaseUrl+$searchPath) -Headers @{'Authorization'="Splunk $sessionkey"} -Body @{'search'="$SplunkSearch"} -SkipCertificateCheck
$SearchSID = $Response.response.sid

#wait for seach to finish
$SearchControlPath="/services/search/jobs/$SearchSID"
$isDone = 0
do {
    Start-Sleep -Seconds 1
    $Response = Invoke-RestMethod -Method Post -Uri ($BaseUrl+$SearchControlPath) -Headers @{'Authorization'="Splunk $sessionkey"} -SkipCertificateCheck
    $isDone = (([xml] $Response.InnerXml).entry.content.dict.key | Where-Object {$_.name -eq "isDone"})."#Text"
}while ($isDone -eq 0)

#Get the Result
$SearchResultPath="$SearchControlPath/results/"
$Response = Invoke-RestMethod -Method Get -Uri ($BaseUrl+$SearchResultPath) -Headers @{'Authorization'="Splunk $sessionkey"} -Body @{'output_mode'="json";"count"="$ProcessLimit"} -SkipCertificateCheck
$List = $Response.results

## ABUSE IPDB CORRELATION AND REPORT
#Analysing each IP
$blacklistIP = @()
$now = get-date
foreach($Ip in $List) {
    if($INTERNAL_ALLOW_IP_LIST.IndexOf($h.ipAddress) -eq -1){
        $abuseinfo = Invoke-RestMethod https://api.abuseipdb.com/api/v2/check -Headers @{"Key"="$APIKEY";"Accept"="application/json"} -Body @{"maxAgeInDays"="90";"ipAddress"="$($Ip.src)"}
        $h = $abuseinfo.data
        if($h.isWhitelisted -eq $false -and $h.isPublic -eq $true -and $h.abuseConfidenceScore -ge $MinConfidenceScore -and $h.totalReports -ge $MinReportsCount -and $h.numDistinctUsers -ge $MinDistinctUserscount -and ($h.lastReportedAt) -gt $now.AddDays($MinLatestReport)){
            Write-host ("Add To Blacklist : " + $Ip.src)
            $blacklistIP += @{"ip"="$($Ip.src)";date="$now"}
        }else{
            #report for Scan
            if($Ip.count -ge $AttemptLimitToReport){
                Write-host ("Add To Reportlist : " + $Ip.src)
                #$abuseinfo = Invoke-RestMethod https://api.abuseipdb.com/api/v2/report -Headers @{"Key"="$APIKEY";"Accept"="application/json"} -Body @{"ip"="$($Ip.src)";"categories"="18,21";"comment"="Wordpress Login bruteforce, $($Ip.count) attemps in 24h"} # not working, yet
                $abuseinfo = Invoke-Expression "curl -s https://api.abuseipdb.com/api/v2/report --data-urlencode `"ip=$($Ip.src)`" -d categories=18,21 --data-urlencode `"comment=Wordpress wp-login.php or xmlrpc.php bruteforce, $($Ip.count) attemps in the last 24h`" -H `"Key: $APIKEY`" -H `"Accept: application/json`""
            }else{
                Write-host ("Ip not reported - not enought try over 24h : " + $Ip.src)
            }
        }
    }
}#

#Fusion and Clean Previous blacklist with the new one
$oldlist = Get-Content $BlacklistIPJSONFile | ConvertFrom-Json
foreach ($oldip in $oldlist){
    if(($oldip.date) -gt ($now.AddDays($MinLatestReport)) -and ($blacklistIP.ip.IndexOf($oldip.ip) -eq -1)){
        # Maintain this IP in blocklist since the ioc is still Fresh
        Write-Host ("Maintaining $($oldip.ip) in blocklist")
        $blacklistIP +=  @{"ip"="$($oldip.ip)";date="$($oldip.date)"}
    }
}

#Backup new blacklist
$blacklistIP | ConvertTo-Json -Compress | Out-File $BlacklistIPJSONFile

##IPTABLE SET MANAGEMENT
#Create à new blocklist
$IpsetBlockkist_new = ($IpsetBlockkist+"_new")
Invoke-Expression ("ipset create $IpsetBlockkist_new hash:ip hashsize 4096")
Foreach ($ip in $blacklistIP){ # Add Ip into it
    Invoke-Expression ("ipset add $IpsetBlockkist_new $($ip.ip)")
}
#Swap Production with the new Blocklist
Invoke-Expression ("ipset -W $IpsetBlockkist $IpsetBlockkist_new")
Invoke-Expression ("ipset -X $IpsetBlockkist_new")
#END
