#!/bin/pwsh

using namespace System
using namespace System.Management.Automation

#requires -Version 7

# Output directory for pod manifest files:
$manifestDirectory = "/home/tony/code/kubeaudit/manifests"

# Target namespace that the pods are resident in:
$namespace = "default"

# Get all pod names in order to iterate through each name to generate an individual manifest per pod:
$allPodNames = (kubectl get pods --namespace $namespace --output json | ConvertFrom-Json).items.metadata.name | Sort-Object

function ConvertFrom-Sarif {
    <#
        .SYNOPSIS
            Takes a Static Analysis Results Interchange Format (SARIF) JSON result and deserializes into a PSCustomObject for processing
        .PARAMETER InputString
            The incoming SARIF JSON.
        .INPUTS
            System.String
        .OUTPUTS
            System.Management.Automation.PSCustomObject
    #>
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)][Alias('JSON', 'InputJson')][String]$InputString
    )

    PROCESS {
        [PSCustomObject]$deserializedPodAuditScanResults = $null

        try {
            $deserializedPodAuditScanResults = ($InputString | ConvertFrom-Json -Depth 25 -ErrorAction Stop).runs.results
        }
        catch {
            $jsonDeserializationExMessage = "Unable to deserialize JSON input string."
            $deserializationException = [System.Runtime.Serialization.SerializationException]::new($jsonDeserializationExMessage)
            Write-Error -Exception $deserializationException -ErrorAction Stop
        }

        $deserializedPodAuditScanResults | ForEach-Object {
            try {
                $messageTextHash = $_.message.text | ConvertFrom-StringData -Delimiter ":" -ErrorAction Stop
                $messageObject = New-Object -TypeName PSObject -Property $messageTextHash -ErrorAction Stop

                $auditFinding = [PSCustomObject]@{
                    RuleID        = $_.ruleId
                    Level         = $_.level.ToUpper()
                    Auditor       = $messageObject.Auditor
                    Details       = $messageObject.Details
                    Description   = $messageObject.Description
                    Documentation = $messageObject.'Auditor docs'
                    ManifestFile  = $(Split-Path -Path $_.locations.physicalLocation.artifactLocation.uri -Leaf)
                }

                Write-Output -InputObject $auditFinding
            }
            catch {
                $sarifParsingExMessage = "Unable to parse SARIF input string."
                $sarifException = [System.IO.FileFormatException]::new($sarifParsingExMessage)
                Write-Error -Exception $sarifException -ErrorAction Stop
            }
        }
    }
}

# Declare empty array to contain all resulting audit objects:
$allAuditFindings = @()

# 1. Iterate through all pod names
# 2. Generate a manifest for each pod
# 3. Run kubeaudit against each manifest and persist results to $rawJsonResult variable
# 4. Deserialize each $rawJsonResult via ConvertFrom-Sarif and add to $allAuditFindings
$allAuditFindings = $allPodNames | ForEach-Object {
    # Build the file path for the resulting manifest file and write to directory:
    $manifestFileName = "{0}.yaml" -f $_
    $manifestFilePath = Join-Path -Path $manifestDirectory -ChildPath $manifestFileName
    kubectl get pod $_ --namespace $namespace --output yaml | Out-File -FilePath $manifestFilePath

    # With docker, map the local manifest directory to the /tmp directory on the container, and execute the following command:
    # kubeaudit all -f <manifest file path> --format="sarif" ...
    # ...and join on literally nothing as this is necessary for string output to be deserialized by ConvertFrom-Json (inside of ConvertFrom-Sarif)
    # to recognize the string as a single string entry and not an array of strings. Weird, I know.
    $rawJsonResult = $(docker run -v $manifestDirectory/:/tmp shopify/kubeaudit all -f /tmp/$manifestFileName --format="sarif" 2>/dev/null) -join ""

    # Deserialize and add item to array $allAuditFindings:
    $rawJsonResult | ConvertFrom-Sarif
}

# Cleanup local manifest files:
Get-ChildItem -Path $manifestDirectory -Filter "*.yaml" | ForEach-Object {
    Remove-Item -Path $_.FullName -Force | Out-Null
}

# Sample filtered view returning only errors (no warnings):
$filteredView = $allAuditFindings | Where-Object -Property Level -eq ERROR
Write-Output -InputObject $filteredView
