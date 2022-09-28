#!/bin/pwsh

using namespace System
using namespace System.Management.Automation

#requires -Version 7

# Global variables:
$manifestDirectory = "/home/tony/code/kubeaudit/manifests"
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
            [PSCustomObject]$auditFinding = $null

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
                    ManifestFile  = $_.locations.physicalLocation.artifactLocation.uri
                }
            }
            catch {
                $sarifParsingExMessage = "Unable to parse SARIF input string."
                $sarifException = [System.IO.FileFormatException]::new($sarifParsingExMessage)
                Write-Error -Exception $sarifException -ErrorAction Stop
            }

            return $auditFinding
        }
    }
}

$allAuditFindings = $allPodNames | ForEach-Object {
    # Build the file path for the resulting manifest file and write to directory:
    $manifestFileName = "{0}.yaml" -f $_
    $manifestFilePath = Join-Path -Path $manifestDirectory -ChildPath $manifestFileName
    kubectl get pod $_ --namespace $namespace --output yaml | Out-File -FilePath $manifestFilePath

    # Get the JSON result from kubeaudit using the sarif format and
    # send to the ConvertFrom-Sarif function to parse the data:
    $rawJsonResult = (kubeaudit all -f $manifestFilePath --format="sarif") -join ""
    $rawJsonResult | ConvertFrom-Sarif
}

$filteredView = $allAuditFindings | Where-Object -Property Level -eq ERROR

Write-Output -InputObject $filteredView
