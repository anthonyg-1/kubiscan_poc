#!/bin/pwsh

using namespace System
using namespace System.IO
using namespace System.Management.Automation
using namespace System.Runtime.Serialization

#requires -Version 7

# Output directory for pod manifest files:
$ManifestDirectory = "/home/tony/code/kubeaudit/manifests"

# Target namespace that the pods are resident in:
$Namespace = "default"

# Docker image for kubaudit:
$DockerImage = "shopify/kubeaudit:v0.20"


# Determine that $ManifestDirectory exists:
if (-not(Test-Path -Path $ManifestDirectory)) {
    $fileNotFoundExMessage = "The following directory was not found: {0}" -f $ManifestDirectory
    $FileNotFoundException = [FileNotFoundException]::new($fileNotFoundExMessage)
    Write-Error -Exception $FileNotFoundException -ErrorAction Stop
}

# Get all pod names in order to iterate through each name to generate an individual manifest per pod:
[string[]]$allPodNames = @()
try {
    $argExMessage = "Error when attempting to list pods in {0} namespace." -f $Namespace
    $ArgumentException = [ArgumentException]::new($argExMessage)

    $allPodsJson = kubectl get pods --namespace $Namespace --output json
    $deserializedPodData = $allPodsJson | ConvertFrom-Json -ErrorAction Stop

    if ($deserializedPodData.items.Count -gt 0) {
        $allPodNames += $deserializedPodData.items.metadata.name | Sort-Object
    }
    else {
        throw $ArgumentException
    }
}
catch {
    Write-Error -Exception $ArgumentException -ErrorAction Stop
}

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
            $SerializationException = [SerializationException]::new($jsonDeserializationExMessage)
            Write-Error -Exception $SerializationException -ErrorAction Stop
        }

        $deserializedPodAuditScanResults | ForEach-Object {
            try {
                # Parse message.text and create new PSObject based on that:
                $messageTextHashTable = $_.message.text | ConvertFrom-StringData -Delimiter ":" -ErrorAction Stop
                $messageObject = New-Object -TypeName PSObject -Property $messageTextHashTable -ErrorAction Stop

                # Obtain the pod name and corresponding manifest file:
                $podManifestFileName = Split-Path -Path $_.locations.physicalLocation.artifactLocation.uri -Leaf
                $podName = $podManifestFileName.Split(".")[0]

                # Generate object,populate property, and send to pipeline:
                $auditFinding = [PSCustomObject]@{
                    RuleID        = $_.ruleId
                    Level         = $_.level.ToUpper()
                    Auditor       = $messageObject.Auditor
                    Details       = $messageObject.Details
                    Description   = $messageObject.Description
                    Documentation = $messageObject.'Auditor docs'
                    PodName       = $podName
                    ManifestFile  = $podManifestFileName
                }
                Write-Output -InputObject $auditFinding
            }
            catch {
                $sarifParsingExMessage = "Unable to parse SARIF input string."
                $FileFormatException = [FileFormatException]::new($sarifParsingExMessage)
                Write-Error -Exception $FileFormatException -ErrorAction Stop
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
    $manifestFilePath = Join-Path -Path $ManifestDirectory -ChildPath $manifestFileName
    kubectl get pod $_ --namespace $Namespace --output yaml | Out-File -FilePath $manifestFilePath

    # With docker, map the local manifest directory to the /tmp directory on the container, and execute the following command:
    # kubeaudit all -f <manifest file path> --format="sarif" ...
    # ...and join on literally nothing as this is necessary for string output to be deserialized by ConvertFrom-Json (inside of ConvertFrom-Sarif)
    # to recognize the string as a single string entry and not an array of strings. Weird, I know.
    $rawJsonResult = $(docker run -v $ManifestDirectory/:/tmp $DockerImage all -f /tmp/$manifestFileName --format="sarif" 2>/dev/null) -join ""

    # Deserialize and add item to array $allAuditFindings:
    $rawJsonResult | ConvertFrom-Sarif
}

# Cleanup local manifest files:
Get-ChildItem -Path $ManifestDirectory -Filter "*.yaml" | ForEach-Object {
    Remove-Item -Path $_.FullName -Force | Out-Null
}

# Sample filtered view returning only errors (no warnings):
$filteredView = $allAuditFindings | Where-Object -Property Level -eq ERROR
Write-Output -InputObject $filteredView
