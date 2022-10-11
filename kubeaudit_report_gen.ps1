#!/bin/pwsh

using namespace System
using namespace System.IO
using namespace System.Management.Automation
using namespace System.Runtime.Serialization

#requires -Version 7
#requires -Module @{ModuleName="ImportExcel";ModuleVersion="7.3.0"}
#requires -Module @{ModuleName="Pester";ModuleVersion="5.3.0"}


# SECTION Global Variables

# All target namespaces:
$Namespaces = @('tigera-access',
    'tigera-compliance',
    'tigera-dex',
    'tigera-dpi',
    'tigera-elasticsearch',
    'tigera-fluentd',
    'tigera-guardian',
    'tigera-image-assurance',
    'tigera-intrusion-detection',
    'tigera-license',
    'tigera-manager',
    'tigera-operator',
    'tigera-packetcapture',
    'tigera-prometheus',
    'tigera-skraper',
    'tigera-system',
    'calico-cloud',
    'calico-system')

# Docker image for kubeaudit:
$KubeauditDockerImageVersion = "0.20.0"
$KubeauditDockerImage = "shopify/kubeaudit:v{0}" -f $KubeauditDockerImageVersion

# Output directory for pod manifest files:
$ManifestDirectory = "C:\code\kubeaudit\manifests"

# Output directory and file path for Excel file:
$OutputReportDirectory = "C:\code\kubeaudit\reports"

# Get today's date as part of file names:
$todaysDate = Get-Date

$excelFileName = "kubeaudit_report_{0}.xlsx" -f $todaysDate.ToShortDateString() -replace "/", "_"
$ExcelFilePath = Join-Path -Path $OutputReportDirectory -ChildPath $excelFileName

# NOTE Raw JSON results as optional
$IncludeJsonResults = $true
$jsonFileName = "kubeaudit_raw_data_{0}.json" -f $todaysDate.ToShortDateString() -replace "/", "_"
$JsonFilePath = Join-Path -Path $OutputReportDirectory -ChildPath $jsonFileName

# Target cluster to run audit against:
$ClusterName = kubectl config view --minify -o jsonpath='{.clusters[].name}'

# !SECTION


# SECTION Checks

# Determine that image exists based on the desired version:
$detectedVersion = docker run --rm $KubeauditDockerImage version
if (($null -eq $detectedVersion) -or ([Version]$detectedVersion -ne [Version]$KubeauditDockerImageVersion)) {
    $imageVersionExMessage = "Unable to obtain the following docker image: {0}" -f $KubeauditDockerImage
    $ArgumentException = [ArgumentException]::new($imageVersionExMessage)
    Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Stop
}

# Determine that $ManifestDirectory exists:
if (-not(Test-Path -Path $ManifestDirectory)) {
    $dirNotFoundExMessage = "The following directory was not found: {0}" -f $ManifestDirectory
    $DirectoryNotFoundException = [DirectoryNotFoundException]::new($dirNotFoundExMessage)
    Write-Error -Exception $DirectoryNotFoundException  -Category InvalidOperation -ErrorAction Stop
}

# Determine that $OutputReportDirectory exists:
if (-not(Test-Path -Path $OutputReportDirectory)) {
    $dirNotFoundExMessage = "The following directory was not found: {0}" -f $OutputReportDirectory
    $DirectoryNotFoundException = [DirectoryNotFoundException]::new($dirNotFoundExMessage)
    Write-Error -Exception $DirectoryNotFoundException  -Category InvalidOperation -ErrorAction Stop
}

# !SECTION


# SECTION Functions

function ConvertFrom-RawSarif {
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
    BEGIN {
        # TODO: Get this into a configuration file eventually:
        $cisBenchmarkTable = '[
            {
                "Auditor":  "automountServiceAccountToken",
                "Benchmark":  "cis-kubernetes-benchmark-5.1.6",
                "Link":  "https://github.com/dev-sec/cis-kubernetes-benchmark/blob/master/controls/5_1_policies_rbac_and_service_accounts.rb"
            },
            {
                "Auditor":  "capabilities",
                "Benchmark":  "cis-kubernetes-benchmark-5.2.9",
                "Link":  "https://github.com/dev-sec/cis-kubernetes-benchmark/blob/master/controls/5_2_policies_pod_security_policies.rb"
            },
            {
                "Auditor":  "hostns",
                "Benchmark":  "cis-kubernetes-benchmark-5.2.4",
                "Link":  "https://github.com/dev-sec/cis-kubernetes-benchmark/blob/master/controls/5_2_policies_pod_security_policies.rb"
            },
            {
                "Auditor":  "nonroot",
                "Benchmark":  "cis-kubernetes-benchmark-5.2.6",
                "Link":  "https://github.com/dev-sec/cis-kubernetes-benchmark/blob/master/controls/5_2_policies_pod_security_policies.rb"
            },
            {
                "Auditor":  "privesc",
                "Benchmark":  "cis-kubernetes-benchmark-5.2.5",
                "Link":  "https://github.com/dev-sec/cis-kubernetes-benchmark/blob/master/controls/5_2_policies_pod_security_policies.rb"
            },
            {
                "Auditor":  "privileged",
                "Benchmark":  "cis-kubernetes-benchmark-5.2.1",
                "Link":  "https://github.com/dev-sec/cis-kubernetes-benchmark/blob/master/controls/5_2_policies_pod_security_policies.rb"
            },
            {
                "Auditor":  "seccomp",
                "Benchmark":  "cis-kubernetes-benchmark-5.6.2",
                "Link":  "https://github.com/dev-sec/cis-kubernetes-benchmark/blob/master/controls/5_6_policies_general_policies.rb"
            }
        ]' | ConvertFrom-Json

    }
    PROCESS {
        [PSCustomObject]$deserializedPodAuditScanResults = $null

        try {
            $deserializedPodAuditScanResults = ($InputString | ConvertFrom-Json -Depth 25 -ErrorAction Stop).runs.results
        }
        catch {
            $jsonDeserializationExMessage = "Unable to deserialize JSON input string."
            $SerializationException = [SerializationException]::new($jsonDeserializationExMessage)
            Write-Error -Exception $SerializationException -Category InvalidType -ErrorAction Stop
        }

        $deserializedPodAuditScanResults | ForEach-Object {
            try {
                # Parse message text and create new PSObject based on that:
                $messageTextHashTable = $_.message.text | ConvertFrom-StringData -Delimiter ":" -ErrorAction Stop
                $messageObject = New-Object -TypeName PSObject -Property $messageTextHashTable -ErrorAction Stop

                # Obtain the pod name and corresponding manifest file:
                $podManifestFileName = Split-Path -Path $_.locations.physicalLocation.artifactLocation.uri -Leaf
                $podName = $podManifestFileName -replace ".yaml", ""

                $targetAuditor = $messageObject.Auditor

                $cisBenchmarkEntry = $cisBenchmarkTable | Where-Object -Property Auditor -eq $targetAuditor

                # Generate object,populate property, and send to pipeline:
                $auditFinding = [PSCustomObject]@{
                    Cluster         = $ClusterName
                    Namespace       = $targetNamespace
                    Pod             = $podName
                    RuleID          = $_.ruleId
                    Level           = $_.level
                    Auditor         = $targetAuditor
                    Details         = $messageObject.Details
                    Description     = $messageObject.Description
                    Documentation   = $messageObject.'Auditor docs'
                    CisBenchmark    = $cisBenchmarkEntry.Benchmark
                    CisBenchmarkUrl = $cisBenchmarkEntry.Link
                }
                Write-Output -InputObject $auditFinding
            }
            catch {
                $sarifParsingExMessage = "Unable to parse SARIF input string."
                $FileFormatException = [FileFormatException]::new($sarifParsingExMessage)
                Write-Error -Exception $FileFormatException -Category InvalidType -ErrorAction Stop
            }
        }
    }
}

# !SECTION


# SECTION Namespace Iteration and Audit Finding Aggregation:

# Declare empty array to contain all resulting audit objects:
$allAuditFindings = @()

foreach ($targetNamespace in $Namespaces) {

    # SECTION Get pod names
    # Get all pod names in order to iterate through each name to generate an individual manifest per pod:
    [string[]]$allPodNames = @()
    try {
        $podQueryExMessage = "Error when attempting to list pods in {0} namespace." -f $targetNamespace
        $ArgumentException = [ArgumentException]::new($podQueryExMessage)

        $allPodsJson = kubectl get pods --namespace $targetNamespace --output json
        $deserializedPodData = $allPodsJson | ConvertFrom-Json -ErrorAction Stop

        if ($deserializedPodData.items.Count -gt 0) {
            $allPodNames += $deserializedPodData.items.metadata.name | Sort-Object
        }
        else {
            throw $ArgumentException
        }
    }
    catch {
        Write-Error -Exception $ArgumentException -Category InvalidArgument -ErrorAction Continue
    }

    # !SECTION


    # SECTION Execute Kubeaudit and obtain all findings

    # 1. Iterate through all pod names
    # 2. Generate a manifest for each pod
    # 3. Run kubeaudit against each manifest and persist results to $rawJsonResult variable
    # 4. Deserialize each $rawJsonResult via ConvertFrom-RawSarif and add to $allAuditFindings
    $allAuditFindings += ($allPodNames | ForEach-Object {
            # Build the file path for the resulting manifest file and write to directory:
            $manifestFileName = "{0}.yaml" -f $_
            $manifestFilePath = Join-Path -Path $ManifestDirectory -ChildPath $manifestFileName
            kubectl get pod $_ --namespace $targetNamespace --output yaml | Out-File -FilePath $manifestFilePath

            # Run kubeaudit, get sarif output and assign it to the $rawJsonResult as a single string (via -join ""):
            $rawJsonResult = (docker run -v $ManifestDirectory/:/tmp $KubeauditDockerImage all -f /tmp/$manifestFileName --format="sarif" 2> $null) -join ""

            # Deserialize and add item to array $allAuditFindings:
            $rawJsonResult | ConvertFrom-RawSarif
        })

    # !SECTION


    # SECTION Cleanup manifest files

    Get-ChildItem -Path $ManifestDirectory -Filter "*.yaml" | ForEach-Object {
        Remove-Item -Path $_.FullName -Force | Out-Null
    }

    # !SECTION
}
# !SECTION


# SECTION Generate Excel and JSON error reports
# Collection containing only errors defined in the CIS baseline:
$errorCollection = $allAuditFindings | Where-Object -Property Level -eq "error" |
Where-Object -FilterScript {
        ($_.Auditor -eq "automountServiceAccountToken") -or
        ($_.Auditor -eq "capabilities") -or
        ($_.Auditor -eq "hostns") -or
        ($_.Auditor -eq "nonroot") -or
        ($_.Auditor -eq "privesc") -or
        ($_.Auditor -eq "privileged") -or
        ($_.Auditor -eq "seccomp")
}

$tableAndWorksheetName = "KubeauditFindings"

# If prior report exists, delete it:
if (Test-Path -Path $ExcelFilePath) {
    Remove-Item -Path $ExcelFilePath -Force
}

# Generate error report:
$excelExportProps = @{
    Path            = $ExcelFilePath
    TableName       = $tableAndWorksheetName
    WorksheetName   = $tableAndWorksheetName
    ConditionalText = (New-ConditionalText -Text "error" -ForeGroundColor Red -BackgroundColor default)
    TitleBold       = $true
    AutoSize        = $true
    WarningAction   = "SilentlyContinue"
    ErrorAction     = "Stop"
}

try {
    $errorCollection | Export-Excel @excelExportProps
}
catch {
    $unauthorizedAccessExMessage = "Unable to write Excel file to: {0}" -f $ExcelFilePath
    $UnauthorizedAccessException = [UnauthorizedAccessException]::new($unauthorizedAccessExMessage)
    Write-Error -Exception $UnauthorizedAccessException -Category SecurityError -ErrorAction Stop
}

if ($IncludeJsonResults) {
    try {
        $errorCollection | ConvertTo-Json -ErrorAction Stop | Out-File -FilePath $JsonFilePath -ErrorAction Stop
        Write-Verbose -Message ("Kubeaudit JSON data written succesfully to the following path: {0}" -f $JsonFilePath) -Verbose
    }
    catch {
        $unauthorizedAccessExMessage = "Unable to write JSON file to: {0}" -f $JsonFilePath
        $UnauthorizedAccessException = [UnauthorizedAccessException]::new($unauthorizedAccessExMessage)
        Write-Error -Exception $UnauthorizedAccessException -Category SecurityError -ErrorAction Stop
    }
}

Write-Verbose -Message ("Kubeaudit Excel report written succesfully to the following path: {0}" -f $ExcelFilePath) -Verbose

# !SECTION


# SECTION Pester tests

Describe "$ClusterName" -ForEach $errorCollection {
    $targetNamespace = $_.Namespace
    $podName = $_.Pod
    $auditor = $_.Auditor
    Context $targetNamespace {
        It "$podName.$auditor" {
            $_.Details | Should -BeNullOrEmpty
        }
    }
}

# !SECTION
