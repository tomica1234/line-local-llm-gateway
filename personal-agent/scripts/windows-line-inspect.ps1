$ErrorActionPreference = "Stop"

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes

$process = Get-Process -Name LINE -ErrorAction Stop |
  Where-Object { $_.MainWindowHandle -ne 0 } |
  Select-Object -First 1

if ($null -eq $process) {
  throw "A visible LINE window was not found."
}

$root = [System.Windows.Automation.AutomationElement]::FromHandle($process.MainWindowHandle)
$elements = $root.FindAll(
  [System.Windows.Automation.TreeScope]::Descendants,
  [System.Windows.Automation.Condition]::TrueCondition
)

$summaries = for ($index = 0; $index -lt $elements.Count; $index++) {
  $element = $elements.Item($index)
  $current = $element.Current
  $name = if ($null -eq $current.Name) { "" } else { [string]$current.Name }
  [PSCustomObject]@{
    ControlType = $current.ControlType.ProgrammaticName
    ClassName = [string]$current.ClassName
    AutomationId = [string]$current.AutomationId
    NamePresent = $name.Length -gt 0
    NameLength = $name.Length
    IsOffscreen = $current.IsOffscreen
  }
}

[PSCustomObject]@{
  ProcessId = $process.Id
  WindowTitlePresent = ([string]$root.Current.Name).Length -gt 0
  ElementCount = $elements.Count
  ControlTypes = @(
    $summaries |
      Group-Object ControlType |
      Sort-Object Count -Descending |
      ForEach-Object {
        [PSCustomObject]@{ Type = $_.Name; Count = $_.Count }
      }
  )
  Classes = @(
    $summaries |
      Where-Object { $_.ClassName } |
      Group-Object ClassName |
      Sort-Object Count -Descending |
      Select-Object -First 30 |
      ForEach-Object {
        [PSCustomObject]@{ Class = $_.Name; Count = $_.Count }
      }
  )
  AutomationIds = @(
    $summaries |
      Where-Object { $_.AutomationId } |
      Group-Object AutomationId |
      Sort-Object Count -Descending |
      Select-Object -First 30 |
      ForEach-Object {
        [PSCustomObject]@{ Id = $_.Name; Count = $_.Count }
      }
  )
  NamedElementCount = @($summaries | Where-Object NamePresent).Count
  VisibleNamedElementCount = @(
    $summaries | Where-Object { $_.NamePresent -and -not $_.IsOffscreen }
  ).Count
} | ConvertTo-Json -Depth 6
