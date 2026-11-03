# keyhop-ask.ps1: asks the user whether a command may use secrets.
#
# Reads the message from $env:KEYHOP_ASK_MESSAGE (never parsed as code) and
# prints deny, once or always. Closing the window or waiting 2 minutes denies.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = 'keyhop: allow access?'
$form.TopMost = $true
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedDialog'
$form.MaximizeBox = $false
$form.MinimizeBox = $false
$form.AutoSize = $true
$form.AutoSizeMode = 'GrowAndShrink'
$form.Padding = New-Object System.Windows.Forms.Padding 12

$layout = New-Object System.Windows.Forms.FlowLayoutPanel
$layout.FlowDirection = 'TopDown'
$layout.AutoSize = $true

$label = New-Object System.Windows.Forms.Label
$label.Text = $env:KEYHOP_ASK_MESSAGE
$label.AutoSize = $true
$label.MaximumSize = New-Object System.Drawing.Size 560, 0
$label.UseMnemonic = $false
$layout.Controls.Add($label)

$buttons = New-Object System.Windows.Forms.FlowLayoutPanel
$buttons.AutoSize = $true
$script:choice = 'deny'
foreach ($pair in @(@('Deny', 'deny'), @('Allow once', 'once'), @('Always allow', 'always'))) {
  $button = New-Object System.Windows.Forms.Button
  $button.Text = $pair[0]
  $button.AutoSize = $true
  $button.Tag = $pair[1]
  $button.Add_Click({ $script:choice = $this.Tag; $form.Close() })
  $buttons.Controls.Add($button)
  if ($pair[1] -eq 'deny') { $form.AcceptButton = $button; $form.CancelButton = $button }
}
$layout.Controls.Add($buttons)
$form.Controls.Add($layout)

$timer = New-Object System.Windows.Forms.Timer
$timer.Interval = 120000
$timer.Add_Tick({ $script:choice = 'deny'; $form.Close() })
$timer.Start()

[void]$form.ShowDialog()
Write-Output $script:choice
