# Byte[] <-> WinRT IBuffer for Windows PowerShell 5.1, dot-sourced by keyhop-auth.ps1.
#
# PowerShell 5.1 sees buffers returned by WinRT as System.__ComObject and can
# neither pick a .NET overload for them nor pass them back into WinRT. So:
#  - bytes -> IBuffer: AsBuffer makes a managed buffer, which WinRT accepts.
#  - IBuffer -> bytes: call ToArray through reflection (like the AsTask call),
#    which bypasses PowerShell's argument conversion; the CLR casts the COM
#    object to IBuffer itself.
Add-Type -AssemblyName System.Runtime.WindowsRuntime
$null = [Windows.Storage.Streams.IBuffer, Windows.Storage.Streams, ContentType = WindowsRuntime]

$bufferExtensions = [System.Runtime.InteropServices.WindowsRuntime.WindowsRuntimeBufferExtensions]
$toArray = $bufferExtensions.GetMethod('ToArray', [Type[]]@([Windows.Storage.Streams.IBuffer]))

function ConvertTo-WinRtBuffer([byte[]]$Bytes) {
  return $bufferExtensions::AsBuffer($Bytes)
}

function ConvertFrom-WinRtBuffer($Buffer) {
  return [byte[]]$toArray.Invoke($null, @($Buffer))
}
