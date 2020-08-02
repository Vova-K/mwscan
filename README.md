# malware_scanner
Minifilter Driver which detects malware file signature during file IO
## Requirements
  * VisualStudio 2015 (2017 ?) <br/>
  * WDK 10(build toolset WindowsKernelModeDriver10.0)<br/>
### Build steps
    Build in visual studio using mwdriver.sln
### Build output
  * mwscan.cer<br/>
  * mwscan.pdb<br/>
  * mwscan.sys<br/>

### Install steps

place the provided 'install.inf' file into build output, and run the 'install' action

### Run/start/stop commands (from administrative Ccommand line)

  * sc query mwscan
  * sc start mwscan
  * sc stop mwscan
  * sc delete mwscan

### Local debugging
  * windbg -kl

  * ed nt!Kd_DEFAULT_Mask 0xf
