```sh
root@osboxes:~# volatility -f wcry.raw imageinfo
Volatility Foundation Volatility Framework 2.5
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/root/wcry.raw)
                      PAE type : No PAE
                           DTB : 0x39000L
                          KDBG : 0x8054cf60L
          Number of Processors : 1
     Image Type (Service Pack) : 3
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2017-05-12 21:26:32 UTC+0000
     Image local date and time : 2017-05-13 02:56:32 +0530
```
```sh
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP2x86 pslist
Volatility Foundation Volatility Framework 2.5
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          Exit
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------ ------------------------------
0x823c8830 System                    4      0     51      244 ------      0
0x82169020 smss.exe                348      4      3       19 ------      0 2017-05-12 21:21:55 UTC+0000
0x82161da0 csrss.exe               596    348     12      352      0      0 2017-05-12 21:22:00 UTC+0000
0x8216e020 winlogon.exe            620    348     23      536      0      0 2017-05-12 21:22:01 UTC+0000
0x821937f0 services.exe            664    620     15      265      0      0 2017-05-12 21:22:01 UTC+0000
0x82191658 lsass.exe               676    620     23      353      0      0 2017-05-12 21:22:01 UTC+0000
0x8221a2c0 svchost.exe             836    664     19      211      0      0 2017-05-12 21:22:02 UTC+0000
0x821b5230 svchost.exe             904    664      9      227      0      0 2017-05-12 21:22:03 UTC+0000
0x821af7e8 svchost.exe            1024    664     79     1366      0      0 2017-05-12 21:22:03 UTC+0000
0x8203b7a8 svchost.exe            1084    664      6       72      0      0 2017-05-12 21:22:03 UTC+0000
0x821bea78 svchost.exe            1152    664     10      173      0      0 2017-05-12 21:22:06 UTC+0000
0x821e2da0 spoolsv.exe            1484    664     14      124      0      0 2017-05-12 21:22:09 UTC+0000
0x821d9da0 explorer.exe           1636   1608     11      331      0      0 2017-05-12 21:22:10 UTC+0000
0x82218da0 tasksche.exe           1940   1636      7       51      0      0 2017-05-12 21:22:14 UTC+0000
0x82231da0 ctfmon.exe             1956   1636      1       86      0      0 2017-05-12 21:22:14 UTC+0000
0x81fb95d8 svchost.exe             260    664      5      105      0      0 2017-05-12 21:22:18 UTC+0000
0x81fde308 @WanaDecryptor@         740   1940      2       70      0      0 2017-05-12 21:22:22 UTC+0000
0x81f747c0 wuauclt.exe            1768   1024      7      132      0      0 2017-05-12 21:22:52 UTC+0000
0x82010020 alg.exe                 544    664      6      101      0      0 2017-05-12 21:22:55 UTC+0000
0x81fea8a0 wscntfy.exe            1168   1024      1       37      0      0 2017-05-12 21:22:56 UTC+0000
```
```sh
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP2x86 psscan
Volatility Foundation Volatility Framework 2.5
Offset(P)          Name                PID   PPID PDB        Time created                   Time exited
------------------ ---------------- ------ ------ ---------- ------------------------------ ------------------------------
0x0000000001f4daf0 taskdl.exe          860   1940 0x199f6000 2017-05-12 21:26:23 UTC+0000   2017-05-12 21:26:23 UTC+0000
0x0000000001f53d18 taskse.exe          536   1940 0x1986c000 2017-05-12 21:26:22 UTC+0000   2017-05-12 21:26:23 UTC+0000
0x0000000001f69b50 @WanaDecryptor@     424   1940 0x18fa2000 2017-05-12 21:25:52 UTC+0000   2017-05-12 21:25:53 UTC+0000
0x0000000001f747c0 wuauclt.exe        1768   1024 0x11629000 2017-05-12 21:22:52 UTC+0000
0x0000000001f8ba58 @WanaDecryptor@     576   1940 0x19671000 2017-05-12 21:26:22 UTC+0000   2017-05-12 21:26:23 UTC+0000
0x0000000001fb95d8 svchost.exe         260    664 0x0ce48000 2017-05-12 21:22:18 UTC+0000
0x0000000001fde308 @WanaDecryptor@     740   1940 0x0de3a000 2017-05-12 21:22:22 UTC+0000
0x0000000001fea8a0 wscntfy.exe        1168   1024 0x12217000 2017-05-12 21:22:56 UTC+0000
0x0000000001ffa710                       0      0 0x17d3f000
0x0000000002010020 alg.exe             544    664 0x1238d000 2017-05-12 21:22:55 UTC+0000
0x000000000203b7a8 svchost.exe        1084    664 0x0838c000 2017-05-12 21:22:03 UTC+0000
0x0000000002161da0 csrss.exe           596    348 0x07752000 2017-05-12 21:22:00 UTC+0000
0x0000000002169020 smss.exe            348      4 0x0683e000 2017-05-12 21:21:55 UTC+0000
0x000000000216e020 winlogon.exe        620    348 0x07957000 2017-05-12 21:22:01 UTC+0000
0x0000000002191658 lsass.exe           676    620 0x07bb7000 2017-05-12 21:22:01 UTC+0000
0x00000000021937f0 services.exe        664    620 0x07bad000 2017-05-12 21:22:01 UTC+0000
0x00000000021af7e8 svchost.exe        1024    664 0x081f7000 2017-05-12 21:22:03 UTC+0000
0x00000000021b5230 svchost.exe         904    664 0x08131000 2017-05-12 21:22:03 UTC+0000
0x00000000021bea78 svchost.exe        1152    664 0x08a15000 2017-05-12 21:22:06 UTC+0000
0x00000000021d9da0 explorer.exe       1636   1608 0x0add4000 2017-05-12 21:22:10 UTC+0000
0x00000000021e2da0 spoolsv.exe        1484    664 0x0a462000 2017-05-12 21:22:09 UTC+0000
0x0000000002218da0 tasksche.exe       1940   1636 0x0c0a2000 2017-05-12 21:22:14 UTC+0000
0x000000000221a2c0 svchost.exe         836    664 0x07e3e000 2017-05-12 21:22:02 UTC+0000
0x0000000002231da0 ctfmon.exe         1956   1636 0x0c01f000 2017-05-12 21:22:14 UTC+0000
0x00000000023c8830 System                4      0 0x00039000
```

```sh
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP2x86 psscan | grep 1940
Volatility Foundation Volatility Framework 2.5
0x0000000001f4daf0 taskdl.exe          860   1940 0x199f6000 2017-05-12 21:26:23 UTC+0000   2017-05-12 21:26:23 UTC+0000
0x0000000001f53d18 taskse.exe          536   1940 0x1986c000 2017-05-12 21:26:22 UTC+0000   2017-05-12 21:26:23 UTC+0000
0x0000000001f69b50 @WanaDecryptor@     424   1940 0x18fa2000 2017-05-12 21:25:52 UTC+0000   2017-05-12 21:25:53 UTC+0000
0x0000000001f8ba58 @WanaDecryptor@     576   1940 0x19671000 2017-05-12 21:26:22 UTC+0000   2017-05-12 21:26:23 UTC+0000
0x0000000001fde308 @WanaDecryptor@     740   1940 0x0de3a000 2017-05-12 21:22:22 UTC+0000
0x0000000002218da0 tasksche.exe       1940   1636 0x0c0a2000 2017-05-12 21:22:14 UTC+0000
```

```sh
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP2x86 psscan | grep 1940 | sort -k 7,7
Volatility Foundation Volatility Framework 2.5
0x0000000002218da0 tasksche.exe       1940   1636 0x0c0a2000 2017-05-12 21:22:14 UTC+0000
0x0000000001fde308 @WanaDecryptor@     740   1940 0x0de3a000 2017-05-12 21:22:22 UTC+0000
0x0000000001f69b50 @WanaDecryptor@     424   1940 0x18fa2000 2017-05-12 21:25:52 UTC+0000   2017-05-12 21:25:53 UTC+0000
0x0000000001f53d18 taskse.exe          536   1940 0x1986c000 2017-05-12 21:26:22 UTC+0000   2017-05-12 21:26:23 UTC+0000
0x0000000001f8ba58 @WanaDecryptor@     576   1940 0x19671000 2017-05-12 21:26:22 UTC+0000   2017-05-12 21:26:23 UTC+0000
0x0000000001f4daf0 taskdl.exe          860   1940 0x199f6000 2017-05-12 21:26:23 UTC+0000   2017-05-12 21:26:23 UTC+0000
```

```sh
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP2x86 dlllist -p 1940
Volatility Foundation Volatility Framework 2.5
************************************************************************
tasksche.exe pid:   1940
Command line : "C:\Intel\ivecuqmanpnirkt615\tasksche.exe"
Service Pack 3

Base             Size  LoadCount Path
---------- ---------- ---------- ----
0x00400000   0x35a000     0xffff C:\Intel\ivecuqmanpnirkt615\tasksche.exe
0x7c900000    0xb2000     0xffff C:\WINDOWS\system32\ntdll.dll
0x7c800000    0xf6000     0xffff C:\WINDOWS\system32\kernel32.dll
0x7e410000    0x91000     0xffff C:\WINDOWS\system32\USER32.dll
0x77f10000    0x49000     0xffff C:\WINDOWS\system32\GDI32.dll
0x77dd0000    0x9b000     0xffff C:\WINDOWS\system32\ADVAPI32.dll
0x77e70000    0x93000     0xffff C:\WINDOWS\system32\RPCRT4.dll
0x77fe0000    0x11000     0xffff C:\WINDOWS\system32\Secur32.dll
0x77c10000    0x58000     0xffff C:\WINDOWS\system32\MSVCRT.dll
0x76390000    0x1d000        0x1 C:\WINDOWS\system32\IMM32.DLL
0x629c0000     0x9000        0x1 C:\WINDOWS\system32\LPK.DLL
0x74d90000    0x6b000        0x1 C:\WINDOWS\system32\USP10.dll
0x77b40000    0x22000        0x1 C:\WINDOWS\system32\Apphelp.dll
0x77c00000     0x8000        0x1 C:\WINDOWS\system32\VERSION.dll
0x68000000    0x36000        0x1 C:\WINDOWS\system32\rsaenh.dll
0x7c9c0000   0x818000        0x1 C:\WINDOWS\system32\SHELL32.dll
0x77f60000    0x76000        0x3 C:\WINDOWS\system32\SHLWAPI.dll
0x773d0000   0x103000        0x2 C:\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202\comctl32.dll
0x76080000    0x65000        0x1 C:\WINDOWS\system32\MSVCP60.dll
0x77690000    0x21000        0x1 C:\WINDOWS\system32\NTMARTA.DLL
0x774e0000   0x13e000        0x1 C:\WINDOWS\system32\ole32.dll
0x71bf0000    0x13000        0x1 C:\WINDOWS\system32\SAMLIB.dll
0x76f60000    0x2c000        0x1 C:\WINDOWS\system32\WLDAP32.dll
0x769c0000    0xb4000        0x1 C:\WINDOWS\system32\USERENV.dll
0x5ad70000    0x38000        0x2 C:\WINDOWS\system32\uxtheme.dll
```

```sh
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP2x86 dlllist -p 740
Volatility Foundation Volatility Framework 2.5
************************************************************************
@WanaDecryptor@ pid:    740
Command line : @WanaDecryptor@.exe
Service Pack 3

Base             Size  LoadCount Path
---------- ---------- ---------- ----
0x00400000    0x3d000     0xffff C:\Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe
0x7c900000    0xb2000     0xffff C:\WINDOWS\system32\ntdll.dll
0x7c800000    0xf6000     0xffff C:\WINDOWS\system32\kernel32.dll
0x73dd0000    0xf2000     0xffff C:\WINDOWS\system32\MFC42.DLL
0x77c10000    0x58000     0xffff C:\WINDOWS\system32\msvcrt.dll
0x77f10000    0x49000     0xffff C:\WINDOWS\system32\GDI32.dll
0x7e410000    0x91000     0xffff C:\WINDOWS\system32\USER32.dll
0x77dd0000    0x9b000     0xffff C:\WINDOWS\system32\ADVAPI32.dll
0x77e70000    0x93000     0xffff C:\WINDOWS\system32\RPCRT4.dll
0x77fe0000    0x11000     0xffff C:\WINDOWS\system32\Secur32.dll
0x7c9c0000   0x818000     0xffff C:\WINDOWS\system32\SHELL32.dll
0x77f60000    0x76000     0xffff C:\WINDOWS\system32\SHLWAPI.dll
0x773d0000   0x103000     0xffff C:\WINDOWS\WinSxS\X86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202\COMCTL32.dll
0x77120000    0x8b000     0xffff C:\WINDOWS\system32\OLEAUT32.dll
0x774e0000   0x13e000     0xffff C:\WINDOWS\system32\ole32.dll
0x78130000   0x134000     0xffff C:\WINDOWS\system32\urlmon.dll
0x3dfd0000   0x1ec000     0xffff C:\WINDOWS\system32\iertutil.dll
0x76080000    0x65000     0xffff C:\WINDOWS\system32\MSVCP60.dll
0x71ab0000    0x17000     0xffff C:\WINDOWS\system32\WS2_32.dll
0x71aa0000     0x8000     0xffff C:\WINDOWS\system32\WS2HELP.dll
0x3d930000    0xe7000     0xffff C:\WINDOWS\system32\WININET.dll
0x00340000     0x9000     0xffff C:\WINDOWS\system32\Normaliz.dll
0x76390000    0x1d000        0x4 C:\WINDOWS\system32\IMM32.DLL
0x629c0000     0x9000        0x1 C:\WINDOWS\system32\LPK.DLL
0x74d90000    0x6b000        0x2 C:\WINDOWS\system32\USP10.dll
0x732e0000     0x5000        0x1 C:\WINDOWS\system32\RICHED32.DLL
0x74e30000    0x6d000        0x1 C:\WINDOWS\system32\RICHED20.dll
0x5ad70000    0x38000        0x3 C:\WINDOWS\system32\uxtheme.dll
0x74720000    0x4c000        0x1 C:\WINDOWS\system32\MSCTF.dll
0x755c0000    0x2e000        0x2 C:\WINDOWS\system32\msctfime.ime
0x769c0000    0xb4000        0x1 C:\WINDOWS\system32\USERENV.dll
0x00ea0000    0x29000        0x1 C:\WINDOWS\system32\msls31.dll
```
```sh
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP2x86 handles -p 1940 -t key
Volatility Foundation Volatility Framework 2.5
Offset(V)     Pid     Handle     Access Type             Details
---------- ------ ---------- ---------- ---------------- -------
0xe1a05938   1940       0x30  0x20f003f Key              MACHINE
0xe1b978d0   1940       0xc4  0x20f003f Key              USER\S-1-5-21-602162358-764733703-1957994488-1003
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP2x86 handles -p 1940 -t Mutant
Volatility Foundation Volatility Framework 2.5
Offset(V)     Pid     Handle     Access Type             Details
---------- ------ ---------- ---------- ---------------- -------
0x821883e8   1940       0x40   0x120001 Mutant           ShimCacheMutex
0x8224f180   1940       0x54   0x1f0001 Mutant           MsWinZonesCacheCounterMutexA
0x822e3b08   1940       0x58   0x1f0001 Mutant           MsWinZonesCacheCounterMutexA0
```
```sh
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP2x86 handles -p 1940 -t file
Volatility Foundation Volatility Framework 2.5
Offset(V)     Pid     Handle     Access Type             Details
---------- ------ ---------- ---------- ---------------- -------
0x81fbce00   1940        0xc   0x100020 File             \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202
0x82233f18   1940       0x34   0x100020 File             \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615
0x822386a8   1940       0x48   0x100001 File             \Device\KsecDD
0x823a0cd0   1940       0x50   0x100020 File             \Device\HarddiskVolume1\WINDOWS\WinSxS\x86_Microsoft.Windows.Common-Controls_6595b64144ccf1df_6.0.2600.6028_x-ww_61e65202
```
```sh
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP2x86 handles -p 740 -t key
Volatility Foundation Volatility Framework 2.5
Offset(V)     Pid     Handle     Access Type             Details
---------- ------ ---------- ---------- ---------------- -------
0xe1a3d558    740       0x34  0x20f003f Key              MACHINE
0xe1a9e6f0    740       0x4c  0x20f003f Key              USER\S-1-5-21-602162358-764733703-1957994488-1003_CLASSES
0xe1a1fcc0    740       0x50  0x20f003f Key              USER\S-1-5-21-602162358-764733703-1957994488-1003
0xe1a2cd68    740       0x5c    0x20019 Key              MACHINE\SOFTWARE\MICROSOFT\INTERNET EXPLORER\MAIN\FEATURECONTROL\FEATURE_PROTOCOL_LOCKDOWN
0xe1a43c20    740       0x60    0x2001f Key              USER\S-1-5-21-602162358-764733703-1957994488-1003\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\INTERNET SETTINGS
0xe1be7690    740       0xcc    0x20019 Key              USER\S-1-5-21-602162358-764733703-1957994488-1003\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINDOWS
0xe1a2e590    740       0xd0    0x20019 Key              MACHINE\SYSTEM\CONTROLSET001\CONTROL\NLS\LOCALE
0xe1a73608    740       0xd4    0x20019 Key              MACHINE\SYSTEM\CONTROLSET001\CONTROL\NLS\LOCALE\ALTERNATE SORTS
0xe1a735a0    740       0xd8    0x20019 Key              MACHINE\SYSTEM\CONTROLSET001\CONTROL\NLS\LANGUAGE GROUPS
0xe1a398e8    740       0xe4    0xf003f Key              MACHINE\SYSTEM\CONTROLSET001\SERVICES\WINSOCK2\PARAMETERS\PROTOCOL_CATALOG9
0xe1a78c78    740       0xec    0xf003f Key              MACHINE\SYSTEM\CONTROLSET001\SERVICES\WINSOCK2\PARAMETERS\NAMESPACE_CATALOG5
```
```sh
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP2x86 printkey -K "Microsoft\Windows\CurrentVersion\Run"
Volatility Foundation Volatility Framework 2.5
Legend: (S) = Stable   (V) = Volatile

----------------------------
Registry: \Device\HarddiskVolume1\WINDOWS\system32\config\software
Key name: Run (S)
Last updated: 2017-05-12 21:14:27 UTC+0000

Subkeys:

Values:
REG_SZ        ivecuqmanpnirkt615 : (S) "C:\Intel\ivecuqmanpnirkt615\tasksche.exe"
```
```sh
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP2x86 connections
Volatility Foundation Volatility Framework 2.5
Offset(V)  Local Address             Remote Address            Pid
---------- ------------------------- ------------------------- ---
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP2x86 connscan
Volatility Foundation Volatility Framework 2.5
Offset(P)  Local Address             Remote Address            Pid
---------- ------------------------- ------------------------- ---
```
```sh
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP2x86 filescan | grep ivecuqmanpnirkt615
Volatility Foundation Volatility Framework 2.5
0x0000000001f871a0      1      0 R--rw- \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe
0x0000000001fb17a8      1      0 R--r-d \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe
0x0000000001fb2278      1      0 R--r-d \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\taskse.exe
0x0000000001fbcef8      1      0 -W---- \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\u.wnry
0x000000000209dbe8      1      0 -W-r-- \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\00000000.res
0x000000000209de48      1      0 R--r-- \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\b.wnry
0x00000000021d8ac0      1      0 -W---- \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\s.wnry
0x00000000021dc028      1      0 R--r-d \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\taskdl.exe
0x00000000021f3870      1      0 R--rw- \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\tasksche.exe
0x000000000220ec40      1      0 -W---- \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\msg\m_turkish.wnry
0x0000000002212028      1      0 -W---- \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\msg\m_russian.wnry
0x0000000002217528      1      0 -W---- \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\msg\m_spanish.wnry
0x0000000002219b30      1      0 -W---- \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\msg\m_slovak.wnry
0x0000000002229748      1      0 -W---- \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\msg\m_vietnamese.wnry
0x0000000002232418      1      0 -W---- \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\msg\m_swedish.wnry
0x0000000002233f18      1      1 R--rw- \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615
0x00000000022456e0      1      1 R--rw- \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615
0x0000000002256c88      1      0 -W---- \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\t.wnry
0x00000000022bb7f8      1      0 R--r-- \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\00000000.pky
0x00000000022c72b0      1      0 R----- \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\msg\m_english.wnry
0x00000000022d2f28      1      0 R--r-d \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\tasksche.exe
0x00000000022ec718      1      0 R--rw- \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\c.wnry
0x00000000022f06f8      1      0 -W---- \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\msg\m_romanian.wnry
```

```sh
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP2x86 dumpfiles -Q 0x00000000022ec718 --dump-dir=.
Volatility Foundation Volatility Framework 2.5
DataSectionObject 0x022ec718   None   \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\c.wnry
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP2x86 dumpfiles -Q 0x00000000021dc028 --dump-dir=.
Volatility Foundation Volatility Framework 2.5
ImageSectionObject 0x021dc028   None   \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\taskdl.exe
DataSectionObject 0x021dc028   None   \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\taskdl.exe
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP2x86 dumpfiles -Q 0x0000000001fb2278 --dump-dir=.
Volatility Foundation Volatility Framework 2.5
ImageSectionObject 0x01fb2278   None   \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\taskse.exe
DataSectionObject 0x01fb2278   None   \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\taskse.exe
```

```sh
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP2x86 dumpfiles -Q 0x0000000001f871a0 --dump-dir=.
Volatility Foundation Volatility Framework 2.5
ImageSectionObject 0x01f871a0   None   \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe
DataSectionObject 0x01f871a0   None   \Device\HarddiskVolume1\Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe
```

```sh
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP2x86 memdump -p 1940,740 -D .
Volatility Foundation Volatility Framework 2.5
************************************************************************
Writing tasksche.exe [  1940] to 1940.dmp
************************************************************************
Writing @WanaDecryptor@ [   740] to 740.dmp
```
```sh
root@osboxes:~# strings 1940.dmp | head -n 100
|@@
|@@
|H;7
wH;7
|@@
|H;7
wH;7
|@@
|@@
|@@
cmd.exe /c start /b @WanaDecryptor@.exe vs
|4'%
"Pd.
1<L@
Qwhc"
ice Pack 3
p"` %
O*DD
I,-J
+oLA
|A#.
C:\Intel\ivecuqmanpnirkt615
tasksche.exe
```
```sh
root@osboxes:~# strings 740.dmp -n 6 | head -n 100
<:v `:v
<:v `:v
A~PB]u
Check &Payment
Check &Payment
A~kwB~
12t9YDPgwueZ9NyMgw519p7AA8isjr6SMw
gx7ekbenv2riucmf.onion;57g7spgrzlojinas.onion;xxlvbrloxvriy2c5.onion;76jdd2ir2embyv47.onion;cwwnhwhlz52maqm7.onion;
https://dist.torproject.org/torbrowser/6.5.1/tor-win32-0.2.9.10.zip
Ls't'=D
Ls't'=D
Ls't'=D
kActx
@WanaDecryptor@.exe
 !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~
C:\Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe
WinSta0\Default
MSCTF.MarshalInterface.FileMap.EBD.DB.CGAN
)s8'!K
High Contrast Black (large)
hr(c\t4
 &   !
Service Pack 3
]u4w\u4w\u[
]u4w\u
```

```sh
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP3x86 timeliner --output-file=/root/timeline.txt --output=body
Volatility Foundation Volatility Framework 2.5
WARNING : volatility.debug    : No ShimCache data found
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP3x86 mftparser --output-file=/root/mftparser.txt --output=body
Volatility Foundation Volatility Framework 2.5
Scanning for MFT entries and building directory, this can take a while
root@osboxes:~# volatility -f wcry.raw --profile WinXPSP3x86 shellbags --output-file=/root/shellbags.txt --output=body
Volatility Foundation Volatility Framework 2.5
Scanning for registries....
Gathering shellbag items and building path tree...
root@osboxes:~# cat timeline.txt >> largetimeliner.txt
root@osboxes:~# cat mftparser.txt >> largetimeliner.txt
root@osboxes:~# cat shellbags.txt >> largetimeliner.txt
```

```sh
root@osboxes:~# mactime -b largetimeliner.txt -d -z UTC+0530 | egrep -i '(tasksche|@WanaDecryptor@|taskdl|taskse)'
Xxx Xxx 00 0000 00:00:00,0,m...,---------------,0,0,0,"[PROCESS] @WanaDecryptor@ PID: 740/PPID: 1940/POffset: 0x01fde308"
Xxx Xxx 00 0000 00:00:00,0,m...,---------------,0,0,0,"[PROCESS] tasksche.exe PID: 1940/PPID: 1636/POffset: 0x02218da0"
Fri Aug 17 2001 03:49:44,0,macb,---------------,0,0,0,"[PE DEBUG] RICHED32.DLL Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x732e0000"
Fri Aug 17 2001 05:33:28,0,macb,---------------,0,0,0,"[PE HEADER (dll)] RICHED32.DLL Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x732e0000"
Wed Jun 28 2006 15:05:42,0,macb,---------------,0,0,0,"[PE DEBUG] Normaliz.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x00340000"
Wed Jun 28 2006 15:05:42,0,macb,---------------,0,0,0,"[PE HEADER (dll)] Normaliz.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x00340000"
Mon Mar 17 2008 14:39:32,0,macb,---------------,0,0,0,"[PE DEBUG] rsaenh.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x68000000"
Mon Mar 17 2008 14:39:32,0,macb,---------------,0,0,0,"[PE HEADER (dll)] rsaenh.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x68000000"
Sat Apr 12 2008 18:38:33,0,macb,---------------,0,0,0,"[PE DEBUG] LPK.DLL Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x629c0000"
Sat Apr 12 2008 18:38:33,0,macb,---------------,0,0,0,"[PE DEBUG] LPK.DLL Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x629c0000"
Sat Apr 12 2008 19:15:01,0,macb,---------------,0,0,0,"[PE DEBUG] Apphelp.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x77b40000"
Sat Apr 12 2008 19:16:17,0,macb,---------------,0,0,0,"[PE DEBUG] NTMARTA.DLL Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x77690000"
Sat Apr 12 2008 19:16:21,0,macb,---------------,0,0,0,"[PE DEBUG] USERENV.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x769c0000"
Sat Apr 12 2008 19:16:21,0,macb,---------------,0,0,0,"[PE DEBUG] USERENV.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x769c0000"
Sat Apr 12 2008 19:16:27,0,macb,---------------,0,0,0,"[PE DEBUG] SAMLIB.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x71bf0000"
Sat Apr 12 2008 19:16:59,0,macb,---------------,0,0,0,"[PE DEBUG] WLDAP32.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x76f60000"
Sat Apr 12 2008 19:17:51,0,macb,---------------,0,0,0,"[PE DEBUG] IMM32.DLL Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x76390000"
Sat Apr 12 2008 19:17:51,0,macb,---------------,0,0,0,"[PE DEBUG] IMM32.DLL Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x76390000"
Sat Apr 12 2008 19:20:45,0,macb,---------------,0,0,0,"[PE DEBUG] WS2HELP.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x71aa0000"
Sat Apr 12 2008 19:22:34,0,macb,---------------,0,0,0,"[PE DEBUG] USER32.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x7e410000"
Sat Apr 12 2008 19:22:34,0,macb,---------------,0,0,0,"[PE DEBUG] USER32.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x7e410000"
Sat Apr 12 2008 19:23:31,0,macb,---------------,0,0,0,"[PE DEBUG] VERSION.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x77c00000"
Sun Apr 13 2008 00:09:35,0,macb,---------------,0,0,0,"[PE HEADER (dll)] Apphelp.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x77b40000"
Sun Apr 13 2008 00:10:13,0,macb,---------------,0,0,0,"[PE HEADER (dll)] LPK.DLL Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x629c0000"
Sun Apr 13 2008 00:10:13,0,macb,---------------,0,0,0,"[PE HEADER (dll)] LPK.DLL Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x629c0000"
Sun Apr 13 2008 00:10:15,0,macb,---------------,0,0,0,"[PE HEADER (dll)] IMM32.DLL Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x76390000"
Sun Apr 13 2008 00:10:15,0,macb,---------------,0,0,0,"[PE HEADER (dll)] IMM32.DLL Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x76390000"
Sun Apr 13 2008 00:10:46,0,macb,---------------,0,0,0,"[PE HEADER (dll)] SAMLIB.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x71bf0000"
Sun Apr 13 2008 00:11:07,0,macb,---------------,0,0,0,"[PE HEADER (dll)] USER32.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x7e410000"
Sun Apr 13 2008 00:11:07,0,macb,---------------,0,0,0,"[PE HEADER (dll)] USER32.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x7e410000"
Sun Apr 13 2008 00:11:08,0,macb,---------------,0,0,0,"[PE HEADER (dll)] NTMARTA.DLL Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x77690000"
Sun Apr 13 2008 00:11:08,0,macb,---------------,0,0,0,"[PE HEADER (dll)] USERENV.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x769c0000"
Sun Apr 13 2008 00:11:08,0,macb,---------------,0,0,0,"[PE HEADER (dll)] USERENV.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x769c0000"
Sun Apr 13 2008 00:11:09,0,macb,---------------,0,0,0,"[PE HEADER (dll)] VERSION.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x77c00000"
Sun Apr 13 2008 00:11:10,0,macb,---------------,0,0,0,"[PE HEADER (dll)] uxtheme.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x5ad70000"
Sun Apr 13 2008 00:11:10,0,macb,---------------,0,0,0,"[PE HEADER (dll)] uxtheme.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x5ad70000"
Sun Apr 13 2008 00:11:26,0,macb,---------------,0,0,0,"[PE HEADER (dll)] WLDAP32.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x76f60000"
Sun Apr 13 2008 00:12:19,0,macb,---------------,0,0,0,"[PE HEADER (dll)] WS2_32.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x71ab0000"
Sun Apr 13 2008 00:12:20,0,macb,---------------,0,0,0,"[PE HEADER (dll)] WS2HELP.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x71aa0000"
Sun Apr 13 2008 00:12:55,0,macb,---------------,0,0,0,"[PE HEADER (dll)] MSVCP60.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x76080000"
Sun Apr 13 2008 00:12:55,0,macb,---------------,0,0,0,"[PE HEADER (dll)] MSVCP60.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x76080000"
Thu Oct 02 2008 11:42:57,0,macb,---------------,0,0,0,"[PE DEBUG] RICHED20.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x74e30000"
Thu Oct 02 2008 14:46:04,0,macb,---------------,0,0,0,"[PE HEADER (dll)] RICHED20.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x74e30000"
Fri Oct 24 2008 12:48:41,0,macb,---------------,0,0,0,"[PE DEBUG] MSVCRT.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x77c10000"
Fri Oct 24 2008 12:48:41,0,macb,---------------,0,0,0,"[PE DEBUG] msvcrt.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x77c10000"
Tue Oct 28 2008 09:48:57,0,macb,---------------,0,0,0,"[PE HEADER (dll)] MSVCRT.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x77c10000"
Tue Oct 28 2008 09:48:57,0,macb,---------------,0,0,0,"[PE HEADER (dll)] msvcrt.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x77c10000"
Wed Feb 25 2009 12:15:02,0,macb,---------------,0,0,0,"[PE DEBUG] msctfime.ime Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x755c0000"
Thu Feb 26 2009 04:42:51,0,macb,---------------,0,0,0,"[PE HEADER (dll)] msctfime.ime Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x755c0000"
Sat Mar 07 2009 11:22:35,0,macb,---------------,0,0,0,"[PE DEBUG] msls31.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x00ea0000"
Sat Mar 07 2009 11:22:35,0,macb,---------------,0,0,0,"[PE HEADER (dll)] msls31.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x00ea0000"
Tue Jun 23 2009 11:20:42,0,macb,---------------,0,0,0,"[PE DEBUG] Secur32.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x77fe0000"
Tue Jun 23 2009 11:20:42,0,macb,---------------,0,0,0,"[PE DEBUG] Secur32.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x77fe0000"
Wed Jun 24 2009 08:41:10,0,macb,---------------,0,0,0,"[PE HEADER (dll)] Secur32.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x77fe0000"
Wed Jun 24 2009 08:41:10,0,macb,---------------,0,0,0,"[PE HEADER (dll)] Secur32.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x77fe0000"
Sun Jul 12 2009 23:19:35,0,macb,---------------,0,0,0,"[PE HEADER (dll)] @WanaDecryptor@.exe Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x00400000"
Sun Dec 06 2009 12:35:52,0,macb,---------------,0,0,0,"[PE DEBUG] SHLWAPI.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x77f60000"
Sun Dec 06 2009 12:35:52,0,macb,---------------,0,0,0,"[PE DEBUG] SHLWAPI.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x77f60000"
Mon Dec 07 2009 09:01:24,0,macb,---------------,0,0,0,"[PE HEADER (dll)] SHLWAPI.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x77f60000"
Mon Dec 07 2009 09:01:24,0,macb,---------------,0,0,0,"[PE HEADER (dll)] SHLWAPI.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x77f60000"
Sun Aug 22 2010 13:00:30,0,macb,---------------,0,0,0,"[PE DEBUG] COMCTL32.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x773d0000"
Sun Aug 22 2010 13:00:30,0,macb,---------------,0,0,0,"[PE DEBUG] comctl32.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x773d0000"
Sun Aug 22 2010 16:12:01,0,macb,---------------,0,0,0,"[PE HEADER (dll)] COMCTL32.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x773d0000"
Sun Aug 22 2010 16:12:01,0,macb,---------------,0,0,0,"[PE HEADER (dll)] comctl32.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x773d0000"
Fri Nov 19 2010 09:05:05,0,macb,---------------,0,0,0,"[PE HEADER (exe)] tasksche.exe Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x00400000"
Wed Dec 08 2010 15:15:41,0,macb,---------------,0,0,0,"[PE HEADER (dll)] ntdll.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x7c900000"
Wed Dec 08 2010 15:15:41,0,macb,---------------,0,0,0,"[PE HEADER (dll)] ntdll.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x7c900000"
Sun Oct 16 2011 14:13:30,0,macb,---------------,0,0,0,"[PE DEBUG] MSCTF.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x74720000"
Mon Oct 17 2011 11:08:10,0,macb,---------------,0,0,0,"[PE HEADER (dll)] MSCTF.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x74720000"
Tue Nov 08 2011 19:26:08,0,macb,---------------,0,0,0,"[PE DEBUG] MFC42.DLL Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x73dd0000"
Mon Nov 21 2011 08:44:20,0,macb,---------------,0,0,0,"[PE HEADER (dll)] MFC42.DLL Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x73dd0000"
Thu Jun 07 2012 13:54:26,0,macb,---------------,0,0,0,"[PE DEBUG] SHELL32.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x7c9c0000"
Thu Jun 07 2012 13:54:26,0,macb,---------------,0,0,0,"[PE DEBUG] SHELL32.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x7c9c0000"
Thu Jun 07 2012 14:24:16,0,macb,---------------,0,0,0,"[PE HEADER (dll)] SHELL32.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x7c9c0000"
Thu Jun 07 2012 14:24:16,0,macb,---------------,0,0,0,"[PE HEADER (dll)] SHELL32.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x7c9c0000"
Sun Sep 30 2012 13:36:25,0,macb,---------------,0,0,0,"[PE DEBUG] kernel32.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x7c800000"
Sun Sep 30 2012 13:36:25,0,macb,---------------,0,0,0,"[PE DEBUG] kernel32.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x7c800000"
Tue Oct 02 2012 04:57:29,0,macb,---------------,0,0,0,"[PE HEADER (dll)] kernel32.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x7c800000"
Tue Oct 02 2012 04:57:29,0,macb,---------------,0,0,0,"[PE HEADER (dll)] kernel32.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x7c800000"
Thu Jan 24 2013 18:49:11,0,macb,---------------,0,0,0,"[PE DEBUG] OLEAUT32.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x77120000"
Fri Jan 25 2013 03:55:10,0,macb,---------------,0,0,0,"[PE HEADER (dll)] OLEAUT32.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x77120000"
Sun Apr 21 2013 02:00:37,0,macb,---------------,0,0,0,"[PE DEBUG] ADVAPI32.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x77dd0000"
Sun Apr 21 2013 02:00:37,0,macb,---------------,0,0,0,"[PE DEBUG] ADVAPI32.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x77dd0000"
Sun Apr 21 2013 09:37:18,0,macb,---------------,0,0,0,"[PE HEADER (dll)] ADVAPI32.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x77dd0000"
Sun Apr 21 2013 09:37:18,0,macb,---------------,0,0,0,"[PE HEADER (dll)] ADVAPI32.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x77dd0000"
Mon May 27 2013 01:31:55,0,macb,---------------,0,0,0,"[PE DEBUG] RPCRT4.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x77e70000"
Mon May 27 2013 01:31:55,0,macb,---------------,0,0,0,"[PE DEBUG] RPCRT4.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x77e70000"
Mon May 27 2013 01:59:37,0,macb,---------------,0,0,0,"[PE HEADER (dll)] RPCRT4.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x77e70000"
Mon May 27 2013 01:59:37,0,macb,---------------,0,0,0,"[PE HEADER (dll)] RPCRT4.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x77e70000"
Mon Jul 08 2013 02:04:03,0,macb,---------------,0,0,0,"[PE DEBUG] USP10.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x74d90000"
Mon Jul 08 2013 02:04:03,0,macb,---------------,0,0,0,"[PE DEBUG] USP10.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x74d90000"
Tue Jul 09 2013 10:37:53,0,macb,---------------,0,0,0,"[PE HEADER (dll)] USP10.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x74d90000"
Tue Jul 09 2013 10:37:53,0,macb,---------------,0,0,0,"[PE HEADER (dll)] USP10.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x74d90000"
Fri Aug 02 2013 01:31:30,0,macb,---------------,0,0,0,"[PE DEBUG] ole32.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x774e0000"
Fri Aug 02 2013 01:31:30,0,macb,---------------,0,0,0,"[PE DEBUG] ole32.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x774e0000"
Sun Aug 04 2013 13:30:32,0,macb,---------------,0,0,0,"[PE HEADER (dll)] ole32.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x774e0000"
Sun Aug 04 2013 13:30:32,0,macb,---------------,0,0,0,"[PE HEADER (dll)] ole32.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x774e0000"
Tue Oct 08 2013 05:27:14,0,macb,---------------,0,0,0,"[PE DEBUG] GDI32.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x77f10000"
Tue Oct 08 2013 05:27:14,0,macb,---------------,0,0,0,"[PE DEBUG] GDI32.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x77f10000"
Tue Oct 08 2013 13:12:48,0,macb,---------------,0,0,0,"[PE HEADER (dll)] GDI32.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x77f10000"
Tue Oct 08 2013 13:12:48,0,macb,---------------,0,0,0,"[PE HEADER (dll)] GDI32.dll Process: tasksche.exe/PID: 1940/PPID: 1636/Process POffset: 0x02218da0/DLL Base: 0x77f10000"
Fri Oct 11 2013 09:31:12,0,macb,---------------,0,0,0,"[PE DEBUG] iertutil.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x3dfd0000"
Fri Oct 11 2013 09:34:03,0,macb,---------------,0,0,0,"[PE DEBUG] WININET.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x3d930000"
Fri Oct 11 2013 09:34:47,0,macb,---------------,0,0,0,"[PE DEBUG] urlmon.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x78130000"
Sat Oct 12 2013 07:24:21,0,macb,---------------,0,0,0,"[PE HEADER (dll)] iertutil.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x3dfd0000"
Sat Oct 12 2013 07:25:26,0,macb,---------------,0,0,0,"[PE HEADER (dll)] urlmon.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x78130000"
Sat Oct 12 2013 07:25:35,0,macb,---------------,0,0,0,"[PE HEADER (dll)] WININET.dll Process: @WanaDecryptor@/PID: 740/PPID: 1940/Process POffset: 0x01fde308/DLL Base: 0x3d930000"
Wed Aug 10 2016 19:08:35,0,macb,---------------,0,0,0,"[Handle (Key)] MACHINE\SYSTEM\CONTROLSET001\SERVICES\WINSOCK2\PARAMETERS\NAMESPACE_CATALOG5 @WanaDecryptor@ PID: 740/PPID: 1940/POffset: 0x01fde308"
Wed Aug 10 2016 19:08:53,0,macb,---------------,0,0,0,"[Handle (Key)] MACHINE\SYSTEM\CONTROLSET001\SERVICES\WINSOCK2\PARAMETERS\PROTOCOL_CATALOG9 @WanaDecryptor@ PID: 740/PPID: 1940/POffset: 0x01fde308"
Wed Aug 10 2016 19:14:10,0,macb,---------------,0,0,0,"[Handle (Key)] MACHINE\SOFTWARE\MICROSOFT\INTERNET EXPLORER\MAIN\FEATURECONTROL\FEATURE_PROTOCOL_LOCKDOWN @WanaDecryptor@ PID: 740/PPID: 1940/POffset: 0x01fde308"
Wed Aug 10 2016 19:28:48,0,macb,---------------,0,0,0,"[Handle (Key)] USER\S-1-5-21-602162358-764733703-1957994488-1003\SOFTWARE\MICROSOFT\WINDOWS NT\CURRENTVERSION\WINDOWS @WanaDecryptor@ PID: 740/PPID: 1940/POffset: 0x01fde308"
Wed Aug 10 2016 19:29:10,0,macb,---------------,0,0,0,"[Handle (Key)] USER\S-1-5-21-602162358-764733703-1957994488-1003_CLASSES @WanaDecryptor@ PID: 740/PPID: 1940/POffset: 0x01fde308"
Thu Aug 11 2016 00:33:53,0,macb,---------------,0,0,0,"[Handle (Key)] MACHINE\SYSTEM\CONTROLSET001\CONTROL\NLS\LANGUAGE GROUPS @WanaDecryptor@ PID: 740/PPID: 1940/POffset: 0x01fde308"
Thu Aug 11 2016 00:33:53,0,macb,---------------,0,0,0,"[Handle (Key)] MACHINE\SYSTEM\CONTROLSET001\CONTROL\NLS\LOCALE @WanaDecryptor@ PID: 740/PPID: 1940/POffset: 0x01fde308"
Thu Aug 11 2016 00:33:53,0,macb,---------------,0,0,0,"[Handle (Key)] MACHINE\SYSTEM\CONTROLSET001\CONTROL\NLS\LOCALE\ALTERNATE SORTS @WanaDecryptor@ PID: 740/PPID: 1940/POffset: 0x01fde308"
Sun Aug 14 2016 09:00:37,0,macb,---------------,0,0,0,"[Handle (Key)] USER\S-1-5-21-602162358-764733703-1957994488-1003\SOFTWARE\MICROSOFT\WINDOWS\CURRENTVERSION\INTERNET SETTINGS @WanaDecryptor@ PID: 740/PPID: 1940/POffset: 0x01fde308"
Wed May 10 2017 14:43:20,0,m...,---------------,0,0,0,"[SHELLBAGS ITEMPOS] Name: @WanaDecryptor@.bmp/Attrs: ARC/FullPath: @WanaDecryptor@.bmp/Registry: \Device\HarddiskVolume1\Documents and Settings\donny\NTUSER.DAT /Key: Software\Microsoft\Windows\Shell\Bags\1\Desktop/LW: 2017-05-12 21:22:25 UTC+0000"
Wed May 10 2017 20:52:56,0,m...,---------------,0,0,0,"[SHELLBAGS ITEMPOS] Name: @WanaDecryptor@.exe/Attrs: ARC/FullPath: @WanaDecryptor@.exe/Registry: \Device\HarddiskVolume1\Documents and Settings\donny\NTUSER.DAT /Key: Software\Microsoft\Windows\Shell\Bags\1\Desktop/LW: 2017-05-12 21:22:25 UTC+0000"
Wed May 10 2017 20:52:56,0,m..b,---a-----------,0,0,17025,"[MFT STD_INFO] Intel\ivecuqmanpnirkt615\taskdl.exe (Offset: 0x10271400)"
Wed May 10 2017 20:52:56,0,m..b,---a-----------,0,0,17026,"[MFT STD_INFO] Intel\ivecuqmanpnirkt615\taskse.exe (Offset: 0x10271800)"
Thu May 11 2017 21:13:47,0,m...,--sa-----------,0,0,16990,"[MFT STD_INFO] Intel\ivecuqmanpnirkt615\tasksche.exe (Offset: 0xf468800)"
Thu May 11 2017 21:13:49,0,macb,--sa-----------,0,0,16990,"[MFT FILE_NAME] Intel\ivecuqmanpnirkt615\tasksche.exe (Offset: 0xf468800)"
Thu May 11 2017 21:13:49,0,...b,--sa-----------,0,0,16990,"[MFT STD_INFO] Intel\ivecuqmanpnirkt615\tasksche.exe (Offset: 0xf468800)"
Thu May 11 2017 21:13:51,0,macb,---a-----------,0,0,17025,"[MFT FILE_NAME] Intel\ivecuqmanpnirkt615\taskdl.exe (Offset: 0x10271400)"
Thu May 11 2017 21:13:51,0,macb,---a-----------,0,0,17026,"[MFT FILE_NAME] Intel\ivecuqmanpnirkt615\taskse.exe (Offset: 0x10271800)"
Thu May 11 2017 21:13:55,0,macb,---a-------I---,0,0,17032,"[MFT FILE_NAME] WINDOWS\Prefetch\TASKDL.EXE-01687054.pf (Offset: 0x13c46000)"
Thu May 11 2017 21:13:55,0,macb,---a-------I---,0,0,17032,"[MFT FILE_NAME] WINDOWS\Prefetch\TASKDL~1.PF (Offset: 0x13c46000)"
Thu May 11 2017 21:13:55,0,...b,---a-------I---,0,0,17032,"[MFT STD_INFO] WINDOWS\Prefetch\TASKDL~1.PF (Offset: 0x13c46000)"
Thu May 11 2017 21:13:55,0,macb,---a-----------,0,0,17033,"[MFT FILE_NAME] Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe (Offset: 0x13c46400)"
Thu May 11 2017 21:13:55,0,macb,---a-----------,0,0,17038,"[MFT FILE_NAME] Documents and Settings\donny\Desktop\@WanaDecryptor@.exe (Offset: 0xbc1c800)"
Thu May 11 2017 21:13:56,0,..cb,---------------,0,0,0,"[SHELLBAGS ITEMPOS] Name: @WanaDecryptor@.exe/Attrs: ARC/FullPath: @WanaDecryptor@.exe/Registry: \Device\HarddiskVolume1\Documents and Settings\donny\NTUSER.DAT /Key: Software\Microsoft\Windows\Shell\Bags\1\Desktop/LW: 2017-05-12 21:22:25 UTC+0000"
Thu May 11 2017 21:13:57,0,macb,---a-----------,0,0,17047,"[MFT FILE_NAME] Intel\ivecuqmanpnirkt615\@WanaDecryptor@.exe.lnk (Offset: 0x14e7ec00)"
Thu May 11 2017 21:13:58,0,macb,---a-----------,0,0,17052,"[MFT FILE_NAME] @WanaDecryptor@.exe (Offset: 0x1ae8a000)"
Thu May 11 2017 21:13:58,0,macb,---a-----------,0,0,17054,"[MFT FILE_NAME] Documents and Settings\All Users\Application Data\Microsoft\User Account Pictures\@WanaDecryptor@.exe.lnk (Offset: 0x1ae8a800)"
Thu May 11 2017 21:13:58,0,macb,---a-----------,0,0,17055,"[MFT FILE_NAME] Documents and Settings\All Users\Documents\My Music\Sample Music\@WanaDecryptor@.exe.lnk (Offset: 0x1ae8ac00)"
Thu May 11 2017 21:14:19,0,macb,---a-----------,0,0,17592,"[MFT FILE_NAME] Documents and Settings\All Users\Desktop\@WanaDecryptor@.bmp (Offset: 0xbdc7000)"
Thu May 11 2017 21:14:19,0,macb,---a-----------,0,0,17593,"[MFT FILE_NAME] Documents and Settings\All Users\Desktop\@WanaDecryptor@.exe (Offset: 0xbdc7400)"
Thu May 11 2017 21:14:19,0,macb,---a-----------,0,0,17594,"[MFT FILE_NAME] Documents and Settings\Default User\Desktop\@WanaDecryptor@.bmp (Offset: 0xbdc7800)"
Thu May 11 2017 21:14:19,0,macb,---a-----------,0,0,17595,"[MFT FILE_NAME] Documents and Settings\Default User\Desktop\@WanaDecryptor@.exe (Offset: 0xbdc7c00)"
Thu May 11 2017 21:14:19,0,macb,---a-----------,0,0,17596,"[MFT FILE_NAME] Documents and Settings\donny\Desktop\@WanaDecryptor@.bmp (Offset: 0x69c1000)"
Thu May 11 2017 21:14:20,0,.acb,---------------,0,0,0,"[SHELLBAGS ITEMPOS] Name: @WanaDecryptor@.bmp/Attrs: ARC/FullPath: @WanaDecryptor@.bmp/Registry: \Device\HarddiskVolume1\Documents and Settings\donny\NTUSER.DAT /Key: Software\Microsoft\Windows\Shell\Bags\1\Desktop/LW: 2017-05-12 21:22:25 UTC+0000"
Thu May 11 2017 21:14:20,0,.acb,---------------,0,0,0,"[SHELLBAGS ITEMPOS] Name: @WanaDecryptor@.exe/Attrs: ARC/FullPath: @WanaDecryptor@.exe/Registry: \Device\HarddiskVolume1\Documents and Settings\donny\NTUSER.DAT /Key: Software\Microsoft\Windows\Shell\Bags\1\Desktop/LW: 2017-05-12 21:22:25 UTC+0000"
Thu May 11 2017 21:14:26,0,macb,---a-------I---,0,0,17612,"[MFT FILE_NAME] WINDOWS\Prefetch\TASKSE.EXE-02A1B304.pf (Offset: 0xde89000)"
Thu May 11 2017 21:14:26,0,macb,---a-------I---,0,0,17612,"[MFT FILE_NAME] WINDOWS\Prefetch\TASKSE~1.PF (Offset: 0xde89000)"
Thu May 11 2017 21:14:26,0,...b,---a-------I---,0,0,17612,"[MFT STD_INFO] WINDOWS\Prefetch\TASKSE~1.PF (Offset: 0xde89000)"
Thu May 11 2017 21:14:28,0,.a..,---------------,0,0,0,"[SHELLBAGS ITEMPOS] Name: @WanaDecryptor@.bmp/Attrs: ARC/FullPath: @WanaDecryptor@.bmp/Registry: \Device\HarddiskVolume1\Documents and Settings\donny\NTUSER.DAT /Key: Software\Microsoft\Windows\Shell\Bags\1\Desktop/LW: 2017-05-12 21:22:25 UTC+0000"
Thu May 11 2017 21:14:30,0,macb,---a-------I---,0,0,17614,"[MFT FILE_NAME] WINDOWS\Prefetch\@WANADECRYPTOR@.EXE-06F053F5.pf (Offset: 0xde89800)"
Thu May 11 2017 21:22:00,0,macb,---------------,0,0,0,"[Handle (Key)] MACHINE @WanaDecryptor@ PID: 740/PPID: 1940/POffset: 0x01fde308"
Thu May 11 2017 21:22:00,0,macb,---------------,0,0,0,"[Handle (Key)] MACHINE tasksche.exe PID: 1940/PPID: 1636/POffset: 0x02218da0"
Thu May 11 2017 21:22:14,0,macb,---------------,0,0,0,"[PROCESS LastTrimTime] tasksche.exe PID: 1940/PPID: 1636/POffset: 0x02218da0"
Thu May 11 2017 21:22:14,0,.acb,---------------,0,0,0,"[PROCESS] tasksche.exe PID: 1940/PPID: 1636/POffset: 0x02218da0"
Thu May 11 2017 21:22:14,0,.ac.,--sa-----------,0,0,16990,"[MFT STD_INFO] Intel\ivecuqmanpnirkt615\tasksche.exe (Offset: 0xf468800)"
Thu May 11 2017 21:22:20,0,..c.,---a-----------,0,0,17025,"[MFT STD_INFO] Intel\ivecuqmanpnirkt615\taskdl.exe (Offset: 0x10271400)"
Thu May 11 2017 21:22:20,0,..c.,---a-----------,0,0,17026,"[MFT STD_INFO] Intel\ivecuqmanpnirkt615\taskse.exe (Offset: 0x10271800)"
Thu May 11 2017 21:22:21,0,.a..,---a-----------,0,0,17025,"[MFT STD_INFO] Intel\ivecuqmanpnirkt615\taskdl.exe (Offset: 0x10271400)"
Thu May 11 2017 21:22:21,0,.a..,---a-----------,0,0,17026,"[MFT STD_INFO] Intel\ivecuqmanpnirkt615\taskse.exe (Offset: 0x10271800)"
Thu May 11 2017 21:22:22,0,macb,---------------,0,0,0,"[PROCESS LastTrimTime] @WanaDecryptor@ PID: 740/PPID: 1940/POffset: 0x01fde308"
Thu May 11 2017 21:22:22,0,.acb,---------------,0,0,0,"[PROCESS] @WanaDecryptor@ PID: 740/PPID: 1940/POffset: 0x01fde308"
Thu May 11 2017 21:22:23,0,macb,---------------,0,0,0,"[Handle (Key)] USER\S-1-5-21-602162358-764733703-1957994488-1003 @WanaDecryptor@ PID: 740/PPID: 1940/POffset: 0x01fde308"
Thu May 11 2017 21:22:23,0,macb,---------------,0,0,0,"[Handle (Key)] USER\S-1-5-21-602162358-764733703-1957994488-1003 tasksche.exe PID: 1940/PPID: 1636/POffset: 0x02218da0"
Thu May 11 2017 21:24:52,0,mac.,---a-------I---,0,0,17612,"[MFT STD_INFO] WINDOWS\Prefetch\TASKSE~1.PF (Offset: 0xde89000)"
Thu May 11 2017 21:25:52,0,.acb,---------------,0,0,0,"[PROCESS] @WanaDecryptor@ PID: 424/PPID: 1940/POffset: 0x01f69b50"
Thu May 11 2017 21:25:53,0,m...,---------------,0,0,0,"[PROCESS] @WanaDecryptor@ PID: 424/PPID: 1940/POffset: 0x01f69b50"
Thu May 11 2017 21:26:22,0,.acb,---------------,0,0,0,"[PROCESS] @WanaDecryptor@ PID: 576/PPID: 1940/POffset: 0x01f8ba58"
Thu May 11 2017 21:26:22,0,.acb,---------------,0,0,0,"[PROCESS] taskse.exe PID: 536/PPID: 1940/POffset: 0x01f53d18"
Thu May 11 2017 21:26:23,0,m...,---------------,0,0,0,"[PROCESS] @WanaDecryptor@ PID: 576/PPID: 1940/POffset: 0x01f8ba58"
Thu May 11 2017 21:26:23,0,macb,---------------,0,0,0,"[PROCESS] taskdl.exe PID: 860/PPID: 1940/POffset: 0x01f4daf0"
Thu May 11 2017 21:26:23,0,m...,---------------,0,0,0,"[PROCESS] taskse.exe PID: 536/PPID: 1940/POffset: 0x01f53d18"
Thu May 11 2017 21:26:23,0,mac.,---a-------I---,0,0,17032,"[MFT STD_INFO] WINDOWS\Prefetch\TASKDL~1.PF (Offset: 0x13c46000)"
```

