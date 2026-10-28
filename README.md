# Malware Developments

> Personal study repository documenting my progress in Windows internals, malware behavior, and malware techniques. This is a learning portfolio aimed at building the foundations needed for a malware analysis and development career.

## About

I use this repository to keep track of concepts and exercises as I learn C/C++, Windows APIs, process behavior, and techniques commonly encountered during malware research. Some exercises demonstrate behaviors that also appear in malicious software; the goal is to understand how they work and how defenders can observe them.

This repository is a work in progress. Code and notes may be incomplete, experimental, or specific to the environment in which I studied them. The projects are inspired by publicly available research, educational material, and my own experiments. They are not intended to be production-ready tools or malware.

## Architecture
These exercises are developed and tested on Windows 11 x64, 26H2.

## Repository map

| Path | What it contains |
| --- | --- |
| `Learn/Started/` | Initial Windows process and API exercises, including `CreateProcess` and a message box example. |
| `Learn/Shellcode Injection/` | A study exercise around shellcode execution and related Windows behavior. |
| `Learn/DLL Injection/` | DLL-related exercises, with a separate `Reflective DLL Injection/` study folder and its supporting `sRDI/` files from the sRDI project. |
| `Learn/NTAPI Injection/` | A research on NtAPI usage in injection techniques. Exercises grouped into `partial/` and `Full NTAPI/` implementations. |
| `Learn/Syscall/` | In progress. |
| `Learn/Process Hollowing/` | In progress. |
| `Final/` | Consolidated experiments and learning projects. |
| `Detours/` | Microsoft Detours source and local build artifacts used by some experiments. |

Folder names describe study topics, not production-ready tools. Refer to each source file and its comments for its current state and dependencies.

## Learning goals

- Strengthen C and C++ fundamentals and Windows programming.
- Understand processes, threads, memory, DLL loading, and relevant Win32/NT APIs.
- Learn to recognize suspicious behaviors through static and dynamic analysis.
- Learn to identify and analyze malware techniques, including injection, shellcode execution, and API hooking.
- Research and develop new techniques to serve the defensive community, including detection and mitigation strategies.

## Lab safety and intended use

All material is for education and authorized research in an isolated lab or other environment where you have explicit permission. Do not run experiments on systems, accounts, networks, or data that you do not own or have permission to test. Do not use this repository to compromise systems, steal data, evade security controls, or deploy malware.

Some examples may trigger antivirus or EDR alerts, affect a test process, or behave differently across Windows versions and architectures. Use disposable virtual machines and snapshots, keep samples and test networks isolated, and never weaken protections on a machine containing sensitive data. Detection by security products is expected and is useful feedback for defensive study; this repository does not claim that its examples are harmless or undetectable.

## Learning references

This repository is informed by publicly available documentation, research, and educational material, including:

[Crow's maldev repository](https://github.com/cr-0w/maldev).

[Microsoft Docs](https://learn.microsoft.com/en-us/windows/win32/api).


[Nt Doc](https://ntdoc.m417z.com/).

[sRDI project](https://github.com/monoxgas/sRDI).

[Open Security Training](https://apps.p.ost2.fyi/learning/course/).

[VNPT Cyber Immunity blog](https://sec.vnpt.vn/tin-tuc/blog). 

## Disclaimer

The author does not endorse or authorize malicious use of this material. You are responsible for following applicable laws, policies, and the terms of any system you access. The repository is provided for educational purposes only.
