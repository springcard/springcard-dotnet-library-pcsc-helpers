# SpringCard PC/SC Helpers for .NET

**SpringCard PC/SC Helpers** is a collection of .NET libraries that simplify working with SpringCard readers, smart cards and NFC/RFID tags. Built on [SpringCard.PCSC](https://www.nuget.org/packages/SpringCard.PCSC), they provide reusable implementations of reader commands, card-specific operations, authentication, secure messaging and NFC data handling.

This repository contains the library source code and related components. **For integration into your own application, use the published NuGet packages whenever possible**.

## NuGet packages

The libraries are delivered as separate packages so you can select the functionality your application needs.

| Package                                                      | Purpose                                                      |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| [SpringCard.PCSC.CardHelpers](https://www.nuget.org/packages/SpringCard.PCSC.CardHelpers) | Shared abstractions and utilities for card-specific helpers. |
| [SpringCard.PCSC.ReaderHelpers](https://www.nuget.org/packages/SpringCard.PCSC.ReaderHelpers) | SpringCard reader information, control commands and device-specific operations. |
| [SpringCard.PCSC.CardHelpers.Desfire](https://www.nuget.org/packages/SpringCard.PCSC.CardHelpers.Desfire) | MIFARE DESFire authentication, secure messaging, application and file management. |
| [SpringCard.PCSC.CardHelpers.SamAV](https://www.nuget.org/packages/SpringCard.PCSC.CardHelpers.SamAV) | MIFARE SAM AV commands, authentication, key management and cryptographic operations. |
| [SpringCard.PCSC.CardHelpers.Mifare](https://www.nuget.org/packages/SpringCard.PCSC.CardHelpers.Mifare) | MIFARE Classic and Ultralight operations, including authentication and memory access. |
| [SpringCard.PCSC.CardHelpers.Smid](https://www.nuget.org/packages/SpringCard.PCSC.CardHelpers.Smid) | SMID protocol handling and cryptographic operations.         |
| [SpringCard.PCSC.NfcForum](https://www.nuget.org/packages/SpringCard.PCSC.NfcForum) | NFC Forum tag access, NDEF messages and records, and LLCP/SNEP communication. |
| [SpringCard.PCSC.CardAnalysis](https://www.nuget.org/packages/SpringCard.PCSC.CardAnalysis) | ATR parsing, card identification data and card attribute analysis. |

Available operations depend on the reader, card or tag, and package version. See each package page and the corresponding project README for details and framework compatibility.

## Installation

Install the packages required by your application using the .NET CLI. For example, for DESFire operations:

```bash
dotnet add package SpringCard.PCSC.CardHelpers.Desfire
```

Or use the NuGet Package Manager in Visual Studio or its Package Manager Console:

```powershell
Install-Package SpringCard.PCSC.CardHelpers.Desfire
```

NuGet provides versioned releases and resolves package dependencies. You do not need to install every package in this repository.

## Libraries and SDK examples

These libraries contain the functional implementations reused by SpringCard applications. The [**SpringCard PC/SC SDK**](https://github.com/springcard/springcard.pcsc.sdk) primarily provides command-line and graphical front ends that demonstrate how to use them.

Use the libraries directly in your application, and refer to the SDK examples for integration patterns.

## Source code

Use this repository when you need to inspect the implementation or build from source. Open [projects/SpringCard.PCSC-Helpers.sln](projects/SpringCard.PCSC-Helpers.sln) in a compatible development environment and restore its NuGet dependencies.

The [projects](projects) directory contains the libraries, additional components and test applications. Framework targets and dependencies are defined in the project files and shared build configuration. Platform compatibility depends on the selected components; access to physical readers also requires a working PC/SC environment and appropriate drivers.

## Documentation

- [PC/SC Helpers API documentation](https://docs.springcard.com/apis/NET/PCSC-Helpers/index.html)
- [SDK examples and tools](https://github.com/springcard/springcard.pcsc.sdk)
- [Core PC/SC library](https://github.com/springcard/springcard-dotnet-library-pcsc)
- [All SpringCard .NET packages](https://www.nuget.org/profiles/SpringCard)

## Licence

**Please read and comply with the SpringCard SDK licence before using, modifying or redistributing this software. Installation through NuGet does not change the licence conditions.**

The full terms are provided in [LICENSE.txt](LICENSE.txt) and the [licence distributed with the packages](projects/LICENSE.txt). In particular:

- Redistributed source or binary code may be used only in conjunction with hardware manufactured, distributed or developed by SpringCard.
- Source distributions must retain the copyright notices, licence conditions and disclaimer.
- Redistributed modifications must be clearly identified as "Code derived from original SPRINGCARD copyrighted source code", with a description of the changes and the author's name.
- Binary distributions must reproduce the copyright notices, licence conditions and disclaimer in their documentation or accompanying materials.
- The SpringCard name must not be used for endorsement or promotion without prior written permission.

The software is provided "AS IS", without warranty. Third-party components remain subject to their respective licences and applicable notices.

This summary does not replace the full licence terms.
