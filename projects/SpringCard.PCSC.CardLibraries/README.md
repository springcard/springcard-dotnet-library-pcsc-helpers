# SpringCard.PCSC.CardLibraries

[![NuGet Version](https://img.shields.io/nuget/v/SpringCard.PCSC.CardLibraries.svg)](https://www.nuget.org/packages/SpringCard.PCSC.CardLibraries)
[![NuGet Downloads](https://img.shields.io/nuget/dt/SpringCard.PCSC.CardLibraries.svg)](https://www.nuget.org/packages/SpringCard.PCSC.CardLibraries)
[![License](https://img.shields.io/badge/license-SpringCard-blue.svg)](LICENSE.txt)

**SpringCard PCSC Card Libraries Library** - Card type libraries and definitions

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Supported Frameworks](#supported-frameworks)
- [Installation](#installation)
- [API Documentation](#api-documentation)
- [License](#license)
- [Support](#support)

---

## Overview

**SpringCard.PCSC.CardLibraries** is a .NET library developed by SpringCard, providing card type definitions, libraries, and utilities for PCSC-compatible smart card readers. This library contains pre-defined card profiles and configurations.

Originally developed for internal use at SpringCard, this library has been made available to facilitate card application development.

---

## Features

### Card Type Definitions
- Pre-defined card profiles
- ATR-based card identification
- Card capability definitions
- Protocol support matrices

### Card Libraries
- Card type catalog
- Manufacturer identification
- Historical bytes databases
- Card feature matrices

### Utility Functions
- Card type detection
- Profile matching
- Capability checking
- Compatibility verification

### Card Information
- ATR interpretation
- Protocol support detection
- Memory capacity information
- Security feature identification

---

## Supported Frameworks

SpringCard.PCSC.CardLibraries is a **.NET Standard 2.0** library, compatible with:

- .NET Framework 4.6.1+
- .NET Core 2.0+
- .NET 5/6/7/8+

---

## Installation

### Via NuGet Package Manager

```powershell
Install-Package SpringCard.PCSC.CardLibraries
```

### Via .NET CLI

```bash
dotnet add package SpringCard.PCSC.CardLibraries
```

### Via PackageReference in csproj

```xml
<PackageReference Include="SpringCard.PCSC.CardLibraries" Version="[latest-version]" />
```

---

## API Documentation

For complete API documentation, please refer to the official SpringCard documentation:

- **[SpringCard PCSC Helpers Documentation](https://docs.springcard.com/apis/NET/PCSC-Helpers/index.html)**

---

## License

This library is licensed under SpringCard proprietary license. See LICENSE.txt for full license text.

```
Copyright (c) 2008-2026 SpringCard - www.springcard.com
All rights reserved
```

---

## Support

For support and inquiries:

- **Website**: [https://www.springcard.com](https://www.springcard.com)
- **Email**: support@springcard.com

---

## Package Information

| Property | Value |
|----------|-------|
| **Package ID** | SpringCard.PCSC.CardLibraries |
| **Author** | SpringCard |
| **Copyright** | Copyright (c) SpringCard SAS, France, 2008-2026 all rights reserved |
| **Dependencies** | SpringCard.PCSC.CardHelpers |

---

## Version History

For complete version history, see the [NuGet Package Page](https://www.nuget.org/packages/SpringCard.PCSC.CardLibraries).

---

## Notes

- This library is actively maintained by SpringCard
- Compatible with Windows, Linux, and macOS environments (depending on target framework)
- Optimized for performance and reliability
- Extensively tested in production environments
- Requires SpringCard.PCSC.CardHelpers
- Contains definitions for various card types and manufacturers

---

*Made with care by SpringCard SAS, France*
