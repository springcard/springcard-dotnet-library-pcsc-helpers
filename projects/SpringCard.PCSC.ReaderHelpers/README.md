# SpringCard.PCSC.ReaderHelpers

[![NuGet Version](https://img.shields.io/nuget/v/SpringCard.PCSC.ReaderHelpers.svg)](https://www.nuget.org/packages/SpringCard.PCSC.ReaderHelpers)
[![NuGet Downloads](https://img.shields.io/nuget/dt/SpringCard.PCSC.ReaderHelpers.svg)](https://www.nuget.org/packages/SpringCard.PCSC.ReaderHelpers)
[![License](https://img.shields.io/badge/license-SpringCard-blue.svg)](LICENSE.txt)

**SpringCard PCSC Reader Helpers Library** - PCSC reader utilities and helpers

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

**SpringCard.PCSC.ReaderHelpers** is a .NET library developed by SpringCard, providing PCSC reader utilities and helper classes for smart card reader operations. This library simplifies reader management and provides enhanced functionality for PCSC-compatible readers.

Originally developed for internal use at SpringCard, this library has been made available to facilitate smart card reader application development.

---

## Features

### Reader Management
- Reader enumeration and discovery
- Reader connection and disconnection
- Reader status monitoring
- Reader capability detection

### Reader Operations
- Card insertion/removal detection
- Card presence checking
- Reader state management
- Multi-reader support

### Enhanced Functionality
- Reader configuration
- Protocol selection
- Card ATR retrieval
- Reader sharing management

### Utility Classes
- Reader information extraction
- Capability flags interpretation
- SCard API wrappers
- Error handling and diagnostics

---

## Supported Frameworks

SpringCard.PCSC.ReaderHelpers is a **.NET Standard 2.0 / .NET Framework 4.8** library, compatible with:

- .NET Framework 4.6.1+
- .NET Core 2.0+
- .NET 5/6/7/8+

---

## Installation

### Via NuGet Package Manager

```powershell
Install-Package SpringCard.PCSC.ReaderHelpers
```

### Via .NET CLI

```bash
dotnet add package SpringCard.PCSC.ReaderHelpers
```

### Via PackageReference in csproj

```xml
<PackageReference Include="SpringCard.PCSC.ReaderHelpers" Version="[latest-version]" />
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
| **Package ID** | SpringCard.PCSC.ReaderHelpers |
| **Author** | SpringCard |
| **Copyright** | Copyright (c) SpringCard SAS, France, 2008-2026 all rights reserved |
| **Dependencies** | SpringCard.LibCs, SpringCard.LibCs.Crypto, SpringCard.PCSC |

---

## Version History

For complete version history, see the [NuGet Package Page](https://www.nuget.org/packages/SpringCard.PCSC.ReaderHelpers).

---

## Notes

- This library is actively maintained by SpringCard
- Compatible with Windows, Linux, and macOS environments (depending on target framework)
- Optimized for performance and reliability
- Extensively tested in production environments
- Foundation library for reader operations
- Works with any PCSC-compatible smart card reader

---

*Made with care by SpringCard SAS, France*
