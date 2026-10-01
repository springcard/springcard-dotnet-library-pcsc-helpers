# SpringCard.PCSC.CardHelpers

[![NuGet Version](https://img.shields.io/nuget/v/SpringCard.PCSC.CardHelpers.svg)](https://www.nuget.org/packages/SpringCard.PCSC.CardHelpers)
[![NuGet Downloads](https://img.shields.io/nuget/dt/SpringCard.PCSC.CardHelpers.svg)](https://www.nuget.org/packages/SpringCard.PCSC.CardHelpers)
[![License](https://img.shields.io/badge/license-SpringCard-blue.svg)](LICENSE.txt)

**SpringCard PCSC Card Helpers Library** - Core utilities for smart card operations

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

**SpringCard.PCSC.CardHelpers** is a .NET library developed by SpringCard, providing core utilities and helper classes for smart card operations with PCSC-compatible readers. This is the foundational library for the SpringCard.PCSC.Helpers suite.

Originally developed for internal use at SpringCard, this library has been made available to facilitate smart card application development.

---

## Features

### Core Card Operations
- Low-level APDU command execution
- Card connection and disconnection management
- Protocol selection and negotiation
- Card reset and ATR retrieval

### Data Handling
- APDU command building and parsing
- Response data interpretation
- Error handling and status code management
- SW1 SW2 status word processing

### Card Communication
- Transmit and receive data buffers
- Extended APDU support
- Block size management
- Timeout configuration

### Utility Classes
- Card reader utilities
- Buffer manipulation helpers
- Conversion utilities (hex, bytes, strings)
- Logging and diagnostics

---

## Supported Frameworks

SpringCard.PCSC.CardHelpers is a **.NET Standard 2.0** library, compatible with:

- .NET Framework 4.6.1+
- .NET Core 2.0+
- .NET 5/6/7/8+

---

## Installation

### Via NuGet Package Manager

```powershell
Install-Package SpringCard.PCSC.CardHelpers
```

### Via .NET CLI

```bash
dotnet add package SpringCard.PCSC.CardHelpers
```

### Via PackageReference in csproj

```xml
<PackageReference Include="SpringCard.PCSC.CardHelpers" Version="[latest-version]" />
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
| **Package ID** | SpringCard.PCSC.CardHelpers |
| **Author** | SpringCard |
| **Copyright** | Copyright (c) SpringCard SAS, France, 2008-2026 all rights reserved |
| **Dependencies** | SpringCard.LibCs, SpringCard.PCSC |

---

## Version History

For complete version history, see the [NuGet Package Page](https://www.nuget.org/packages/SpringCard.PCSC.CardHelpers).

---

## Notes

- This library is actively maintained by SpringCard
- Compatible with Windows, Linux, and macOS environments (depending on target framework)
- Optimized for performance and reliability
- Extensively tested in production environments
- Foundation library for other SpringCard.PCSC.Helpers packages

---

*Made with care by SpringCard SAS, France*
