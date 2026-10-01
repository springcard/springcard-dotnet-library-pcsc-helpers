# SpringCard.PCSC.CardHelpers.Mifare

[![NuGet Version](https://img.shields.io/nuget/v/SpringCard.PCSC.CardHelpers.Mifare.svg)](https://www.nuget.org/packages/SpringCard.PCSC.CardHelpers.Mifare)
[![NuGet Downloads](https://img.shields.io/nuget/dt/SpringCard.PCSC.CardHelpers.Mifare.svg)](https://www.nuget.org/packages/SpringCard.PCSC.CardHelpers.Mifare)
[![License](https://img.shields.io/badge/license-SpringCard-blue.svg)](LICENSE.txt)

**SpringCard PCSC Card Helpers Mifare Library** - MIFARE card operations and utilities

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

**SpringCard.PCSC.CardHelpers.Mifare** is a .NET library developed by SpringCard, providing specialized utilities for MIFARE card operations with PCSC-compatible readers. This library extends the core CardHelpers functionality with MIFARE-specific features.

Originally developed for internal use at SpringCard, this library has been made available to facilitate MIFARE card application development.

---

## Features

### MIFARE Card Operations
- MIFARE card identification and type detection
- Block reading and writing
- Sector access and key management
- Value operations

### Card Type Support
- MIFARE Classic 1K/4K
- MIFARE Ultralight
- MIFARE DESFire (via CardHelpers.Desfire)
- MIFARE Plus

### Security Features
- Authentication (A/B keys)
- Key management
- Access bits configuration
- Trailer block operations

### Advanced Features
- Sector dump and restore
- Block formatting
- Increment/decrement operations
- Transfer and restore operations

---

## Supported Frameworks

SpringCard.PCSC.CardHelpers.Mifare is a **.NET Standard 2.0** library, compatible with:

- .NET Framework 4.6.1+
- .NET Core 2.0+
- .NET 5/6/7/8+

---

## Installation

### Via NuGet Package Manager

```powershell
Install-Package SpringCard.PCSC.CardHelpers.Mifare
```

### Via .NET CLI

```bash
dotnet add package SpringCard.PCSC.CardHelpers.Mifare
```

### Via PackageReference in csproj

```xml
<PackageReference Include="SpringCard.PCSC.CardHelpers.Mifare" Version="[latest-version]" />
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
| **Package ID** | SpringCard.PCSC.CardHelpers.Mifare |
| **Author** | SpringCard |
| **Copyright** | Copyright (c) SpringCard SAS, France, 2008-2026 all rights reserved |
| **Dependencies** | SpringCard.PCSC.CardAnalysis, SpringCard.PCSC.CardHelpers |

---

## Version History

For complete version history, see the [NuGet Package Page](https://www.nuget.org/packages/SpringCard.PCSC.CardHelpers.Mifare).

---

## Notes

- This library is actively maintained by SpringCard
- Compatible with Windows, Linux, and macOS environments (depending on target framework)
- Optimized for performance and reliability
- Extensively tested in production environments
- Requires SpringCard.PCSC.CardAnalysis and SpringCard.PCSC.CardHelpers
- Supports various MIFARE card types

---

*Made with care by SpringCard SAS, France*
