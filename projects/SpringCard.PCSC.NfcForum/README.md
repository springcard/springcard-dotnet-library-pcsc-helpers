# SpringCard.PCSC.NfcForum

[![NuGet Version](https://img.shields.io/nuget/v/SpringCard.PCSC.NfcForum.svg)](https://www.nuget.org/packages/SpringCard.PCSC.NfcForum)
[![NuGet Downloads](https://img.shields.io/nuget/dt/SpringCard.PCSC.NfcForum.svg)](https://www.nuget.org/packages/SpringCard.PCSC.NfcForum)
[![License](https://img.shields.io/badge/license-SpringCard-blue.svg)](LICENSE.txt)

**SpringCard PCSC NFC Forum Library** - NFC Forum tag operations and utilities

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

**SpringCard.PCSC.NfcForum** is a .NET library developed by SpringCard, providing NFC Forum tag operations and utilities for PCSC-compatible readers. This library implements NFC Forum specifications for tag types 1-5.

Originally developed for internal use at SpringCard, this library has been made available to facilitate NFC application development.

---

## Features

### NFC Forum Tag Support
- Type 1 Tag support
- Type 2 Tag support (MIFARE Ultralight, NTAG)
- Type 3 Tag support (FeliCa)
- Type 4 Tag support (ISO 14443-4)
- Type 5 Tag support (ISO 15693)

### NDEF Operations
- NDEF message reading
- NDEF message writing
- NDEF record parsing
- NDEF record creation

### Tag Operations
- Tag detection and identification
- Tag capability container parsing
- Memory operations
- Command execution

### Standard Compliance
- NFC Forum Type Tag specifications
- NDEF (NFC Data Exchange Format) specification
- RTD (Record Type Definition) support
- URI, Text, MIME, and other RTD types

---

## Supported Frameworks

SpringCard.PCSC.NfcForum is a **.NET Standard 2.0** library, compatible with:

- .NET Framework 4.6.1+
- .NET Core 2.0+
- .NET 5/6/7/8+

---

## Installation

### Via NuGet Package Manager

```powershell
Install-Package SpringCard.PCSC.NfcForum
```

### Via .NET CLI

```bash
dotnet add package SpringCard.PCSC.NfcForum
```

### Via PackageReference in csproj

```xml
<PackageReference Include="SpringCard.PCSC.NfcForum" Version="[latest-version]" />
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
| **Package ID** | SpringCard.PCSC.NfcForum |
| **Author** | SpringCard |
| **Copyright** | Copyright (c) SpringCard SAS, France, 2008-2026 all rights reserved |
| **Dependencies** | SpringCard.PCSC.CardHelpers, SpringCard.LibCs.Windows |

---

## Version History

For complete version history, see the [NuGet Package Page](https://www.nuget.org/packages/SpringCard.PCSC.NfcForum).

---

## Notes

- This library is actively maintained by SpringCard
- Compatible with Windows environments
- Optimized for performance and reliability
- Extensively tested in production environments
- Requires SpringCard.PCSC.CardHelpers and SpringCard.LibCs.Windows
- Implements NFC Forum specifications

---

*Made with care by SpringCard SAS, France*
