# SpringCard.PCSC.CardHelpers.SamAV

[![NuGet Version](https://img.shields.io/nuget/v/SpringCard.PCSC.CardHelpers.SamAV.svg)](https://www.nuget.org/packages/SpringCard.PCSC.CardHelpers.SamAV)
[![NuGet Downloads](https://img.shields.io/nuget/dt/SpringCard.PCSC.CardHelpers.SamAV.svg)](https://www.nuget.org/packages/SpringCard.PCSC.CardHelpers.SamAV)
[![License](https://img.shields.io/badge/license-SpringCard-blue.svg)](LICENSE.txt)

**SpringCard PCSC Card Helpers SamAV Library** - SAM AV card operations and utilities

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

**SpringCard.PCSC.CardHelpers.SamAV** is a .NET library developed by SpringCard, providing specialized utilities for SAM AV (Secure Application Module) card operations with PCSC-compatible readers. This library extends the core CardHelpers functionality with SAM AV-specific features.

Originally developed for internal use at SpringCard, this library has been made available to facilitate secure application module development.

---

## Features

### SAM AV Operations
- SAM AV card identification and initialization
- Secure session management
- Cryptographic operations
- Key diversification

### Cryptographic Features
- DES/3DES encryption and decryption
- MAC generation and verification
- Challenge-response authentication
- Secure messaging support

### Application Support
- Calypso application support
- ISO 7816-4 compliant operations
- APDU command building and parsing
- Response data interpretation

### Key Management
- Key storage and retrieval
- Key derivation
- Access rights management
- Key versioning

---

## Supported Frameworks

SpringCard.PCSC.CardHelpers.SamAV is a **.NET Standard 2.0** library, compatible with:

- .NET Framework 4.6.1+
- .NET Core 2.0+
- .NET 5/6/7/8+

---

## Installation

### Via NuGet Package Manager

```powershell
Install-Package SpringCard.PCSC.CardHelpers.SamAV
```

### Via .NET CLI

```bash
dotnet add package SpringCard.PCSC.CardHelpers.SamAV
```

### Via PackageReference in csproj

```xml
<PackageReference Include="SpringCard.PCSC.CardHelpers.SamAV" Version="[latest-version]" />
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
| **Package ID** | SpringCard.PCSC.CardHelpers.SamAV |
| **Author** | SpringCard |
| **Copyright** | Copyright (c) SpringCard SAS, France, 2008-2026 all rights reserved |
| **Dependencies** | SpringCard.PCSC.CardHelpers, SpringCard.PCSC.CardHelpers.Desfire |

---

## Version History

For complete version history, see the [NuGet Package Page](https://www.nuget.org/packages/SpringCard.PCSC.CardHelpers.SamAV).

---

## Notes

- This library is actively maintained by SpringCard
- Compatible with Windows, Linux, and macOS environments (depending on target framework)
- Optimized for performance and reliability
- Extensively tested in production environments
- Requires SpringCard.PCSC.CardHelpers and SpringCard.PCSC.CardHelpers.Desfire
- Supports various SAM AV card types

---

*Made with care by SpringCard SAS, France*
