# SpringCard.PCSC.CardHelpers.Smid

[![NuGet Version](https://img.shields.io/nuget/v/SpringCard.PCSC.CardHelpers.Smid.svg)](https://www.nuget.org/packages/SpringCard.PCSC.CardHelpers.Smid)
[![NuGet Downloads](https://img.shields.io/nuget/dt/SpringCard.PCSC.CardHelpers.Smid.svg)](https://www.nuget.org/packages/SpringCard.PCSC.CardHelpers.Smid)
[![License](https://img.shields.io/badge/license-SpringCard-blue.svg)](LICENSE.txt)

**SpringCard PCSC Card Helpers Smid Library** - SMID card operations and utilities

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

**SpringCard.PCSC.CardHelpers.Smid** is a .NET library developed by SpringCard, providing specialized utilities for SMID card operations with PCSC-compatible readers. This library extends the core CardHelpers functionality with SMID-specific features for Ok V1 and V2 protocols.

Originally developed for internal use at SpringCard, this library has been made available to facilitate SMID card application development.

---

## Features

### SMID Card Operations
- SMID card identification and selection
- Ok V1 and V2 protocol support
- Card initialization and personalization
- Secure messaging

### Protocol Support
- Ok V1 protocol implementation
- Ok V2 protocol implementation
- Protocol version detection
- Backward compatibility

### Security Features
- AES encryption and decryption
- MAC generation and verification
- Key diversification
- Secure session management

### Application Support
- SMID application directory management
- File operations (read, write, delete)
- Access rights management
- Key management

---

## Supported Frameworks

SpringCard.PCSC.CardHelpers.Smid is a **.NET Standard 2.0** library, compatible with:

- .NET Framework 4.6.1+
- .NET Core 2.0+
- .NET 5/6/7/8+

---

## Installation

### Via NuGet Package Manager

```powershell
Install-Package SpringCard.PCSC.CardHelpers.Smid
```

### Via .NET CLI

```bash
dotnet add package SpringCard.PCSC.CardHelpers.Smid
```

### Via PackageReference in csproj

```xml
<PackageReference Include="SpringCard.PCSC.CardHelpers.Smid" Version="[latest-version]" />
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
| **Package ID** | SpringCard.PCSC.CardHelpers.Smid |
| **Author** | SpringCard |
| **Copyright** | Copyright (c) SpringCard SAS, France, 2008-2026 all rights reserved |
| **Dependencies** | SpringCard.PCSC.CardHelpers, SpringCard.LibCs.Crypto |

---

## Version History

For complete version history, see the [NuGet Package Page](https://www.nuget.org/packages/SpringCard.PCSC.CardHelpers.Smid).

---

## Notes

- This library is actively maintained by SpringCard
- Compatible with Windows, Linux, and macOS environments (depending on target framework)
- Optimized for performance and reliability
- Extensively tested in production environments
- Requires SpringCard.PCSC.CardHelpers and SpringCard.LibCs.Crypto
- Supports SMID cards with Ok V1 and V2 protocols

---

*Made with care by SpringCard SAS, France*
