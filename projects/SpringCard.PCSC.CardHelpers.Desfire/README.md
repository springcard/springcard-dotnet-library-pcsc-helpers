# SpringCard.PCSC.CardHelpers.Desfire

[![NuGet Version](https://img.shields.io/nuget/v/SpringCard.PCSC.CardHelpers.Desfire.svg)](https://www.nuget.org/packages/SpringCard.PCSC.CardHelpers.Desfire)
[![NuGet Downloads](https://img.shields.io/nuget/dt/SpringCard.PCSC.CardHelpers.Desfire.svg)](https://www.nuget.org/packages/SpringCard.PCSC.CardHelpers.Desfire)
[![License](https://img.shields.io/badge/license-SpringCard-blue.svg)](LICENSE.txt)

**SpringCard PCSC Card Helpers Desfire Library** - DESFire card operations and utilities

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

**SpringCard.PCSC.CardHelpers.Desfire** is a .NET library developed by SpringCard, providing specialized utilities for DESFire card operations with PCSC-compatible readers. This library extends the core CardHelpers functionality with DESFire-specific features.

Originally developed for internal use at SpringCard, this library has been made available to facilitate DESFire card application development.

---

## Features

### DESFire Card Operations
- DESFire card identification and selection
- Application directory (AID) management
- File creation, reading, writing, and deletion
- Key management and authentication

### Security Features
- AES, 3DES, and DES encryption support
- Key diversification
- Access rights management
- Secure messaging

### File Operations
- Standard data files
- Value files
- Linear record files
- Cyclic record files

### Application Management
- Application creation and deletion
- ISO file ID management
- DF name management
- Application directory listing

---

## Supported Frameworks

SpringCard.PCSC.CardHelpers.Desfire is a **.NET Standard 2.0** library, compatible with:

- .NET Framework 4.6.1+
- .NET Core 2.0+
- .NET 5/6/7/8+

---

## Installation

### Via NuGet Package Manager

```powershell
Install-Package SpringCard.PCSC.CardHelpers.Desfire
```

### Via .NET CLI

```bash
dotnet add package SpringCard.PCSC.CardHelpers.Desfire
```

### Via PackageReference in csproj

```xml
<PackageReference Include="SpringCard.PCSC.CardHelpers.Desfire" Version="[latest-version]" />
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
| **Package ID** | SpringCard.PCSC.CardHelpers.Desfire |
| **Author** | SpringCard |
| **Copyright** | Copyright (c) SpringCard SAS, France, 2008-2026 all rights reserved |
| **Dependencies** | SpringCard.PCSC.CardHelpers, SpringCard.LibCs.Crypto |

---

## Version History

For complete version history, see the [NuGet Package Page](https://www.nuget.org/packages/SpringCard.PCSC.CardHelpers.Desfire).

---

## Notes

- This library is actively maintained by SpringCard
- Compatible with Windows, Linux, and macOS environments (depending on target framework)
- Optimized for performance and reliability
- Extensively tested in production environments
- Requires SpringCard.PCSC.CardHelpers and SpringCard.LibCs.Crypto
- Supports DESFire EV1, EV2, EV3, and Light cards

---

*Made with care by SpringCard SAS, France*
