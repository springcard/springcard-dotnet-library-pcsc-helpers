# SpringCard.PCSC.CardEmulation

[![NuGet Version](https://img.shields.io/nuget/v/SpringCard.PCSC.CardEmulation.svg)](https://www.nuget.org/packages/SpringCard.PCSC.CardEmulation)
[![NuGet Downloads](https://img.shields.io/nuget/dt/SpringCard.PCSC.CardEmulation.svg)](https://www.nuget.org/packages/SpringCard.PCSC.CardEmulation)
[![License](https://img.shields.io/badge/license-SpringCard-blue.svg)](LICENSE.txt)

**SpringCard PCSC Card Emulation Library** - Smart card emulation utilities for PCSC

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

**SpringCard.PCSC.CardEmulation** is a .NET library developed by SpringCard, providing smart card emulation capabilities for PCSC-compatible readers. This library enables developers to emulate smart cards and test card reader applications without physical cards.

Originally developed for internal use at SpringCard, this library has been made available to facilitate smart card application testing and development.

---

## Features

### Card Emulation
- Virtual card creation and management
- ATR emulation with customizable parameters
- Protocol emulation (T=0, T=1)
- APDU command and response handling

### Testing Capabilities
- Simulate various card types and behaviors
- Custom response configuration
- Error condition simulation
- Historical bytes emulation

### Integration
- JSON-based card profile configuration
- Easy integration with existing applications
- Support for multiple virtual cards simultaneously

---

## Supported Frameworks

SpringCard.PCSC.CardEmulation is a **.NET Standard 2.0 / .NET Framework 4.8** library, compatible with:

- .NET Framework 4.6.1+
- .NET Core 2.0+
- .NET 5/6/7/8+

---

## Installation

### Via NuGet Package Manager

```powershell
Install-Package SpringCard.PCSC.CardEmulation
```

### Via .NET CLI

```bash
dotnet add package SpringCard.PCSC.CardEmulation
```

### Via PackageReference in csproj

```xml
<PackageReference Include="SpringCard.PCSC.CardEmulation" Version="[latest-version]" />
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
| **Package ID** | SpringCard.PCSC.CardEmulation |
| **Author** | SpringCard |
| **Copyright** | Copyright (c) SpringCard SAS, France, 2008-2026 all rights reserved |
| **Dependencies** | Newtonsoft.Json, SpringCard.PCSC.CardHelpers, SpringCard.PCSC.ReaderHelpers |

---

## Version History

For complete version history, see the [NuGet Package Page](https://www.nuget.org/packages/SpringCard.PCSC.CardEmulation).

---

## Notes

- This library is actively maintained by SpringCard
- Compatible with Windows, Linux, and macOS environments (depending on target framework)
- Optimized for performance and reliability
- Extensively tested in production environments
- Requires Newtonsoft.Json package

---

*Made with care by SpringCard SAS, France*
