# SpringCard.PCSC.CardAnalysis

[![NuGet Version](https://img.shields.io/nuget/v/SpringCard.PCSC.CardAnalysis.svg)](https://www.nuget.org/packages/SpringCard.PCSC.CardAnalysis)
[![NuGet Downloads](https://img.shields.io/nuget/dt/SpringCard.PCSC.CardAnalysis.svg)](https://www.nuget.org/packages/SpringCard.PCSC.CardAnalysis)
[![License](https://img.shields.io/badge/license-SpringCard-blue.svg)](LICENSE.txt)

**SpringCard PCSC Card Analysis Library** - Advanced card analysis and parsing utilities for PCSC

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

**SpringCard.PCSC.CardAnalysis** is a .NET library developed by SpringCard, providing advanced card analysis capabilities for PCSC-compatible smart card readers. This library enables developers to parse and analyze smart card data with ease.

Originally developed for internal use at SpringCard, this library has been made available to facilitate smart card application development.

---

## Features

### Card Analysis
- ATR Parsing: Parse Answer-To-Reset (ATR) strings from smart cards
- Card Identification: Identify card types and manufacturers
- Protocol Detection: Detect supported communication protocols (T=0, T=1, etc.)

### Data Parsing
- Historical Bytes Analysis: Parse historical bytes from ATR
- Interface Bytes Interpretation: Understand card interface capabilities
- Card Type Classification: Classify cards by type and capabilities

### Utility Functions
- ATR String Formatting: Convert ATR bytes to standard string representation
- Card Info Extraction: Extract manufacturer, card type, and version information
- Protocol Parameters: Determine optimal protocol parameters

---

## Supported Frameworks

SpringCard.PCSC.CardAnalysis is a .NET Standard 2.0 library, compatible with:

- .NET Framework 4.6.1+
- .NET Core 2.0+
- .NET 5/6/7/8+

---

## Installation

### Via NuGet Package Manager

```powershell
Install-Package SpringCard.PCSC.CardAnalysis
```

### Via .NET CLI

```bash
dotnet add package SpringCard.PCSC.CardAnalysis
```

### Via PackageReference in csproj

```xml
<PackageReference Include="SpringCard.PCSC.CardAnalysis" Version="[latest-version]" />
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
| **Package ID** | SpringCard.PCSC.CardAnalysis |
| **Author** | SpringCard |
| **Copyright** | Copyright (c) SpringCard SAS, France, 2008-2026 all rights reserved |
| **Dependencies** | SpringCard.PCSC |

---

## Version History

For complete version history, see the [NuGet Package Page](https://www.nuget.org/packages/SpringCard.PCSC.CardAnalysis).

---

## Notes

- This library is actively maintained by SpringCard
- Compatible with Windows, Linux, and macOS environments (depending on target framework)
- Optimized for performance and reliability
- Extensively tested in production environments
- Requires SpringCard.PCSC package

---

*Made with care by SpringCard SAS, France*
