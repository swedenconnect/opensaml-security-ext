![Logo](https://docs.swedenconnect.se/technical-framework/img/sweden-connect.png)

# credentials-support

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0) ![Maven Central](https://img.shields.io/maven-central/v/se.swedenconnect.opensaml/opensaml-security-ext.svg)

---

## Release Notes

### 4.2.3

**Date:** 2026-10-30

- Fixed Base64 decoding errors (for example of certificates and EC keys) caused by commons-codec 1.23.0. The library now depends on commons-codec 1.22.1 directly. If you declare commons-codec yourself, stay on 1.22.x until a shib-support release later than 9.2.3 fixes this.

---

Copyright &copy; 2016-2026, [Sweden Connect](https://swedenconnect.se). Licensed under version 2.0 of the [Apache License](http://www.apache.org/licenses/LICENSE-2.0).
