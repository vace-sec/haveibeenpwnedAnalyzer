# HaveIBeenPwned Analyzer

This analyzer checks a mail address on haveibeenpawned.

This is a [Cortex-Analyzer](https://github.com/TheHive-Project/Cortex-Analyzers).

The HaveIBeenPwned API v2 is sometimes a little bit unstable. Sometimes the API returns a 403 - "Forbidden — no user agent has been specified in the request" even if there is a User-Agent. In this cases, try it again a fiew minutes later.
