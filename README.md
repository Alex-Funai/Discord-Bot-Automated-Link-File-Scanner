<!---
Alexander Funai
https://alexanderfunai.com
July 07, 2021
DBS
-->


# <u> dbs: </u> 
dbs is a Discord Bot that utilizes VirusTotal and Discord4j to automatically scan all server messages that
contain URLs and file attachments (files, images, videos, etc.). 

When a URL or file attachment is detected, the bot will:
1. Delete the incoming message, to prevent users from clicking phishing, fraud, or malicious links/files.
2. Scan the object via VirusTotals API.
3. Create and send an embedded discord message, that contains the original message, as well as scan report information.

## Getting Started:
1. Open and import project. Gradle.Wrapper, Kotlin Script, and gradle.jar are included.
2. Edit project configuration, and set api tokens to system/environment variables.
	+ DISCORD_TOKEN
	+ VIRUS_TOKEN
3. Modify Authenticator.main, to include/disclude commands and listeners, if you want.
4. Run Authenticator.main.

### Prerequisites:
+ JDK-16.0.1
+ Gradle

## Built With
- Discord4j-3.1.5
- kdkanishka: Virustotal-Public-API-V2.0-Client


## Contributing

Please read [CONTRIBUTING.md](https://github.com/Iteratr-Learning/Real-World-Software-Development) for details on our code of conduct, and the process for submitting pull requests to us.