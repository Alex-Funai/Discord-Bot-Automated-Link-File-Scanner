<!---
Alexander Funai
https://alexanderfunai.com
July 07, 2021
DBS
-->



# <u> Discord-Bot-Automated-Link-File-Scanner: </u> 



## Description:
<img align="right" width="420" height="860" src="https://user-images.githubusercontent.com/79816891/136109263-c720f9a4-aca1-416e-8411-5d7ba68a04c9.png">

&nbsp;&nbsp;&nbsp;&nbsp; 
Discord-Bot-Automated-Link-File-Scanner, is a bot that checks the integrity of urls and file attachments sent through a Discord server. The objects are parsed through VirusTotal.com's database, and the domain, hash, or attachmentments are scanned. Virustotal's database references over 100+ other threat-analysis databases such as: otx.AlienVault, CINSArmy. The scan returns simple information such as: hashes, reverse DNS, host-ip, cidr, asc, and communal insight.

&nbsp;&nbsp;&nbsp;&nbsp; 
Discord-Bot-Automated-Link-File-Scanner works by utilizing Discord4j's gateway listener events. The gateway listener events leverage the Discord API's response data, and determines whether or not a URL or file attachment is present. For example, if the message's body contains text specified by regex / to http/https/www, it will get passed into a checkURI method (utilizing commons.apache), and tested/verified for valid HTTP(tcp 80) establishment. When a message response contains data in the attachments field, it's value becomes 1, and the listener will search for that indicator, and proceed to extract the attachment data into the programs cache. The attachment then extracts the backend discord upload, and passed as a link through the final message. The listeners are also setup to handle comments and multiple objects simultaneously, but you may be rate limited by your api keys subscription.

&nbsp;&nbsp;&nbsp;&nbsp; 
Once Discord-Bot-Automated-Link-File-Scanner detects a link or URL, it deletes the user's initial message, to protect server members from phishing attempts, or malicious links  very quickly ( time =< 1s), and then resubmits it as an informative embedded message that includes:
+ A link to the integrity report (the title is clickable)
+ A link to the original scanned object.
+ The original users comment/messsage accompanying the object.
+ Relevant data to the scan such as: flags thrown and hashes.
+ Embed accent color for integrity, if the object appears unknown (grey/black), safe (green), or risky (red).

&nbsp;&nbsp;&nbsp;&nbsp; 
The solution isn't a primary solution or defense, but it does provide some mitigation that could affect common pc users, and large public servers that are often saturated in unknown spam.

## Abstract:
&nbsp;&nbsp;&nbsp;&nbsp; 
The idea came from visiting a public crypto discord server. I had posted a link to a book I was reading on chart analyses and trading strategies, and instantly a causcious user yelled "DO NOT CLICK THE LINK", which makes sense from a security perspective, because there could be malware creating backdoor and loggers to siphon crypto wallets, and that's a reasonable precaution. However I was just trying to spread the knowledge. I posted my virustotal scan, and realized that it would be nice possibly for large public servers (especially those with thousands of members) to have this process automated to protect their server members from the pervasive threats of script kiddies and phishing.

## Prerequisites:
```
+ JDK-16.0.1 < 
+ Gradle-7.2
+ VirusTotal API Key: (https://support.virustotal.com/hc/en-us/articles/115002100149-API)
+ DiscorBot API Token: (https://discord.com/developers/applications)
```

## Built With:
```
 Discord4j-3.1.5
 kdkanishka: Virustotal-Public-API-V2.0-Client
```

## Getting Started:
```![example](https://user-images.githubusercontent.com/79816891/136109243-4c4a2fe7-4fcf-48b8-b2b6-4af3b4c2ffdc.png)
1. Clone the repository.
2. Open the project.
3. Add all the .jar files from "Discord-Bot-Automated-Link-File-Scanner\lib\*" as project dependencies.
4. Set your personal VirusTotal and Discord API token to the system environment variables: "DISCORD_TOKEN" and "VIRUS_TOKEN".
5. Follow DiscordBot documentation to invite you're DiscordBot to a Discord server.
6. Initialize the DiscordBot gateway/connection via running discord.Authenticator class -> main method.
7. Test the bot in your server by typing a URL or sending a file attachment (image, video, gif, etc).
```
