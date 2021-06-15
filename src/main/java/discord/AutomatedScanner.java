package discord;

import discord4j.common.util.Snowflake;
import discord4j.core.object.entity.Message;
import discord4j.core.object.entity.User;
import discord4j.core.object.entity.channel.Channel;
import discord4j.core.object.entity.channel.MessageChannel;
import discord4j.core.spec.EmbedCreateSpec;
import discord4j.rest.util.Color;
import reactor.core.publisher.Mono;
import virustotal.virustotal.dto.FileScanReport;
import virustotal.virustotal.dto.VirusScanInfo;
import virustotal.virustotal.exception.InvalidArguentsException;
import virustotal.virustotal.exception.QuotaExceededException;
import virustotal.virustotal.exception.UnauthorizedAccessException;
import virustotal.virustotalv2.VirustotalPublicV2;
import virustotal.virustotal.exception.APIKeyNotFoundException;
import virustotal.virustotalv2.VirusTotalConfig;
import virustotal.virustotalv2.VirustotalPublicV2Impl;

import java.io.File;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;

import static com.google.gson.internal.bind.TypeAdapters.URL;


/**
 * AutomatedScanner :: <br>
 * AutomatedScanner is an interface that manages creating scan reports, and then creating an embedded discord
 * message that entails the report results. The results are retrieved from VirusTotal's database, but will likely
 * include data from otx.alienvault later through development.
 */
public interface AutomatedScanner extends Processor {

    /**
     * ScanUrls() :: <br>
     * ScanUrls will scan an array of urls and create an embedded discord message containing relevant information
     * retrieved from VirusTotal's database.
     * </ul>
     */
      static void scanUrls(Message message) {

          String [] urls = (message.getContent()).split(" ");

        try {
            VirusTotalConfig
                    .getConfigInstance()
                    .setVirusTotalAPIKey ( System.getenv( "VIRUS_TOKEN" ) );

            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            Snowflake snowflake = message.getId();

            message.delete (
                    snowflake.asString()
            ).subscribe();


            FileScanReport[] reports = virusTotalRef.getUrlScanReport(urls, false);


            for ( FileScanReport report : reports ) {

                if ( report.getResponseCode() == 0 ) {
                    System.out.println ( "Verbose Msg :\t" + report.getVerboseMessage() ); continue;
                }

                MessageChannel channel = message
                        .getChannel()
                        .block();

                assert channel != null;

                channel.createEmbed ( spec -> spec

                        .setColor (
                                Processor.getMessageColor (report)
                        )

                        .setAuthor(
                                "set author", null, null
                        )

                        .setImage(
                                "resources/virustotal-avatar.png"
                        )

                        .setTitle(
                                Arrays.toString( urls )
                        )

                        .setUrl(
                                report.getResource()
                        )

                        .setDescription(
                                ""
                                + "** Report Link: ** \t" + report.getPermalink() + "\n"
                                + "** Scan Date: ** \t" + report.getScanDate() + "\n"
                                + "** Verbose Msg: ** \t" + report.getVerboseMessage() + "\n"
                        )

                        .addField(
                                "[Hashes]" ,
                                "SHA256 : \t" + report.getSha256() + "\n"
                                    + "SHA1 : \t" + report.getSha1() + "\n"
                                    + "MD5 : \t" + report.getMd5(), true
                        )

                        .addField(
                                "[Statistics]",
                                "Malicious Flags : \t" + report.getPositives() + "\n"
                                    + "Databases Referenced : \t" + report.getTotal() + "\n"
                                    + "Response Code : \t" + report.getResponseCode(), true
                        )

                        .setFooter(
                                "Scan ID: \t" + report.getScanId(),"resources/virustotal-avatar.png"

                        )

                        .setTimestamp(
                                Instant.now()
                        )
                ).block();

                System.out.println("MD5 :\t" + report.getMd5());
                System.out.println("Perma link :\t" + report.getPermalink());
                System.out.println("Resource :\t" + report.getResource());
                System.out.println("Scan Date :\t" + report.getScanDate());
                System.out.println("Scan Id :\t" + report.getScanId());
                System.out.println("SHA1 :\t" + report.getSha1());
                System.out.println("SHA256 :\t" + report.getSha256());
                System.out.println("Verbose Msg :\t" + report.getVerboseMessage());
                System.out.println("Response Code :\t" + report.getResponseCode());
                System.out.println("Positives :\t" + report.getPositives());
                System.out.println("Total :\t" + report.getTotal());

                Map<String, VirusScanInfo> scans = report.getScans();
                for (String key : scans.keySet()) {
                    VirusScanInfo virusInfo = scans.get(key);
                    System.out.println("Scanner : " + key);
                    System.out.println("\t\t Result : " + virusInfo.getResult());
                    System.out.println("\t\t Update : " + virusInfo.getUpdate());
                    System.out.println("\t\t Version :" + virusInfo.getVersion());
                }
            }

        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (UnsupportedEncodingException ex) {
            System.err.println("Unsupported Encoding Format!" + ex.getMessage());
        } catch (UnauthorizedAccessException ex) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Something Bad Happened! " + ex.getMessage());
        }
    }
}


