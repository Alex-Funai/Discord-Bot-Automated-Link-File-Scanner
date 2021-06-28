package discord;

import discord4j.common.util.Snowflake;
import discord4j.core.object.entity.Message;
import discord4j.core.object.entity.channel.MessageChannel;
import discord4j.rest.util.Color;
import virustotal.virustotal.dto.FileScanReport;
import virustotal.virustotal.dto.ScanInfo;
import virustotal.virustotal.dto.VirusScanInfo;
import virustotal.virustotal.exception.UnauthorizedAccessException;
import virustotal.virustotalv2.VirustotalPublicV2;
import virustotal.virustotal.exception.APIKeyNotFoundException;
import virustotal.virustotalv2.VirusTotalConfig;
import virustotal.virustotalv2.VirustotalPublicV2Impl;
import java.io.File;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import org.apache.commons.io.FileUtils;

/**
 * AutomatedScanner : <br>
 * The AutomatedScanner interface will manage creating scan reports -- then creating an embedded discord
 * message that entails the report results. The results are retrieved from VirusTotal's database. Need to create API for
 * VirusTotalV3 which I believe will enable more detailed results. Also investigating otx.AlienVault, and other sources
 * to include more information. Currently seems like otx.AlienVault mainly provides pulse information (pulses are user managed
 * events and records for threat intelligence).
 */
public interface AutomatedScanner extends Processor, Authenticator {

    /**
     * scanUrls() : <br>
     * The scanUrls() method will scan an array of urls and create an embedded discord message containing relevant information
     * retrieved from VirusTotal's database.
     * </ul>
     */
      static void scanUrls(Message message) {

          String [] urls = ( message.getContent() ).split ( " " );

        try {
            VirusTotalConfig
                    .getConfigInstance()
                    .setVirusTotalAPIKey ( System.getenv( "VIRUS_TOKEN" ) );

            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            Snowflake snowflake = message.getId();

            message.delete ( snowflake.asString() ).subscribe();


            FileScanReport[] reports = virusTotalRef.getUrlScanReport(urls, false);


            for ( FileScanReport report : reports ) {

                if ( report.getResponseCode() == 0 ) {
                    System.out.println ( "Verbose Msg :\t" + report.getVerboseMessage() ); continue;
                }

                MessageChannel channel = message
                        .getChannel()
                        .block();

                String thisUser = message.getData().author().username().toString();

                assert channel != null;

                URL authorURL = new URL("https://pbs.twimg.com/profile_images/903041019331174400/BIaetD1J_400x400.jpg");
                channel.createEmbed ( spec -> spec

                        .setColor (
                                Processor.getMessageColor (report)
                        )

                        .setAuthor(
                                "URL Scan Report: ", report.getPermalink(), "https://pbs.twimg.com/profile_images/903041019331174400/BIaetD1J_400x400.jpg"
                        )

                      .setImage(
                                "https://www.virustotal.com/gui/images/vt-enterprise.svg"
                        )

                        .setTitle(
                                Arrays.toString( urls )
                        )

                        .setUrl(
                                report.getResource()
                        )

                        .setDescription(
                                Processor.getIntegrityRatingPositives(report)
                        )

                        .addField(
                                "[Submission]" ,
                                "**Author: ** \t" + message.getData().author().username().toString() + "\n"
                                    + "**Discriminator: ** \t" + message.getData().author().discriminator().toString() + "\n"
                                    + "**Date: ** \t" + report.getScanDate(), true
                        )

                        .addField(
                                "[Statistics]",
                                "**Malicious Flags: ** \t" + report.getPositives() + "\n"
                                    + "**Databases Referenced: ** \t" + report.getTotal() + "\n"
                                    + "**Response Code: ** \t" + report.getResponseCode(), true
                        )

                        .setFooter(
                                "ID: " + report.getScanId(),"https://pbs.twimg.com/profile_images/903041019331174400/BIaetD1J_400x400.jpg"

                        )
                        .setTimestamp(
                                Instant.now()
                        )
                ).block();


                // CONSOLE INFORMATION: [start]
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
                // Console Information: [end]
                }
            }

        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (UnsupportedEncodingException ex) {
            System.err.println("Unsupported Encoding Format!" + ex.getMessage());
        } catch (UnauthorizedAccessException ex) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Operation FUBAR! " + ex.getMessage());
        }
    }

    /**
     * scanAttachments() : <br>
     * The scanAttachments() method will retrieve retrieve attachments from a discord message (images, videos, files).
     * After retrieving files, the items are downloaded, and then parsed into a VirusTotal file scan. The scan returns
     * file hash information, and whether or not there are known suspicions to regard. Currently the files are downloaded
     * to the main directory, but I would like to use some type of cache, and later tonight will put a simple java.file
     * line to delete file after the scan/message is executed.
     *
     * @param message intakes a discord message that contains attachments.
     */
    static void scanAttachments ( Message message ) {

        try {
            VirusTotalConfig
                    .getConfigInstance()
                    .setVirusTotalAPIKey (
                            System.getenv ( "VIRUS_TOKEN" ) );

            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            URL attachmentURL = new URL (
                    message
                            .getData()
                            .attachments()
                            .get(0)
                            .url());

            File attachmentFileName = new File (
                    message
                            .getData()
                            .attachments()
                            .get(0)
                            .filename());

            FileUtils.copyURLToFile ( attachmentURL, attachmentFileName );

            ScanInfo scanInformation = virusTotalRef.scanFile ( attachmentFileName );

            MessageChannel channel = message
                    .getChannel()
                    .block();

            assert channel != null;
            channel.createEmbed ( spec -> spec

                    .setColor (
                            Color.BLACK
                    )
                    .setAuthor (
                            "File Scan Report : ", scanInformation.getPermalink(),
                            "https://pbs.twimg.com/profile_images/903041019331174400/BIaetD1J_400x400.jpg")
                    .setTitle (
                            message
                                    .getData()
                                    .attachments()
                                    .get(0)
                                    .filename()
                    )
                    .setUrl (
                            message
                                    .getData()
                                    .attachments()
                                    .get(0)
                                    .url())
                    .setDescription (
                            Processor.getIntegrityResponseFromBoolean (
                                    Processor.getIntegrityRatingResponseCode ( scanInformation )
                            )
                    )
                    .addField (
                            "[Submission] " ,
                            "**Author: **" + message.getData().author().username() + "\n"
                            + "**Discriminator: ** " + message.getData().author().discriminator() + "\n"
                            + "**Date: **" + message.getData().timestamp(),
                            true
                    )
                    .addField (
                            "[Hashes]",
                            "**SHA1: **" + scanInformation.getSha1() + "\n"
                                + "**SHA256: **" + scanInformation.getSha256() + "\n"
                                + "**MD5: **" + scanInformation.getMd5(),
                            true
                    )
                    .setFooter (
                            "Id: " + scanInformation.getScanId(),
                            "https://pbs.twimg.com/profile_images/903041019331174400/BIaetD1J_400x400.jpg"
                    )
                    .setTimestamp (
                            Instant.now()
                    )
            ).block();

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