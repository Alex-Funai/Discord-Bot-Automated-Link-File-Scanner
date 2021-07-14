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
import java.nio.file.Files;
import java.nio.file.NoSuchFileException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import org.apache.commons.io.FileUtils;

/**
 * AutomatedScanner : <br>
 * The AutomatedScanner interface will manage creating scan reports -- then creating an embedded discord
 * message that entails the report results. The results are retrieved from VirusTotal's database. Need to create API for
 * VirusTotalV3 which I believe will enable more detailed results. Also investigating otx.AlienVault, and other sources
 * to include more information. Currently seems like otx.AlienVault mainly provides pulse information (pulses are user managed
 * events and records for threat intelligence).
 */
public interface Scanners extends Processor, Authenticator {

    /**
     * scanUrls() : <br>
     * The scanUrls() method will scan an array of urls and create an embedded discord message containing relevant information
     * retrieved from VirusTotal's database.
     * </ul>
     */
      static void scanUrls(Message message) {

        try {
            VirusTotalConfig
                    .getConfigInstance()
                    .setVirusTotalAPIKey ( System.getenv( "VIRUS_TOKEN" ) );

            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            Snowflake snowflake = message.getId();

            System.out.println(message.getData());


            message.delete (snowflake.asString()
            ).subscribe();

            String [] urls = Processor.getUrlsArray(message);
            FileScanReport[] reports = virusTotalRef.getUrlScanReport(urls, false);
            AtomicInteger count = new AtomicInteger();

            for ( FileScanReport report : reports ) {
                if (report.getResponseCode() == 0) {
                    System.out.println("Verbose Msg :\t" + report.getVerboseMessage());
                    continue;
                }

                MessageChannel channel = message
                        .getChannel()
                        .block();

                String thisUser = message.getData().author().username().toString();
                System.out.println("Now creating report embed message with results to relative channel");

                assert channel != null;
                URL authorURL = new URL("https://pbs.twimg.com/profile_images/903041019331174400/BIaetD1J_400x400.jpg");

                channel.createEmbed(spec -> spec
                        .setColor(Processor.getMessageColor(report))
                        .setAuthor(
                                "URL Scan Report: ",
                                report.getPermalink(),
                                "https://pbs.twimg.com/profile_images/903041019331174400/BIaetD1J_400x400.jpg")
                        .setImage("https://www.virustotal.com/gui/images/vt-enterprise.svg")
                        .setTitle(urls[count.getAndAdd(1)])
                        .setUrl(report.getResource())
                        .setDescription("__Message:__ \n" + message.getContent()
                        )
                        .addField(
                                "__Submission:__",
                                "Author:  \t" + message.getData().author().username().toString() + "\n"
                                        + "Discriminator:  \t" + message.getData().author().discriminator().toString() + "\n"
                                        + "Date:  \t" + report.getScanDate(), true)
                        .addField(
                                "__Statistics:__",
                                "Malicious Flags:  \t" + report.getPositives() + "\n"
                                        + "Databases Referenced:  \t" + report.getTotal() + "\n"
                                        + "Response Code:  \t" + report.getResponseCode(), true)
                        .setFooter(
                                report.getScanId(),
                                "https://pbs.twimg.com/profile_images/903041019331174400/BIaetD1J_400x400.jpg")
                        .setTimestamp(Instant.now())
                ).block();
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
     * file hash information, and whether or not there are known suspicions to regard.
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

            File attachmentFile = new File (
                    message
                            .getData()
                            .attachments()
                            .get(0)
                            .filename());

            FileUtils.copyURLToFile ( attachmentURL, attachmentFile);

            System.out.println(message.getData());

            ScanInfo scanInformation = virusTotalRef
                    .scanFile ( attachmentFile );

            Snowflake snowflake = message.getId();

            message.delete (
                    snowflake.asString()
            ).subscribe();

            MessageChannel channel = message
                    .getChannel()
                    .block();

            System.out.println ( "Now creating report embed message with results to relative channel");

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
                            "**Comment: **" +
                            message.getData().content()
                    )
                    .addField (
                            "__Submission:__" ,
                            "Author: " + message.getData().author().username() + "\n"
                            + "Discriminator:  " + message.getData().author().discriminator() + "\n"
                            + "Date: " + message.getData().timestamp(),
                            true
                    )
                    .addField (
                            "__Hashes:__",
                            "SHA1: " + scanInformation.getSha1() + "\n"
                                + "SHA256: " + scanInformation.getSha256() + "\n"
                                + "MD5: " + scanInformation.getMd5(),
                            true
                    )
                    .setFooter (
                            "Scan ID: " + scanInformation.getScanId(),
                            "https://pbs.twimg.com/profile_images/903041019331174400/BIaetD1J_400x400.jpg"
                    )
                    .setTimestamp (
                            Instant.now()
                    )
            ).block();

            try {
                Path filePath = attachmentFile.toPath();

                Files.delete ( filePath );

            } catch ( NoSuchFileException e ) {
                System.out.println ( "ERROR: file path is invalid, or does no exist" );
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