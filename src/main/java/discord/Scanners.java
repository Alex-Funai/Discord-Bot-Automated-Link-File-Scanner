package discord;
import discord4j.common.util.Snowflake;
import discord4j.core.object.entity.Message;
import discord4j.core.object.entity.channel.MessageChannel;
import discord4j.rest.util.Color;
import virustotal.virustotal.dto.FileScanReport;
import virustotal.virustotal.dto.VirusScanInfo;
import virustotal.virustotal.exception.UnauthorizedAccessException;
import virustotal.virustotalv2.VirustotalPublicV2;
import virustotal.virustotal.exception.APIKeyNotFoundException;
import virustotal.virustotalv2.VirusTotalConfig;
import virustotal.virustotalv2.VirustotalPublicV2Impl;

import java.io.UnsupportedEncodingException;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;

/**
 * [0]
 * Scanners :: <br>
 * class for defining and managing virustotal scans that discord4j can utilize..
 * @see > set virustotal api-token/key in virustotalv2.VirusTotalConfig/
 */
public class Scanners  {


    /**
     * [B]
     * scanURL() :: <br>
     * Scans an array of urls for general virustotal information. <br><br>
     *
     * @param Urls an array of urls to scan.
     * @return string of the scaninfo.
     * @implSpec <ul>
     * <li>Handle multiple Urls</li>
     *
     * </ul>
     */
    public static void scanUrl(Message message) {

        try {
            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(System.getenv("VIRUS_TOKEN"));
            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            Snowflake snowflake = message.getId();
            message.delete(snowflake.asString()).subscribe();

            String[] urls = message.getContent().split(" ");

            FileScanReport[] reports = virusTotalRef.getUrlScanReport(urls, false);

            for (FileScanReport report : reports) {
                if(report.getResponseCode()==0){
                    System.out.println("Verbose Msg :\t" + report.getVerboseMessage());
                    continue;
                }
                String IMAGE_URL = null; // replace with iamge url

                final MessageChannel channel = message.getChannel().block();
                assert channel != null;
                channel.createEmbed(spec ->
                        spec.setColor(Color.RED)
                        .setAuthor("setAuthor", "null", IMAGE_URL)
                        .setImage(IMAGE_URL)
                        .setTitle(Arrays.toString(urls))
                        .setUrl(report.getResource())
                        .setDescription("" +
                                "MD5: \t" + report.getMd5() + "\n" +
                                "PermaLink: \t" + report.getPermalink() + "\n" +
                                "Scan Date: \t" + report.getScanDate() + "\n" +
                                "Scan Id: \t" + report.getScanId() + "\n" +
                                "SHA1: \t" + report.getSha1() + "\n" +
                                "SHA256: \t" + report.getSha256() + "\n" +
                                "Verbose Message: \t" + report.getVerboseMessage() + "\n" +
                                "Response Code: \t" + report.getResponseCode() + "\n" +
                                "Positives: \t" + report.getPositives() + "\n" +
                                "Total: \t " + report.getTotal()
                                )

                        .addField("addField", "inline = true", true)
                        .addField("addField", "inline=true", true)
                        .addField("addField", "inline=true", true)
                        .setThumbnail(IMAGE_URL)
                        .setFooter("VirusTotal.com", IMAGE_URL).setTimestamp(Instant.now())
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

