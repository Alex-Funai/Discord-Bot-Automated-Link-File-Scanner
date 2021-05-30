package discord;

import virustotal.virustotal.dto.ScanInfo;
import virustotal.virustotal.exception.UnauthorizedAccessException;
import virustotal.virustotalv2.VirusTotalConfig;
import virustotal.virustotalv2.VirustotalPublicV2;
import virustotal.virustotalv2.VirustotalPublicV2Impl;

import java.io.UnsupportedEncodingException;

/**
 * [0]
 * Scanners :: <br>
 * class for defining and managing virustotal scans that discord4j can utilize..
 * @see > set virustotal api-token/key in virustotalv2.VirusTotalConfig/
 */
public class Scanners {

    /**[A]
     * API_KEY :: <br>
     * initialize virustotal api-key/token through virustotal services configurator.
     */
    private static final String API_KEY = VirusTotalConfig.getConfigInstance().getVirusTotalAPIKey();


    /**
     * [B]
     * String listenForUrls() :: <br>
     * Scans an array of urls for general virustotal information. <br><br>
     * @param Urls an array of urls to scan.
     * @return string of the scaninfo.
     * @implSpec
     * <ul>
     *     <li>Handle multiple Urls</li>
     *
     * </ul>
     *
     *
     */
    public static String scanUrl(String[] Urls) {
        try {
            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(API_KEY);
            VirustotalPublicV2 virusTotal = new VirustotalPublicV2Impl();
            ScanInfo[] scanInfoArr = virusTotal.scanUrls(Urls);

            for (ScanInfo scanInformation : scanInfoArr) {
                System.out.println("___SCAN INFORMATION___");
                System.out.println("MD5 :\t" + scanInformation.getMd5());
                System.out.println("Perma Link :\t" + scanInformation.getPermalink());
                System.out.println("Resource :\t" + scanInformation.getResource());
                System.out.println("Scan Date :\t" + scanInformation.getScanDate());
                System.out.println("Scan Id :\t" + scanInformation.getScanId());
                System.out.println("SHA1 :\t" + scanInformation.getSha1());
                System.out.println("SHA256 :\t" + scanInformation.getSha256());
                System.out.println("Verbose Msg :\t" + scanInformation.getVerboseMessage());
                System.out.println("Response Code :\t" + scanInformation.getResponseCode());
                System.out.println("done.");

                return "SCAN RESULTS:" + "\n"
                        + "MD5: " + scanInformation.getMd5() + "\n"
                        + "PermaLink: " + scanInformation.getPermalink() + "\n"
                        + "Resource: " + scanInformation.getResource() + "\n"
                        + "Scan Date: " + scanInformation.getScanDate() + "\n"
                        + "Scan Id: " + scanInformation.getScanId() + "\n"
                        + "SHA1: " + scanInformation.getSha1() + "\n"
                        + "SHA256: " + scanInformation.getSha1() + "\n"
                        + "Verbose Message: " + scanInformation.getVerboseMessage() + "n"
                        + "Response Code: " + scanInformation.getResponseCode() + "\n";
            }

        } catch ( UnsupportedEncodingException ex ) {
            System.err.println("Unsupported Encoding Format!" + ex.getMessage());
        } catch ( UnauthorizedAccessException ex ) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch ( Exception ex ) {
            System.err.println("Something Bad Happened! " + ex.getMessage());
        }
        return null;
    }
}

