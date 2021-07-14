import org.junit.jupiter.api.Test;
import virustotal.virustotal.dto.FileScanReport;
import virustotal.virustotal.dto.VirusScanInfo;
import virustotal.virustotal.exception.APIKeyNotFoundException;
import virustotal.virustotal.exception.UnauthorizedAccessException;
import virustotal.virustotalv2.VirusTotalConfig;
import virustotal.virustotalv2.VirustotalPublicV2;
import virustotal.virustotalv2.VirustotalPublicV2Impl;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Queue;

public class UnitTests {


    @Test
    static String GetBodySha256(String uri) throws NoSuchAlgorithmException, IOException, InterruptedException {

        HttpClient client = HttpClient.newHttpClient();

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(uri))
                .build();

        HttpResponse<String> response =
                client.send(request, HttpResponse.BodyHandlers.ofString());

        System.out.println(response.body());

        MessageDigest md = MessageDigest.getInstance("SHA-256");

        String text = response.body();

        md.update(text.getBytes(StandardCharsets.UTF_8));

        byte[] digest = md.digest();

        String hex = String.format("%064x", new BigInteger(1, digest));

        System.out.println("\n" + "Hex below");
        System.out.println(hex);

        return hex;
    }

    @Test
    static void testApiConnect() throws IOException, InterruptedException {

        URL VT_ENDPOINT = new URL("https://www.virustotal.com/api/v3/urls/");

        HttpClient client = HttpClient.newHttpClient();

        HttpRequest request = HttpRequest.newBuilder()
                .header("x-apikey", System.getenv("VIRUS_TOKEN"))
                .POST(HttpRequest.BodyPublishers.ofString(null))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    @Test
    static void getAllMessageDebug() {

    }


    public static void main(String[] args) {
        try {
            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(System.getenv("VIRUS_TOKEN"));
            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            String[] urls = {"http://www.toll-net.be/ ","www.google.lk"};
            FileScanReport[] reports = virusTotalRef.getUrlScanReport(urls, false);

            for (FileScanReport report : reports) {
                if(report.getResponseCode()==0){
                    System.out.println("Verbose Msg :\t" + report.getVerboseMessage());
                    continue;
                }
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
                System.out.println("\n" + "BEGIN NEXT REPORT");

/*                Map<String, VirusScanInfo> scans = report.getScans();
                for (String key : scans.keySet()) {
                    VirusScanInfo virusInfo = scans.get(key);
                    System.out.println("Scanner : " + key);
                    System.out.println("\t\t Result : " + virusInfo.getResult());
                    System.out.println("\t\t Update : " + virusInfo.getUpdate());
                    System.out.println("\t\t Version :" + virusInfo.getVersion());
                }*/
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