package discord;

import discord4j.core.object.entity.Message;
import discord4j.rest.util.Color;
import org.apache.commons.validator.routines.UrlValidator;
import virustotal.virustotal.dto.FileScanReport;
import virustotal.virustotal.dto.ScanInfo;

import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static discord.Authenticator.gateway;


public interface Processes {

    /**
     * containsUrls() :: <br>
     * The containsUrls() method will validate a url string by definition of toURI(). <br>
     * @param Url intakes a string object that's value represents a URI or URL.
     * @return true, if the method's intake string is a valid Url || false, if not.
     */
    static boolean containsUrls (Message message) {

        String messageContent = message.getContent();
        List<String> tokenizedContent = Arrays.asList(messageContent.split("\\s"));

        String [] validationSchemes = {"https", "http"};
        UrlValidator urlValidator = new UrlValidator (validationSchemes);
        int urlCount = (int) tokenizedContent.stream().filter(urlValidator::isValid).count();
        return urlCount > 0;
    }

    /**
     * getUrlsArray() <br>
     * The getUrlsArray() method will tokenize return of message.getContent() into an ArrayList, validate URL's
     * in contrast to text, and then add them to a string. getUrlsArray() method is used for prepping a message intended
     * to be input to urlScanner().
     * @param message a user's discord message.
     * @return a String[] to use with getUrlsArray().
     */
    static String[] getUrlsArray (Message message ) {

        String content = message.getContent();
        String [] tokenizedContentArray = content.split("\\s");
        String [] validatorSchemes = { "https", "http" };
        UrlValidator urlValidator = new UrlValidator ( validatorSchemes );
        ArrayList<String> urlsList = new ArrayList<>();

        for ( String token : tokenizedContentArray ) {
            if ( urlValidator.isValid (token) ) {
                urlsList.add(token);
            }
        }
        return urlsList.toArray(new String[0]);
    }

    /** @deprecated <br>
     * getBodySha256() : <br>
     * The getBodySha256() method will process a uri and performs a http GET request, to retrieve the objects' HTML body,
     * and then converts it to checksum-SHA256. <br><br>
     * @param uri intakes a string with value of a uri or url.
     * @return a checksum-SHA256 hex, as a string object.
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InterruptedException
     */
    @Deprecated
    static String getBodySha256(String uri) throws NoSuchAlgorithmException, IOException, InterruptedException {

        HttpClient client = HttpClient.newHttpClient();
        HttpRequest request = HttpRequest.newBuilder()
                .uri ( URI.create ( uri ) )
                .build();

        HttpResponse<String> response =
                client.send ( request, HttpResponse.BodyHandlers.ofString() );

        System.out.println ( response.body() );

        MessageDigest md = MessageDigest.getInstance ( "SHA-256" );
        String text = response.body();
        md.update ( text.getBytes ( StandardCharsets.UTF_8 ) );

        byte[] digest = md.digest();
        String hex = String.format ( "%064x",new BigInteger ( 1, digest ) );
        System.out.println ( hex );

        return hex;
    }


    /**
     * getMessageColor() : <br>
     * The getMessageColor() method is a conditional statement for checking the value of malicious flags returned from a report --
     * it then assigns and returns a color value for an embedded message depending on the increment of severity.
     * @param report intake a FileScanReport[] array.
     * @return conditional color corresponding to pre-determined severity of flags, based off the value of .getTotal().
     */
    static Color getMessageColor ( FileScanReport report ) {

        int numberOfPositives = report.getPositives();

        if ( numberOfPositives == 0 ) {
            return ( Color.GREEN );
        } else if (numberOfPositives >= 1 && numberOfPositives <= 2) {
            return ( Color.MOON_YELLOW );
        } else if (numberOfPositives >= 3) {
            return ( Color.RED );
        } else {
            return ( Color.GRAY_CHATEAU );
        }
    }

    /**
     * getIntegrityRatingPositives() : <br>
     * The getIntegrityRatingPositives() method will intake a report, and return a message that evaluates/represents
     * the threat level of a scan. The results are based upon the number of positive flags returned in a report.
     * @param report url or file reports.
     * @return strings that represent a reports threat level, non-verbatim.
     */
    static String getIntegrityRatingPositives(FileScanReport report) {

        int numberOfPositives = report.getPositives();

        if ( numberOfPositives == 0 ) {
            return ( "URL is safe" );
        } else if (numberOfPositives >= 1 && numberOfPositives <= 2) {
            return ( "URL likely safe, discern false flag potential, and proceed wisely.");
        } else if (numberOfPositives >= 3) {
            return ( "URL is definitely sus and not safe, proceed with CAUTION.");
        } else {
            return ( "Unknown");
        }
    }

    /**
     * @deprecated <br>
     * getIntegrityRatingResponseCode() : <br>
     * The getIntegrityRatingResponseCode() method is a quick boolean switch, for determining the integrity of a fileScan.
     * ScanInfo.getVerboseStatus() is the determining variable -- it returns 1 when a VirusTotal scan catches a flag in
     * one of it's databases, and a 0 if not (symbolizing, a technically clean scan). FileScanReport.getTotal() wasn't
     * available in the current class, so this sufficed for now.
     * @param scanInfo intakes a ScanInfo object used with VirusTotal file scans.
     * @return a boolean value -- true = dirty || false = clean.
     */
    @Deprecated
    static Boolean getIntegrityRatingResponseCode ( ScanInfo scanInfo ) {

          Boolean verboseStatus;

          if (Integer.parseInt(scanInfo.getVerboseMessage()) == 1) {
              return verboseStatus = true;
          } else if (Integer.parseInt(scanInfo.getVerboseMessage()) == 0) {
              return verboseStatus = false;
          }
          return verboseStatus = true;
      }

     /**
      * @deprecated <br>
     * getIntegrityResponseFromBoolean() : <br>
     * The getIntegrityResponseFromBoolean method extends getIntegrityRatingResponseCode() and provides congruent output
     * to an object's scan integrity. In some ways unnecessary, because this could have been implemented within
     * getIntegrityRatingResponseCode(), but in-case for future methods -- this could be useful.
     * @param yorn intakes a boolean, where "yorn" represents a yes-or-no determination scenario.
     * @return returns a congruent statement to the status of an integrity scan.
     */
     @Deprecated
     static String getIntegrityResponseFromBoolean ( Boolean yorn ) {
          String yesForSafe = "Object is seemingly safe, and VirusTotal databases indicated no suspicious flags thrown.." +
                  "However proceed with caution and use wise judgement before proceeding.";
          String noForNah = "Object has known suspicious references in VirusTotal databases. This could be a false-flag," +
                  "however definitely investigate the object before executing or parsing.";
          String ukForUnknown = "Insufficient data for the given object, be careful.";
          if ( yorn = true ) {
              return yesForSafe;
          } else if ( yorn = false ) {
              return noForNah;
          }
          return ukForUnknown;
      }




    /**
     * shutDownBot : <br>
     * The shutDownBot() method will resolve a (gateway + client)'s  shutdown, in-case the onDisconnect() method doesn't
     * properly work. I currently have it setup incorrectly, so this is a start for correcting that. Doesn't matter for
     * now tho, everything still all good for testing.
     */
    static void shutDownBot() {
        assert gateway != null;
        gateway.logout();
        gateway.onDisconnect().block();
    }

}