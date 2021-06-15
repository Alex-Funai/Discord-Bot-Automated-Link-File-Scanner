package discord;

import discord4j.rest.util.Color;
import virustotal.virustotal.dto.FileScanReport;
import java.io.IOException;
import java.math.BigInteger;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import static discord.Authenticator.gateway;


public interface Processor {

    /**
     * isURL() :: <br>
     * A method that validates a url string by definition of toURI(). <br>
     * @param Url intakes a string object that's value represents a URI or URL.
     * @return true, if the method's intake string is a valid Url || false, if not.
     */
    static boolean isURL(String Url) {

        try {

            URL url_intake = new URL(Url);

            url_intake.toURI();

            return true;

        } catch (Exception e) { return false; }
    }

    /**
     * GetBodySha256 :: <br>
     * GetBodySha256() will process a uri and performs a http GET request, to retrieve the objects' HTML body,
     * and then converts it to checksum-SHA256. <br><br>
     * @param uri intakes a string with value of a uri or url.
     * @return a checksum-SHA256 hex, as a string object.
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InterruptedException
     */
    static String GetBodySha256 (String uri) throws NoSuchAlgorithmException, IOException, InterruptedException {

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
     * getMessageColor :: <br>
     * getMessageColor() is a conditional statement for checking the value of malicious flags returned from a report --
     * it then assigns and returns a color value for an embedded message depending on the increment of severity.
     * @param report intake a FileScanReport[] array.
     * @return conditional color corresponding to pre-determined severity of flags, based off the value of .getTotal().
     */
    static Color getMessageColor(FileScanReport report) {

        int numberOfPositives = report.getPositives();

        if (numberOfPositives == 0) {
            return ( Color.GREEN );
        } else if (numberOfPositives >= 1 && numberOfPositives <= 2) {
            return ( Color.YELLOW );
        } else if (numberOfPositives >= 3) {
            return ( Color.RED );
        } else {
            return ( Color.GRAY_CHATEAU );
        }
    }


    /**
     * ShutDownBot :: <br>
     * ShutDownBot() is a method for resolving gateway and client shutdown, if the disconnect function doesn't
     * properly work. Sometimes utilizing onDisconnect().
     */
    static void ShutDownBot() {
        assert gateway != null;
        gateway.logout();
        gateway.onDisconnect().block();
    }
}





