import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MainTests {

    public static void main ( String [] args ) throws NoSuchAlgorithmException, IOException, InterruptedException {

        testApiConnect();
    }


    static String GetBodySha256 ( String uri ) throws NoSuchAlgorithmException, IOException, InterruptedException {

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

        String hex = String.format ( "%064x",new BigInteger( 1, digest ) );

        System.out.println("\n" + "Hex below");
        System.out.println ( hex );

        return hex;
    }

    static void testApiConnect() throws IOException, InterruptedException {

        URL VT_ENDPOINT = new URL ("https://www.virustotal.com/api/v3/urls/");

        HttpClient client = HttpClient.newHttpClient();

        HttpRequest request = HttpRequest.newBuilder()
                .header("x-apikey", System.getenv("VIRUS_TOKEN"))
                .POST(HttpRequest.BodyPublishers.ofString(null))
                .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

    }
}