package discord;


import java.io.IOException;
import java.math.BigInteger;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;


public class Converter {

    public static void main(String... args) throws Exception {
        getBodySha256("https://www.google.com");

    }

    public static void getBodySha256(String uri) throws NoSuchAlgorithmException, IOException, InterruptedException {
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

        String hex = String.format("%064x",new BigInteger(1, digest));
        System.out.println(hex);
    }
}





