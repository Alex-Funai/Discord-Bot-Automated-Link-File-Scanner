package discord;


import discord4j.rest.util.Color;
import virustotal.virustotal.dto.FileScanReport;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.net.*;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static discord.Authenticator.gateway;


public interface Processor {



    public static void main(String... args) throws Exception {
        getBodySha256("https://www.google.com");
    }

    static void getBodySha256(String uri) throws NoSuchAlgorithmException, IOException, InterruptedException {
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
     * [E]
     * logOff :: <br>
     * disconnect and end the discord-bot (gateway + client) services.
     */
    static void ShutDownBot() {
        assert gateway != null;
        gateway.logout();
        gateway.onDisconnect().block();
    }
}





