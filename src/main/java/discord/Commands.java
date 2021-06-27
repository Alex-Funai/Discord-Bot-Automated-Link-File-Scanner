package discord;

import discord4j.core.event.domain.message.MessageCreateEvent;
import discord4j.core.object.entity.Message;
import discord4j.core.object.entity.User;
import discord4j.core.object.entity.channel.MessageChannel;
import virustotal.virustotal.dto.FileScanReport;
import virustotal.virustotal.exception.APIKeyNotFoundException;
import virustotal.virustotal.exception.InvalidArguentsException;
import virustotal.virustotal.exception.QuotaExceededException;
import virustotal.virustotal.exception.UnauthorizedAccessException;
import virustotal.virustotalv2.VirusTotalConfig;
import virustotal.virustotalv2.VirustotalPublicV2;
import virustotal.virustotalv2.VirustotalPublicV2Impl;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.time.Instant;
import java.util.Arrays;


/**
 * Commands ; <br>
 * Commands interface manages user-bot interactions, and defines commands that human users can utilize to
 * interact with the bot, as long as the messages are within the bot's scope. The commands dominantly pertain to
 * gateway listener events. This interface will most likely include oSINT or random lookup tools that I can find and include.
 */
public interface Commands extends EventListener {


    /**
     * pingPong() : <br>
     * The pingPong() method is a command that creates and sends a channel message "pong", when a user
     * within the bot's scope sends the message "!pong". pingPong is a basic introduction task for validating gateway
     * listener events, and automated bot tasks. <br><br>
     * @see
     * <ol>
     *     <li> Creates a listener event for messages. </li>
     *     <li> Initializes argument to filter execution, to the command "!ping" by humans. </li>
     *     <li> Initializes a new message object within the "!ping" channel. </li>
     *     <li> Defines the message's response as, "pong", and then executes sending via .block() </li>
     * </ol>
     */
    static void pingPong() {


        assert gateway != null;

        gateway.on (MessageCreateEvent.class ).subscribe (event -> {

            final Message message = event.getMessage();

            if ( "!ping".equals ( message.getContent() ) ) {

                final MessageChannel channel = message
                        .getChannel()
                        .block();

                assert channel != null;
                channel.createMessage(
                        "pong"
                ).block();
            }
        });

    }


    /**
     * getUrlReport() :: <br>
     * The getUrlReport method is an extension to a VirusTotal scan, and will retrieve information that specifically
     * pertains to each of the 80+ databases that VirusTotal utilizes.
     * @throws APIKeyNotFoundException
     * @throws InvalidArguentsException
     * @throws QuotaExceededException
     * @throws UnauthorizedAccessException
     * @throws IOException
     */
    static void getUrlReport(Message message) {

        try {
            VirusTotalConfig
                    .getConfigInstance()
                    .setVirusTotalAPIKey(System.getenv("API_KEY"));

            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            String[] urls = ( message
                    .getContent() )
                    .split ( " " );

            FileScanReport[] reports = virusTotalRef.getUrlScanReport ( urls, false );

            for ( FileScanReport report : reports ) {
                if ( report.getResponseCode() == 0 ) {
                    System.out.println ( "Verbose Msg :\t" + report.getVerboseMessage() );
                    continue;
                }

                MessageChannel channel = message
                        .getChannel()
                        .block();

                assert channel != null;
                Message details = channel
                        .getLastMessage()
                        .block();

                assert details != null;
                String author = details
                        .getAuthor()
                        .toString();

                String authorUrl = details
                        .getAuthor()
                        .getClass()
                        .getName();

                String authorIconUrl = new User
                        ( details.getClient(), message.getUserData() )
                        .getAvatarUrl();

                // Initialize an embeded message, and set the desired properties for it.
                channel.createEmbed ( spec -> spec

                        .setColor(
                                Processor.getMessageColor ( report )
                        )
                        // Set who is displayed as the author of the embedded message.
                        .setAuthor (
                                author, authorUrl, authorIconUrl
                        )
                        .setImage (
                                "resources/virustotal-avatar.png"
                        )
                        // Set the title of the the embedded message.
                        .setTitle (
                                Arrays.toString(urls)
                        )
                        // Set the URL reference of the embedded message.
                        .setUrl (
                                report.getResource()
                        )
                        // Set the body-description of the embedded message.
                        .setDescription (
                                ""
                                        + "** Report Link:  ** \t" + report.getPermalink() + "\n"
                                        + "** Scan Date:  ** \t" + report.getScanDate() + "\n"
                                        + "** Scan Id : ** \t" + report.getScanId() + "\n"
                                        + "** MD5: ** \t" + report.getMd5() + "\n"
                                        + "** SHA1: ** \t" + report.getSha1() + "\n"
                                        + "** SHA256: ** \t" + report.getSha256() + "\n"
                                        + "** Verbose: ** \t" + report.getVerboseMessage() + "\n"
                                        + "** Response Code: ** \t" + report.getResponseCode() + "\n"
                                        + "** Positives: ** \t" + report.getPositives() + "\n"
                                        + "** Total: ** \t " + report.getTotal()
                        )
                        // Create a field -- this will split the bottom section of the embedded message table into columns.
                        .addField (
                                "[Hash]",
                                "SHA256 : \t" + report.getSha256() + "\n"
                                        + "SHA1 : \t" + report.getSha1() + "\n"
                                        + "MD5 : \t" + report.getMd5(), true
                        )
                        // Create a second field, for ...
                        .addField(
                                "[Statistics]",
                                "Malicious Flags : \t" + report.getPositives() + "\n"
                                        + "Databases Referenced : \t" + report.getTotal() + "\n"
                                        + "Response Code : \t" + report.getResponseCode(), true
                        )

                        // Set the footer of the embedded message, to display the Scan ID.
                        .setFooter (
                                "Scan ID: \t" + report.getScanId(), null
                        )

                        // Set the TimeStamp -- which appears in smaller text, at the bottom
                        .setTimestamp (
                                Instant.now()
                        )
                ).block();

            }
        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (
        UnsupportedEncodingException ex) {
            System.err.println("Unsupported Encoding Format!" + ex.getMessage());
        } catch (UnauthorizedAccessException ex) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Something Bad Happened! " + ex.getMessage());
        }
    }
}