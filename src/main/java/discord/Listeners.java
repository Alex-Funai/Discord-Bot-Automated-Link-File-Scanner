package discord;

import com.sun.tools.javac.Main;
import discord4j.common.util.Snowflake;
import discord4j.core.event.domain.message.MessageCreateEvent;
import discord4j.core.object.entity.Message;
import discord4j.core.object.entity.channel.MessageChannel;
import java.net.URL;
/**
 * [0]
 * Bot_Events :: <br>
 * domain class for defining and managing discord-gateway-events.
 */
public class Listeners implements Authenticator {


    /**
     * isURL() :: <br>
     * validates a url string by definition of toURI(). <br><br>
     * @implNote should refactor parameter for array, list, stack, or queue.
     * @param Url a url of type string.
     * @return boolean value == url validation.
     */
    public static boolean isURL(String Url) {

        try {
            URL url_intake = new URL(Url);
            url_intake.toURI();
            return true;
        } catch (Exception e) {
            return false;
        }
    }


    /**
     * pingPong() :: <br>
     * gateway-listener-event for command "!ping" that responds "pong". <br><br>
     * @implNote
     * <ol>
     *     <li> Creates a listener event for messages. </li>
     *     <li> Initializes argument to regulate execution, to only the command "!ping" by humans. </li>
     *     <li> Initializes a new message object set to channel of current "!ping" interaction </li>
     *     <li> Defines the message's response as, "pong", and then executes sending via .block() </li>
     * </ol>
     */
       void listenForPing() {
        assert gateway != null;
        gateway.on(MessageCreateEvent.class).subscribe(event -> {
            final Message message = event.getMessage();
            if ("!ping".equals(message.getContent())) {
                final MessageChannel channel = message.getChannel().block();
                assert channel != null;
                channel.createMessage("pong").block();
            }
        });
    }

    /**
     * listenForUrls() :: <br>
     * listener event for URL(s) in any message's content. <br><br>
     * @implNote
     * <ol>
     *     <li> Create a gateway-listener-event for listening to all guild messages. </li>
     *     <li> Store the messageid (snowflake), and scan messages' content. </li>
     *     <li> Pass message's content through isURL() to determine if they contain a url. </li>
     *     <li> If isUrl()==true --> delete their message, and respond with scan-introduction-message</li>
     *     <li> Pass user's url(s) into an array, and then through virustotal url scanner.</li>
     *     <li> Print virustotal url scanners returned results.</li>
     * </ol>
     */
    public void listenForUrls() {

        assert gateway != null;
        gateway.getEventDispatcher().on(MessageCreateEvent.class).subscribe(event -> {
            Message message = event.getMessage();
            message.getContent();

            if (isURL(message.getContent())) {
                Scanners.scanUrl(message);


/*                message.delete(messageSnowflake.asString()).subscribe();
                MessageChannel channel = message.getChannel().block();
                assert channel != null;
                channel.createMessage("" + "\n"
                        + "```"
                        + "Scanning URL and verifying integrity via VirusTotal.com..." + "\n"
                        + "URL: " + message.getContent() + "\n"
                        + "User: " + message.getUserData().username() + "\n"
                        + "Time: " + message.getTimestamp() + "\n"
                        + "```").block();

                String[] urls = {message.getContent()};
                String results = Scanners.scanUrl(urls);
                channel.createMessage("```" + results + "```").block();*/
            }
        });
    }
    /**
     * listenForAttachments() :: <br>
     * gateway-listener-event for hearing and scanning message-attachments. <br><br>
     * @implNote asdasdasdasd
     * <ol>
     *     <li> Listen to guild messages, and reference snowflake flags with an integer comparator to verify
     *          if a message contains any attachments.
     *          <i>(Examples: file attachments, images, videos, widgets)</i> </li>
     *     <li> If message contains attachments --> delete it so it can be scanned before being exposed to the server. </li>
     *     <li> Convert, store, and retrieve the attachments (SHA256, SHA1, MDA5).hex </li>
     *     <li> Hand off hex values through virustotal to scan for known compramizations, malware, threats, and viruses. </li>
     *     <li> If/else || switch(case) --> for either allowing link, or to some extent supressing it with an explanation messeage.</li>
     * </ol>
     */
    public void listenForAttachments() {

        assert gateway != null;
        gateway.getEventDispatcher().on(MessageCreateEvent.class).subscribe(event -> {
            Message message = event.getMessage();

            if (message.getAttachments().size() > 0) {
                System.out.println("The test passes and it can tell there are attachments.");
                MessageChannel channel = message.getChannel().block();
                assert channel != null;
                channel.createMessage("One moment...Scanning file integrity via VirusTotal.com").block();
            }
        });
    }
}

