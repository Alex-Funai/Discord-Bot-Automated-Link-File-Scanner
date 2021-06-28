package discord;

import discord4j.common.util.Snowflake;
import discord4j.core.event.domain.message.MessageCreateEvent;
import discord4j.core.object.entity.Message;
import discord4j.core.object.entity.channel.MessageChannel;

import java.net.URL;


/**
 * EventListener : <br>
 * The EventListener interface will manage discord's gateway listener events. The EventListener interface
 * contains actions the discord bot will execute, as it passively listens to the channels within it's scope. EventListener
 * is a reactive interface that only executes it's method's independently if their execution requirements are met.
 */
public interface EventListener extends Authenticator, AutomatedScanner, Processor {

    /**
     * listenForUrls() :: <br>
     * The listenForUrls method is a reactive discord gateway listener, for determining if a URL is present in any message
     * that is passed by the discord bot's scope.<br><br>
     * @see
     * <ol>
     *     <li> Create a gateway-listener-event for listening to all guild messages. </li>
     *     <li> Store the messageid (snowflake), and scan messages' content. </li>
     *     <li> Pass message's content through isURL() to determine if they contain a url. </li>
     *     <li> If isUrl()==true --> delete their message, and respond with scan-introduction-message</li>
     *     <li> Pass user's url(s) into an array, and then through virustotal url scanner.</li>
     *     <li> Print virustotal url scanners returned results.</li>
     * </ol>
     */
    static void listenForUrls() {

        assert gateway != null;

        gateway
            .getEventDispatcher()
            .on ( MessageCreateEvent.class )
            .subscribe ( event -> {

               final Message message = event
                        .getMessage();

                Snowflake snowflake = message.getId();


                if ( Processor.isURL ( message.getContent() ) ) {

                    AutomatedScanner.scanUrls( message );
                }

            });
     }

    /**
     * listenForAttachments() : <br>
     * The listenForAttachments() method is a reactive gateway listener event that activates when the bot determines an attachment
     * has been passed through it's scope.
     * @see
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
    static void listenForAttachments() {

        assert gateway != null;

        gateway
                .getEventDispatcher()
                .on( MessageCreateEvent.class )
                .subscribe ( event -> {

                    Message message = event.getMessage();

                    if ( message.getAttachments().size() > 0 ) {

                        System.out.println ( "The test passes and it can tell there are attachments." );

                        AutomatedScanner.scanAttachments(message);

                    }
                });
    }
}