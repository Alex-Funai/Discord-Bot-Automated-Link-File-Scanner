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
public interface Commands extends Listeners {


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
}