

package discord;

import discord4j.core.DiscordClient;
import discord4j.core.GatewayDiscordClient;
import virustotal.virustotal.exception.APIKeyNotFoundException;
import virustotal.virustotalv2.VirusTotalConfig;
import virustotal.virustotalv2.VirustotalPublicV2;
import virustotal.virustotalv2.VirustotalPublicV2Impl;



/**
 * [0]
 * Authenticator :: <br>
 * Authenticator is the main interface to use, and is for authenticating, connecting, and
 * initializing discord-bot's client and gateway services. <br><br>
 * @implSpec
 * <ol>
 *     <li> Obtain unique DiscordBot api-token via discord/developer/application. </li>
 *     <li> <u> Masquerade token |value| via encapsulation, by assigning to environment/system variables. </u> </li>
 *     <li> Declare your api-token variable to equate: [A] TOKEN <br>
 *         <i> (example:  private final String TOKEN = "$DISCORD_TOKEN"). </i> </li>
 * </ol>
 */
public interface Authenticator extends Processor {


    DiscordClient client = DiscordClient.create (
            System.getenv ( "DISCORD_TOKEN" ) );

    GatewayDiscordClient gateway = client
            .login()
            .block();


    default VirustotalPublicV2 vT() throws APIKeyNotFoundException {

        VirusTotalConfig
                .getConfigInstance()
                .setVirusTotalAPIKey(
                        System.getenv ( "VIRUS_TOKEN" ) );

        return new VirustotalPublicV2Impl();
    }


    /**
     * main ::
     * Run this class to initialize the bot, gateway, and event listeners for virustotal stuff.
     * @param args
     */
    public static void main ( String[] args ) {

        Commands.PingPong();
        EventListener.listenForUrls();
        EventListener.listenForAttachments();

        assert gateway != null;



    }
}


