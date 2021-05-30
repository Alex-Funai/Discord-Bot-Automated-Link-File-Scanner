package discord;

import discord4j.core.DiscordClient;
import discord4j.core.GatewayDiscordClient;


/**
 * [0]
 * Authenticator :: <br>
 * domain class for authenticating, connecting, and initializing discord-bot's (client + gateway) services. <br><br>
 * @implSpec
 * <ol>
 *     <li> Obtain unique discord-bot api-token via discord/developer/application. </li>
 *     <li> <u> Masquerade token |value| via encapsulation, by assigning to environment/system variables. </u> </li>
 *     <li> Declare your api-token variable to equate: [A] TOKEN <br>
 *         <i> (example:  private final String TOKEN = "$DISCORD_TOKEN"). </i> </li>
 * </ol>
 */

interface Authenticator {

    /**
     * [A] DISCORD_TOKEN :: <br>
     * sets discord api-token for the bot to use, and attempts to privatize user's key via encapsulation.
     */
      final String DISCORD_TOKEN = System.getenv("DISCORD_TOKEN");
      final String VIRUS_TOKEN = System.getenv("VIRUS_TOKEN");
    /**
     * [B]
     * DiscordClient client :: <br>
     * initialize an authenticated bot, that uses an api-token.
     */
    final DiscordClient client = DiscordClient.create(DISCORD_TOKEN);

    /**
     * [C]
     * GateweayDiscordClient gateway :: <br>
     * initialize a discord-network-gateway client, to connect with discord's services.
     */
    final GatewayDiscordClient gateway = client.login().block();

}

    /**
     * [D] getStatus() :: <br>
     * sanity check bot services are established properly, by printing it's username to the client-host terminal -
     * only-if/after discord (gateway + cilent) services are authenticated and connected.
     */
/*    public void getStatus() {

        assert gateway != null;
        gateway.getEventDispatcher().on(ReadyEvent.class)
                .subscribe(event -> {
                    final User self = event.getSelf();
                    System.out.println(String.format(
                            "Logged in as %s%s", self.getUsername(), self.getDiscriminator()
                    ));
                });*/

    /**
     * [E]
     * logOff :: <br>
     * disconnect and end the discord-bot (gateway + client) services.
     */
/*    public void logOff() {
        gateway.logout();
        gateway.onDisconnect().block();
    }*/

