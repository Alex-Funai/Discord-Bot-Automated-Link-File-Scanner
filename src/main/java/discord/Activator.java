package discord;

/**
 * [0]
 * Activator :: <br>
 *
 */

abstract class Activator implements Authenticator  {

    public static void main (String ... args) {
        Events events = new Events();
        events.listenForUrls();
        events.listenForAttachments();
    }
}
