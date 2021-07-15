import org.apache.commons.validator.routines.UrlValidator;

import java.util.*;


public interface MainTests {

    public static void main (String... args) {
        String messageContent = "asdfasf asdfasdf cheese";
        System.out.println(testUrls(messageContent));


    }

    static Boolean testUrls(String messageContent) {
        List<String> tokenizedContent = Arrays.asList(messageContent.split("\\s"));

        String [] validationSchemes = {"https", "http"};
        UrlValidator urlValidator = new UrlValidator (validationSchemes);
        int urlCount = (int) tokenizedContent.stream().filter(urlValidator::isValid).count();

        return urlCount > 0;
    }



  /*  interface Authenticator extends Processor {

        DiscordClient client = DiscordClient.create(
                System.getenv("DISCORD_TOKEN"));

        GatewayDiscordClient gateway = client
                .login()
                .block();

        default VirustotalPublicV2 vT() throws APIKeyNotFoundException {

            VirusTotalConfig
                    .getConfigInstance()
                    .setVirusTotalAPIKey(
                            System.getenv("VIRUS_TOKEN"));

            return new VirustotalPublicV2Impl();
        }
    }

    static void listenForUrls() {

        assert gateway != null;

        gateway
                .getEventDispatcher()
                .on(MessageCreateEvent.class)
                .subscribe(event -> {

                    final Message message = event
                            .getMessage();

                    Snowflake snowflake = message.getId();

                    System.out.println(message.getData());

                    ArrayList<String> tokenizedMessageContent = tokenizeMessageContent(message);

                    int urlCount = separateUrlsFromTokenizedContent(tokenizedMessageContent).length;
                    System.out.println("Counting the number of urls..." + "==" + urlCount);

                    if (urlCount > 0) {

                        System.out.println("URL(s) detected in message. Now passing URL(s) into AutomatedScanner.scanURLS()");

                        Scanners.scanUrls(message);

                        System.out.println("URL scan and report message complete ");
                    }

                });
    }

    static void scanUrls(Message message) {

        String messageContent = message.getContent();


        try {
            VirusTotalConfig
                    .getConfigInstance()
                    .setVirusTotalAPIKey(System.getenv("VIRUS_TOKEN"));

            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            Snowflake snowflake = message.getId();

            System.out.println(message.getData());



            message.delete(
                    snowflake.asString()
            ).subscribe();


            String [] urls = {"https://www.google.com", "https://www.yahoo.com"};


            FileScanReport[] reports = virusTotalRef.getUrlScanReport(urls, false);
            System.out.println("File Scan report broken.");


            for (FileScanReport report : reports) {

                if (report.getResponseCode() == 0) {
                    System.out.println("Verbose Msg :\t" + report.getVerboseMessage());
                    continue;
                }

                MessageChannel channel = message
                        .getChannel()
                        .block();

                String thisUser = message.getData().author().username().toString();

                System.out.println("Now creating report embed message with results to relative channel");


                assert channel != null;
                URL authorURL = new URL("https://pbs.twimg.com/profile_images/903041019331174400/BIaetD1J_400x400.jpg");
                channel.createEmbed(spec -> spec

                        .setColor(
                                Processor.getMessageColor(report)
                        )

                        .setAuthor(
                                "URL Scan Report: ", report.getPermalink(), "https://pbs.twimg.com/profile_images/903041019331174400/BIaetD1J_400x400.jpg"
                        )

                        .setImage(
                                "https://www.virustotal.com/gui/images/vt-enterprise.svg"
                        )

                        .setTitle(
                                "asdsad"//urlToken
                        )

                        .setUrl(
                                report.getResource()
                        )

                        .setDescription(
                                Processor.getIntegrityRatingPositives(report)
                        )

                        .addField(
                                "__Submission:__",
                                "Author:  \t" + message.getData().author().username().toString() + "\n"
                                        + "Discriminator:  \t" + message.getData().author().discriminator().toString() + "\n"
                                        + "Date:  \t" + report.getScanDate(), true
                        )

                        .addField(
                                "__Statistics:__",
                                "Malicious Flags:  \t" + report.getPositives() + "\n"
                                        + "Databases Referenced:  \t" + report.getTotal() + "\n"
                                        + "Response Code:  \t" + report.getResponseCode(), true
                        )

                        .setFooter(
                                "ID: " + report.getScanId(), "https://pbs.twimg.com/profile_images/903041019331174400/BIaetD1J_400x400.jpg"

                        )
                        .setTimestamp(
                                Instant.now()
                        )
                ).block();


                // CONSOLE INFORMATION: [start]
                System.out.println("MD5 :\t" + report.getMd5());
                System.out.println("Perma link :\t" + report.getPermalink());
                System.out.println("Resource :\t" + report.getResource());
                System.out.println("Scan Date :\t" + report.getScanDate());
                System.out.println("Scan Id :\t" + report.getScanId());
                System.out.println("SHA1 :\t" + report.getSha1());
                System.out.println("SHA256 :\t" + report.getSha256());
                System.out.println("Verbose Msg :\t" + report.getVerboseMessage());
                System.out.println("Response Code :\t" + report.getResponseCode());
                System.out.println("Positives :\t" + report.getPositives());
                System.out.println("Total :\t" + report.getTotal());

*//*                Map<String, VirusScanInfo> scans = report.getScans();
                for (String key : scans.keySet()) {
                    VirusScanInfo virusInfo = scans.get(key);
                    System.out.println("Scanner : " + key);
                    System.out.println("\t\t Result : " + virusInfo.getResult());
                    System.out.println("\t\t Update : " + virusInfo.getUpdate());
                    System.out.println("\t\t Version :" + virusInfo.getVersion());
                // Console Information: [end]
                }*//*
            }

        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (UnsupportedEncodingException ex) {
            System.err.println("Unsupported Encoding Format!" + ex.getMessage());
        } catch (UnauthorizedAccessException ex) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Operation FUBAR! " + ex.getMessage());
        }

    }


    public static void main(String... args) {

        listenForUrls();
        assert gateway != null;
        gateway.onDisconnect().block();
    }


    *//**
     * Tokenizes message.getContent() by using whitespace as a delimiter.
     *//*
    static ArrayList <String> tokenizeMessageContent ( Message message ) {

        String content = message.getContent();

        ArrayList <String> tokenizedContent = new ArrayList <> ( Arrays.asList ( content.split ( "\\s" ) ));
        Queue<String []> stringQueue = new LinkedList<>();
        stringQueue.add(content.split("\\s"));
        System.out.println(stringQueue);
        System.out.println("Tokenized content");
        System.out.println ( tokenizedContent );

        return tokenizedContent;    //List*/
    }


    /**
     * Returns separated URLs from message.getContent().
     */
/*     static String[] separateUrlsFromTokenizedContent ( ArrayList <String> tokenizedContent ) {

         String[] schemes = {"http", "https"};

         UrlValidator urlValidator = new UrlValidator(schemes);

         ArrayList<String> separatedUrls = new ArrayList<String>();
         Queue<String> separatedUrlsQueue = new LinkedList<>();


         tokenizedContent.forEach((token) -> {

             if (urlValidator.isValid(token)) {
                 separatedUrlsQueue.add(token);
                 separatedUrls.add(token);
             }
         });
         System.out.println(separatedUrlsQueue);

         Object[] separatedUrlsObjectArray = separatedUrls.toArray();
         String arrString = Arrays.toString(separatedUrlsObjectArray);
         return arrString.split(",");
    }*/

    /**
     * Returns separated message from message.getContent().
     */
/*    static Queue <String> separateUrlsFromTokenizedContent ( ArrayList <String> tokenizedContent ) {

        String [] schemes = { "http", "https" };

        UrlValidator urlValidator = new UrlValidator ( schemes );

        Queue <String> separatedMessageQueue = new LinkedList<>();

        tokenizedContent.forEach ( ( token ) -> {

            if ( urlValidator.isValid ( token ) ) {
                separatedMessageQueue.add ( token );
            }
            System.out.println(separatedMessageQueue);
        });

        return separatedMessageQueue;
    }*/

/*    static String [] separateUrlsFromTokenizedContent (ArrayList <String> tokenizedContent) {

        String [] urlSchemes = { "http", "https" };

        UrlValidator urlValidator = new UrlValidator ( urlSchemes );

        tokenizedContent.forEach ( ( token ) -> {

            int i = 0;
            if ( urlValidator.isValid ( token ) ) {
                separatedUrlsArray[i]= token;
            }
        });

    }*/