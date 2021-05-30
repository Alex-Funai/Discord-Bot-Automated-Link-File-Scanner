/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package virustotal.virustotalv2;

/**
 * Configuration singleton which allows to maintain configurations
 * @author kdkanishka@gmail.com
 */
public final class VirusTotalConfig {

    private String virusTotalAPIKey;
    private static VirusTotalConfig configInstance = null;

    public VirusTotalConfig() {
        virusTotalAPIKey = System.getenv("VIRUS_TOKEN");
    }

    public static VirusTotalConfig getConfigInstance() {
        if (configInstance == null) {
            synchronized (VirusTotalConfig.class) {
                if (configInstance == null) {
                    configInstance = new VirusTotalConfig();
                }
            }
        }
        return configInstance;
    }

    public String getVirusTotalAPIKey() {
        return virusTotalAPIKey;
    }

    public void setVirusTotalAPIKey(String virusTotalAPIKey) {
        this.virusTotalAPIKey = virusTotalAPIKey;
    }

}
