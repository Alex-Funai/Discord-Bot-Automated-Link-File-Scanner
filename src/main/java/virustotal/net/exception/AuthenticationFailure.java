/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package virustotal.net.exception;

/**
 *
 * @author kdkanishka@gmail.com
 */
public class AuthenticationFailure extends Exception {

    public AuthenticationFailure() {
    }

    public AuthenticationFailure(String message) {
        super(message);
    }

    public AuthenticationFailure(String message, Throwable cause) {
        super(message, cause);
    }

    public AuthenticationFailure(Throwable cause) {
        super(cause);
    }
}
