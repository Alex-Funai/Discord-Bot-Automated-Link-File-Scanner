/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package virustotal.net.commons;

import virustotal.net.exception.RequestNotComplete;
import virustotal.net.model.*;

import java.io.IOException;
import java.util.List;

/**
 * @author kdkanishka@gmail.com
 */
public interface HTTPRequest {

    Response request(String urlStr, List<Header> reqHeaders,
                     List<FormData> formData,
                     RequestMethod requestMethod,
                     List<MultiPartEntity> multiParts) throws
            RequestNotComplete, IOException, RequestNotComplete;
}
