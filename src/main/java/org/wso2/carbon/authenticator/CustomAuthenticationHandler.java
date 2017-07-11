/*
 *   Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *   WSO2 Inc. licenses this file to you under the Apache License,
 *   Version 2.0 (the "License"); you may not use this file except
 *   in compliance with the License.
 *   You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing,
 *   software distributed under the License is distributed on an
 *   "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *   KIND, either express or implied.  See the License for the
 *   specific language governing permissions and limitations
 *   under the License.
 *
 */
package org.wso2.carbon.authenticator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.synapse.MessageContext;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.rest.AbstractHandler;

import java.util.Map;

public class CustomAuthenticationHandler extends AbstractHandler {

    private static final Log log = LogFactory.getLog(CustomAuthenticationHandler.class);
    private static final String X_JWT_ASSERTION = "X-JWT-Assertion";
    private static final String CUSTOM_AUTHENTICATION_HEADER = "Custom-Authentication";

    //This method is invoked everytime the API is called and the handler is engaged. The logic written here is executed
    // prior to forwarding the request to the IoT server API.
    public boolean handleRequest(MessageContext messageContext) {
        if (log.isDebugEnabled()) {
            log.debug("CustomAuthenticationHandler handleRequest called");
        }

        //Authenticate the request.
        if (authenticate(messageContext)) {
            return true;
        }

        return false;
    }

    public boolean authenticate(MessageContext synCtx) {

        Map headers = getTransportHeaders(synCtx);
        String authHeader = (String) headers.get(CUSTOM_AUTHENTICATION_HEADER);


        // These values must be passed from the device and these variables has to be populated.
        String tenantDomain = "carbon.super";
        String deviceType = "android";
        String username = "admin";


        // Fill here with the custom authentication logic as you wish. For example call an external system to
        // validate a value that comes in the CUSTOM_AUTHENTICATION_HEADER

        //if (authHeader.startsWith("custom_authenticated_value")) {
        try {
            headers.put(X_JWT_ASSERTION, AuthenticationUtils.createJWTToken(username, tenantDomain, deviceType));
            return true;
        } catch (CustomAuthenticatorException e) {
            log.error("Error while attempting to authenticate the request.", e);
            return false;
        }
        //}
        //return false;
    }


    private Map getTransportHeaders(MessageContext messageContext) {
        return (Map) ((Axis2MessageContext) messageContext).getAxis2MessageContext().
                getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
    }

    public boolean handleResponse(MessageContext messageContext) {
        return true;
    }
}