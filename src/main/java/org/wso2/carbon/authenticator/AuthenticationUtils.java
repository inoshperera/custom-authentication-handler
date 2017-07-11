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
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.jwt.client.extension.exception.JWTClientException;
import org.wso2.carbon.identity.jwt.client.extension.service.JWTClientManagerService;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.HashMap;
import java.util.Map;

public class AuthenticationUtils {

    private static final Log log = LogFactory.getLog(AuthenticationUtils.class);

    public static String createJWTToken(String username, String tenantDomain) throws
            CustomAuthenticatorException {
        String tenantId = String.valueOf(getTenantID(tenantDomain));
        Map<String, String> claims = new HashMap<>();

        claims.put("http://wso2.org/claims/enduserTenantId", tenantId);
        claims.put("http://wso2.org/claims/enduser", username + "@" + tenantDomain);

        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext.getThreadLocalCarbonContext()
                    .setTenantId(Integer.parseInt(tenantId));
            PrivilegedCarbonContext.getThreadLocalCarbonContext()
                    .setTenantDomain(tenantDomain);
            JWTClientManagerService jwtClientManagerService = getJwtClientManagerService();
            return jwtClientManagerService.getJWTClient().getJwtToken(username, claims, true);
        } catch (JWTClientException e) {
            String msg = "Erroe while creating, JWT token";
            log.error(msg);
            throw new CustomAuthenticatorException(msg);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
    }

    private static int getTenantID(String tenantDomain) throws CustomAuthenticatorException {
        int tenantId = -1234;
        try {
            PrivilegedCarbonContext.startTenantFlow();
            PrivilegedCarbonContext ctx = PrivilegedCarbonContext.getThreadLocalCarbonContext();

            RealmService realmService = (RealmService) ctx.getOSGiService(RealmService.class, null);
            if (realmService == null) {
                String msg = "RealmService is not initialized";
                log.error(msg);
                throw new CustomAuthenticatorException(msg);
            }

            if (tenantDomain == null || tenantDomain.isEmpty()) {
                tenantId = MultitenantConstants.SUPER_TENANT_ID;
                ctx.setTenantDomain(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
            } else {
                tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
                ctx.setTenantDomain(tenantDomain);
            }

            if (tenantId == MultitenantConstants.INVALID_TENANT_ID) {
                tenantId = MultitenantConstants.SUPER_TENANT_ID;
            }

        } catch (UserStoreException e) {
            String msg = "User store not initialized";
            log.error(msg);
            throw new CustomAuthenticatorException(msg, e);
        } finally {
            PrivilegedCarbonContext.endTenantFlow();
        }
        return tenantId;
    }

    public static JWTClientManagerService getJwtClientManagerService() {
        PrivilegedCarbonContext ctx = PrivilegedCarbonContext.getThreadLocalCarbonContext();
        JWTClientManagerService jwtClientManagerService = (JWTClientManagerService)
                ctx.getOSGiService(JWTClientManagerService.class, null);

        if (jwtClientManagerService == null) {
            String msg = "JWTClientManagerService Management service not initialized.";
            log.error(msg);
            throw new IllegalStateException(msg);
        }

        return jwtClientManagerService;
    }
}
