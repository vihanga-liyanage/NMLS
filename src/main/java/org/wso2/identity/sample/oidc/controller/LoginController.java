/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 *
 */

package org.wso2.identity.sample.oidc.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.ResolvableType;
import org.springframework.core.env.Environment;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.util.HashMap;
import java.util.Map;


/**
 * Use this controller if tou want to customize your login page. Else the application will uses the default logoin
 * page provided by spring-boot-security.
 */
@Controller
public class LoginController {


    private static String authorizationRequestBaseUri = "oauth2/authorization";

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Autowired
    private Environment env;


    /**
     * To customize the default login page to a different login page with "/oauth-login" redirection.
     *
     * @param model Model
     * @return login page
     */
    @GetMapping("/login")
    public String getLoginPage(Model model) {

        Map<String, String> oauth2AuthenticationUrls = new HashMap<>();

        Iterable<ClientRegistration> clientRegistrations = null;
        ResolvableType type = ResolvableType.forInstance(clientRegistrationRepository).as(Iterable.class);
        if (type != ResolvableType.NONE &&
                ClientRegistration.class.isAssignableFrom(type.resolveGenerics()[0])) {
            clientRegistrations = (Iterable<ClientRegistration>) clientRegistrationRepository;
        }

        clientRegistrations.forEach(registration -> oauth2AuthenticationUrls.put(registration.getClientName(),
                authorizationRequestBaseUri + "/" + registration.getRegistrationId()));
        model.addAttribute("urls", oauth2AuthenticationUrls);

        String clientId=env.getProperty("app-config.reset-password.application-client-id");
        String clientSecret=env.getProperty("app-config.reset-password.application-client-secret");
        String redirectUrl=env.getProperty("app-config.reset-password.reset-password-app-redirect-url");
        String idpHost=env.getProperty("provider.host");
        String passwordResetUrl = idpHost+"/oauth2/authorize?response_type=code&client_id="+clientId+"&scope=openid%20internal_login&redirect_uri="+redirectUrl;
        model.addAttribute("passwordResetURL", passwordResetUrl);
        return "login";
    }

}