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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.impl.DefaultJwtParser;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.wso2.identity.sample.oidc.util.Util;

import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Handles the redirection after successful authentication from Identity Server
 */
@Controller
public class IndexController {

    private final Logger LOGGER = Logger.getLogger(IndexController.class.getName());
    private String userName;
    private DefaultOidcUser user;

    private final OAuth2AuthorizedClientService authorizedClientService;

    public IndexController(OAuth2AuthorizedClientService authorizedClientService) {

        this.authorizedClientService = authorizedClientService;
    }

    @Autowired
    private Environment env;

    @Autowired
    private HttpSession session;
    @Value("${client.client-id}")
    private String clientId;

    @Value("${client.client-secret}")
    private String clientSecret;

    @Value("${provider.host}")
    private String idpHost;

    /**
     * Redirects to this method once the user successfully authenticated and this method will redirect to index page.
     *
     * @param model          Model.
     * @param authentication Authentication.
     * @return Index page.
     */
    @GetMapping("/")
    public String checkCurrentUser(Model model, Authentication authentication) throws IOException {

        user = (DefaultOidcUser) authentication.getPrincipal();
        if (user != null) {
            userName = user.getName();
        }
        model.addAttribute("userName", userName);
        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        String clientRegistrationId = oauthToken.getAuthorizedClientRegistrationId();
        OAuth2AuthorizedClient client =
                authorizedClientService.loadAuthorizedClient(clientRegistrationId, oauthToken.getName());
        String accessToken = client.getAccessToken().getTokenValue();
        Map<String, String> orgs = Util.getOrganizationsListForUser(idpHost, accessToken);
        if (orgs == null || orgs.size() == 0) {
            model.addAttribute("message", "No organizations found for the user");
            return "error";
        } else {
            String organization = null;
            if (orgs.size() > 1) {
                if (session.getAttribute("currentOrg") != null && orgs.containsKey(session.getAttribute("currentOrg"))) {
                    organization = session.getAttribute("currentOrg").toString();
                }else {
                    organization = orgs.keySet().toArray()[0].toString();
                }
            } else {
                organization = orgs.keySet().toArray()[0].toString();
            }
            model.addAttribute("organizations", orgs);
            model.addAttribute("currentOrg", organization);

            if (client != null && client.getAccessToken() != null) {

                Set<String> scopesList = client.getAccessToken().getScopes();
                String scopes = env.getProperty("client.scope").replace(",", " ");
                JSONObject orgToken = Util.switchToken(idpHost,accessToken, scopes, organization, clientId, clientSecret);
                String idTokenString = orgToken.getString("id_token");
                Claims claims = Util.decodeTokenClaims(idTokenString);
                String orgaccessToken = orgToken.getString("access_token");
                Set<String> scope =  new HashSet<>(Arrays.asList(orgToken.getString("scope").split(" ")));
                String tokenType = orgToken.getString("token_type");
                String refreshToken = orgToken.getString("refresh_token");
                String accessTokenExp = claims.getExpiration().toString();
                model.addAttribute("accessToken", orgaccessToken);
                model.addAttribute("tokenType", tokenType);
                model.addAttribute("accessTokenExp", accessTokenExp);
                model.addAttribute("scope", scope);
                model.addAttribute("idtoken", claims);
                model.addAttribute("refreshToken", refreshToken);
                session.setAttribute("currentOrg", organization);
                session.setAttribute("orgToken", orgToken);
            }
            if (orgs.size() == 1) {
                return "redirect:/home";
            } else if (orgs.size() > 1) {
                return "index";
            }
        }
        return "error";
    }


    /**
     * Handles the redirection to /userinfo endpoint and get the user information from authentication object. This
     * method will display the id-token and user information in the UI.
     *
     * @param authentication Authentication
     * @param model          Model.
     * @return userinfo html page.
     */
    @GetMapping("/userinfo")
    public String getUser(Authentication authentication, Model model) {

        JSONObject orgToken = (JSONObject) session.getAttribute("orgToken");
        String idTokenString = orgToken.getString("id_token");
        Claims claims = Util.decodeTokenClaims(idTokenString);

        model.addAttribute("userName", claims.getSubject());
        model.addAttribute("idtoken", claims);
        LOGGER.log(Level.INFO, "UserName : " + claims.getSubject());
        LOGGER.log(Level.INFO, "User Attributes: " + claims);
        return "userinfo";
    }

}
