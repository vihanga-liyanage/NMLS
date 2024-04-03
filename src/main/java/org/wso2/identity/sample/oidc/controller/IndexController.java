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

import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.impl.DefaultJwtParser;
import org.json.JSONArray;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpSession;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.ProtocolException;

import org.json.JSONObject;

import java.net.URL;
import java.net.URLConnection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

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
    private HttpSession session;

    /**
     * Redirects to this method once the user successfully authenticated and this method will redirect to index page.
     *
     * @param model          Model.
     * @param authentication Authentication.
     * @return Index page.
     */
    @GetMapping("/")
    public String currentUserName(Model model, Authentication authentication) throws IOException {

        user = (DefaultOidcUser) authentication.getPrincipal();
        if (user != null) {
            userName = user.getName();
        }
        model.addAttribute("userName", userName);
        getTokenDetails(model, authentication);
        Map<String, String> orgs = getOrganizationsListForUser(userName, model);
        model.addAttribute("organizations", orgs);
        model.addAttribute("currentOrg", session.getAttribute("currentOrg"));
        return "index";
    }

    private Map<String, String> getOrganizationsListForUser(String userName, Model model) throws IOException {
        String idpUrl = "https://localhost:9443";
        String scimEp = idpUrl + "/api/users/v1/me/organizations";
        HttpsURLConnection urlConnection = (HttpsURLConnection) new URL(scimEp).openConnection();
        urlConnection.setRequestMethod("GET");
        urlConnection.setRequestProperty("Authorization", getBearerHeader(model.getAttribute("accessToken").toString()));
        urlConnection.setRequestProperty("Content-Type", "application/json");
        urlConnection.setDoOutput(true);
        String res = readFromResponse(urlConnection);
        JSONObject jsonResp = new JSONObject(res);
        Map<String, String> orgsList = new HashMap<>();
        if (jsonResp.has("organizations") && jsonResp.getJSONArray("organizations").length() > 0) {
            JSONArray orgsJson = jsonResp.getJSONArray("organizations");
            for (int i = 0; i < orgsJson.length(); i++) {
                JSONObject org = orgsJson.getJSONObject(i);
                if (org.getString("status").equals("ACTIVE")) {
                    orgsList.put(org.getString("id"), org.getString("name"));
                }
            }
        }
        return orgsList;
    }

    private String getBearerHeader(String accessToken) {
        return "Bearer " + accessToken;
    }

    private String readFromResponse(final URLConnection urlConnection) throws IOException {

        final BufferedReader BufferedReader = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));

        final StringBuilder stringBuilder = new StringBuilder();

        String line;
        while ((line = BufferedReader.readLine()) != null) {
            stringBuilder.append(line);
        }

        return stringBuilder.toString();
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

        //if httpsession has the current organization which is NMLS org or null, then add them to the model or open a new block and extract data from token json object from httpsession
        if (session.getAttribute("currentOrg") == null || session.getAttribute("currentOrg").equals("nmls")) {
            model.addAttribute("userName", userName);
            model.addAttribute("idtoken", user.getClaims());
            LOGGER.log(Level.INFO, "UserName : " + userName);
            LOGGER.log(Level.INFO, "User Attributes: " + user.getClaims());
        } else {
            //extract the token json object from httpsession and add them to the model
            JSONObject orgToken = (JSONObject) session.getAttribute("orgToken");
            String idTokenString = orgToken.getString("id_token");
            Claims claims = decodeTokenClaims(idTokenString);

            model.addAttribute("userName", claims.getSubject());
            model.addAttribute("idtoken", claims);
            LOGGER.log(Level.INFO, "UserName : " + claims.getSubject());
            LOGGER.log(Level.INFO, "User Attributes: " + claims);
        }
        return "userinfo";
    }

    public Claims decodeTokenClaims(String token) {
        String[] splitToken = token.split("\\.");
        String unsignedToken = splitToken[0] + "." + splitToken[1] + ".";
        DefaultJwtParser parser = new DefaultJwtParser();
        Jwt<?, ?> jwt = parser.parse(unsignedToken);
        Claims claims = (Claims) jwt.getBody();
        return claims;
    }

    private void getTokenDetails(Model model, Authentication authentication) {

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        String clientRegistrationId = oauthToken.getAuthorizedClientRegistrationId();
        OAuth2AuthorizedClient client =
                authorizedClientService.loadAuthorizedClient(clientRegistrationId, oauthToken.getName());

        if (client != null && client.getAccessToken() != null) {
            String accessToken = client.getAccessToken().getTokenValue();
            Set<String> scope = client.getAccessToken().getScopes();
            String tokenType = client.getAccessToken().getTokenType().getValue();
            String accessTokenExp = client.getAccessToken().getExpiresAt().toString();
            LOGGER.log(Level.INFO, "Access token : " + accessToken);
            LOGGER.log(Level.INFO, "Token type : " + tokenType);
            LOGGER.log(Level.INFO, "Scope : " + scope);
            LOGGER.log(Level.INFO, "Access token Exp : " + accessTokenExp);
            model.addAttribute("accessToken", accessToken);
            model.addAttribute("tokenType", tokenType);
            model.addAttribute("accessTokenExp", accessTokenExp);
            model.addAttribute("scope", scope);

        }

        if (client != null && client.getRefreshToken() != null) {
            String refreshToken = client.getRefreshToken().getTokenValue();
            LOGGER.log(Level.INFO, "Refresh token: " + refreshToken);
            model.addAttribute("refreshToken", refreshToken);

        }
    }
}
