package org.wso2.identity.sample.oidc.controller;

import org.json.JSONArray;
import org.json.JSONObject;
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
import java.net.URL;
import java.net.URLConnection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

@Controller
public class HomeController {
    private final Logger LOGGER = Logger.getLogger(HomeController.class.getName());

    private String userName;
    private DefaultOidcUser user;
    @Autowired
    private HttpSession session;

    private final OAuth2AuthorizedClientService authorizedClientService;

    public HomeController(OAuth2AuthorizedClientService authorizedClientService) {

        this.authorizedClientService = authorizedClientService;
    }
    /**
     * Redirects to this method once the user successfully authenticated and this method will redirect to index page.
     *
     * @param model          Model.
     * @param authentication Authentication.
     * @return Index page.
     */
    @GetMapping("/home")
    public String homeContext(Model model, Authentication authentication) throws IOException {

        user = (DefaultOidcUser) authentication.getPrincipal();
        if (user != null) {
            userName = user.getName();
        }
        model.addAttribute("userName", userName);
        getTokenDetails(model, authentication);
        Map<String,String> orgs=getOrganizationsListForUser(userName,model);
        model.addAttribute("organizations",orgs);
        model.addAttribute("currentOrg",session.getAttribute("currentOrg"));
        return "home";
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

    private Map<String,String> getOrganizationsListForUser(String userName, Model model) throws IOException {
        String idpUrl = "https://localhost:9443";
        String scimEp = idpUrl + "/api/users/v1/me/organizations";
        HttpsURLConnection urlConnection = (HttpsURLConnection) new URL(scimEp).openConnection();
        urlConnection.setRequestMethod("GET");
        urlConnection.setRequestProperty("Authorization", getBearerHeader(model.getAttribute("accessToken").toString()));
        urlConnection.setRequestProperty("Content-Type", "application/json");
        urlConnection.setDoOutput(true);
        String res = readFromResponse(urlConnection);
        JSONObject jsonResp = new JSONObject(res);
        Map<String,String> orgsList=new HashMap<>();
        if (jsonResp.has("organizations") && jsonResp.getJSONArray("organizations").length() > 0) {
        JSONArray orgsJson = jsonResp.getJSONArray("organizations");
        //iterate through the organizations and get the organization names and add them to the list where org status is active
        for (int i = 0; i < orgsJson.length(); i++) {
            JSONObject org = orgsJson.getJSONObject(i);
            if (org.getString("status").equals("ACTIVE")) {
                orgsList.put(org.getString("id"),org.getString("name"));
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
}
