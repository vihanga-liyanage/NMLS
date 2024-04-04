package org.wso2.identity.sample.oidc.controller;

import org.springframework.beans.factory.annotation.Autowired;
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
import java.util.Map;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

@Controller
public class SettingsController {

    private final Logger LOGGER = Logger.getLogger(SettingsController.class.getName());

    private String userName;
    private DefaultOidcUser user;
    @Autowired
    private HttpSession session;

    private final OAuth2AuthorizedClientService authorizedClientService;

    public SettingsController(OAuth2AuthorizedClientService authorizedClientService) {

        this.authorizedClientService = authorizedClientService;
    }

    @GetMapping("/settings")
    public String homeContext(Model model, Authentication authentication) throws IOException {

        user = (DefaultOidcUser) authentication.getPrincipal();
        if (user != null) {
            userName = user.getName();
        }
        model.addAttribute("userName", userName);
        getTokenDetails(model, authentication);
        Map<String,String> orgs= Util.getOrganizationsListForUser(userName,model);
        model.addAttribute("organizations",orgs);
        model.addAttribute("currentOrg",session.getAttribute("currentOrg"));
        if(userName.equals("steve@carbon.super")){//implement logic
            model.addAttribute("isAdmin",true);
        }
        return "settings";
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
