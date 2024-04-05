package org.wso2.identity.sample.oidc.controller;

import io.jsonwebtoken.Claims;
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
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.wso2.identity.sample.oidc.util.Util;

import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
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

    @Autowired
    private Environment env;
    @Value("${provider.host}")
    private String idpHost;

    @Value("${app-config.admin-permission}")
    private String adminPermission;

    private final OAuth2AuthorizedClientService authorizedClientService;

    public SettingsController(OAuth2AuthorizedClientService authorizedClientService) {

        this.authorizedClientService = authorizedClientService;
    }

    @GetMapping("/settings")
    public String homeContext(Model model, Authentication authentication) throws IOException {

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        String clientRegistrationId = oauthToken.getAuthorizedClientRegistrationId();
        OAuth2AuthorizedClient client =
                authorizedClientService.loadAuthorizedClient(clientRegistrationId, oauthToken.getName());
        String accessToken = client.getAccessToken().getTokenValue();
        user = (DefaultOidcUser) authentication.getPrincipal();
        if (user != null) {
            userName = user.getName();
        }
        model.addAttribute("userName", userName);
        Map<String,String> orgs= Util.getOrganizationsListForUser(idpHost,accessToken);
        model.addAttribute("organizations",orgs);
        model.addAttribute("currentOrg",session.getAttribute("currentOrg"));

        JSONObject orgToken = (JSONObject) session.getAttribute("orgToken");
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
        session.setAttribute("orgToken", orgToken);

        if(scope.contains(adminPermission)){
            model.addAttribute("isAdmin",true);
        }
        return "settings";
    }


    @PostMapping("/notify")
    public String notifyToEmail(Authentication authentication, Model model,@RequestParam String email) throws IOException {

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        String clientRegistrationId = oauthToken.getAuthorizedClientRegistrationId();
        OAuth2AuthorizedClient client =
                authorizedClientService.loadAuthorizedClient(clientRegistrationId, oauthToken.getName());
        String accessToken = client.getAccessToken().getTokenValue();
        user = (DefaultOidcUser) authentication.getPrincipal();
        if (user != null) {
            userName = user.getName();
        }
        model.addAttribute("userName", userName);
        Map<String,String> orgs= Util.getOrganizationsListForUser(idpHost,accessToken);
        model.addAttribute("organizations",orgs);
        model.addAttribute("currentOrg",session.getAttribute("currentOrg"));

        JSONObject orgToken = (JSONObject) session.getAttribute("orgToken");
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
        session.setAttribute("orgToken", orgToken);

        if(scope.contains(adminPermission)){
            model.addAttribute("isAdmin",true);
        }

        String token=Util.getClientCredentialsToken(idpHost,env.getProperty("app-config.notify.application-client-id"),env.getProperty("app-config.notify.application-client-secret"));

        Util.sendNotification(token,email,idTokenString,env.getProperty("app-config.notify.notify-url"));


        model.addAttribute("emailSent", true);
        return "settings";
    }



}
