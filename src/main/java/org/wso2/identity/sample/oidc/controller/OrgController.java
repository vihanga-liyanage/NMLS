package org.wso2.identity.sample.oidc.controller;

import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.wso2.identity.sample.oidc.util.Util;

import javax.net.ssl.HttpsURLConnection;
import javax.servlet.http.HttpSession;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.URL;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Level;
import java.util.logging.Logger;

@Controller
public class OrgController {

    private final Logger LOGGER = Logger.getLogger(OrgController.class.getName());
    private String userName;
    private DefaultOidcUser user;

    private final OAuth2AuthorizedClientService authorizedClientService;

    public OrgController(OAuth2AuthorizedClientService authorizedClientService) {

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
     * Handles the redirection to /userinfo endpoint and get the user information from authentication object. This
     * method will display the id-token and user information in the UI.
     *
     * @param authentication Authentication
     * @param model          Model.
     * @return userinfo html page.
     */
    @GetMapping("/orgswitch")
    public String handleOrgSwitch(Authentication authentication, Model model,@RequestParam("organization") String selectedOrg) throws IOException {

        if(selectedOrg!=null && !selectedOrg.isEmpty()) {
            OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
            String clientRegistrationId = oauthToken.getAuthorizedClientRegistrationId();
            OAuth2AuthorizedClient client =
                    authorizedClientService.loadAuthorizedClient(clientRegistrationId, oauthToken.getName());

            if (client != null && client.getAccessToken() != null) {
                String accessToken = client.getAccessToken().getTokenValue();
                // Extract ID token from access token (if applicable
                Set<String> scopesList = client.getAccessToken().getScopes();
                String scopes = String.join(" ", scopesList);
                JSONObject orgToken = Util.switchToken(idpHost,accessToken, scopes, selectedOrg, clientId, clientSecret);

                session.setAttribute("currentOrg", selectedOrg);
                session.setAttribute("orgToken", orgToken);
            }
        }else{
            session.setAttribute("currentOrg", "nmls");
        }
        return "redirect:/home";
    }



}
