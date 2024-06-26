package org.wso2.identity.sample.oidc.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.impl.DefaultJwtParser;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.net.ssl.HttpsURLConnection;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class Util {

    public static String readFromResponse(final URLConnection urlConnection) throws IOException {

        final BufferedReader BufferedReader = new BufferedReader(new InputStreamReader(urlConnection.getInputStream()));

        final StringBuilder stringBuilder = new StringBuilder();

        String line;
        while ((line = BufferedReader.readLine()) != null) {
            stringBuilder.append(line);
        }

        return stringBuilder.toString();
    }

    public static String readFromError(final HttpURLConnection urlConnection) throws IOException {

        final BufferedReader BufferedReader = new BufferedReader(new InputStreamReader(urlConnection.getErrorStream()));

        final StringBuilder stringBuilder = new StringBuilder();

        String line;
        while ((line = BufferedReader.readLine()) != null) {
            stringBuilder.append(line);
        }

        return stringBuilder.toString();
    }

    public static Map<String, String> getOrganizationsListForUser(String idpHost, String accessToken) throws IOException {
        String scimEp = idpHost + "/api/users/v1/me/organizations";
        HttpsURLConnection urlConnection = (HttpsURLConnection) new URL(scimEp).openConnection();
        urlConnection.setRequestMethod("GET");
        urlConnection.setRequestProperty("Authorization", getBearerHeader(accessToken));
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

    public static String getBearerHeader(String accessToken) {
        return "Bearer " + accessToken;
    }

    public static JSONObject switchToken(String idpHost,String token,String scopes,String selectedOrg, String clientId, String clientSecret) throws IOException {

        HttpsURLConnection urlConnection1 = (HttpsURLConnection) new URL(idpHost+"/oauth2/token").openConnection();
        urlConnection1.setRequestMethod("POST");

        String encodedCredentials = new String(Base64.getEncoder().encode(String.join(":", clientId, clientSecret)
                .getBytes()));

        urlConnection1.setRequestProperty("Authorization", "Basic " + encodedCredentials);
        urlConnection1.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

        urlConnection1.setDoOutput(true);
        DataOutputStream dataOutputStream = new DataOutputStream(urlConnection1.getOutputStream());

        String payload = "grant_type=organization_switch" +
                "&token=" + token +
                "&scope=" + scopes+
                "&switching_organization=" + selectedOrg;
        dataOutputStream.writeBytes(payload);

        String jsonresp;
        if (urlConnection1.getResponseCode() >= 400) {
            jsonresp = Util.readFromError(urlConnection1);
            return null;
        } else {
            jsonresp = Util.readFromResponse(urlConnection1);
            JSONObject json = new JSONObject(jsonresp);
            return json;
        }
    }

    public static String getClientCredentialsToken(String idpHost,String clientID,String clientSecret) throws IOException {

        HttpsURLConnection urlConnection1 = (HttpsURLConnection) new URL(idpHost+"/oauth2/token").openConnection();
        urlConnection1.setRequestMethod("POST");

        String encodedCredentials = new String(Base64.getEncoder().encode(String.join(":", clientID, clientSecret)
                .getBytes()));

        urlConnection1.setRequestProperty("Authorization", "Basic " + encodedCredentials);
        urlConnection1.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

        urlConnection1.setDoOutput(true);
        DataOutputStream dataOutputStream = new DataOutputStream(urlConnection1.getOutputStream());

        String payload = "grant_type=client_credentials";
        dataOutputStream.writeBytes(payload);

        String jsonresp;
        if (urlConnection1.getResponseCode() >= 400) {
            jsonresp = readFromError(urlConnection1);
            return null;
        } else {
            jsonresp = readFromResponse(urlConnection1);
            JSONObject json = new JSONObject(jsonresp);
            return json.getString("access_token");
        }
    }

    public static Claims decodeTokenClaims(String token) {
        String[] splitToken = token.split("\\.");
        String unsignedToken = splitToken[0] + "." + splitToken[1] + ".";
        DefaultJwtParser parser = new DefaultJwtParser();
        Jwt<?, ?> jwt = parser.parse(unsignedToken);
        Claims claims = (Claims) jwt.getBody();
        return claims;
    }

    public static void sendNotification(String token, String email, String idToken, String notifyurl) throws IOException {
        HttpsURLConnection urlConnection1 = (HttpsURLConnection) new URL(notifyurl).openConnection();
        urlConnection1.setRequestMethod("POST");

        urlConnection1.setRequestProperty("Authorization", "Bearer " + token);
        urlConnection1.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

        urlConnection1.setDoOutput(true);
        DataOutputStream dataOutputStream = new DataOutputStream(urlConnection1.getOutputStream());

        String payload = "email="+email+"&id_token="+idToken;
        dataOutputStream.writeBytes(payload);

        String resp;
        if (urlConnection1.getResponseCode() >= 400) {
            resp = readFromError(urlConnection1);
        } else {
            resp = readFromResponse(urlConnection1);
        }

    }
}
