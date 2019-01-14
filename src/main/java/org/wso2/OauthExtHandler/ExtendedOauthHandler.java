package org.wso2.OauthExtHandler;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.log4j.Logger;
import org.apache.synapse.Mediator;
import org.apache.synapse.MessageContext;
import org.apache.synapse.SynapseConstants;
import org.apache.synapse.core.axis2.Axis2MessageContext;
import org.apache.synapse.transport.passthru.PassThroughConstants;
import org.apache.synapse.transport.passthru.util.RelayUtils;
import org.apache.ws.security.util.Base64;
import org.wso2.carbon.apimgt.gateway.APIMgtGatewayConstants;
import org.wso2.carbon.apimgt.gateway.handlers.Utils;
import org.wso2.carbon.apimgt.gateway.handlers.security.*;
import org.wso2.carbon.apimgt.impl.APIConstants;
import org.wso2.carbon.apimgt.impl.APIManagerConfiguration;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.bean.OAuthClientAuthnContext;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenReqDTO;
import org.wso2.carbon.identity.oauth2.dto.OAuth2AccessTokenRespDTO;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;

import java.io.IOException;
import java.net.URLEncoder;
import java.util.Map;
import java.util.TreeMap;

//import org.wso2.carbon.identity.oauth.client.authn.filter.OAuthClientAuthenticatorProxy;


//@InInterceptors(classes = OAuthClientAuthenticatorProxy.class)
public class ExtendedOauthHandler extends APIAuthenticationHandler {

    private static final String UTF_8 = "UTF-8";
    private static final String SINGLE_NODE = "ALL_IN_ONE";
    private static final String AUTHORIZATION_HEADER = "Authorization";
    private static final String CONTENT_TYPE_HEADER = "Content-Type";
    private static final String APPLICATION_X_WWW_FORM_URLENCODED = "application/x-www-form-urlencoded";
    static Logger log = Logger.getLogger(ExtendedOauthHandler.class.getName());
    private String deploymentPattern;
    private String clientKey;
    private String clientSecret;


    public boolean handleRequest(MessageContext messageContext) {


        org.apache.axis2.context.MessageContext axis2MessageContext =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        Object headers = axis2MessageContext
                .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);


        String username = null;
        String password = null;
        try {
            if (headers != null && headers instanceof Map) {
                Map headersMap = (Map) headers;
                String authHeader = (String) headersMap.get("Authorization");
                if (authHeader == null) {
                    headersMap.clear();
                    throw new APISecurityException(APISecurityConstants.API_AUTH_MISSING_CREDENTIALS,
                            "Required OAuth credentials not provided");
                } else {
                    if (authHeader.contains("Basic")) {
                        String credentials[] =
                                new String(Base64.decode(authHeader.substring(6).trim()))
                                        .split(":");
                        username = credentials[0];
                        password = credentials[1];
                        return authenticateUser(messageContext, username,
                                password);
                    } else if (authHeader.contains("Bearer")) {
                        return super.handleRequest(messageContext);
                    } else {
                        throw new APISecurityException(APISecurityConstants.API_AUTH_MISSING_CREDENTIALS,
                                "Required OAuth credentials not provided");

                    }
                }
            }
            //return authenticateUser(axis2MessageContext, messageContext, username,    password);
            return false;

        } catch (APISecurityException e) {
            handleAuthFailure(messageContext, e);
            log.error("Unable to execute the authorization process : ", e);
            return false;
        } catch (Exception e) {


            return false;
        }
    }

    private boolean authenticateUser(MessageContext messageContext, String username,
                                     String password) throws InvalidOAuthClientException, IdentityOAuth2Exception, IdentityOAuthAdminException {

        //if its a single node deployment authenticate using OAuth2Service
        if (SINGLE_NODE.equals(deploymentPattern)) {
            if (log.isDebugEnabled()) {
                log.debug("Deployment Pattern Set to :" + SINGLE_NODE);
            }
            OAuth2Service oAuth2Service = (OAuth2Service) PrivilegedCarbonContext.getThreadLocalCarbonContext()
                    .getOSGiService(OAuth2Service.class, null);
            OAuth2AccessTokenReqDTO oAuth2AccessTokenReqDTO = new OAuth2AccessTokenReqDTO();
            oAuth2AccessTokenReqDTO.setGrantType("password");
            oAuth2AccessTokenReqDTO.setClientId(clientKey);
            oAuth2AccessTokenReqDTO.setClientSecret(clientSecret);

            oAuth2AccessTokenReqDTO.setResourceOwnerUsername(username);
            oAuth2AccessTokenReqDTO.setResourceOwnerPassword(password);
            OAuthClientAuthnContext oAuthClientAuthnContext = new OAuthClientAuthnContext();
            oAuthClientAuthnContext.setAuthenticated(OAuth2Util.authenticateClient(clientKey, clientSecret));
            oAuthClientAuthnContext.setClientId(clientKey);
            oAuth2AccessTokenReqDTO.setoAuthClientAuthnContext(oAuthClientAuthnContext);


            OAuth2AccessTokenRespDTO oAuth2AccessTokenRespDTO = oAuth2Service.issueAccessToken(oAuth2AccessTokenReqDTO);

            if (oAuth2AccessTokenRespDTO.getAccessToken() != null) {
                if (log.isDebugEnabled()) {
                    log.debug("Authentication Successful");

                }
                setAuthenticateInfo(messageContext, username);
                setAPIParametersToMessageContext(messageContext);
                return true;
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Authentication Failed with Error Message :" + oAuth2AccessTokenRespDTO.getErrorMsg());
                    log.debug("Authentication Failed with Error Code :" + oAuth2AccessTokenRespDTO.getErrorCode());

                }
                sendUnauthorizedResponse(messageContext, HttpStatus.SC_UNAUTHORIZED);
                return false;
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Deployment Pattern Set to DISTRIBUTED");
            }
            // if its a distributed deployment use the token endpoint to authenticate the user
            String revokeUrl = getAPIManagerConfiguration().getFirstProperty(APIConstants.REVOKE_API_URL);
            String tokenUrl = revokeUrl != null ? revokeUrl.replace("revoke", "token") : null;
            tokenUrl = tokenUrl != null ? tokenUrl.replace("'", "") : null;

            CloseableHttpClient httpClient = HttpClients.createDefault();
            try {
                HttpPost postRequest = new HttpPost(tokenUrl);
                String credentials = Base64.encode((clientKey + ":" + clientSecret).getBytes());
                postRequest.setHeader(CONTENT_TYPE_HEADER, APPLICATION_X_WWW_FORM_URLENCODED);
                postRequest.setHeader(AUTHORIZATION_HEADER, "Basic " + credentials);
                String query = String.format("grant_type=password&username=%s&password=%s",
                        URLEncoder.encode(username, UTF_8), URLEncoder.encode(password, UTF_8));
                StringEntity input = new StringEntity(query);
                postRequest.setEntity(input);
                HttpResponse response = httpClient.execute(postRequest);
                if (response.getStatusLine().getStatusCode() == 200) {
                    setAuthenticateInfo(messageContext, username);
                    setAPIParametersToMessageContext(messageContext);
                    if (log.isDebugEnabled()) {
                        log.debug("Authentication Successful");
                    }
                    return true;
                } else {

                    if (log.isDebugEnabled()) {
                        if (response.getStatusLine().getStatusCode() == HttpStatus.SC_BAD_REQUEST) {
                            log.debug("Authentication Failed with Error code " + response.getStatusLine().getStatusCode()
                                    + " (Invalid UserName / Password)");
                        } else if (response.getStatusLine().getStatusCode() == HttpStatus.SC_UNAUTHORIZED) {
                            log.debug(("Authentication Failed with Error code " + response.getStatusLine().getStatusCode()
                                    + " (Invalid Application id/secret)"));
                        } else {
                            log.debug(("Authentication Failed with Error code " + response.getStatusLine().getStatusCode()));
                        }
                    }

                    sendUnauthorizedResponse(messageContext, HttpStatus.SC_UNAUTHORIZED);
                    return false;
                }
            } catch (IOException ex) {
                sendUnauthorizedResponse(messageContext, HttpStatus.SC_INTERNAL_SERVER_ERROR);
            } finally {
                try {
                    httpClient.close();
                } catch (IOException e) {
                    log.warn("Error occurred when closing the HTTPClient", e);
                }
            }
        }
        return false;
    }

    private void setAuthenticateInfo(MessageContext messageContext, String userName) {
        String clientIP = null;

        org.apache.axis2.context.MessageContext axis2MessageContext =
                ((Axis2MessageContext) messageContext).getAxis2MessageContext();
        TreeMap<String, String> transportHeaderMap = (TreeMap<String, String>) axis2MessageContext
                .getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);

        if (transportHeaderMap != null) {
            clientIP = transportHeaderMap.get(APIMgtGatewayConstants.X_FORWARDED_FOR);
        }

        //Setting IP of the client
        if (clientIP != null && !clientIP.isEmpty()) {
            if (clientIP.indexOf(",") > 0) {
                clientIP = clientIP.substring(0, clientIP.indexOf(","));
            }
        } else {
            clientIP = (String) axis2MessageContext
                    .getProperty(org.apache.axis2.context.MessageContext.REMOTE_ADDR);
        }

        AuthenticationContext authContext = new AuthenticationContext();
        authContext.setAuthenticated(true);
        authContext.setTier(APIConstants.UNAUTHENTICATED_TIER);
        authContext.setStopOnQuotaReach(true);
        authContext.setApiKey(clientIP);
        authContext.setKeyType(APIConstants.API_KEY_TYPE_PRODUCTION);
        authContext.setUsername(userName);
        authContext.setCallerToken(null);
        authContext.setApplicationName(null);
        authContext.setApplicationId(clientIP);
        authContext.setConsumerKey(null);
        APISecurityUtils.setAuthenticationContext(messageContext, authContext, null);
    }

    private void sendUnauthorizedResponse(MessageContext messageContext, int status) {

        messageContext.setProperty(SynapseConstants.ERROR_CODE, status);
        messageContext.setProperty(SynapseConstants.ERROR_MESSAGE,
                "API_Error_msg");
        Mediator sequence = messageContext.getSequence(APISecurityConstants.API_AUTH_FAILURE_HANDLER);
        // Invoke the custom error handler specified by the user
        if (sequence != null && !sequence.mediate(messageContext)) {
            // If needed user should be able to prevent the rest of the fault handling
            // logic from getting executed
            return;
        }
        // By default we send a 401 response back
        org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) messageContext).
                getAxis2MessageContext();
        // This property need to be set to avoid sending the content in pass-through pipe (request message)
        // as the response.
        axis2MC.setProperty(PassThroughConstants.MESSAGE_BUILDER_INVOKED, Boolean.TRUE);
        try {
            RelayUtils.consumeAndDiscardMessage(axis2MC);
        } catch (AxisFault axisFault) {
            //In case of an error it is logged and the process is continued because we're setting a fault message in the payload.
            log.error("Error occurred while consuming and discarding the message", axisFault);
        }
        axis2MC.setProperty(Constants.Configuration.MESSAGE_TYPE, "application/soap+xml");

        Map<String, String> headers =
                (Map) axis2MC.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
        if (headers != null) {
            axis2MC.setProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS, headers);
        }

        if (messageContext.isDoingPOX() || messageContext.isDoingGET()) {
            OMFactory fac = OMAbstractFactory.getOMFactory();
            OMNamespace ns = fac.createOMNamespace(APISecurityConstants.API_SECURITY_NS,
                    APISecurityConstants.API_SECURITY_NS_PREFIX);
            OMElement payload = fac.createOMElement("fault", ns);

            OMElement errorCode = fac.createOMElement("code", ns);
            errorCode.setText(String.valueOf(status));
            OMElement errorMessage = fac.createOMElement("message", ns);
            errorMessage.setText(APISecurityConstants
                    .getAuthenticationFailureMessage(APISecurityConstants.API_AUTH_INVALID_CREDENTIALS));
            OMElement errorDetail = fac.createOMElement("description", ns);
            errorDetail.setText(APISecurityConstants
                    .getFailureMessageDetailDescription(APISecurityConstants.API_AUTH_INVALID_CREDENTIALS,
                            "Invalid Credentials"));

            payload.addChild(errorCode);
            payload.addChild(errorMessage);
            payload.addChild(errorDetail);

            Utils.setFaultPayload(messageContext, payload);
        } else {
            Utils.setSOAPFault(messageContext, "Client", "Authentication Failure", "Invalid Username or Password");
        }
        Utils.sendFault(messageContext, status);
    }


    private void handleAuthFailure(MessageContext messageContext, APISecurityException e) {
        messageContext.setProperty(SynapseConstants.ERROR_CODE, e.getErrorCode());
        messageContext.setProperty(SynapseConstants.ERROR_MESSAGE,
                APISecurityConstants.getAuthenticationFailureMessage(e.getErrorCode()));
        messageContext.setProperty(SynapseConstants.ERROR_EXCEPTION, e);

        Mediator sequence = messageContext.getSequence(APISecurityConstants.API_AUTH_FAILURE_HANDLER);
        // Invoke the custom error handler specified by the user
        if (sequence != null && !sequence.mediate(messageContext)) {
            // If needed user should be able to prevent the rest of the fault handling
            // logic from getting executed
            return;
        }
        // By default we send a 401 response back
        org.apache.axis2.context.MessageContext axis2MC = ((Axis2MessageContext) messageContext).
                getAxis2MessageContext();
        // This property need to be set to avoid sending the content in pass-through pipe (request message)
        // as the response.
        axis2MC.setProperty(PassThroughConstants.MESSAGE_BUILDER_INVOKED, Boolean.TRUE);
        try {
            RelayUtils.consumeAndDiscardMessage(axis2MC);
        } catch (AxisFault axisFault) {
            //In case of an error it is logged and the process is continued because we're setting a fault message in the payload.
            log.error("Error occurred while consuming and discarding the message", axisFault);
        }
        axis2MC.setProperty(Constants.Configuration.MESSAGE_TYPE, "application/soap+xml");
        int status;
        if (e.getErrorCode() == APISecurityConstants.API_AUTH_GENERAL_ERROR) {
            status = HttpStatus.SC_INTERNAL_SERVER_ERROR;
        } else if (e.getErrorCode() == APISecurityConstants.API_AUTH_INCORRECT_API_RESOURCE ||
                e.getErrorCode() == APISecurityConstants.API_AUTH_FORBIDDEN ||
                e.getErrorCode() == APISecurityConstants.INVALID_SCOPE) {
            status = HttpStatus.SC_FORBIDDEN;
        } else {
            status = HttpStatus.SC_UNAUTHORIZED;
            Map<String, String> headers =
                    (Map) axis2MC.getProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS);
            if (headers != null) {
                headers.put(HttpHeaders.WWW_AUTHENTICATE, getAuthenticator().getChallengeString() +
                        ", error=\"invalid token\"" +
                        ", error_description=\"The access token expired\"");
                axis2MC.setProperty(org.apache.axis2.context.MessageContext.TRANSPORT_HEADERS, headers);
            }
        }

        if (messageContext.isDoingPOX() || messageContext.isDoingGET()) {
            setFaultPayload(messageContext, e);
        } else {
            setSOAPFault(messageContext, e);
        }
        sendFault(messageContext, status);
    }


    private APIManagerConfiguration getAPIManagerConfiguration() {
        return BasicAuthServiceComponent.getAmConfigService().getAPIManagerConfiguration();
    }

    public String getDeploymentPattern() {
        return deploymentPattern;
    }

    public void setDeploymentPattern(String deploymentPattern) {
        this.deploymentPattern = deploymentPattern;
    }

    public String getClientKey() {
        return clientKey;
    }

    public void setClientKey(String clientKey) {
        this.clientKey = clientKey;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }
}







