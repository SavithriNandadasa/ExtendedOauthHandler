# ExtendedOauthHandler

- Place the handler (ExtendedOauthHandler-1.0-SNAPSHOT.jar) inside <APIM>/repository/components/lib. Once you do this restart the server.
Go to your API configuration file inside <APIM>/repository/deployments/server/synapse-configs/default/api/ and do the following changes manually:
1. Remove the default APIAuthenticationHandler from the list of handlers
```
<handler class="org.wso2.carbon.apimgt.gateway.handlers.security.APIAuthenticationHandler"/>
```
2. Add the sample ExtendedOauthHandler in place of the default handler as below
```
<handler class="org.wso2.OauthExtHandler.ExtendedOauthHandler">
	<property name="deploymentPattern" value="ALL_IN_ONE"/>
	<property name="clientKey" value="s1ydlgyj0FoqVktMNIMJtOVgA2Qa"/>
        <property name="clientSecret" value="igibwC7yuV09AYyAYnhLzfJg2Zwa"/>
    </handler>
```

- Curl Command for Basic Authentication
```
curl -k -X GET "https://172.17.0.1:8243/ExtAPI/1.0.0/checkExtAPI" -H  "accept: application/json" -H  "Authorization: Basic YWRtaW46YWRtaW4="
```

Curl Command for Bearer Token

```
curl -k -X GET "https://172.17.0.1:8243/ExtAPI/1.0.0/checkExtAPI" -H  "accept: application/json" -H  "Authorization: Bearer 0f3c428c-b504-3ed4-9ef0-48b81f7260c7"
```
