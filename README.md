# BouncingBall
This is just a basic JS fun game developed, because of my boredom.


import org.keycloak.models.KeycloakSession;
import org.keycloak.provider.Provider;
import org.keycloak.provider.ProviderFactory;
import org.keycloak.models.ClientModel;
import org.keycloak.models.RealmModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.services.managers.AuthenticationManager;
import org.keycloak.services.resources.admin.AdminAuth;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.managers.ClientSessionCode;
import org.keycloak.protocol.oidc.TokenManager;

public class ClientCredentialsTokenProvider implements Provider {
    private final KeycloakSession session;

    public ClientCredentialsTokenProvider(KeycloakSession session) {
        this.session = session;
    }

    public AccessTokenResponse generateToken(String clientId, String clientSecret, String realmName) {
        RealmModel realm = session.realms().getRealmByName(realmName);
        if (realm == null) {
            throw new IllegalArgumentException("Realm not found");
        }

        ClientModel client = session.clients().getClientByClientId(realm, clientId);
        if (client == null || !client.isEnabled()) {
            throw new IllegalArgumentException("Client not found or not enabled");
        }

        if (!client.getSecret().equals(clientSecret)) {
            throw new IllegalArgumentException("Invalid client secret");
        }

        TokenManager tokenManager = new TokenManager();

        // Create client session and token context
        ClientSessionCode clientSessionCode = new ClientSessionCode(session, realm, client);
        clientSessionCode.setAction(AuthenticationManager.ACTION_TOKEN);

        // Generate access token response
        AccessTokenResponse tokenResponse = tokenManager.responseBuilder(realm, client, client, session, null, null, clientSessionCode.getRequestedUri())
                .generateAccessToken().build();

        return tokenResponse;
    }

    @Override
    public void close() {
        // Cleanup if necessary
    }
}

public class ClientCredentialsTokenProviderFactory implements ProviderFactory<ClientCredentialsTokenProvider> {
    @Override
    public ClientCredentialsTokenProvider create(KeycloakSession session) {
        return new ClientCredentialsTokenProvider(session);
    }

    @Override
    public String getId() {
        return "client-credentials-token-provider";
    }
}
