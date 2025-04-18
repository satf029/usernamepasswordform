package com.miempresa;

import java.security.cert.X509Certificate;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpResponse;
import org.apache.http.client.CookieStore;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.events.Errors;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.services.messages.Messages;

import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;

public class CustomUsernamePasswordForm extends UsernamePasswordForm {

    private static final String CAS_BASE_URLS = "https://cas.example.org:8443/cas";
    private static final String CAS_LOGIN_URL = CAS_BASE_URLS + "/v1/tickets";
    
    @Override
    public void authenticate(AuthenticationFlowContext context) {
        // Mostrar el formulario de inicio de sesión predeterminado
        Response challenge = context.form().createLoginUsernamePassword();
        context.challenge(challenge);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        // Obtener las credenciales del formulario
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String username = formData.getFirst("username");
        String password = formData.getFirst("password");

        if (username == null || password == null) {
            // Si no hay datos del formulario, mostrar un error
            context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                    context.form().setError(Messages.INVALID_USER).createLoginUsernamePassword());
            return;
        }

        // Verificar si el usuario existe en Keycloak
        UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username);

        if (user != null) {
            // Si el usuario existe, validar la contraseña manualmente
            boolean valid = validatePasswordManually(user, password);
            if (!valid) {
                // Si la contraseña es incorrecta, mostrar un error
                context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
                Response challenge = context.form()
                        .setError(Messages.INVALID_USER)
                        .createLoginUsernamePassword();
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
                return;
            }
            context.setUser(user);
            context.success(); // Autenticación exitosa
        } else {
            // Si el usuario no existe, autenticar con CAS
            boolean casAuthSuccess = authenticateWithCAS(username, password);

            if (casAuthSuccess) {
                // Autenticación exitosa con CAS, pero sin crear un usuario en Keycloak
                context.success(); // Permitir el acceso sin crear un usuario
            } else {
                // Si la autenticación con CAS falla, mostrar un error
                context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
                Response challenge = context.form()
                        .setError("Usuario o contraseña incorrectos")
                        .createLoginUsernamePassword();
                context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS, challenge);
            }
        }
    }

    private boolean validatePasswordManually(UserModel user, String password) {
        // Validar la contraseña manualmente
        UserCredentialModel credential = UserCredentialModel.password(password);
        return user.credentialManager().isValid(credential);
        //return true;
    }

    private boolean authenticateWithCAS(String username, String password) {
        // Lógica para autenticar con CAS
        // Aquí debes implementar la llamada a la API de CAS
        // Retorna true si la autenticación es exitosa, false en caso contrario
        return false; // Por defecto, retorna false para evitar crear usuarios
    }
    private String getTGT(String username, String password, CookieStore cookieStore) {
        try {
            // Crear un TrustManager que no valide las cadenas de certificados
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
            };

            // Crear un SSLContext con el TrustManager personalizado
            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

            // Configurar el HttpClient para usar el SSLContext personalizado
            SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
                sslContext, NoopHostnameVerifier.INSTANCE);

            CloseableHttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(sslSocketFactory)
                .setDefaultCookieStore(cookieStore) // Usar el almacén de cookies
                .build();

            // Crear la solicitud POST
            HttpPost httpPost = new HttpPost(CAS_LOGIN_URL);
            httpPost.setHeader("Content-Type", "application/x-www-form-urlencoded");

            // Crear el cuerpo de la solicitud con las credenciales
            String body = "username=" + username + "&password=" + password;
            httpPost.setEntity(new StringEntity(body));

            // Enviar la solicitud a CAS
            HttpResponse response = httpClient.execute(httpPost);

            // Verificar si la autenticación fue exitosa
            if (response.getStatusLine().getStatusCode() == 201) {
                // Extraer el TGT de la cabecera "Location"
                String location = response.getFirstHeader("Location").getValue();
                return location.substring(location.lastIndexOf('/') + 1);
            } else {
                // Log del error
                System.err.println("Error en la autenticación CAS: " + response.getStatusLine().getStatusCode());
            }
        } catch (Exception e) {
            // Manejar errores de comunicación
            e.printStackTrace();
        }

        return null;
    }

    private String getServiceTicket(String tgt, String serviceUrl, CookieStore cookieStore) {
        try {
            // Crear un TrustManager que no valide las cadenas de certificados
            TrustManager[] trustAllCerts = new TrustManager[] {
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return null;
                    }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
            };

            // Crear un SSLContext con el TrustManager personalizado
            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

            // Configurar el HttpClient para usar el SSLContext personalizado
            SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
                sslContext, NoopHostnameVerifier.INSTANCE);

            CloseableHttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(sslSocketFactory)
                .setDefaultCookieStore(cookieStore) // Usar el almacén de cookies
                .build();

            // Crear la solicitud POST
            HttpPost httpPost = new HttpPost(CAS_BASE_URLS + "/v1/tickets/" + tgt);
            httpPost.setHeader("Content-Type", "application/x-www-form-urlencoded");

            // Crear el cuerpo de la solicitud con la URL del servicio
            String body = "service=" + serviceUrl;
            httpPost.setEntity(new StringEntity(body));

            // Enviar la solicitud a CAS
            HttpResponse response = httpClient.execute(httpPost);

            // Verificar si la solicitud fue exitosa
            if (response.getStatusLine().getStatusCode() == 200) {
                // Leer el ST de la respuesta
                return EntityUtils.toString(response.getEntity());
            } else {
                // Log del error
                System.err.println("Error al obtener el Service Ticket: " + response.getStatusLine().getStatusCode());
            }
        } catch (Exception e) {
            // Manejar errores de comunicación
            e.printStackTrace();
        }

        return null;
    }
}