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

import org.apache.http.client.methods.HttpGet;

public class CustomUsernamePasswordForm extends UsernamePasswordForm {

    private static final String CAS_BASE_URLS = "https://localhost:8443/cas";
    private static final String CAS_LOGIN_URL = CAS_BASE_URLS + "/v1/tickets";
    private static final String CAS_TGT_COOKIE_NAME = "CASTGT";
    private static final int COOKIE_MAX_AGE = 28800; // 8 horas en segundos
    
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
            String tgt = getTGT(username, password);
            if (tgt != null) {
                // Verificar que podemos obtener un Service Ticket
                String serviceUrl = "http://localhost:8000"; // URL de tu servicio
                String st = getServiceTicket(tgt, serviceUrl);
                
                if (st != null) {
                    boolean isValid = validateServiceTicket(serviceUrl, st);
                    if (!isValid) {
                        System.err.println("El Service Ticket no es válido");
                        context.failureChallenge(AuthenticationFlowError.INVALID_CREDENTIALS,
                            context.form().setError(Messages.INVALID_USER).createLoginUsernamePassword());
                        return;
                    }
                    // Autenticación CAS exitosa, crear el usuario en Keycloak
                    UserModel newUser = findOrCreateUser(context, username);
    
                    
                    context.setUser(newUser);
                
                    context.success();
                    return;
                }
            }
        }
    }
    private UserModel findOrCreateUser(AuthenticationFlowContext context, String username) {
        UserModel user = context.getSession().users().getUserByUsername(context.getRealm(), username);
        
        if (user == null) {
            // Crear usuario si no existe
            user = context.getSession().users().addUser(context.getRealm(), username);
            user.setEnabled(true);
        }
        
        return user;
    }

    private boolean validatePasswordManually(UserModel user, String password) {
        // Validar la contraseña manualmente
        UserCredentialModel credential = UserCredentialModel.password(password);
        return user.credentialManager().isValid(credential);
        //return true;
    }

    private boolean authenticateWithCAS(String username, String password) {
        try {
            // Obtener el Ticket Granting Ticket (TGT)
            String tgt = getTGT(username, password);
            
            if (tgt == null) {
                System.err.println("No se pudo obtener el TGT para el usuario: " + username);
                return false;
            }

            // Obtener el Service Ticket (ST) para el servicio al que se está autenticando
            String serviceUrl = "http://localhost:8000"; // Reemplaza con la URL de tu servicio
            String st = getServiceTicket(tgt, serviceUrl);
            if (st == null) {
                System.err.println("No se pudo obtener el Service Ticket para el usuario: " + username);
                return false;
            }

            // Aquí puedes validar el Service Ticket (ST) con CAS para completar la autenticación
            // Esto se puede hacer verificando que el ST sea válido o consultando la API de CAS para validarlo.
            // Si es válido, la autenticación con CAS es exitosa.

            // Para este ejemplo, asumimos que la autenticación es exitosa
            System.out.println("Autenticación CAS exitosa para el usuario: " + username);
            return true;
        } catch (Exception e) {
            // Manejar errores de comunicación
            e.printStackTrace();
            return false;
        }
    }

    private String getTGT(String username, String password) {
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
                .build();

            // Crear la solicitud POST
            HttpPost httpPost = new HttpPost(CAS_LOGIN_URL);
            httpPost.setHeader("Content-Type", "application/x-www-form-urlencoded");

            // Crear el cuerpo de la solicitud con las credenciales
            String body = "username=" + username + "&password=" + password + "&rememberMe=true";
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

    private String getServiceTicket(String tgt, String serviceUrl) {
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
    private boolean validateServiceTicket(String serviceUrl, String serviceTicket) {
        try {
            String validateUrl = CAS_BASE_URLS + "/p3/serviceValidate"
                + "?service=" + java.net.URLEncoder.encode(serviceUrl, "UTF-8")
                + "&ticket=" + java.net.URLEncoder.encode(serviceTicket, "UTF-8");

            // Saltamos verificación de SSL (igual que antes)
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() { return null; }
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                }
            };

            SSLContext sslContext = SSLContext.getInstance("SSL");
            sslContext.init(null, trustAllCerts, new java.security.SecureRandom());

            SSLConnectionSocketFactory sslSocketFactory = new SSLConnectionSocketFactory(
                sslContext, NoopHostnameVerifier.INSTANCE);

            CloseableHttpClient httpClient = HttpClients.custom()
                .setSSLSocketFactory(sslSocketFactory)
                .build();

            HttpGet httpGet = new HttpGet(validateUrl);
            HttpResponse response = httpClient.execute(httpGet);

            if (response.getStatusLine().getStatusCode() == 200) {
                String xmlResponse = EntityUtils.toString(response.getEntity());

                // Validación básica: buscar el username en la respuesta
                return xmlResponse.contains("<cas:user>");
            } else {
                System.err.println("Error validando el Service Ticket: " + response.getStatusLine().getStatusCode());
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }
}