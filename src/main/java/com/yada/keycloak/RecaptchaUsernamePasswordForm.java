package com.yada.keycloak;

import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpGet;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Details;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.util.Map;

public class RecaptchaUsernamePasswordForm extends UsernamePasswordForm implements Authenticator {

    public static final String G_RECAPTCHA_RESPONSE = "g-recaptcha-response";
    public static final String SITE_KEY = "site.key";
    public static final String SITE_SECRET = "secret";
    public static final String API_URI = "apiUrl";
    public static final String VERIFY_URL = "verifyUrl";
    public static final String PROXY_HOST = "proxyHost";
    public static final String PROXY_PORT = "proxyPort";

    private final Logger logger = Logger.getLogger(this.getClass());
    private String siteKey;

    @Override
    protected Response createLoginForm(LoginFormsProvider form) {
        form.setAttribute("recaptchaRequired", true);
        form.setAttribute("recaptchaSiteKey", siteKey);
        return super.createLoginForm(form);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        context.getEvent().detail(Details.AUTH_METHOD, "auth_method");
        if (logger.isInfoEnabled()) {
            logger.info(
                    "validateRecaptcha(AuthenticationFlowContext, boolean, String, String) - Before the validation");
        }

        AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
        LoginFormsProvider form = context.form();
        String userLanguageTag = context.getSession().getContext().resolveLocale(context.getUser()).toLanguageTag();

        if (captchaConfig == null || captchaConfig.getConfig() == null
                || captchaConfig.getConfig().get(SITE_KEY) == null
                || captchaConfig.getConfig().get(SITE_SECRET) == null) {
            form.addError(new FormMessage(null, Messages.RECAPTCHA_NOT_CONFIGURED));
            return;
        }
        siteKey = captchaConfig.getConfig().get(SITE_KEY);
        String apiUrl = captchaConfig.getConfig().get(API_URI);
        form.setAttribute("recaptchaRequired", true);
        form.setAttribute("recaptchaSiteKey", siteKey);
        form.addScript(String.format("%s?hl=%s", apiUrl, userLanguageTag));

        super.authenticate(context);
    }

    @Override
    public void action(AuthenticationFlowContext context) {
        if (logger.isDebugEnabled()) {
            logger.debug("action(AuthenticationFlowContext) - start");
        }
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        boolean success = false;
        context.getEvent().detail(Details.AUTH_METHOD, "auth_method");

        String captcha = formData.getFirst(G_RECAPTCHA_RESPONSE);
        if (!Validation.isBlank(captcha)) {
            AuthenticatorConfigModel captchaConfig = context.getAuthenticatorConfig();
            String url = captchaConfig.getConfig().get(VERIFY_URL);
            String secret = captchaConfig.getConfig().get(SITE_SECRET);
            String proxyHost = captchaConfig.getConfig().get(PROXY_HOST);
            String proxyPort = captchaConfig.getConfig().get(PROXY_PORT);

            success = validateRecaptcha(context, String.format("%s?secret=%s&response=%s", url, secret, captcha), proxyHost, proxyPort);
        }
        if (success) {
            super.action(context);
        } else {
            formData.remove(G_RECAPTCHA_RESPONSE);
            context.forkWithErrorMessage(new FormMessage(null, Messages.RECAPTCHA_FAILED));
            // context.failure(AuthenticationFlowError.INVALID_CREDENTIALS, challenge(context, Messages.RECAPTCHA_FAILED));
            return;
        }
        if (logger.isDebugEnabled()) {
            logger.debug("action(AuthenticationFlowContext) - end");
        }
    }

    protected boolean validateRecaptcha(AuthenticationFlowContext context, String url, String proxyHost, String proxyPort) {
        HttpClient httpClient = context.getSession().getProvider(HttpClientProvider.class).getHttpClient();
        InputStream content = null;
        try {
            HttpGet get = new HttpGet(url);
            if (!Validation.isBlank(proxyHost) && !Validation.isBlank(proxyPort)) {
                get.setConfig(RequestConfig.custom().setProxy(new HttpHost(proxyHost, Integer.parseInt(proxyPort))).build());
            }
            HttpResponse response = httpClient.execute(get);
            content = response.getEntity().getContent();
            Map json = JsonSerialization.readValue(content, Map.class);
            Object val = json.get("success");
            return Boolean.TRUE.equals(val);
        } catch (Exception e) {
            logger.error(e);
            return false;
        } finally {
            if (content != null) {
                try {
                    content.close();
                } catch (IOException e) {
                    logger.error(e);
                }
            }
        }
    }

}
