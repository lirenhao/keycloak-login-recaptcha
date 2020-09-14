package com.yada.keycloak;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.message.BasicNameValuePair;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.browser.UsernamePasswordForm;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.events.Details;
import org.keycloak.events.Errors;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.utils.FormMessage;
import org.keycloak.services.ServicesLogger;
import org.keycloak.services.messages.Messages;
import org.keycloak.services.validation.Validation;
import org.keycloak.util.JsonSerialization;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

public class RecaptchaUsernamePasswordForm extends UsernamePasswordForm implements Authenticator {

    public static final String G_RECAPTCHA_RESPONSE = "g-recaptcha-response";
    public static final String RECAPTCHA_REFERENCE_CATEGORY = "recaptcha";
    public static final String SITE_KEY = "site.key";
    public static final String SITE_SECRET = "secret";

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
        form.setAttribute("recaptchaRequired", true);
        form.setAttribute("recaptchaSiteKey", siteKey);
        form.addScript("https://www.google.com/recaptcha/api.js?hl=" + userLanguageTag);

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
            String secret = captchaConfig.getConfig().get(SITE_SECRET);

            success = validateRecaptcha(context, success, captcha, secret);
        }
        if (success) {
            super.action(context);
        } else {
            formData.remove(G_RECAPTCHA_RESPONSE);
            context.forkWithErrorMessage(new FormMessage(null, Messages.RECAPTCHA_FAILED));
            return;
        }
        if (logger.isDebugEnabled()) {
            logger.debug("action(AuthenticationFlowContext) - end");
        }
    }

    protected boolean validateRecaptcha(AuthenticationFlowContext context, boolean success, String captcha, String secret) {
        HttpClient httpClient = context.getSession().getProvider(HttpClientProvider.class).getHttpClient();
        HttpPost post = new HttpPost("https://www.google.com/recaptcha/api/siteverify");
        List<NameValuePair> formParams = new LinkedList<>();
        formParams.add(new BasicNameValuePair("secret", secret));
        formParams.add(new BasicNameValuePair("response", captcha));
        formParams.add(new BasicNameValuePair("remoteip", context.getConnection().getRemoteAddr()));
        try {
            UrlEncodedFormEntity form = new UrlEncodedFormEntity(formParams, "UTF-8");
            post.setEntity(form);
            HttpResponse response = httpClient.execute(post);
            InputStream content = response.getEntity().getContent();
            try {
                Map json = JsonSerialization.readValue(content, Map.class);
                Object val = json.get("success");
                success = Boolean.TRUE.equals(val);
            } finally {
                content.close();
            }
        } catch (Exception e) {
            ServicesLogger.LOGGER.recaptchaFailed(e);
        }
        return success;
    }

}
