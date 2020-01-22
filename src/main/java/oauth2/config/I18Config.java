package oauth2.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.web.servlet.LocaleResolver;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.i18n.LocaleChangeInterceptor;
import org.springframework.web.servlet.i18n.SessionLocaleResolver;

import java.util.Locale;

@Configuration
public class I18Config implements WebMvcConfigurer {

    private YAMLToDoConfig yamlToDoConfig;

    public I18Config(YAMLToDoConfig yamlToDoConfig){
        this.yamlToDoConfig = yamlToDoConfig;
    }

    private static String DEFAULT_LANGUAGE = "FRENCH";

    @Bean
    public LocaleResolver localeResolver() {
        SessionLocaleResolver slr = new SessionLocaleResolver();
        String language = yamlToDoConfig.getLanguage();
        if (language != null && !language.isEmpty()) {

            if (language.equals(DEFAULT_LANGUAGE)) {
                slr.setDefaultLocale(Locale.FRENCH);
            } else {
                slr.setDefaultLocale(Locale.ENGLISH);
            }
        }
        return slr;
    }

    @Bean
    public LocaleChangeInterceptor localeChangeInterceptor() {
        LocaleChangeInterceptor lci = new LocaleChangeInterceptor();
        lci.setParamName("messages");
        return lci;
    }

    @Bean(name = "messageSource")
    public ResourceBundleMessageSource bundleMessageSource() {
        ResourceBundleMessageSource messageSource = new ResourceBundleMessageSource();
        messageSource.setBasename("messages");
        return messageSource;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(localeChangeInterceptor());
    }
}
