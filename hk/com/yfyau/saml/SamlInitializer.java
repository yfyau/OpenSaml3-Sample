/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hk.com.yfyau.saml;

import java.security.Provider;
import java.security.Security;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.xmlsec.config.impl.JavaCryptoValidationInitializer;

/**
 * This package uses for @initialize the OpenSaml3
 * Please make sure SamlInitializer.init is called before any other method in hk.com.ayers.saml
 * 
 * @author jason.yau
 */
public class SamlInitializer {
    public static void init() {
        // Nextline char would break the format when send to HSBC
        System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
        
        JavaCryptoValidationInitializer javaCryptoValidationInitializer = new JavaCryptoValidationInitializer();
        try {
            System.out.println("Initializing OpenSaml: JavaCryptoValidationInitializer");
            javaCryptoValidationInitializer.init();
        } catch (InitializationException e) {
            System.out.println(e);
        }

        for (Provider jceProvider : Security.getProviders()) {
            System.out.println("Initializing OpenSaml: " + jceProvider.getInfo());
        }

        try {
            System.out.println("Initializing OpenSaml: InitializationService");
            InitializationService.initialize();
        } catch (InitializationException e) {
            throw new RuntimeException("OpenSaml Initialization failed");
        }
        
        System.out.println("Saml Init");
    }
}
