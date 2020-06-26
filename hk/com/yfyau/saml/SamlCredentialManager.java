/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hk.com.yfyau.saml;

import hk.com.yfyau.net.ConfigFileHelper;
import hk.com.yfyau.server.StaticConfig;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.X509Certificate;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;

/**
 * This package uses for generate the Credential that used in signing
 * Please make sure following @params are set in @config.properties:
 *      - SAML_KEY_STORE_PATH
 *      - SAML_KEY_STORE_PASSWORD
 *      - SAML_KEY_ALIAS_ID
 * 
 * @author jason.yau
 */
public class SamlCredentialManager {
    
    private static class ConfigProperties {
        String SAML_KEY_STORE_PATH = ConfigFileHelper.getSharedInstance().getCurrentConfigDirectoryAbsolutePath() + StaticConfig.SAML_KEY_STORE_PATH;
        String SAML_KEY_STORE_PASSWORD = StaticConfig.SAML_KEY_STORE_PASSWORD;
        String SAML_KEY_ALIAS_ID = StaticConfig.SAML_KEY_ALIAS_ID;
    }
    
    private static ConfigProperties config;
    private static Credential credential;

    public static Credential getCredential() {
        config = new ConfigProperties();
        
        try {
            KeyStore keystore = readKeystoreFromFile(config.SAML_KEY_STORE_PATH, config.SAML_KEY_STORE_PASSWORD);
            credential = GenCredentialFromKeyStore(keystore);

        } catch (RuntimeException e) {
            System.out.println("********** Saml Failed to get credential");
            throw new RuntimeException("Failed to reading credential", e);
        }
        
        return credential;
    }
    
    private static Credential GenCredentialFromKeyStore(KeyStore keystore) {
        KeyStore.PrivateKeyEntry pkEntry = null;
        try
        {
           pkEntry = (KeyStore.PrivateKeyEntry) keystore.getEntry(config.SAML_KEY_ALIAS_ID, 
                   new KeyStore.PasswordProtection(config.SAML_KEY_STORE_PASSWORD.toCharArray()));
        }
        catch (NoSuchAlgorithmException e)
        {
            System.out.println(e);
            throw new RuntimeException("Failed to generate credential", e);
        }
        catch (UnrecoverableEntryException e)
        {
            System.out.println(e);
            throw new RuntimeException("Failed to generate credential", e);
        }
        catch (KeyStoreException e)
        {
            System.out.println(e);
            throw new RuntimeException("Failed to generate credential", e);
        }
        
        PrivateKey pk = pkEntry.getPrivateKey();
        X509Certificate certificate = (X509Certificate) pkEntry.getCertificate();
      
        BasicX509Credential basicX509credential = new BasicX509Credential(certificate, pk);
        
        return basicX509credential;
    }
    
    private static KeyStore readKeystoreFromFile(String pathToKeyStore, String keyStorePassword) {
        try {
            KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
            FileInputStream inputStream = new FileInputStream(pathToKeyStore);
            keystore.load(inputStream, keyStorePassword.toCharArray());
            inputStream.close();
            return keystore;
        } catch (Exception e) {
            throw new RuntimeException("Failed to reading keystore", e);
        }
    }
}
