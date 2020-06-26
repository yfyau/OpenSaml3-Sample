/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hk.com.yfyau.saml;

import hk.com.yfyau.server.StaticConfig;
import java.util.HashMap;
import java.util.Map;
import org.apache.xml.security.c14n.Canonicalizer;
import org.joda.time.DateTime;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.*;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.KeyName;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;

/**
 * This package uses for build the SAML Token
 * Please make sure following @params are set in @config.properties:
 * 
 * @author jason.yau
 */
public class SamlBuilder {
    
    private static class ConfigProperties {
        String SAML_KEY_ALIAS_ID = StaticConfig.SAML_KEY_ALIAS_ID;
        String SAML_SIGNATURE_ALGORITHM = getSignatureAlgorithmConstant(StaticConfig.SAML_SIGNATURE_ALGORITHM);
        String SAML_DIGEST_ALGORITHM = getDigestAlgorithmConstant(StaticConfig.SAML_DIGEST_ALGORITHM);
        Integer SAML_NOT_BEFORE = Integer.parseInt(StaticConfig.SAML_NOT_BEFORE);
        Integer SAML_NOT_ON_OR_AFTER = Integer.parseInt(StaticConfig.SAML_NOT_ON_OR_AFTER);
        Boolean SAML_SAVE_INTO_FILE = "Y".equals(StaticConfig.SAML_SAVE_INTO_FILE);
        
    }
    
    public static Response buildResponse() {
        
        ConfigProperties config = new ConfigProperties();
        
        Response response = SamlUtils.buildSAMLObject(Response.class);
        response.setID(SamlUtils.generateSecureRandomId());

        Signature signature = SamlUtils.buildSAMLObject(Signature.class);
        signature.setSigningCredential(SamlCredentialManager.getCredential());
        signature.setCanonicalizationAlgorithm(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signature.setSignatureAlgorithm(config.SAML_SIGNATURE_ALGORITHM);

        KeyInfo keyinfo = SamlUtils.buildSAMLObject(KeyInfo.class);
        KeyName keyname = SamlUtils.buildSAMLObject(KeyName.class);
        keyname.setValue(config.SAML_KEY_ALIAS_ID);
        keyinfo.getKeyNames().add(keyname);
        signature.setKeyInfo(keyinfo);

        response.setSignature(signature);

        // Change DigestMethod Algorithm
        ((SAMLObjectContentReference)signature.getContentReferences().get(0)).setDigestAlgorithm(config.SAML_DIGEST_ALGORITHM);
        // --- Signature Part End ---

        Status status = SamlUtils.buildSAMLObject(Status.class);
        StatusCode statusCode = SamlUtils.buildSAMLObject(StatusCode.class);
        statusCode.setValue(StatusCode.SUCCESS);
        status.setStatusCode(statusCode);
        
        response.setStatus(status);
        // --- Status Part End ---

        Assertion assertion = SamlUtils.buildSAMLObject(Assertion.class);
        assertion.setID(SamlUtils.generateSecureRandomId());

        Issuer issuer = SamlUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(config.SAML_KEY_ALIAS_ID);
        assertion.setIssuer(issuer);
        assertion.setIssueInstant(new DateTime());


        Subject subject = SamlUtils.buildSAMLObject(Subject.class);
        assertion.setSubject(subject);

        NameID nameID = SamlUtils.buildSAMLObject(NameID.class);
        subject.setNameID(nameID);

        SubjectConfirmation subjectConfirmation = SamlUtils.buildSAMLObject(SubjectConfirmation.class);
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);

        SubjectConfirmationData subjectConfirmationData = SamlUtils.buildSAMLObject(SubjectConfirmationData.class);
        subjectConfirmationData.setNotOnOrAfter(new DateTime().plusSeconds(config.SAML_NOT_ON_OR_AFTER));
        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);
        subject.getSubjectConfirmations().add(subjectConfirmation);
        // --- Assertion > Subject End ---

        Conditions conditions = SamlUtils.buildSAMLObject(Conditions.class);
        conditions.setNotBefore(new DateTime().plusSeconds(config.SAML_NOT_BEFORE));
        conditions.setNotOnOrAfter(new DateTime().plusSeconds(config.SAML_NOT_ON_OR_AFTER));
        assertion.setConditions(conditions);
        // --- Assertion > Conditions End ---

        AttributeStatement attributeStatement = SamlUtils.buildSAMLObject(AttributeStatement.class);
        assertion.getAttributeStatements().add(attributeStatement);
        // --- Assertion > AttributeStatment End ---

        AuthnStatement authnStatement = SamlUtils.buildSAMLObject(AuthnStatement.class);
        authnStatement.setAuthnInstant(new DateTime());

        AuthnContext authnContext = SamlUtils.buildSAMLObject(AuthnContext.class);
        AuthnContextClassRef authnContextClassRef = SamlUtils.buildSAMLObject(AuthnContextClassRef.class);
        authnContextClassRef.setAuthnContextClassRef(AuthnContext.UNSPECIFIED_AUTHN_CTX);
        authnContext.setAuthnContextClassRef(authnContextClassRef);
        authnStatement.setAuthnContext(authnContext);
        assertion.getAuthnStatements().add(authnStatement);
        // --- Assertion > AuthnStatement End ---

        response.getAssertions().add(assertion);
        // --- Assertion End ---


        // Signing the XML to get DigestValue & SignatureValue
        try {
            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(response).marshall(response);
        } catch (MarshallingException e) {
            throw new RuntimeException(e);
        }

        try {
            Signer.signObject(signature);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
        // Signing End
        
        
        // For Debug - Save SAML to File
        if (config.SAML_SAVE_INTO_FILE){
            try {
                SamlUtils.saveSAMLObject(response);
            } catch (Exception e){
                throw new RuntimeException(e);
            }
        }
        
        return response;
    }
    
    public static String getSignatureAlgorithmConstant(String algorithm) {
        switch (algorithm){
            case "rsa-sha256": return SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
            case "rsa-sha384": return SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA384;
            case "rsa-sha512": return SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA512;
        }
        
        return SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256;
    }
    
    public static String getDigestAlgorithmConstant(String algorithm) {
        switch (algorithm){
            case "sha256": return SignatureConstants.ALGO_ID_DIGEST_SHA256;
            case "sha384": return SignatureConstants.ALGO_ID_DIGEST_SHA384;
            case "sha512": return SignatureConstants.ALGO_ID_DIGEST_SHA512;
        }
        
        return SignatureConstants.ALGO_ID_DIGEST_SHA256;
    }
}
