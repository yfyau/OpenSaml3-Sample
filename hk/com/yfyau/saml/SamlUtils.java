/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hk.com.yfyau.saml;

import hk.com.yfayu.net.ConfigFileHelper;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SignableSAMLObject;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;
import net.shibboleth.utilities.java.support.security.RandomIdentifierGenerationStrategy;

/**
 *
 * @author jason.yau
 */
public class SamlUtils {
    private static RandomIdentifierGenerationStrategy secureRandomIdGenerator;

    static {
        secureRandomIdGenerator = new RandomIdentifierGenerationStrategy();
    }

    public static <T> T buildSAMLObject(final Class<T> clazz) {
        T object = null;
        try {
            XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
            QName defaultElementName = (QName)clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
            object = (T)builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
        } catch (IllegalAccessException e) {
            throw new IllegalArgumentException("Failed to create SAML object");
        } catch (NoSuchFieldException e) {
            throw new IllegalArgumentException("Failed to create SAML object");
        }

        return object;
    }

    public static String generateSecureRandomId() {
        return secureRandomIdGenerator.generateIdentifier();
    }

    public static String SAMLObjectToString(final XMLObject object) {
        String result = "";
        Element element = null;

        if (object instanceof SignableSAMLObject && ((SignableSAMLObject)object).isSigned() && object.getDOM() != null) {
            element = object.getDOM();
        } else {
            try {
                Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
                out.marshall(object);
                element = object.getDOM();

            } catch (MarshallingException e) {
                System.out.println(e);
            }
        }

        try {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            StreamResult streamResult = new StreamResult(new StringWriter());
            DOMSource source = new DOMSource(element);

            transformer.transform(source, streamResult);
            result = streamResult.getWriter().toString();
            result = result.replace("\r", "");
            result = result.replace("\n", "");

        } catch (TransformerConfigurationException e) {
            System.out.println(e);
        } catch (TransformerException e) {
            System.out.println(e);
        }
        
        return result;
    }
    
    public static void saveSAMLObject(final XMLObject object) throws FileNotFoundException {
        Element element = null;

        if (object instanceof SignableSAMLObject && ((SignableSAMLObject)object).isSigned() && object.getDOM() != null) {
            element = object.getDOM();
        } else {
            try {
                Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
                out.marshall(object);
                element = object.getDOM();

            } catch (MarshallingException e) {
                System.out.println(e);
            }
        }

        try {
            Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");

            File file = new File(ConfigFileHelper.getSharedInstance().getCurrentConfigDirectoryAbsolutePath() + "generated_saml_token.xml");
            FileOutputStream outStream = new FileOutputStream(file); 
            DOMSource source = new DOMSource(element);

            transformer.transform(source, new StreamResult(outStream));
        } catch (TransformerConfigurationException e) {
            System.out.println(e);
        } catch (TransformerException e) {
            System.out.println(e);
        }
    }
}
