package net.mhcomputing.sdn_sensor.utils;

import java.io.File;
import java.io.StringWriter;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpression;
import javax.xml.xpath.XPathFactory;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

public class XmlUtils {
    private static Logger log =
        LoggerFactory.getLogger(XmlUtils.class);
    
    private XmlUtils() {
    }
    
    private static ThreadLocal<DocumentBuilderFactory> builderFactories =
        new ThreadLocal<DocumentBuilderFactory>() {
            protected DocumentBuilderFactory initialValue() {
                DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();
                return builderFactory;
            }
    };
    
    private static ThreadLocal<DocumentBuilder> builders =
        new ThreadLocal<DocumentBuilder>() {
            protected DocumentBuilder initialValue() {
                try {
                    DocumentBuilder builder = builderFactories.get().newDocumentBuilder();
                    return builder;
                }
                catch (Exception e) {
                    log.error("could not load XML parser", e);
                    throw new RuntimeException(e);
                }
            }
    };
    
    public static Document getDocument(File file) {
        try {
            DocumentBuilder builder = builders.get();
            Document document = builder.parse(file);
            return document;
        }
        catch (Exception e) {
            log.warn("could not parse XML document", e);
            return null;
        }
    }
    
    private static ThreadLocal<XPathFactory> xpathFactories =
        new ThreadLocal<XPathFactory>() {
            protected XPathFactory initialValue() {
                XPathFactory xpathFactory = XPathFactory.newInstance();
                return xpathFactory;
            }
    };
    
    private static ThreadLocal<XPath> xpathImpls =
        new ThreadLocal<XPath>() {
            protected XPath initialValue() {
                XPath xpath = xpathFactories.get().newXPath();
                return xpath;
            }
    };
    
    @SuppressWarnings("unchecked")
    public static <T> T getXpathResult(Object xmlItem, String xpath, QName xtype, Class<T> clazz) {
        try {
            XPathExpression filter = xpathImpls.get().compile(xpath);
            T result = (T) filter.evaluate(xmlItem, xtype);
            return result;
        }
        catch (Exception e) {
            log.error("xpath result generation error", e);
            throw new RuntimeException(e);
        }
    }
    
    public static String getXpathString(Object xmlItem, String xpath) {
        return getXpathResult(xmlItem, xpath, XPathConstants.STRING, String.class);
    }
    
    public static Number getXpathNumber(Object xmlItem, String xpath) {
        return getXpathResult(xmlItem, xpath, XPathConstants.NUMBER, Number.class);
    }
    
    public static String displayDomSource(DOMSource source) {
        try {
            TransformerFactory factory = TransformerFactory.newInstance();
            Transformer transformer = factory.newTransformer();
            // transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            StringWriter writer = new StringWriter();
            StreamResult result = new StreamResult(writer);
            transformer.transform(source, result);
            String output = writer.getBuffer().toString();
            return output;
        }
        catch (Exception e) {
            log.error("corrupt XML document", e);
            return "corrupt XML document";
        }
    }
    
    public static String displayDocument(Document document) {
        document.normalizeDocument();
        DOMSource source = new DOMSource(document);
        return displayDomSource(source);
    }
    
    public static String displayNode(Node node) {
        node.normalize();
        DOMSource source = new DOMSource(node);
        return displayDomSource(source);
    }
}
