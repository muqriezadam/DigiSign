import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Scanner;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import xades4j.algorithms.EnvelopedSignatureTransform;
import xades4j.production.DataObjectReference;
import xades4j.production.SignedDataObjects;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSigner;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.DirectKeyingDataProvider;

public class DigiSignatureGenerator {

    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String PFX_FILE_PATH = "C:\\Users\\mnazlanshah\\OneDrive - Deloitte (O365D)\\Desktop\\How To\\2530.PFX";
    private static final String PFX_PASSWORD = "Agribio@123";

    public static void main(String[] args) {
        try {
            Scanner scanner = new Scanner(System.in);
            System.out.println("Choose an option:");
            System.out.println("1. Create and sign a new XML document");
            System.out.println("2. Sign an existing XML document");
            int choice = scanner.nextInt();
            scanner.nextLine();

            Document doc;
            if (choice == 1) {
                doc = createNewXMLDocument(scanner);
            } else if (choice == 2) {
                System.out.print("Enter the path to your XML file: ");
                String xmlFilePath = scanner.nextLine();
                File inputFile = new File(xmlFilePath);
                if (!inputFile.exists()) {
                    System.out.println("Error: File does not exist.");
                    scanner.close();
                    return;
                }
                doc = loadXMLDocument(inputFile);
            } else {
                System.out.println("Invalid choice. Exiting.");
                scanner.close();
                return;
            }

            scanner.close();
            signDocument(doc);
            saveSignedDocument(doc);

            System.out.println("XAdES signature created successfully.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static Document createNewXMLDocument(Scanner scanner) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.newDocument();

        System.out.print("Enter root element name: ");
        String rootName = scanner.nextLine();
        Element root = doc.createElementNS("urn:oasis:names:specification:ubl:schema:xsd:Invoice-2", rootName);
        doc.appendChild(root);

        while (true) {
            System.out.print("Enter child element name (or 'done' to finish): ");
            String childName = scanner.nextLine();
            if (childName.equalsIgnoreCase("done")) {
                break;
            }
            System.out.print("Enter text content for " + childName + ": ");
            String childContent = scanner.nextLine();
            Element child = doc.createElementNS("urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2", "cbc:" + childName);
            child.setTextContent(childContent);
            root.appendChild(child);
        }

        return doc;
    }

    private static Document loadXMLDocument(File inputFile) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(inputFile);
    }

    private static void signDocument(Document doc) throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE_TYPE);
        ks.load(new FileInputStream(PFX_FILE_PATH), PFX_PASSWORD.toCharArray());

        String alias = null;
        X509Certificate cert = null;
        PrivateKey privateKey = null;

        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            alias = aliases.nextElement();
            if (ks.isKeyEntry(alias)) {
                cert = (X509Certificate) ks.getCertificate(alias);
                privateKey = (PrivateKey) ks.getKey(alias, PFX_PASSWORD.toCharArray());
                break;
            }
        }

        if (cert == null || privateKey == null) {
            throw new Exception("No suitable certificate and private key found in the keystore.");
        }

        KeyingDataProvider keyingDataProvider = new DirectKeyingDataProvider(cert, privateKey);

        XadesBesSigningProfile profile = new XadesBesSigningProfile(keyingDataProvider);
        XadesSigner signer = profile.newSigner();

        DataObjectReference objectReference = new DataObjectReference("");
        objectReference.withTransform(new EnvelopedSignatureTransform());
        SignedDataObjects dataObjs = new SignedDataObjects().withSignedDataObject(objectReference);

        signer.sign(dataObjs, doc.getDocumentElement());
    }

    private static void saveSignedDocument(Document doc) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        try (FileOutputStream fos = new FileOutputStream("signed_document_v2.xml")) {
            trans.transform(new DOMSource(doc), new StreamResult(fos));
        }
        System.out.println("Signed document saved as: signed_document.xml");
    }
}