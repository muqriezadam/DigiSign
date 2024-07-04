package com.example.xades;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Scanner;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import xades4j.production.Enveloped;
import xades4j.production.XadesBesSigningProfile;
import xades4j.production.XadesSigner;
import xades4j.providers.KeyingDataProvider;
import xades4j.providers.impl.DirectKeyingDataProvider;

public class XAdESSignatureGenerator {

    private static final String KEYSTORE_TYPE = "PKCS12";
    private static final String KEYSTORE_FILE = "keystore.p12";
    private static final String KEYSTORE_PASSWORD = "password";
    private static final String KEY_ALIAS = "mykey";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";

    public static void main(String[] args) throws Exception {
        // Initialize XML security
        org.apache.xml.security.Init.init();

        Scanner scanner = new Scanner(System.in);
        System.out.println("Choose an option:");
        System.out.println("1. Create and sign a new XML document");
        System.out.println("2. Sign an existing XML document");
        int choice = scanner.nextInt();
        scanner.nextLine(); // Consume newline

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

        // Generate keystore and certificate
        generateKeyStoreAndCertificate();

        // Sign the document
        signDocument(doc);

        // Save the signed document
        saveSignedDocument(doc);

        System.out.println("XAdES signature created successfully.");
        System.out.println("Keystore file: " + KEYSTORE_FILE);
        System.out.println("Keystore password: " + KEYSTORE_PASSWORD);
        System.out.println("Key alias: " + KEY_ALIAS);
    }

    private static Document createNewXMLDocument(Scanner scanner) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        Document doc = db.newDocument();

        System.out.print("Enter root element name: ");
        String rootName = scanner.nextLine();
        Element root = doc.createElement(rootName);
        doc.appendChild(root);

        while (true) {
            System.out.print("Enter child element name (or 'done' to finish): ");
            String childName = scanner.nextLine();
            if (childName.equalsIgnoreCase("done")) {
                break;
            }
            System.out.print("Enter text content for " + childName + ": ");
            String childContent = scanner.nextLine();
            Element child = doc.createElement(childName);
            child.setTextContent(childContent);
            root.appendChild(child);
        }

        return doc;
    }

    private static void generateKeyStoreAndCertificate() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        X500Name issuerName = new X500Name("CN=Test Issuer");
        X500Name subjectName = new X500Name("CN=Test Subject");

        long now = System.currentTimeMillis();
        Date startDate = new Date(now);
        Date endDate = new Date(now + 365 * 24 * 60 * 60 * 1000L);

        BigInteger serialNumber = BigInteger.valueOf(now);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuerName,
                serialNumber,
                startDate,
                endDate,
                subjectName,
                keyPair.getPublic());

        ContentSigner contentSigner = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).build(keyPair.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certBuilder.build(contentSigner));

        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        keyStore.load(null, null);
        keyStore.setKeyEntry(KEY_ALIAS, keyPair.getPrivate(), KEYSTORE_PASSWORD.toCharArray(), new Certificate[]{cert});

        try (FileOutputStream fos = new FileOutputStream(KEYSTORE_FILE)) {
            keyStore.store(fos, KEYSTORE_PASSWORD.toCharArray());
        }
    }

    private static Document loadXMLDocument(File inputFile) throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        return db.parse(inputFile);
    }

    private static void signDocument(Document doc) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_TYPE);
        try (FileInputStream fis = new FileInputStream(KEYSTORE_FILE)) {
            keyStore.load(fis, KEYSTORE_PASSWORD.toCharArray());
        }

        PrivateKey privateKey = (PrivateKey) keyStore.getKey(KEY_ALIAS, KEYSTORE_PASSWORD.toCharArray());
        X509Certificate cert = (X509Certificate) keyStore.getCertificate(KEY_ALIAS);

        KeyingDataProvider kdp = new DirectKeyingDataProvider(cert, privateKey);

        XadesBesSigningProfile profile = new XadesBesSigningProfile(kdp);
        XadesSigner signer = profile.newSigner();

        new Enveloped(signer).sign(doc.getDocumentElement());
    }

    private static void saveSignedDocument(Document doc) throws Exception {
        TransformerFactory tf = TransformerFactory.newInstance();
        Transformer trans = tf.newTransformer();
        try (FileOutputStream fos = new FileOutputStream("signed_document.xml")) {
            trans.transform(new DOMSource(doc), new StreamResult(fos));
        }
    }
}