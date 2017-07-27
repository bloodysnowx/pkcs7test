import java.nio.file.{ Files, Paths }
import java.io.{ FileOutputStream, BufferedOutputStream, FileInputStream, BufferedInputStream }
import java.security.{ KeyStore, PrivateKey, Signature }
import sun.security.pkcs.{ PKCS7, SignerInfo, ContentInfo }
import sun.security.x509.{ AlgorithmId, X500Name }
import java.security.cert.X509Certificate
import sun.security.util.DerValue

object Test extends App {
    def loadClientStore = {
        val clientStore = KeyStore.getInstance("PKCS12")
        val fis = new FileInputStream("./test2.p12")
        clientStore.load(fis, "test".toCharArray)
        fis.close()
        clientStore
    }

    def loadPrivateKeyAndCertificate = {
        val clientStore = loadClientStore
        val alias = clientStore.aliases.nextElement
        val privateKey = clientStore.getKey(alias, "test".toCharArray).asInstanceOf[java.security.PrivateKey]
        val certificate = clientStore.getCertificate(alias).asInstanceOf[X509Certificate]
        val certs = clientStore.getCertificateChain(alias).map(_.asInstanceOf[X509Certificate])
        (privateKey, certificate, certs)
    }

    val (privateKey, certificate, certs) = loadPrivateKeyAndCertificate

    val dataToSign = "data".getBytes

    def sign = {
        val signAlg = Signature.getInstance("SHA1withRSA")
        signAlg.initSign(privateKey)
        signAlg.update(dataToSign)
        signAlg.sign
    }

    val signedData = sign

    val digestAlgorithmId = new AlgorithmId(AlgorithmId.SHA_oid)

    def createSignerInfo = {
        val xName = X500Name.asX500Name(certificate.getSubjectX500Principal)
        val serial = certificate.getSerialNumber
        val signAlgorithmId = new AlgorithmId(AlgorithmId.RSAEncryption_oid)
        new SignerInfo(xName, serial, digestAlgorithmId, signAlgorithmId, signedData)
    }

    val sInfo = createSignerInfo

    val cInfo = new ContentInfo(ContentInfo.DIGESTED_DATA_OID, new DerValue(DerValue.tag_OctetString, dataToSign))

    def loadWwdrcCertificate = {
        val certificateFactory = java.security.cert.CertificateFactory.getInstance("X.509")
        val fis = new FileInputStream("./WWDRC.pem")
        val bis = new BufferedInputStream(fis)
        val wwdrcCert = certificateFactory.generateCertificate(bis).asInstanceOf[X509Certificate]
        bis.close
        fis.close
        wwdrcCert
    }

    val wwdrcCert = loadWwdrcCertificate
    
    val pkcs7 = new PKCS7(Array(digestAlgorithmId), cInfo, certs, Array(sInfo))

    val bos = new BufferedOutputStream(new FileOutputStream("./scala.signed"))
    pkcs7.encodeSignedData(bos)
    bos.close
}