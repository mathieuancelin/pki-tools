package io.otoroshi.ssl.pki

import java.io.{ByteArrayInputStream, File, StringReader}
import java.nio.charset.StandardCharsets.US_ASCII
import java.nio.file.Files
import java.security._
import java.security.cert.{CertificateFactory, CertificateParsingException, X509Certificate}
import java.security.spec.PKCS8EncodedKeySpec
import java.util.Base64
import java.util.concurrent.atomic.AtomicLong

import akka.actor.ActorSystem
import akka.http.scaladsl.util.FastFuture
import akka.stream.{ActorMaterializer, Materializer}
import akka.util.ByteString
import io.otoroshi.ssl.pki.model._
import io.otoroshi.ssl.pki.utils.IdGenerator
import javax.crypto.Cipher.DECRYPT_MODE
import javax.crypto.spec.PBEKeySpec
import javax.crypto.{Cipher, EncryptedPrivateKeyInfo, SecretKey, SecretKeyFactory}
import org.bouncycastle.asn1._
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509._
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder
import org.bouncycastle.operator.{DefaultDigestAlgorithmIdentifierFinder, DefaultSignatureAlgorithmIdentifierFinder}
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.bouncycastle.util.io.pem.PemReader
import play.api.libs.json._
import sun.security.util.ObjectIdentifier
import sun.security.x509.AlgorithmId

import scala.collection.SortedMap
import scala.concurrent.{ExecutionContext, Future}
import scala.util.{Failure, Random, Success, Try}

object model {

  import utils.SSLImplicits._

  case class GenKeyPairQuery(algo: String = "rsa", size: Int = 2048) {
    def json: JsValue = GenKeyPairQuery.format.writes(this)
  }
  object GenKeyPairQuery {
    private val format = Json.format[GenKeyPairQuery]
    def fromJson(json: JsValue): Either[String, GenKeyPairQuery] = format.reads(json).asEither match {
      case Left(errs) => Left("error while parsing json")
      case Right(q) => Right(q)
    }
  }

  case class GenCsrQuery(
      hosts: Seq[String],
      key: GenKeyPairQuery,
      name: Map[String, String],
      client: Boolean = false,
      ca: Boolean = false,
      days: Int = 365,
      signatureAlg: String = "SHA256WithRSAEncryption",
      digestAlg: String = "SHA-256"
  ) {
    def json: JsValue = GenCsrQuery.format.writes(this)
  }
  object GenCsrQuery {
    private val format = new Format[GenCsrQuery] {
      override def reads(json: JsValue): JsResult[GenCsrQuery] = Try {
        GenCsrQuery(
          hosts = (json \ "hosts").asOpt[Seq[String]].getOrElse(Seq.empty),
          key = (json \ "key").asOpt[JsValue].flatMap(v => GenKeyPairQuery.fromJson(v).toOption).getOrElse(GenKeyPairQuery()),
          name = (json \ "name").as[Map[String, String]],
          client = (json \ "client").asOpt[Boolean].getOrElse(false),
          ca = (json \ "ca").asOpt[Boolean].getOrElse(false),
          days = (json \ "days").asOpt[Int].getOrElse(365),
          signatureAlg = (json \ "signatureAlg").asOpt[String].getOrElse("SHA256WithRSAEncryption"),
          digestAlg = (json \ "digestAlg").asOpt[String].getOrElse("SHA-256"),
        )
      } match {
        case Failure(e) => JsError(e.getMessage)
        case Success(s) => JsSuccess(s)
      }

      override def writes(o: GenCsrQuery): JsValue = Json.obj(
        "hosts" -> o.hosts,
        "key" -> o.key.json,
        "name" -> o.name,
        "client" -> o.client,
        "ca" -> o.ca,
        "days" -> o.days,
        "signatureAlg" -> o.signatureAlg,
        "digestAlg" -> o.digestAlg,
      )
    }
    def fromJson(json: JsValue): Either[String, GenCsrQuery] = format.reads(json).asEither match {
      case Left(errs) => Left("error while parsing json")
      case Right(q) => Right(q)
    }
  }

  case class GenKeyPairResponse(publicKey: PublicKey, privateKey: PrivateKey) {
    def json: JsValue = Json.obj(
      "publicKey" -> publicKey.asPem,
      "privateKey" -> privateKey.asPem
    )
    def chain: String = s"${publicKey.asPem}\n${privateKey.asPem}"
  }

  case class GenCsrResponse(csr: PKCS10CertificationRequest, key: PrivateKey) {
    def json: JsValue = Json.obj(
      "csr" -> csr.asPem,
      "key" -> key.asPem,
    )
    def chain: String = s"${csr.asPem}\n${key.asPem}"
  }

  case class GenCertResponse(cert: X509Certificate, csr: PKCS10CertificationRequest, key: PrivateKey, ca: X509Certificate) {
    def json: JsValue = Json.obj(
      "cert" -> cert.asPem,
      "csr" -> csr.asPem,
      "key" -> key.asPem,
      "ca" -> ca.asPem
    )
    def chain: String = s"${cert.asPem}\n${ca.asPem}\n${key.asPem}\n${csr.asPem}"
  }

  case class SignCertResponse(cert: X509Certificate, csr: PKCS10CertificationRequest, ca: X509Certificate) {
    def json: JsValue = Json.obj(
      "cert" -> cert.asPem,
      "csr" -> csr.asPem,
      "ca" -> ca.asPem
    )
    def chain: String = s"${cert.asPem}\n${ca.asPem}\n${csr.asPem}"
  }

  case class PkiToolConfig(ca: X509Certificate, caKey: PrivateKey, snowflakeSeed: Long) {
    def keyPair: KeyPair = new KeyPair(ca.getPublicKey, caKey)
  }
}

trait Env {
  def config: PkiToolConfig
  def generator: IdGenerator
}

trait Api {

  import utils.AsyncImplicits._

  // genkeypair          generate a public key / private key pair
  def genKeyPair(query: ByteString)(implicit env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[String, GenKeyPairResponse]] = GenKeyPairQuery.fromJson(Json.parse(query.utf8String)) match {
    case Left(err) => Left(err).future
    case Right(q)  => genKeyPair(q)
  }

  // gencsr           generate a private key and a certificate request
  def genCsr(query: ByteString)(implicit env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[String, GenCsrResponse]] = GenCsrQuery.fromJson(Json.parse(query.utf8String)) match {
    case Left(err) => Left(err).future
    case Right(q)  => genCsr(q)
  }

  // gencert          generate a private key and a certificate
  def genCert(query: ByteString)(implicit env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[String, GenCertResponse]] = GenCsrQuery.fromJson(Json.parse(query.utf8String)) match {
    case Left(err) => Left(err).future
    case Right(q)  => genCert(q)
  }

  // sign             signs a certificate
  def signCert(csr: ByteString)(implicit env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[String, SignCertResponse]] = {
    val pemReader = new PemReader(new StringReader(csr.utf8String))
    val pemObject = pemReader.readPemObject()
    val _csr = new PKCS10CertificationRequest(pemObject.getContent)
    pemReader.close()
    signCert(_csr, false)
  }

  // selfsign         generates a self-signed certificate
  def selfSignCert(csr: ByteString)(implicit env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[String, SignCertResponse]] = {
    val pemReader = new PemReader(new StringReader(csr.utf8String))
    val pemObject = pemReader.readPemObject()
    val _csr = new PKCS10CertificationRequest(pemObject.getContent)
    pemReader.close()
    signCert(_csr, true)
  }

  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // actual implementation
  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  // genkeypair          generate a public key / private key pair
  def genKeyPair(query: GenKeyPairQuery)(implicit env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[String, GenKeyPairResponse]]

  // gencsr           generate a private key and a certificate request
  def genCsr(query: GenCsrQuery)(implicit env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[String, GenCsrResponse]]

  // gencert          generate a private key and a certificate
  def genCert(query: GenCsrQuery)(implicit env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[String, GenCertResponse]]

  // sign             signs a certificate
  def signCert(csr: PKCS10CertificationRequest, self: Boolean)(implicit env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[String, SignCertResponse]]
}

class BouncyCastleApi extends Api {

  import utils.AsyncImplicits._

  // genkeypair          generate a public key / private key pair
  override def genKeyPair(query: GenKeyPairQuery)(implicit env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[String, GenKeyPairResponse]] = {
    Try {
      val keyPairGenerator = KeyPairGenerator.getInstance(query.algo.toUpperCase())
      keyPairGenerator.initialize(query.size, new SecureRandom())
      keyPairGenerator.generateKeyPair()
    } match {
      case Failure(e) => Left(e.getMessage).future
      case Success(keyPair) => Right(GenKeyPairResponse(keyPair.getPublic, keyPair.getPrivate)).future
    }
  }

  // gencsr           generate a private key and a certificate request
  override def genCsr(query: GenCsrQuery)(implicit env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[String, GenCsrResponse]] = {
    genKeyPair(query.key).flatMap {
      case Left(e) => Left(e).future
      case Right(kpr) => {
        Try {
          val privateKey = PrivateKeyFactory.createKey(env.config.caKey.getEncoded)
          val signatureAlgorithm = new DefaultSignatureAlgorithmIdentifierFinder().find(query.signatureAlg)
          val digestAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find(query.digestAlg)
          val signer = new BcRSAContentSignerBuilder(signatureAlgorithm, digestAlgorithm).build(privateKey)

          val names = new GeneralNames(query.hosts.map(name => new GeneralName(GeneralName.dNSName, name)).toArray)
          val csrBuilder = new JcaPKCS10CertificationRequestBuilder(new X500Name(query.name.map(t => s"${t._1}=${t._2}").mkString(", ")), env.config.ca.getPublicKey)
          val extensionsGenerator = new ExtensionsGenerator
          extensionsGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(false)) // TODO: handle generating ca ?
          extensionsGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment))
          extensionsGenerator.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(Seq(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth).toArray)) // TODO:
          // extensionsGenerator.addExtension(Extension.subjectKeyIdentifier, false, ???) // TODO:
          extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, names)
          csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest /* x509Certificate */ , extensionsGenerator.generate)
          csrBuilder.build(signer)
        } match {
          case Failure(e) => Left(e.getMessage).future
          case Success(csr) => Right(GenCsrResponse(csr, kpr.privateKey)).future
        }
      }
    }
  }

  // gencert          generate a private key and a certificate
  override def genCert(query: GenCsrQuery)(implicit env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[String, GenCertResponse]] = {
    (for {
      csr <- genCsr(query)
      cert <- csr match {
        case Left(err) => FastFuture.successful(Left(err))
        case Right(_csr) => signCert(_csr.csr, false)
      }
    } yield cert match {
      case Left(err) => Left(err)
      case Right(resp) => Right(GenCertResponse(resp.cert, resp.csr, csr.right.get.key, env.config.ca))
    }).transformWith {
      case Failure(e) => Left(e.getMessage).future
      case Success(Left(e)) => Left(e).future
      case Success(Right(response)) => Right(response).future
    }
  }

  // sign             signs a certificate
  override def signCert(csr: PKCS10CertificationRequest, self: Boolean)(implicit env: Env, ec: ExecutionContext, mat: Materializer): Future[Either[String, SignCertResponse]] = {

    import java.security.SecureRandom

    import org.bouncycastle.asn1.x500.X500Name
    import org.bouncycastle.asn1.x509.{AuthorityKeyIdentifier, BasicConstraints, GeneralName, GeneralNames, X509Name}
    import org.bouncycastle.cert.X509v3CertificateBuilder
    import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder
    val issuer = new X500Name(env.config.ca.getSubjectX500Principal.getName)
    val serial = new java.math.BigInteger(32, new SecureRandom)
    val from = new java.util.Date
    val to = new java.util.Date(System.currentTimeMillis + (365 * 86400000L))

    val certgen = new X509v3CertificateBuilder(issuer, serial, from, to, csr.getSubject, csr.getSubjectPublicKeyInfo)
    certgen.addExtension(Extension.basicConstraints, true, new BasicConstraints(false))
    // certgen.addExtension(Extension.subjectKeyIdentifier, true, new SubjectKeyIdentifier(csr.getSubjectPublicKeyInfo.))
    certgen.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(new GeneralNames(new GeneralName(new X509Name(env.config.ca.getSubjectX500Principal.getName))), env.config.ca.getSerialNumber))
    certgen.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment))
    certgen.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(Seq(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth).toArray))

    // certgen.addExtension(Extension.subjectAlternativeName, false, names)


    val signatureAlgorithm = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WithRSAEncryption")
    val digestAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find("SHA-256")
    val signer = new BcRSAContentSignerBuilder(signatureAlgorithm, digestAlgorithm).build(PrivateKeyFactory.createKey(env.config.caKey.getEncoded))
    val holder = certgen.build(signer)
    val certencoded = holder.toASN1Structure.getEncoded
    val certificateFactory: CertificateFactory = CertificateFactory.getInstance("X.509")
    val cert = certificateFactory
      .generateCertificate(new ByteArrayInputStream(certencoded))
      .asInstanceOf[X509Certificate]
    Right(SignCertResponse(cert, csr, env.config.ca)).future
  }
}

class Server(env: Env) {
  def start(): Unit = ???
  def stop(): Unit = ???
}

class ProdEnv() extends Env {
  val _config = {
    val caContent = utils.base64Decode(Files.readString(new File("/Users/mathieuancelin/projects/cfssl/test-ca/ca.pem").toPath).replace(utils.PemHeaders.BeginCertificate, "").replace(utils.PemHeaders.EndCertificate, ""))
    val cc = Files.readString(new File("/Users/mathieuancelin/projects/cfssl/test-ca/ca-key-e.pem").toPath).replace(utils.PemHeaders.BeginPrivateKey, "").replace(utils.PemHeaders.EndPrivateKey, "").replace(utils.PemHeaders.BeginPrivateRSAKey, "").replace(utils.PemHeaders.EndPrivateRSAKey, "")
    val caKeyContent = utils.base64Decode(cc.trim)
    val certificateFactory: CertificateFactory = CertificateFactory.getInstance("X.509")
    val ca = certificateFactory
      .generateCertificate(new ByteArrayInputStream(caContent))
      .asInstanceOf[X509Certificate]
    val encodedKeySpec = new PKCS8EncodedKeySpec(caKeyContent)
    val key: PrivateKey = Try(KeyFactory.getInstance("RSA"))
      .orElse(Try(KeyFactory.getInstance("DSA")))
      .map(_.generatePrivate(encodedKeySpec))
      .get

    PkiToolConfig(
      ca = ca,
      caKey = key,
      snowflakeSeed = 1
    )
  }
  override def config: PkiToolConfig = _config
  override def generator: IdGenerator = IdGenerator(config.snowflakeSeed)
}

object PkiTools {

  def startServer(): Unit = {
    val env = new ProdEnv()
    val server = new Server(env)
    server.start()
    Runtime.getRuntime.addShutdownHook(new Thread(new Runnable {
      override def run(): Unit = server.stop()
    }))
  }

  def main(args: Array[String]): Unit = {
    val system = ActorSystem("pki-tools")
    implicit val env = new ProdEnv()
    implicit val ec = system.dispatcher
    implicit val mat = Materializer.createMaterializer(system)
    val api = new BouncyCastleApi()
    api.genCert(GenCsrQuery(
      hosts = Seq("www.oto.tools"),
      key = GenKeyPairQuery(),
      name = SortedMap(
        "O" -> "Otoroshi",
        "C" -> "FR"
      ).toMap
    )).map {
      case Left(err) => println(s"ERROR: $err")
      case Right(resp) => println(resp.chain) //println(Json.prettyPrint(resp.json))
    }
  }
}

object utils {

  def base64Decode(base64: String): Array[Byte] = Base64.getMimeDecoder.decode(base64.getBytes(US_ASCII))

  object KeystoreSettings {
    val SignatureAlgorithmName                  = "SHA256withRSA"
    val KeyPairAlgorithmName                    = "RSA"
    val KeyPairKeyLength                        = 2048 // 2048 is the NIST acceptable key length until 2030
    val KeystoreType                            = "JKS"
    val SignatureAlgorithmOID: ObjectIdentifier = AlgorithmId.sha256WithRSAEncryption_oid
  }

  object PemHeaders {
    val BeginCertificate        = "-----BEGIN CERTIFICATE-----"
    val EndCertificate          = "-----END CERTIFICATE-----"
    val BeginPublicKey          = "-----BEGIN PUBLIC KEY-----"
    val EndPublicKey            = "-----END PUBLIC KEY-----"
    val BeginPrivateKey         = "-----BEGIN PRIVATE KEY-----"
    val EndPrivateKey           = "-----END PRIVATE KEY-----"
    val BeginPrivateRSAKey      = "-----BEGIN RSA PRIVATE KEY-----"
    val EndPrivateRSAKey        = "-----END RSA PRIVATE KEY-----"
    val BeginCertificateRequest = "-----BEGIN CERTIFICATE REQUEST-----"
    val EndCertificateRequest   = "-----END CERTIFICATE REQUEST-----"
  }

  object AsyncImplicits {
    implicit final class EnhancedObject[A](any: A) {
      def future: Future[A] = FastFuture.successful(any)
    }
  }

  object SSLImplicits {

    implicit class EnhancedCertificate(val cert: X509Certificate) extends AnyVal {
      def asPem: String = s"${PemHeaders.BeginCertificate}\n${Base64.getEncoder.encodeToString(cert.getEncoded).grouped(64).mkString("\n")}\n${PemHeaders.EndCertificate}\n"
      // def altNames: Seq[String] = CertInfo.getSubjectAlternativeNames(cert)
      // def rawDomain: Option[String] = {
      //   Option(cert.getSubjectDN.getName)
      //     .flatMap(_.split(",").toSeq.map(_.trim).find(_.toLowerCase.startsWith("cn=")))
      //     .map(_.replace("CN=", "").replace("cn=", ""))
      // }
      // def maybeDomain: Option[String] = domains.headOption
      // def domain: String = domains.headOption.getOrElse(cert.getSubjectDN.getName)
      // def domains: Seq[String] = (rawDomain ++ altNames).toSeq
    }
    implicit class EnhancedPublicKey(val key: PublicKey) extends AnyVal {
      def asPem: String = s"${PemHeaders.BeginPublicKey}\n${Base64.getEncoder.encodeToString(key.getEncoded).grouped(64).mkString("\n")}\n${PemHeaders.EndPublicKey}\n"
    }
    implicit class EnhancedPrivateKey(val key: PrivateKey) extends AnyVal {
      def asPem: String = s"${PemHeaders.BeginPrivateKey}\n${Base64.getEncoder.encodeToString(key.getEncoded).grouped(64).mkString("\n")}\n${PemHeaders.EndPrivateKey}\n"
    }
    implicit class EnhancedPKCS10CertificationRequest(val csr: PKCS10CertificationRequest) extends AnyVal {
      def asPem: String = s"${PemHeaders.BeginCertificateRequest}\n${Base64.getEncoder.encodeToString(csr.getEncoded).grouped(64).mkString("\n")}\n${PemHeaders.EndCertificateRequest}\n"
    }
  }


  class IdGenerator(generatorId: Long) {
    def nextId(): Long      = IdGenerator.nextId(generatorId)
    def nextIdStr(): String = IdGenerator.nextIdStr(generatorId)
  }

  object IdGenerator {

    private[this] val CHARACTERS =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray.map(_.toString)
    private[this] val EXTENDED_CHARACTERS =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789*$%)([]!=+-_:/;.><&".toCharArray.map(_.toString)
    private[this] val INIT_STRING = for (i <- 0 to 15) yield Integer.toHexString(i)

    private[this] val minus         = 1288834974657L
    private[this] val counter       = new AtomicLong(-1L)
    private[this] val lastTimestamp = new AtomicLong(-1L)
    private[this] val duplicates    = new AtomicLong(-0L)

    def apply(generatorId: Long) = new IdGenerator(generatorId)

    def nextId(generatorId: Long): Long = synchronized {
      if (generatorId > 1024L) throw new RuntimeException("Generator id can't be larger than 1024")
      val timestamp = System.currentTimeMillis
      if (timestamp < lastTimestamp.get()) throw new RuntimeException("Clock is running backward. Sorry :-(")
      lastTimestamp.set(timestamp)
      counter.compareAndSet(4095, -1L)
      ((timestamp - minus) << 22L) | (generatorId << 10L) | counter.incrementAndGet()
    }

    def nextIdStr(generatorId: Long): String = synchronized {
      if (generatorId > 1024L) throw new RuntimeException("Generator id can't be larger than 1024")
      val timestamp = System.currentTimeMillis
      val append    = if (timestamp < lastTimestamp.get()) s"-${duplicates.incrementAndGet() + generatorId}" else ""
      lastTimestamp.set(timestamp)
      counter.compareAndSet(4095, -1L)
      (((timestamp - minus) << 22L) | (generatorId << 10L) | counter.incrementAndGet()) + append
    }

    def uuid: String =
      (for {
        c <- 0 to 36
      } yield
        c match {
          case i if i == 9 || i == 14 || i == 19 || i == 24 => "-"
          case i if i == 15                                 => "4"
          case i if c == 20                                 => INIT_STRING((Random.nextDouble() * 4.0).toInt | 8)
          case i                                            => INIT_STRING((Random.nextDouble() * 15.0).toInt | 0)
        }).mkString("")

    def token(characters: Array[String], size: Int): String =
      (for {
        i <- 0 to size - 1
      } yield characters(Random.nextInt(characters.size))).mkString("")

    def token(size: Int): String         = token(CHARACTERS, size)
    def token: String                    = token(64)
    def extendedToken(size: Int): String = token(EXTENDED_CHARACTERS, size)
    def extendedToken: String            = token(EXTENDED_CHARACTERS, 64)
  }

  /*object CertInfo {

    import collection.JavaConverters._

    def getSubjectAlternativeNames(certificate: X509Certificate): Seq[String] = {
      val identities: java.util.List[String] = new java.util.ArrayList[String]
      try {
        val altNames: java.util.Collection[java.util.List[_]] = certificate.getSubjectAlternativeNames
        if (altNames == null) {
          Seq.empty
        } else {
          for (item <- altNames.asScala) {
            val `type`: Integer = item.get(0).asInstanceOf[Integer]
            if ((`type` eq 0) || (`type` eq 2)) {
              try {
                var decoder: ASN1InputStream = null
                item.asScala.toArray.apply(1) match {
                  case bytes: Array[Byte] =>
                    decoder = new ASN1InputStream(bytes)
                  case str: String =>
                    identities.add(str)
                  case _ =>
                }
                if (decoder != null) {
                  var encoded: ASN1Encodable = decoder.readObject
                  encoded = encoded.asInstanceOf[DERSequence].getObjectAt(1)
                  encoded = encoded.asInstanceOf[DERTaggedObject].getObject
                  encoded = encoded.asInstanceOf[DERTaggedObject].getObject
                  val identity: String = encoded.asInstanceOf[DERUTF8String].getString
                  identities.add(identity)
                }
              } catch {
                case e: Exception =>
                  println("Error decoding subjectAltName" + e.getLocalizedMessage, e)
              }
            } else {
              println("SubjectAltName of invalid type found: " + certificate)
            }
          }
        }
      } catch {
        case e: CertificateParsingException =>
          println("Error parsing SubjectAltName in certificate: " + certificate + "\r\nerror:" + e.getLocalizedMessage, e)
      }
      identities.asScala.toSeq
    }
  }*/
}
