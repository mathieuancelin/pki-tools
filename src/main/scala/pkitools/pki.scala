package io.otoroshi.pki

import java.io.{ByteArrayInputStream, File, StringReader}
import java.nio.charset.StandardCharsets.US_ASCII
import java.nio.file.Files
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.spec.PKCS8EncodedKeySpec
import java.security.{SecureRandom, _}
import java.util.Base64
import java.util.concurrent.Executors
import java.util.concurrent.atomic.{AtomicLong, AtomicReference}

import akka.actor.ActorSystem
import akka.http.scaladsl.Http.ServerBinding
import akka.http.scaladsl.model._
import akka.http.scaladsl.model.headers.{Accept, RawHeader}
import akka.http.scaladsl.util.FastFuture
import akka.http.scaladsl.{ConnectionContext, Http, HttpsConnectionContext}
import akka.stream.{Materializer, TLSClientAuth}
import akka.util.ByteString
import com.auth0.jwt.JWT
import com.auth0.jwt.algorithms.Algorithm
import com.typesafe.config.{Config, ConfigFactory}
import io.otoroshi.pki.PkiTools.logger
import io.otoroshi.pki.models._
import io.otoroshi.pki.utils.IdGenerator
import io.otoroshi.pki.utils.SSLImplicits._
import javax.net.ssl.{KeyManagerFactory, SSLContext, TrustManagerFactory}
import org.apache.commons.cli.{DefaultParser, Options}
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.{AuthorityKeyIdentifier, BasicConstraints, GeneralName, GeneralNames, X509Name, _}
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder
import org.bouncycastle.operator.{DefaultDigestAlgorithmIdentifierFinder, DefaultSignatureAlgorithmIdentifierFinder}
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder
import org.bouncycastle.util.io.pem.PemReader
import org.slf4j.LoggerFactory
import play.api.libs.json._
import sun.security.util.ObjectIdentifier
import sun.security.x509.AlgorithmId

import scala.collection.SortedMap
import scala.concurrent.duration._
import scala.concurrent.{Await, ExecutionContext, Future}
import scala.util.{Failure, Random, Success, Try}

object models {

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
      hosts: Seq[String] = Seq.empty,
      key: GenKeyPairQuery = GenKeyPairQuery(),
      name: Map[String, String] = Map.empty,
      subject: Option[String] = None,
      client: Boolean = false,
      ca: Boolean = false,
      days: Int = 365,
      signatureAlg: String = "SHA256WithRSAEncryption",
      digestAlg: String = "SHA-256"
  ) {
    def subj: String = subject.getOrElse(name.map(t => s"${t._1}=${t._2}").mkString(","))
    def json: JsValue = GenCsrQuery.format.writes(this)
  }
  object GenCsrQuery {
    private val format = new Format[GenCsrQuery] {
      override def reads(json: JsValue): JsResult[GenCsrQuery] = Try {
        GenCsrQuery(
          hosts = (json \ "hosts").asOpt[Seq[String]].getOrElse(Seq.empty),
          key = (json \ "key").asOpt[JsValue].flatMap(v => GenKeyPairQuery.fromJson(v).toOption).getOrElse(GenKeyPairQuery()),
          name = (json \ "name").asOpt[Map[String, String]].getOrElse(Map.empty),
          subject = (json \ "subject").asOpt[String],
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
        "subject" -> o.subject.map(JsString.apply).getOrElse(JsNull).as[JsValue],
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
    def chain: String = s"${key.asPem}\n${cert.asPem}\n${ca.asPem}"
    def chainWithCsr: String = s"${key.asPem}\n${cert.asPem}\n${ca.asPem}\n${csr.asPem}"
  }

  case class SignCertResponse(cert: X509Certificate, csr: PKCS10CertificationRequest, ca: Option[X509Certificate]) {
    def json: JsValue = Json.obj(
      "cert" -> cert.asPem,
      "csr" -> csr.asPem,
    ) ++ ca.map(c => Json.obj("ca" -> c.asPem)).getOrElse(Json.obj())
    def chain: String = s"${cert.asPem}\n${ca.map(_.asPem + "\n").getOrElse("")}"
    def chainWithCsr: String = s"${cert.asPem}\n${ca.map(_.asPem + "\n").getOrElse("")}${csr.asPem}"
  }

  case class PkiToolConfig(
      ca: X509Certificate,
      caKey: PrivateKey,
      snowflakeSeed: Long,
      interface: String = "0.0.0.0",
      port: Int = 8443,
      externalPort: Int = 443,
      hostname: String = "pki.oto.tools",
      https: Boolean = true,
      otoroshi: Boolean = false,
      otoroshiSecret: String = "secret",
      otoroshiIssuer: String = "Otoroshi"
  ) {
    def keyPair: KeyPair = new KeyPair(ca.getPublicKey, caKey)
  }
}

trait Env {
  def conf: Config
  def config: PkiToolConfig
  def generator: IdGenerator
  def getString(path: String): Option[String]
  def getLong(path: String): Option[Long]
  def getInt(path: String): Option[Int]
  def getBoolean(path: String): Option[Boolean]
}

trait Pki {

  import utils.AsyncImplicits._

  // genkeypair          generate a public key / private key pair
  def genKeyPair(query: ByteString)(implicit ec: ExecutionContext): Future[Either[String, GenKeyPairResponse]] = GenKeyPairQuery.fromJson(Json.parse(query.utf8String)) match {
    case Left(err) => Left(err).future
    case Right(q)  => genKeyPair(q)
  }

  // gencsr           generate a private key and a certificate request
  def genCsr(query: ByteString, caCert: X509Certificate, caKey: PrivateKey)(implicit ec: ExecutionContext): Future[Either[String, GenCsrResponse]] = GenCsrQuery.fromJson(Json.parse(query.utf8String)) match {
    case Left(err) => Left(err).future
    case Right(q)  => genCsr(q, caCert, caKey)
  }

  // gencert          generate a private key and a certificate
  def genCert(query: ByteString, caCert: X509Certificate, caKey: PrivateKey)(implicit ec: ExecutionContext): Future[Either[String, GenCertResponse]] = GenCsrQuery.fromJson(Json.parse(query.utf8String)) match {
    case Left(err) => Left(err).future
    case Right(q)  => genCert(q, caCert, caKey)
  }

  // sign             signs a certificate
  def signCert(csr: ByteString, caCert: X509Certificate, caKey: PrivateKey)(implicit ec: ExecutionContext): Future[Either[String, SignCertResponse]] = {
    val pemReader = new PemReader(new StringReader(csr.utf8String))
    val pemObject = pemReader.readPemObject()
    val _csr = new PKCS10CertificationRequest(pemObject.getContent)
    pemReader.close()
    signCert(_csr, caCert, caKey)
  }

  // selfsign         generates a self-signed certificate
  def genSelfSignedCert(query: ByteString)(implicit ec: ExecutionContext): Future[Either[String, GenCertResponse]] = GenCsrQuery.fromJson(Json.parse(query.utf8String)) match {
    case Left(err) => Left(err).future
    case Right(q)  => genSelfSignedCert(q)
  }

  def genSelfSignedCA(query: ByteString)(implicit ec: ExecutionContext, mat: Materializer): Future[Either[String, GenCertResponse]] = GenCsrQuery.fromJson(Json.parse(query.utf8String)) match {
    case Left(err) => Left(err).future
    case Right(q)  => genSelfSignedCA(q)
  }

  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  // actual implementation
  //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

  // genkeypair          generate a public key / private key pair
  def genKeyPair(query: GenKeyPairQuery)(implicit ec: ExecutionContext): Future[Either[String, GenKeyPairResponse]]

  // gencsr           generate a private key and a certificate request
  def genCsr(query: GenCsrQuery, caCert: X509Certificate, caKey: PrivateKey)(implicit ec: ExecutionContext): Future[Either[String, GenCsrResponse]]

  // gencert          generate a private key and a certificate
  def genCert(query: GenCsrQuery, caCert: X509Certificate, caKey: PrivateKey)(implicit ec: ExecutionContext): Future[Either[String, GenCertResponse]]

  // sign             signs a certificate
  def signCert(csr: PKCS10CertificationRequest, caCert: X509Certificate, caKey: PrivateKey)(implicit ec: ExecutionContext): Future[Either[String, SignCertResponse]]

  def genSelfSignedCA(query: GenCsrQuery)(implicit ec: ExecutionContext): Future[Either[String, GenCertResponse]]

  def genSelfSignedCert(query: GenCsrQuery)(implicit ec: ExecutionContext): Future[Either[String, GenCertResponse]]
}

class BouncyCastlePki extends Pki {

  import utils.AsyncImplicits._

  // genkeypair          generate a public key / private key pair
  override def genKeyPair(query: GenKeyPairQuery)(implicit ec: ExecutionContext): Future[Either[String, GenKeyPairResponse]] = {
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
  override def genCsr(query: GenCsrQuery, caCert: X509Certificate, caKey: PrivateKey)(implicit ec: ExecutionContext): Future[Either[String, GenCsrResponse]] = {
    genKeyPair(query.key).flatMap {
      case Left(e) => Left(e).future
      case Right(kpr) => {
        Try {
          val privateKey = PrivateKeyFactory.createKey(kpr.privateKey.getEncoded)
          val signatureAlgorithm = new DefaultSignatureAlgorithmIdentifierFinder().find(query.signatureAlg)
          val digestAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find(query.digestAlg)
          val signer = new BcRSAContentSignerBuilder(signatureAlgorithm, digestAlgorithm).build(privateKey)
          val names = new GeneralNames(query.hosts.map(name => new GeneralName(GeneralName.dNSName, name)).toArray)
          val csrBuilder = new JcaPKCS10CertificationRequestBuilder(new X500Name(query.subj), kpr.publicKey)
          val extensionsGenerator = new ExtensionsGenerator
          extensionsGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(query.ca))
          if (!query.ca) {
            extensionsGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment))
            // extensionsGenerator.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(Seq(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth).toArray))
            if (query.client) {
              extensionsGenerator.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(Seq(KeyPurposeId.id_kp_clientAuth).toArray))
            } else {
              extensionsGenerator.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(Seq(KeyPurposeId.id_kp_serverAuth).toArray))
            }
            extensionsGenerator.addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(new GeneralNames(new GeneralName(new X509Name(caCert.getSubjectX500Principal.getName))), caCert.getSerialNumber))
            extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, names)
          } else {
            extensionsGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign  | KeyUsage.cRLSign))
          }
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
  override def genCert(query: GenCsrQuery, caCert: X509Certificate, caKey: PrivateKey)(implicit ec: ExecutionContext): Future[Either[String, GenCertResponse]] = {
    (for {
      csr <- genCsr(query, caCert, caKey)
      cert <- csr match {
        case Left(err) => FastFuture.successful(Left(err))
        case Right(_csr) => signCert(_csr.csr,caCert, caKey)
      }
    } yield cert match {
      case Left(err) => Left(err)
      case Right(resp) => Right(GenCertResponse(resp.cert, resp.csr, csr.right.get.key, caCert))
    }).transformWith {
      case Failure(e) => Left(e.getMessage).future
      case Success(Left(e)) => Left(e).future
      case Success(Right(response)) => Right(response).future
    }
  }

  // sign             signs a certificate
  override def signCert(csr: PKCS10CertificationRequest, caCert: X509Certificate, caKey: PrivateKey)(implicit ec: ExecutionContext): Future[Either[String, SignCertResponse]] = {
    Try {
      val issuer = new X500Name(caCert.getSubjectX500Principal.getName)
      val serial = new java.math.BigInteger(32, new SecureRandom)
      val from = new java.util.Date
      val to = new java.util.Date(System.currentTimeMillis + (365 * 86400000L))
      val certgen = new X509v3CertificateBuilder(issuer, serial, from, to, csr.getSubject, csr.getSubjectPublicKeyInfo)
      csr.getAttributes.foreach(attr => {
        attr.getAttributeValues.collect {
          case exts: Extensions => {
            exts.getExtensionOIDs.map(id => exts.getExtension(id)).filter(_ != null).foreach { ext =>
              certgen.addExtension(ext.getExtnId, ext.isCritical, ext.getParsedValue)
            }
          }
        }
      })
      // val signatureAlgorithm = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WithRSAEncryption")
      val digestAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find("SHA-256")
      val signer = new BcRSAContentSignerBuilder(csr.getSignatureAlgorithm, digestAlgorithm).build(PrivateKeyFactory.createKey(caKey.getEncoded))
      val holder = certgen.build(signer)
      val certencoded = holder.toASN1Structure.getEncoded
      val certificateFactory: CertificateFactory = CertificateFactory.getInstance("X.509")
      val cert = certificateFactory
        .generateCertificate(new ByteArrayInputStream(certencoded))
        .asInstanceOf[X509Certificate]
      cert
    } match {
      case Failure(err) => Left(err.getMessage).future
      case Success(cert) => Right(SignCertResponse(cert, csr, Some(caCert))).future
    }
  }

  override def genSelfSignedCert(query: GenCsrQuery)(implicit ec: ExecutionContext): Future[Either[String, GenCertResponse]] = {
    if (query.ca) {
      genSelfSignedCA(query)
    } else {
      genKeyPair(query.key).flatMap {
        case Left(e) => Left(e).future
        case Right(kpr) => Try {
          val privateKey = PrivateKeyFactory.createKey(kpr.privateKey.getEncoded)
          val signatureAlgorithm = new DefaultSignatureAlgorithmIdentifierFinder().find(query.signatureAlg)
          val digestAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find(query.digestAlg)
          val signer = new BcRSAContentSignerBuilder(signatureAlgorithm, digestAlgorithm).build(privateKey)
          val names = new GeneralNames(query.hosts.map(name => new GeneralName(GeneralName.dNSName, name)).toArray)
          val csrBuilder = new JcaPKCS10CertificationRequestBuilder(new X500Name(query.subj), kpr.publicKey)
          val extensionsGenerator = new ExtensionsGenerator
          extensionsGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(query.ca))
          if (!query.ca) {
            extensionsGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment))
            // extensionsGenerator.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(Seq(KeyPurposeId.id_kp_serverAuth, KeyPurposeId.id_kp_clientAuth).toArray))
            if (query.client) {
              extensionsGenerator.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(Seq(KeyPurposeId.id_kp_clientAuth).toArray))
            } else {
              extensionsGenerator.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(Seq(KeyPurposeId.id_kp_serverAuth).toArray))
            }
            extensionsGenerator.addExtension(Extension.subjectAlternativeName, false, names)
          } else {
            extensionsGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign))
          }
          csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest /* x509Certificate */ , extensionsGenerator.generate)
          val csr = csrBuilder.build(signer)
          val issuer = csr.getSubject
          val serial = new java.math.BigInteger(32, new SecureRandom)
          val from = new java.util.Date
          val to = new java.util.Date(System.currentTimeMillis + (365 * 86400000L))
          val certgen = new X509v3CertificateBuilder(issuer, serial, from, to, csr.getSubject, csr.getSubjectPublicKeyInfo)
          csr.getAttributes.foreach(attr => {
            attr.getAttributeValues.collect {
              case exts: Extensions => {
                exts.getExtensionOIDs.map(id => exts.getExtension(id)).filter(_ != null).foreach { ext =>
                  certgen.addExtension(ext.getExtnId, ext.isCritical, ext.getParsedValue)
                }
              }
            }
          })
          // val signatureAlgorithm = new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256WithRSAEncryption")
          val holder = certgen.build(signer)
          val certencoded = holder.toASN1Structure.getEncoded
          val certificateFactory: CertificateFactory = CertificateFactory.getInstance("X.509")
          val cert = certificateFactory
            .generateCertificate(new ByteArrayInputStream(certencoded))
            .asInstanceOf[X509Certificate]
          Right(GenCertResponse(cert, csr, kpr.privateKey, cert))
        } match {
          case Failure(e) => Left(e.getMessage).future
          case Success(either) => either.future
        }
      }
    }
  }

  def genSelfSignedCA(query: GenCsrQuery)(implicit ec: ExecutionContext): Future[Either[String, GenCertResponse]] = {
    genKeyPair(query.key).flatMap {
      case Left(e) => Left(e).future
      case Right(kpr) => Try {
        val privateKey = PrivateKeyFactory.createKey(kpr.privateKey.getEncoded)
        val signatureAlgorithm = new DefaultSignatureAlgorithmIdentifierFinder().find(query.signatureAlg)
        val digestAlgorithm = new DefaultDigestAlgorithmIdentifierFinder().find(query.digestAlg)
        val signer = new BcRSAContentSignerBuilder(signatureAlgorithm, digestAlgorithm).build(privateKey)
        val names = new GeneralNames(query.hosts.map(name => new GeneralName(GeneralName.dNSName, name)).toArray)
        val csrBuilder = new JcaPKCS10CertificationRequestBuilder(new X500Name(query.subj), kpr.publicKey)
        val extensionsGenerator = new ExtensionsGenerator
        extensionsGenerator.addExtension(Extension.basicConstraints, true, new BasicConstraints(true))
        extensionsGenerator.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign))
        csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest /* x509Certificate */ , extensionsGenerator.generate)
        val csr = csrBuilder.build(signer)
        val issuer = csr.getSubject
        val serial = new java.math.BigInteger(32, new SecureRandom)
        val from = new java.util.Date
        val to = new java.util.Date(System.currentTimeMillis + (365 * 86400000L))
        val certgen = new X509v3CertificateBuilder(issuer, serial, from, to, csr.getSubject, csr.getSubjectPublicKeyInfo)
        csr.getAttributes.foreach(attr => {
          attr.getAttributeValues.collect {
            case exts: Extensions => {
              exts.getExtensionOIDs.map(id => exts.getExtension(id)).filter(_ != null).foreach { ext =>
                certgen.addExtension(ext.getExtnId, ext.isCritical, ext.getParsedValue)
              }
            }
          }
        })
        val holder = certgen.build(signer)
        val certencoded = holder.toASN1Structure.getEncoded
        val certificateFactory: CertificateFactory = CertificateFactory.getInstance("X.509")
        val cert = certificateFactory
          .generateCertificate(new ByteArrayInputStream(certencoded))
          .asInstanceOf[X509Certificate]
        Right(GenCertResponse(cert, csr, kpr.privateKey, cert))
      } match {
        case Failure(e) => Left(e.getMessage).future
        case Success(either) => either.future
      }
    }
  }
}

class Server(pki: Pki, env: Env) {

  import utils.AsyncImplicits._

  implicit val system = ActorSystem("pki-tools")
  implicit val ec = system.dispatcher
  implicit val mat = Materializer.createMaterializer(system)
  implicit val e = env
  implicit val http = Http()

  private val ref = new AtomicReference[ServerBinding](null)

  def passWithOtoroshiAndBody(request: HttpRequest)(f: ByteString => Future[HttpResponse]): Future[HttpResponse] = {
    passWithOtoroshi(request) {
      request.entity.dataBytes.runFold(ByteString.empty)(_ ++ _).flatMap(bs => f(bs))
    }
  }

  def passWithOtoroshi(request: HttpRequest)(f: => Future[HttpResponse]): Future[HttpResponse] = {
    if (env.config.otoroshi) {
      request.getHeader("Otoroshi-State") match {
        case h if !h.isPresent => badRequest("no state !").future
        case h if h.isPresent => {
          val algo = Algorithm.HMAC512(env.config.otoroshiSecret)
          Try(JWT.require(algo).withIssuer(env.config.otoroshiIssuer).build().verify(h.get().value())) match {
            case Success(jwt) =>
              val token = JWT.create()
                .withAudience(env.config.otoroshiIssuer)
                .withIssuedAt(org.joda.time.DateTime.now().toDate)
                .withExpiresAt(org.joda.time.DateTime.now().plusSeconds(30).toDate)
                .withClaim("state-resp", jwt.getClaim("state").asString())
                .sign(algo)
              f.map(r => r.copy(headers = r.headers :+ RawHeader("Otoroshi-State-Resp", token)))
            case Failure(e) => badRequest("bad state !").future
          }
        }
      }
    } else {
      f
    }
  }.andThen {
    case _ => request.discardEntityBytes()
  }

  def badRequest(err: String) = HttpResponse(
    400,
    entity = HttpEntity(
      ContentTypes.`application/json`,
      Json.stringify(Json.obj("error" -> err))
    )
  )

  def notFound() = HttpResponse(
    404,
    entity = HttpEntity(
      ContentTypes.`application/json`,
      Json.stringify(Json.obj("error" -> "not found !"))
    )
  )

  def createdText(body: String) = HttpResponse(
    201,
    entity = HttpEntity(
      ContentTypes.`text/plain(UTF-8)`,
      body
    )
  )

  def createdJson(body: JsValue) = HttpResponse(
    201,
    entity = HttpEntity(
      ContentTypes.`application/json`,
      Json.stringify(body)
    )
  )

  def handle(request: HttpRequest): Future[HttpResponse] = {
    (request.method, request.uri.toRelative.path.toString()) match {
      case (HttpMethods.GET, "/api/pki/ca") => passWithOtoroshi(request) {
        if (!request.header[Accept].exists(_.value.contains("text/plain"))) {
          HttpResponse(
            200,
            entity = HttpEntity(
              ContentTypes.`application/json`,
              Json.stringify(Json.obj("cert" -> env.config.ca.asPem))
            )
          ).future
        } else {
          HttpResponse(
            200,
            entity = HttpEntity(
              ContentTypes.`text/plain(UTF-8)`,
              env.config.ca.asPem
            )
          ).future
        }
      }
      case (HttpMethods.POST, "/api/pki/cert") => passWithOtoroshiAndBody(request) { body =>
        GenCsrQuery.fromJson(Json.parse(body.utf8String)) match {
          case Left(err) => badRequest(err).future
          case Right(query)  => {
            request.uri.query().get("self-signed").exists(_.toBoolean) match {
              case false => pki.genCert(body, env.config.ca, env.config.caKey).map {
                case Left(err) => badRequest(err)
                case Right(resp) if request.header[Accept].exists(_.value.contains("text/plain")) => createdText(resp.chain)
                case Right(resp) => createdJson(resp.json)
              }
              case true if query.ca => pki.genSelfSignedCert(body).map {
                case Left(err) => badRequest(err)
                case Right(resp) if request.header[Accept].exists(_.value.contains("text/plain")) => createdText(resp.chain)
                case Right(resp) => createdJson(resp.json)
              }
              case true if !query.ca => pki.genSelfSignedCA(body).map {
                case Left(err) => badRequest(err)
                case Right(resp) if request.header[Accept].exists(_.value.contains("text/plain")) => createdText(resp.chain)
                case Right(resp) => createdJson(resp.json)
              }
            }
          }
        }
      }
      case (HttpMethods.POST, "/api/pki/csr") => passWithOtoroshiAndBody(request) { body =>
        pki.genCsr(body, env.config.ca, env.config.caKey).map {
          case Left(err) => badRequest(err)
          case Right(resp) if request.header[Accept].exists(_.value.contains("text/plain")) => createdText(resp.chain)
          case Right(resp) => createdJson(resp.json)
        }
      }
      case (HttpMethods.POST, "/api/pki/keypair") => passWithOtoroshiAndBody(request) { body =>
        pki.genKeyPair(body).map {
          case Left(err) => badRequest(err)
          case Right(resp) if request.header[Accept].exists(_.value.contains("text/plain")) => createdText(resp.chain)
          case Right(resp) => createdJson(resp.json)
        }
      }
      case (HttpMethods.POST, "/api/pki/_sign") => passWithOtoroshiAndBody(request) { body =>
        pki.signCert(body, env.config.ca, env.config.caKey).map {
          case Left(err) => badRequest(err)
          case Right(resp) if request.header[Accept].exists(_.value.contains("text/plain")) => createdText(resp.chain)
          case Right(resp) => createdJson(resp.json)
        }
      }
      //case (HttpMethods.POST, "/api/pki/_self-sign") =>
      case _ => passWithOtoroshi(request) {
        notFound().future
      }
    }
  }

  def start(): Unit = {
    if (env.config.https) {
      val EMPTY_PASSWORD: Array[Char] = Array.emptyCharArray
      val ks: KeyStore = KeyStore.getInstance("JKS")
      ks.load(null, null)
      // add ca to keystore
      val id = "ca-" + env.config.ca.getSerialNumber.toString(16)
      if (!ks.containsAlias(id)) {
        ks.setKeyEntry(id, env.config.caKey, EMPTY_PASSWORD, Array(env.config.ca))
      }
      val autoGenerate = env.getBoolean("pki.autoGenerateCertFiles").getOrElse(false)

      {
        val serverCertPath = env.getString("pki.http.cert").getOrElse("./server-cert.pem")
        val serverCertKeyPath = env.getString("pki.http.key").getOrElse("./server-key.pem")
        val serverCertFile = new File(serverCertPath)
        val serverCertKeyFile = new File(serverCertKeyPath)
        Try {
          val serverContent = {
            if (serverCertFile.exists()) {
              utils.base64Decode(Files.readString(serverCertFile.toPath).replace(utils.PemHeaders.BeginCertificate, "").replace(utils.PemHeaders.EndCertificate, ""))
            } else {
              utils.base64Decode(serverCertPath.replace(utils.PemHeaders.BeginCertificate, "").replace(utils.PemHeaders.EndCertificate, ""))
            }
          }
          val serverKeyContent = {
            if (serverCertKeyFile.exists()) {
              val content = Files.readString(serverCertKeyFile.toPath).replace(utils.PemHeaders.BeginPrivateKey, "").replace(utils.PemHeaders.EndPrivateKey, "").replace(utils.PemHeaders.BeginPrivateRSAKey, "").replace(utils.PemHeaders.EndPrivateRSAKey, "")
              utils.base64Decode(content)
            } else {
              utils.base64Decode(serverCertKeyPath.replace(utils.PemHeaders.BeginPrivateKey, "").replace(utils.PemHeaders.EndPrivateKey, "").replace(utils.PemHeaders.BeginPrivateRSAKey, "").replace(utils.PemHeaders.EndPrivateRSAKey, ""))
            }
          }

          val certificateFactory: CertificateFactory = CertificateFactory.getInstance("X.509")
          val cert = certificateFactory
            .generateCertificate(new ByteArrayInputStream(serverContent))
            .asInstanceOf[X509Certificate]
          val encodedKeySpec = new PKCS8EncodedKeySpec(serverKeyContent)
          val key: PrivateKey = Try(KeyFactory.getInstance("RSA"))
            .orElse(Try(KeyFactory.getInstance("DSA")))
            .map(_.generatePrivate(encodedKeySpec))
            .get
          ks.setKeyEntry(cert.getSubjectDN.getName, key, EMPTY_PASSWORD, Array(cert, env.config.ca))
        } match {
          case Success(_) =>
            logger.info(s"Loading server cert. from $serverCertPath")
            logger.info(s"Loading server cert. private key from $serverCertKeyPath")
          case Failure(e) => {
            logger.info("Auto-generating server certificate ...")
            Await.result(pki.genCert(GenCsrQuery(
              hosts = Seq(env.config.hostname),
              key = GenKeyPairQuery(),
              name = SortedMap(
                "C" -> "FR",
                "L" -> "Poitiers",
                "O" -> "OtoroshiLabs",
                "OU" -> "Pki-Server"
              ).toMap
            ), env.config.ca, env.config.caKey), 30.seconds) match {
              case Left(err) =>
                logger.error(s"Error while generating server certificate ... - $err")
                sys.exit(1)
              case Right(resp) => {
                if (autoGenerate) {
                  logger.info(s"Writing server certificate and key to ${serverCertPath} and ${serverCertKeyPath}")
                  Files.writeString(new File(serverCertPath).toPath, resp.cert.asPem)
                  Files.writeString(new File(serverCertKeyPath).toPath, resp.key.asPem)
                }
                ks.setKeyEntry(resp.cert.getSubjectDN.getName, resp.key, EMPTY_PASSWORD, Array(resp.cert, resp.ca))
              }
            }
          }
        }
      }
      val mtls = env.getBoolean("pki.http.mtls").getOrElse(false)
      if (mtls) {
        val clientCertPath = env.getString("pki.http.clientCert").getOrElse("./server-client-cert.pem")
        val clientCertKeyPath = env.getString("pki.http.clientKey").getOrElse("./server-client-key.pem")
        val clientCertFile = new File(clientCertPath)
        val clientCertKeyFile = new File(clientCertKeyPath)
        Try {

          val clientContent = {
            if (clientCertFile.exists()) {
              utils.base64Decode(Files.readString(clientCertFile.toPath).replace(utils.PemHeaders.BeginCertificate, "").replace(utils.PemHeaders.EndCertificate, ""))
            } else {
              utils.base64Decode(clientCertPath.replace(utils.PemHeaders.BeginCertificate, "").replace(utils.PemHeaders.EndCertificate, ""))
            }
          }
          val clientKeyContent = {
            if (clientCertKeyFile.exists()) {
              val content = Files.readString(clientCertKeyFile.toPath).replace(utils.PemHeaders.BeginPrivateKey, "").replace(utils.PemHeaders.EndPrivateKey, "").replace(utils.PemHeaders.BeginPrivateRSAKey, "").replace(utils.PemHeaders.EndPrivateRSAKey, "")
              utils.base64Decode(content)
            } else {
              utils.base64Decode(clientCertKeyPath.replace(utils.PemHeaders.BeginPrivateKey, "").replace(utils.PemHeaders.EndPrivateKey, "").replace(utils.PemHeaders.BeginPrivateRSAKey, "").replace(utils.PemHeaders.EndPrivateRSAKey, ""))
            }
          }

          val certificateFactory: CertificateFactory = CertificateFactory.getInstance("X.509")
          val cert = certificateFactory
            .generateCertificate(new ByteArrayInputStream(clientContent))
            .asInstanceOf[X509Certificate]
          val encodedKeySpec = new PKCS8EncodedKeySpec(clientKeyContent)
          val key: PrivateKey = Try(KeyFactory.getInstance("RSA"))
            .orElse(Try(KeyFactory.getInstance("DSA")))
            .map(_.generatePrivate(encodedKeySpec))
            .get
          ks.setKeyEntry(cert.getSubjectDN.getName, key, EMPTY_PASSWORD, Array(cert, env.config.ca))
        } match {
          case Success(_) =>
            logger.info(s"Loading client cert. from $clientCertPath")
            logger.info(s"Loading client cert. private key from $clientCertKeyPath")
          case Failure(e) =>
            logger.info("Auto-generating client certificate ...")
            Await.result(pki.genCert(GenCsrQuery(
              hosts = Seq(env.config.hostname),
              key = GenKeyPairQuery(),
              name = SortedMap(
                "C" -> "FR",
                "L" -> "Poitiers",
                "O" -> "OtoroshiLabs",
                "OU" -> "Pki-Client"
              ).toMap,
              client = true
            ), env.config.ca, env.config.caKey), 30.seconds) match {
              case Left(err) =>
                logger.error(s"Error while generating client certificate ... - $err")
                sys.exit(1)
              case Right(resp) => {
                if (autoGenerate) {
                  logger.info(s"Writing client certificate and key to ${clientCertPath} and ${clientCertKeyPath}")
                  Files.writeString(new File(clientCertPath).toPath, resp.cert.asPem)
                  Files.writeString(new File(clientCertKeyPath).toPath, resp.key.asPem)
                }
                ks.setKeyEntry(resp.cert.getSubjectDN.getName, resp.key, EMPTY_PASSWORD, Array(resp.cert, resp.ca))
              }
            }
        }
      }
      val keyManagerFactory: KeyManagerFactory = Try(KeyManagerFactory.getInstance("X509")).orElse(Try(KeyManagerFactory.getInstance("SunX509"))).get
      keyManagerFactory.init(ks, EMPTY_PASSWORD)
      val tmf: TrustManagerFactory = Try(TrustManagerFactory.getInstance("X509")).orElse(Try(TrustManagerFactory.getInstance("SunX509"))).get
      tmf.init(ks)
      val sslContext: SSLContext = SSLContext.getInstance("TLS")
      sslContext.init(keyManagerFactory.getKeyManagers, tmf.getTrustManagers, new SecureRandom)
      val https: HttpsConnectionContext = ConnectionContext.https(sslContext, clientAuth = if (mtls) Some(TLSClientAuth.Need) else None)
      http.bindAndHandleAsync(
        handler = handle,
        interface = env.config.interface,
        port = env.config.port,
        connectionContext = https
      ).map { binding =>
        ref.set(binding)
        logger.info(s"pki-tools server started on https://${env.config.hostname}:${env.config.port} - ${env.config.interface}")
      }
    } else {
      http.bindAndHandleAsync(
        handler = handle,
        interface = env.config.interface,
        port = env.config.port
      ).map { binding =>
        ref.set(binding)
        logger.info(s"pki-tools server started on https://${env.config.interface}:${env.config.port}")
      }
    }
  }

  def stop(): Unit = Option(ref.get()).foreach(_.unbind())
}

class ProdEnv(val conf: Config) extends Env {

  def getString(path: String): Option[String] = {
    Try(conf.getString(path)).toOption
  }

  def getLong(path: String): Option[Long] = {
    Try(conf.getLong(path)).toOption
  }

  def getInt(path: String): Option[Int] = {
    Try(conf.getInt(path)).toOption
  }

  def getBoolean(path: String): Option[Boolean] = {
    Try(conf.getBoolean(path)).toOption
  }

  val _config = {

    val snowflakeSeed: Long = getLong("pki.snowflakeSeed").getOrElse(0L)

    val autoGenerate = getBoolean("pki.autoGenerateCertFiles").getOrElse(false)

    val caPath = getString("pki.ca").getOrElse("./ca.pem")
    val caFile = new File(caPath)
    val caKeyPath = getString("pki.caKey").getOrElse("./ca-key.pem")
    val caKeyFile = new File(caKeyPath)

    val (finalCa, finalKey) = Try {
      val caContent = {
        if (caFile.exists()) {
          utils.base64Decode(Files.readString(caFile.toPath).replace(utils.PemHeaders.BeginCertificate, "").replace(utils.PemHeaders.EndCertificate, ""))
        } else {
          utils.base64Decode(caPath.replace(utils.PemHeaders.BeginCertificate, "").replace(utils.PemHeaders.EndCertificate, ""))
        }
      }
      val caKeyContent = {
        if (caKeyFile.exists()) {
          val content = Files.readString(caKeyFile.toPath).replace(utils.PemHeaders.BeginPrivateKey, "").replace(utils.PemHeaders.EndPrivateKey, "").replace(utils.PemHeaders.BeginPrivateRSAKey, "").replace(utils.PemHeaders.EndPrivateRSAKey, "")
          utils.base64Decode(content)
        } else {
          utils.base64Decode(caKeyPath.replace(utils.PemHeaders.BeginPrivateKey, "").replace(utils.PemHeaders.EndPrivateKey, "").replace(utils.PemHeaders.BeginPrivateRSAKey, "").replace(utils.PemHeaders.EndPrivateRSAKey, ""))
        }
      }

      val certificateFactory: CertificateFactory = CertificateFactory.getInstance("X.509")
      val ca = certificateFactory
        .generateCertificate(new ByteArrayInputStream(caContent))
        .asInstanceOf[X509Certificate]
      val encodedKeySpec = new PKCS8EncodedKeySpec(caKeyContent)
      val key: PrivateKey = Try(KeyFactory.getInstance("RSA"))
        .orElse(Try(KeyFactory.getInstance("DSA")))
        .map(_.generatePrivate(encodedKeySpec))
        .get
      (ca, key)
    } match {
      case Success((ca, key)) =>
        logger.info(s"Loading CA cert. from $caPath")
        logger.info(s"Loading CA cert. private key from $caKeyPath")
        (ca, key)
      case Failure(e) =>
        logger.info("Auto-generating CA certificate ...")
        implicit val ec = ExecutionContext.fromExecutor(Executors.newFixedThreadPool(4))
        val pki = new BouncyCastlePki()
        val ca = Await.result(pki.genSelfSignedCA(GenCsrQuery(
          hosts = Seq.empty,
          key = GenKeyPairQuery(),
          name = SortedMap(
            "C" -> "FR",
            "L" -> "Poitiers",
            "O" -> "OtoroshiLabs",
            "OU" -> "CA"
          ).toMap
        )), 30.seconds).right.get
        val caPath = getString("pki.ca").getOrElse("./ca.pem")
        val caKeyPath = getString("pki.caKey").getOrElse("./ca-key.pem")
        if (autoGenerate) {
          logger.info(s"Writing CA certificate and key to ${caPath} and ${caKeyPath}")
          Files.writeString(new File(caPath).toPath, ca.ca.asPem)
          Files.writeString(new File(caKeyPath).toPath, ca.key.asPem)
        }
        (ca.cert, ca.key)
    }

    PkiToolConfig(
      ca = finalCa,
      caKey = finalKey,
      snowflakeSeed = snowflakeSeed,
      interface = getString("pki.http.interface").getOrElse("0.0.0.0"),
      port = getInt("pki.http.port").getOrElse(8443),
      externalPort = getInt("pki.http.externalPort").getOrElse(443),
      hostname = getString("pki.http.hostname").getOrElse("pki.oto.tools"),
      https = getBoolean("pki.http.https").getOrElse(true),
      otoroshi = getBoolean("pki.otoroshi.enabled").getOrElse(false),
      otoroshiSecret = getString("pki.otoroshi.secret").getOrElse("secret"),
      otoroshiIssuer = getString("pki.otoroshi.issuer").getOrElse("Otoroshi")
    )
  }
  override def config: PkiToolConfig = _config
  override def generator: IdGenerator = IdGenerator(_config.snowflakeSeed)
}

object PkiTools {

  val logger = LoggerFactory.getLogger("pki-tools")

  def startServer(overrideConfig: Config): Unit = {
    val env = new ProdEnv(overrideConfig.withFallback(ConfigFactory.load()))
    val pki = new BouncyCastlePki()
    val server = new Server(pki, env)
    server.start()
    Runtime.getRuntime.addShutdownHook(new Thread(new Runnable {
      override def run(): Unit = server.stop()
    }))
  }

  def main(args: Array[String]): Unit = {

    val options = new Options()
    options.addOption("caCert", true, "Path to the cacert file path")
    options.addOption("caKey", true, "Path to the cacert private key file path")
    options.addOption("autogen", false, "Write files when autogenerating a certificate")
    options.addOption("snowflake", true, "Snowflake instance number")
    options.addOption("oto", false, "Serving through Otoroshi")
    options.addOption("otoSecret", true, "Otoroshi secret value")
    options.addOption("otoIss", true, "Otoroshi issuer values")
    options.addOption("https", false, "HTTPS enabled")
    options.addOption("interface", true, "Network Interface for listening")
    options.addOption("port", true, "Port number")
    options.addOption("host", true, "Host name")
    options.addOption("servCert", true, "Server certificate file path")
    options.addOption("servCertKey", true, "Server certificate private key  file path")
    options.addOption("mtls", false, "mTLS enabled")
    options.addOption("cliCert", true, "Client certificate file path")
    options.addOption("cliCertKey", true, "Client certificate private key file path")
    val parser = new DefaultParser()

    def parse(ar: List[String]) = {
      val cmd = parser.parse(options, ar.toArray)
      ConfigFactory.parseString(
        s"""
          |pki.ca = "${Try(cmd.getOptionValue("caCert")).toOption.getOrElse("null")}"
          |pki.caKey = "${Try(cmd.getOptionValue("caKey")).toOption.getOrElse("null")}"
          |pki.autoGenerateCertFiles = ${Try(cmd.getOptionValue("autogen")).toOption.getOrElse("null")}
          |pki.snowflakeSeed = ${Try(cmd.getOptionValue("snowflake")).toOption.getOrElse("null")}
          |pki.otoroshi.enabled = ${Try(cmd.getOptionValue("oto")).toOption.getOrElse("null")}
          |pki.otoroshi.secret = "${Try(cmd.getOptionValue("otoSecret")).toOption.getOrElse("null")}"
          |pki.otoroshi.issuer = "${Try(cmd.getOptionValue("otoIss")).toOption.getOrElse("null")}"
          |pki.http.https = ${Try(cmd.getOptionValue("https")).toOption.getOrElse("null")}
          |pki.http.interface = "${Try(cmd.getOptionValue("interface")).toOption.getOrElse("null")}"
          |pki.http.port = ${Try(cmd.getOptionValue("port")).toOption.getOrElse("null")}
          |pki.http.hostname = "${Try(cmd.getOptionValue("host")).toOption.getOrElse("null")}"
          |pki.http.mtls = ${Try(cmd.getOptionValue("mtls")).toOption.getOrElse("null")}
          |pki.http.cert = "${Try(cmd.getOptionValue("servCert")).toOption.getOrElse("null")}"
          |pki.http.key = "${Try(cmd.getOptionValue("servCertKey")).toOption.getOrElse("null")}"
          |pki.http.clientCert = "${Try(cmd.getOptionValue("cliCert")).toOption.getOrElse("null")}"
          |pki.http.clientKey = "${Try(cmd.getOptionValue("cliCertKey")).toOption.getOrElse("null")}"
        """.stripMargin)
    }

    args.toList match {
      case Nil => startServer(ConfigFactory.empty())
      case "serve" :: tail =>
        startServer(parse(tail))
      case "server" :: tail =>
        startServer(parse(tail))
      case "serve help" :: tail =>
        import org.apache.commons.cli.HelpFormatter
        val formatter = new HelpFormatter
        formatter.printHelp("pki-tools serve", options)
      case "server help" :: tail =>
        import org.apache.commons.cli.HelpFormatter
        val formatter = new HelpFormatter
        formatter.printHelp("pki-tools servers", options)
      case "remote" :: tail =>
        logger.info("Remoting not implemented yet") // TODO
      case "help" :: tail =>
        import org.apache.commons.cli.HelpFormatter
        val formatter = new HelpFormatter
        formatter.printHelp("pki-tools", options)
      case _ =>
        import org.apache.commons.cli.HelpFormatter
        val formatter = new HelpFormatter
        formatter.printHelp("pki-tools", options)
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
    def nextIdSafe(): Option[Long]      = Try(IdGenerator.nextId(generatorId)).toOption
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
}
