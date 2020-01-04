import Dependencies._
import sbt.Keys.publishArtifact

ThisBuild / scalaVersion     := "2.12.8"
ThisBuild / version          := "1.0.0-dev"
ThisBuild / organization     := "io.otoroshi.pki"
ThisBuild / organizationName := "pki-tools"

lazy val root = (project in file("."))
  .enablePlugins(JavaServerAppPackaging)
  .settings(
    name := "pki-tools",
    mainClass in (Compile, run) := Some("io.otoroshi.pki.PkiTools"),
    mainClass in reStart := Some("io.otoroshi.pki.PkiTools"),
    mainClass in assembly := Some("io.otoroshi.pki.PkiTools"),
    sources in (Compile, doc) := Seq.empty,
    publishArtifact in (Compile, packageDoc) := false,
    parallelExecution in Test := false,
    test in assembly := {},
    assemblyJarName in assembly := "pki-tools.jar",
    assemblyMergeStrategy in assembly := {
      case PathList("org", "apache", "commons", "logging", xs @ _*)       => MergeStrategy.first
      case PathList(ps @ _*) if ps.last == "io.netty.versions.properties" => MergeStrategy.first
      case PathList(ps @ _*) if ps.contains("reference-overrides.conf")   => MergeStrategy.concat
      case PathList(ps @ _*) if ps.contains("module-info.class")          => MergeStrategy.first // ???
      case PathList("javax", xs @ _*)                                     => MergeStrategy.first
      case x =>
        val oldStrategy = (assemblyMergeStrategy in assembly).value
        oldStrategy(x)
    },
    libraryDependencies ++= Seq(
      // "com.github.blemale"       %% "scaffeine"                % "3.1.0",
      // "org.shredzone.acme4j"     %  "acme4j-client"            % "2.8",
      // "org.shredzone.acme4j"     %  "acme4j-utils"             % "2.8",
      // "org.shredzone.acme4j"     %  "acme4j"                   % "2.7",
      "org.bouncycastle"         %  "bcprov-jdk15on"           % "1.64",
      "org.bouncycastle"         %  "bcpkix-jdk15on"           % "1.64",
      "org.bouncycastle"         %  "bcpg-jdk15on"             % "1.64",
      "com.typesafe.play"        %% "play-json"                % "2.6.8",
      "com.typesafe.play"        %% "play-json-joda"           % "2.6.8",
      "com.typesafe.akka"        %% "akka-http"                % "10.1.11",
      "com.typesafe.akka"        %% "akka-stream"              % "2.6.1",
      "com.auth0"                % "java-jwt"                  % "3.4.0",
      scalaTest % Test
    )
  )
