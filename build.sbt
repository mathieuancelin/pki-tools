import Dependencies._

ThisBuild / scalaVersion     := "2.12.8"
ThisBuild / version          := "1.0.0-dev"
ThisBuild / organization     := "io.otoroshi.ssl"
ThisBuild / organizationName := "pki-tools"

lazy val root = (project in file("."))
  .settings(
    name := "pki-tools",
    mainClass in (Compile, run) := Some("io.otoroshi.ssl.pki.PkiTools"),
    libraryDependencies ++= Seq(
      "com.github.blemale"       %% "scaffeine"                % "3.1.0",
      "org.shredzone.acme4j"     %  "acme4j-client"            % "2.8",
      "org.shredzone.acme4j"     %  "acme4j-utils"             % "2.8",
      "org.shredzone.acme4j"     %  "acme4j"                   % "2.7",
      "com.typesafe.play"        %% "play-json"                % "2.6.8",
      "com.typesafe.play"        %% "play-json-joda"           % "2.6.8",
      "com.typesafe.akka"        %% "akka-http"                % "10.1.11",
      "com.typesafe.akka"        %% "akka-stream"              % "2.6.1",
      scalaTest % Test
    )
  )
