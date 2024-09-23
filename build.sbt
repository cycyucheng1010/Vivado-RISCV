val chiselVersion = "3.5.1"
val firrtlVersion = "1.5.1"
val chiselTestVersion = "2.5.1"

lazy val commonSettings = Seq(
  organization := "edu.berkeley.cs",
  version := "1.6", //1.0
  scalaVersion := "2.12.10",
  crossScalaVersions := Seq("2.12.10"),
  parallelExecution in Global := false,
  scalacOptions ++= Seq("-deprecation","-unchecked","-Xsource:2.11","-P:chiselplugin:useBundlePlugin"),
  addCompilerPlugin("edu.berkeley.cs" % "chisel3-plugin" % chiselVersion cross CrossVersion.full),
  libraryDependencies ++= Seq("edu.berkeley.cs" %% "chisel3" % chiselVersion))

lazy val vivado = (project in file("."))
  .dependsOn(boom)
  .dependsOn(rocketchip)
  .dependsOn(sifive_cache)
  .dependsOn(gemmini)
  .dependsOn(fft_generator)
  .dependsOn(dsptools)
  .dependsOn(rocket_dsp_utils)
  .settings(libraryDependencies ++= rocketLibDeps.value)
  .settings(commonSettings)

lazy val rocketchip = (project in file("rocket-chip"))
  .dependsOn(rocketConfig)
  .settings(commonSettings)

lazy val rocketLibDeps = (rocketchip / Keys.libraryDependencies)


lazy val testchipip = (project in file("generators/testchipip"))
  .dependsOn(rocketchip)
  .settings(commonSettings)
  .settings(includeFilter in unmanagedSources := { "Util.scala" || "TraceIO.scala" })

lazy val boom = (project in file("generators/riscv-boom"))
  .dependsOn(rocketchip)
  .dependsOn(testchipip)
  .settings(commonSettings)
  .settings(addCompilerPlugin("org.scalamacros" % "paradise" % "2.1.1" cross CrossVersion.full))

lazy val sifive_cache = (project in file("generators/sifive-cache"))
  .dependsOn(rocketchip)
  .settings(commonSettings)
  .settings(scalaSource in Compile := baseDirectory.value / "design/craft")

lazy val gemmini = (project in file("generators/gemmini"))
  .dependsOn(rocketchip)
  .dependsOn(testchipip)
  .dependsOn(targetutils)
  .settings(commonSettings)

lazy val targetutils = (project in file("generators/targetutils"))
  .settings(commonSettings)

lazy val fft_generator = (project in file("generators/fft-generator"))
  .dependsOn(rocketchip, rocket_dsp_utils)
  .settings(libraryDependencies ++= rocketLibDeps.value)
  .settings(commonSettings)

lazy val dsptools = freshProject("dsptools", file("rocket-chip/dsptools")) //./tools/dsptools
  .settings(
    chiselSettings,
    chiselTestSettings,
    commonSettings,
    libraryDependencies ++= Seq(
      "org.scalatest" %% "scalatest" % "3.2.+" % "test",
      "org.typelevel" %% "spire" % "0.16.2",
      "org.scalanlp" %% "breeze" % "1.1",
      "junit" % "junit" % "4.13" % "test",
      "org.scalacheck" %% "scalacheck" % "1.14.3" % "test",
  ))


val rocketChipDir = file("generators/rocket-chip")
lazy val rocketConfig = (project in rocketChipDir / "api-config-chipsalliance/build-rules/sbt")
  .settings(commonSettings)
  .settings(
    libraryDependencies ++= Seq(
      "org.scala-lang" % "scala-reflect" % scalaVersion.value,
      "org.json4s" %% "json4s-jackson" % "3.6.1",
      "org.scalatest" %% "scalatest" % "3.2.0" % "test"
    )
  )


lazy val api_config_chipsalliance = freshProject("api-config-chipsalliance", file("rocket-chip/api-config-chipsalliance")) // ./tools/api-config-chipsalliance
  .settings(
    commonSettings,
    libraryDependencies ++= Seq(
      "org.scalatest" %% "scalatest" % "3.0.+" % "test",
      "org.scalacheck" %% "scalacheck" % "1.14.3" % "test",
    ))

lazy val rocket_dsp_utils = freshProject("rocket-dsp-utils", file("rocket-chip/rocket-dsp-utils")) // ./tools/rocket-dsp-utils
  .dependsOn(rocketchip, api_config_chipsalliance, dsptools)
  .settings(libraryDependencies ++= rocketLibDeps.value)
  .settings(commonSettings)

lazy val sifive_blocks = (project in file("generators/sifive-blocks"))
  .dependsOn(rocketchip)
  .settings(libraryDependencies ++= rocketLibDeps.value)
  .settings(commonSettings)

def freshProject(name: String, dir: File): Project = {
  Project(id = name, base = dir / "src")
    .settings(
      Compile / scalaSource := baseDirectory.value / "main" / "scala",
      Compile / resourceDirectory := baseDirectory.value / "main" / "resources"
    )
}



lazy val chiselSettings = Seq(
   libraryDependencies ++= Seq("edu.berkeley.cs" %% "chisel3" % chiselVersion,
   "org.apache.commons" % "commons-lang3" % "3.12.0",
   "org.apache.commons" % "commons-text" % "1.9"),
   addCompilerPlugin("edu.berkeley.cs" % "chisel3-plugin" % chiselVersion cross CrossVersion.full))



lazy val firrtlSettings = Seq(libraryDependencies ++= Seq("edu.berkeley.cs" %% "firrtl" % firrtlVersion))

lazy val chiselTestSettings = Seq(libraryDependencies ++= Seq("edu.berkeley.cs" %% "chisel-iotesters" % chiselTestVersion))
