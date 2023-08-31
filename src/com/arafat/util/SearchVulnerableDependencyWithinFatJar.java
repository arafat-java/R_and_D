package com.arafat.util;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.stream.Stream;

/**
 * This is a utility class that can be used to search for a vulnerable dependency across a fat jar
 * Useful when your code uses the latest non-vulnerable version of a jar, but some of the 3rd party
 * dependency is pulling in a vulnerable version and the Vulnerability Scan flags the usage of
 * vulnerable jar
 */
public class SearchVulnerableDependencyWithinFatJar {

  private static final List<String> matches = new ArrayList<>();
  private static final Set<String> jarsWithMatches = new HashSet<>();
  private static final Set<String> pomsWithMatches = new HashSet<>();
  public static final String SECTION_SEPERATOR =
    "----------------------------------------------------------------------------------";

  public static void main(String[] args) throws Exception {
    if (args.length < 2) {
      logError("Usage: java SearchVulnerableDependencyWithinFatJar <jarFilePath> <dependencyName>");
      return;
    }

    String jarFilePath = args[0];
    if (args.length == 3) {
      String destinationFolder = args[2];
      if (!destinationFolder.endsWith("/")) {
        destinationFolder = destinationFolder + "/";
      }
      String existingFileName = new File(jarFilePath).getName();
      Path destinationJarPath = Files.copy(Path.of(jarFilePath), Path.of(destinationFolder + existingFileName),
        StandardCopyOption.REPLACE_EXISTING);
      jarFilePath = destinationJarPath.toString();
    }
    File outputDir = new File(jarFilePath + "_exploded");
    Path outputDirPath = Path.of(outputDir.getAbsolutePath());
    if (outputDir.exists()) {
      try (Stream<Path> pathStream = Files.walk(outputDirPath)) {
        pathStream
          .sorted(Comparator.reverseOrder())
          .map(Path::toFile)
          .forEach(File::delete);
      }
    }


    String vulnerableDependencyName = args[1].toLowerCase();
    logInfo("Starting introspection for :- " + args[0]);
    logInfo("Starting introspection for :- " + vulnerableDependencyName);
    explodeJarRecursively(jarFilePath, vulnerableDependencyName);

    logInfo("Introspection completed.");
    logInfo("\nOverall matches as follows");
    logInfo(SECTION_SEPERATOR);
    matches.forEach(SearchVulnerableDependencyWithinFatJar::logInfo);

    logInfo("\n\n\nFollowing poms contain vulnerable dependency :- " + vulnerableDependencyName);
    logInfo(SECTION_SEPERATOR);
    pomsWithMatches.forEach(SearchVulnerableDependencyWithinFatJar::logInfo);

    logInfo("\n\n\nFollowing jars contain vulnerable dependency :- " + vulnerableDependencyName);
    logInfo(SECTION_SEPERATOR);
    jarsWithMatches.forEach(SearchVulnerableDependencyWithinFatJar::logInfo);
  }

  private static void explodeJarRecursively(String jarFilePath, String dependencyName) throws Exception {
    File jarFile = new File(jarFilePath);

    if (!jarFile.exists() || !jarFile.isFile() || !jarFilePath.endsWith(".jar")) {
      logError("Invalid JAR file: " + jarFilePath);
      return;
    }

    File outputDir = new File(jarFile.getParent(), jarFile.getName() + "_exploded");
    if (!outputDir.exists() && !outputDir.mkdirs()) {
      logError("Failed to create directory :- " + outputDir);
    }

    try (JarFile jar = new JarFile(jarFile)) {
      ArrayList<JarEntry> fileList = Collections.list(jar.entries());

      for (JarEntry entry : fileList) {
        handleIndividualFile(dependencyName, entry, outputDir, jarFile, jar);
      }
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  private static void handleIndividualFile(String dependencyName, JarEntry entry, File outputDir, File jarFile,
                                           JarFile jar)
    throws Exception {
    File file = new File(outputDir, entry.getName());
    if (file.getAbsolutePath().toLowerCase().contains(dependencyName) && !file.getName().endsWith(".class")) {
      matches.add(file.getAbsolutePath());
      jarsWithMatches.add(jarFile.getName());
    }

    if (entry.isDirectory()) {
      file.mkdirs();
    } else if (!file.getName().endsWith(".class")) {
      String parent = file.getParent();
      createFolderHierarchy(parent);

      extractAndCreateFile(entry, jar, file);
      if (file.getAbsolutePath().toLowerCase().contains(dependencyName) && file.getName().endsWith("pom.xml")) {
        String dependencyVersion = extractDependencyVersionFromPomFile(file, dependencyName);
        pomsWithMatches.add(String.format("%15s    %s", dependencyVersion, file.getAbsolutePath()));
      }
    }

    if (file.getName().endsWith(".jar")) {
      explodeJarRecursively(file.getAbsolutePath(), dependencyName);
    }
  }

  private static String extractDependencyVersionFromPomFile(File pomFile, String dependencyName)
    throws ParserConfigurationException, IOException, SAXException {
    DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
    DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
    Document doc = dBuilder.parse(pomFile);

    doc.getDocumentElement().normalize();

    NodeList dependenciesList = doc.getElementsByTagName("project");
    for (int temp = 0; temp < dependenciesList.getLength(); temp++) {
      Node dependencyNode = dependenciesList.item(temp);

      if (dependencyNode.getNodeType() == Node.ELEMENT_NODE) {
        Element dependencyElement = (Element) dependencyNode;
        String groupId = dependencyElement.getElementsByTagName("groupId").item(0).getTextContent();
        String artifactId = dependencyElement.getElementsByTagName("artifactId").item(0).getTextContent();
        String version = dependencyElement.getElementsByTagName("version").item(0).getTextContent();
        if (artifactId.toLowerCase().contains(dependencyName)) {
          return version;
        }

        if (dependencyName.equals(groupId + ":" + artifactId)) {
          return version;
        }
      }
    }
    return null;
  }

  private static void extractAndCreateFile(JarEntry entry, JarFile jar, File entryFile) {
    try (InputStream is = jar.getInputStream(entry); OutputStream os = new FileOutputStream(entryFile)) {
      byte[] buffer = new byte[4096];
      int bytesRead;
      while ((bytesRead = is.read(buffer)) != -1) {
        os.write(buffer, 0, bytesRead);
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  public static void createFolderHierarchy(String path) {
    File folder = new File(path);
    if (!folder.exists()) {
      boolean created = folder.mkdirs();
      if (!created) {
        logError("Failed to create directory :- " + path);
      }
    }
  }

  private static void logInfo(String message) {
    System.out.println(message);
  }

  private static void logError(String message) {
    System.err.println(message);
  }
}
