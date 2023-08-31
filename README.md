# R_and_D

## Utils
1. SearchVulnerableDependencyWithinFatJar.java
   * Useful for finding out all the usages of a vulnerable jar by the current apps 3rd party dependencies.
   * So basically when your code uses the latest non-vulnerable version of a jar, but some of the 3rd party dependency is pulling in a vulnerable version and the Vulnerability Scan flags the usage of vulnerable jar.
