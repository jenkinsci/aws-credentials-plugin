# Changelog

### Version 1.28 (Sep 2nd, 2019)

-   [PR\#69](https://github.com/jenkinsci/aws-credentials-plugin/pull/69):
    Fix for an obvious case of
     \[[JENKINS-58842](https://issues.jenkins-ci.org/browse/JENKINS-58842)\].

### Version 1.27 (May 14th, 2019)

-   [PR\#54](https://github.com/jenkinsci/aws-credentials-plugin/pull/54):
    \[[JENKINS-57426](https://issues.jenkins-ci.org/browse/JENKINS-57426)\]
    Make pipeline-model-extensions dependency optional.

### Version 1.26 (Feb 25th, 2019)

-   [PR\#48](https://github.com/jenkinsci/aws-credentials-plugin/pull/48):
    Configurable Session Token Duration.
-   [PR\#51](https://github.com/jenkinsci/aws-credentials-plugin/pull/51): Define
    default region for STS actions to fix regression introduced in 1.24

### Version 1.25 (Feb 24th, 2019)

-   [PR\#50](https://github.com/jenkinsci/aws-credentials-plugin/pull/50):
    \[JENKINS-53101\] Add Declarative credentials handler for AWS creds.

### Version 1.24 (Nov 18th, 2018)

-   [PR\#46](https://github.com/jenkinsci/aws-credentials-plugin/pull/46):
    Use the default provider chain from the AWS SDK.

### Version 1.23 (Sept 28th, 2017)

-   [PR\#33](https://github.com/jenkinsci/aws-credentials-plugin/pull/33): 
    -   Bump to Java 7 as minimum requirement
    -   Bump to 1.625.1 as minimum Jenkins version
    -   Update credentials plugin dependency to version 2.1.6

### Version 1.22 (Aug 30th, 2017)

-   "Assume Role" support improvements

### Version 1.21 (Jun 15th, 2017)

-   Fix backward compatibility issue introduced by v1.17

### Version 1.20 (Jun 3rd, 2017)

-   [JENKINS-41967](https://issues.jenkins-ci.org/browse/JENKINS-41967):
    Fix backward compatibility issue introduced by v1.17

### Version 1.19 (Jan 23, 2017)

-   Fix backward compatibility issue introduced by v1.17

### Version 1.18 (Jan 23, 2017)

-   Expose method through interface for getting credentials with MFA
    token passed in

### Version 1.17 (Jan 13th, 2017)

-   Add support for assuming IAM roles ([PR
    \#12](https://github.com/jenkinsci/aws-credentials-plugin/pull/12))

### Version 1.16 (Jul 1st, 2016)

-   [JENKINS-35017](https://issues.jenkins-ci.org/browse/JENKINS-35017):
    Migrate to new parent POM.
    