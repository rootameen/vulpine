# Vulpine

Correlate Security Findings between AWS Inspector, AWS Elastic Container Registry (ECR), and Kubernetes

## The Idea

When running Kubernetes workloads referencing images hosted on AWS Elastic Container Registry (ECR), Security Findings found via AWS Inspector did not contain all the information needed to action the things that matter:

* Which of those vulnerabilities are actually running on my Kubernetes cluster?
* Who's the team that's responsibile for that container image?
* Is the reported security finding coming from the Base Image (OS), or the running application code and libraries (GO, JAR, NODE, etc)

The needed info exists, but in different places without any corrolation, hence Vulpine was made

This graph summarizes the use case:
![](https://i.imgur.com/yCiXXZi.png)

```
Usage of ./vulpine:
  -ecrImageRegistry string
        ECR Image Registry to scan, e.g. 424851304182
  -ecrProfile string
        AWS Profile to use which contains ECR Repos
  -format string
        output format: table, csv (default "table")
  -interval int
        interval in seconds to run scan when in server mode (default 60)
  -k8sctx string
        comma delimited k8s contexts to scan (default "preprod")
  -listenAddr string
        Listen address for prometheus metrics (default ":8080")
  -mode string
        mode: cli (to run a scan once), server (to run a scan every hour and expose metrics) (default "cli")
  -output string
        output: stdout, filename (default "stdout")
  -repoTag string
        Repo tag to associate with findings (default "Team")
  -scanTarget string
        scanTarget: eks (to show findings for pods in eks), ecr (to show findings for all images in ECR) (default "ecr")
  -scanType string
        scanType type: short (100 findings), full (default "short")       
```

## Examples

### Kubernetes Scanning

To scan a single or multiple kubernetes clusters against findings in inspector, you need to provide:

* Kubernetes context, or multiple comma separated contexts
* AWS account ID of the ECR Profile
* Set Scan Target as EKS
* AWS profile containing your ECR repo, as defined in `~/.aws/config`.

#### Scan a single kubernetes cluster

```
vulpine -ecrImageRegistry 424851304182 -ecrProfile infra -k8sctx preprod -scanTarget eks
```

#### Scan multiple kubernetes cluster

```
vulpine -ecrImageRegistry 424851304182 -ecrProfile infra -k8sctx preprod,prod -scanTarget eks
```

### ECR Scanning

To scan and display the entire findings on ECR, to benefit from fiding who's the owner of each finding, it can be done with:

```
vulpine -ecrImageRegistry 424851304182 -ecrProfile infra -scanTarget ecr
```

## Output
It is possible for output to be sent to a file and formatted in CSV, instead of printing as a table or sending to stdout.
```
+----+------------------------------------------------------------+----------+---------------+----------------------------------------------------+-----------------+-----------------------------------------------+-----------------------+
|  # | TITLE                                                      | SEVERITY | FIX AVAILABLE | REMEDIATION                                        | PACKAGE MANAGER | ECR REPO                                      | ONWERS                |
+----+------------------------------------------------------------+----------+---------------+----------------------------------------------------+-----------------+-----------------------------------------------+-----------------------+
|  0 | CVE-2023-0215 - openssl-libs, openssl                      | HIGH     | YES           | yum update openssl-libs                            | OS              | network-ninjas-repository/config-client       | Network Ninjas        |
|  1 | CVE-2015-8394 - pcre                                       | HIGH     | YES           | yum update pcre                                    | OS              | product-engineering/pe-stats                  | Product Engineering   |
|  2 | CVE-2019-17563 - org.apache.tomcat.embed:tomcat-embed-core | HIGH     | YES           | Update tomcat-embed-core to 9.0.30                 | JAR             | bi/intelligent                                | Business Intelligence |
|  3 | CVE-2021-21348 - com.thoughtworks.xstream:xstream          | HIGH     | YES           | Update xstream to 1.4.16                           | JAR             | infra/jenkins-slave                           | Business Intelligence |
|  4 | CVE-2021-43859 - com.thoughtworks.xstream:xstream          | HIGH     | YES           | Update xstream to 1.4.19                           | JAR             | snapshots/services/actionwrapper              | Data 2                |
|  5 | CVE-2019-0232 - org.apache.tomcat.embed:tomcat-embed-core  | HIGH     | YES           | Update tomcat-embed-core to 9.0.18                 | JAR             | snapshots/products/instant-service            | Product Engineering   |
|  6 | CVE-2021-3999 - glibc                                      | HIGH     | YES           | apt-get update && apt-get upgrade                  | OS              | snapshots/infrastructure/outbound-traffic     | Data 1                |
|  7 | CVE-2022-4450 - openssl, openssl                           | HIGH     | YES           | apt-get update && apt-get upgrade                  | OS              | infra/fluentd                                 | Business Intelligence |
|  8 | CVE-2022-25235 - libexpat1                                 | HIGH     | YES           | apt update && apt install --only-upgrade libexpat1 | OS              | network-ninjas-repository/some-random-service | Network Ninjas        |
+----+------------------------------------------------------------+----------+---------------+----------------------------------------------------+-----------------+-----------------------------------------------+-----------------------+
```

## More about Scan Modes

The tool functions in two different ways

  1. Kubernetes Oriented
  2. ECR Oriented

When setting `-scanTarget` to `eks`, the tool will load the currently running pods from the provided comma delimeted list of kubernetes contexts provided with `-k8sctx`, and display the relevant security findings only for those running images from AWS Inspector.

If `-scanTarget` is set to `ecr`, the tool will display the entire findings of ECR. The column `ONWERS` display info from tags that are user defined during the creation of the ECR repository itself. If your org specifies a tag "Team" or "Stakeholders" on ECR repos, you can set that tag via `-repoTag` parameter to see that info with the findings, which is useful when using this mode to have a general view about the everything hosted on your registry. 

Please note that `-ecrProfile` flag only required if both Scan Target is `eks` and that `ecr` is coming from a different account. In `ecr` scan mode, or if k8s and ECR are running from the same profile, the profile can be loaded automatically via short-term credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN` environment variables)

## Metrics

When running in `server` mode, Vulpine exposes prometheus format metrics about vulnerabilities and counts
```
$ curl http://localhost:8080/metrics
# HELP promhttp_metric_handler_errors_total Total number of internal errors encountered by the promhttp metric handler.
# TYPE promhttp_metric_handler_errors_total counter
promhttp_metric_handler_errors_total{cause="encoding"} 0
promhttp_metric_handler_errors_total{cause="gathering"} 0
# HELP vulpine_critical_vulns_total Number of Critical Vulnerabilities
# TYPE vulpine_critical_vulns_total counter
vulpine_critical_vulns_total{packagemanager="JAR",repo="service/core-service",tag="3.0.3",team="core-svc-team"} 1
vulpine_critical_vulns_total{packagemanager="JAR",repo="service/billing-checks",tag="3.0.9",team="core-svc-team"} 1
# HELP vulpine_high_vulns_total Number of High Vulnerabilities
# TYPE vulpine_high_vulns_total counter
vulpine_high_vulns_total{packagemanager="GOBINARY",repo="network-ninjas-repository/config-client",tag="v1.10.2",team="Network Ninjas"} 1
vulpine_high_vulns_total{packagemanager="OS",repo="data/data-injector",tag="1.4.0",team="Data 1"} 2
# HELP vulpine_informational_vulns_total Number of Informational Vulnerabilities
# TYPE vulpine_informational_vulns_total counter
vulpine_informational_vulns_total{packagemanager="OS",repo="nn/packet-inspector",tag="6.6.3",team="Network Ninjas"} 5
# HELP vulpine_low_vulns_total Number of Low Vulnerabilities
# TYPE vulpine_low_vulns_total counter
vulpine_low_vulns_total{packagemanager="JAR",repo="data/svc1",tag="1.15.0",team="Data 1"} 1
# HELP vulpine_medium_vulns_total Number of Medium Vulnerabilities
# TYPE vulpine_medium_vulns_total counter
vulpine_medium_vulns_total{packagemanager="JAR",repo="service/core-service",tag="3.0.3",team="core-svc-team"} 1
```