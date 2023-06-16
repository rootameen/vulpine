
# Vulpine

Corrolate Security Findings between AWS Inspector, AWS Elastic Container Registry (ECR), and Kubernetes

## The Idea
When running Kubernetes workloads referencing images hosted on AWS Elastic Container Registry (ECR), Security Findings found via AWS Inspector did not contain all the information needed to action the things that matter:

*  Which of those vulnerabilities are actually running on my Kubernetes cluster?
* Who's the team that's responsibile for that container image? 
* Is the reported security finding coming from the Base Image (OS), or the running application code and libraries (GO, JAR, NODE, etc)

The needed info exists, but in different places without any corrolation, hence Vulpine was made

This graph sort of summarized the purpose
![](https://i.imgur.com/yCiXXZi.png)

```
Usage of ./vulpine:
  -ecrImageRegistry string
        ECR Image Registry to scan, e.g. 424851304182
  -ecrProfile string
        AWS Profile to use which contains ECR Repos (default "infra")
  -format string
        output format: table, csv (default "table")
  -k8sctx string
        comma delimited k8s contexts to scan (default "preprod")
  -output string
        output: stdout, filename (default "stdout")
  -repoTag string
        Repo tag to associate with findings (default "Team")
  -scanTarget string
        scanTarget: eks (to show findings for pods in eks), ecr (to show findings for all images in ECR) (default "ecr")
  -scanType string
        scanType type: short (100 findings), full (default "short")        
```

## Scan Modes 
The tool functions in two different ways
  1. Kubernetes Oriented 
  2. ECR Oriented

When setting `-scanTarget` to `eks`, the tool will load the currently running pods from the provided comma delimeted list of kubernetes contexts provided with `-k8sctx`, and display the relevant security findings only for those running images from AWS Inspector. 

If `-scanTarget` is set to `ecr`, the tool will display the entire findings of ECR, the benefit here is that you'll also see any required additional tag from Image Repo Tags. If your org specifies a tag "Team" on ECR repos, you can set that tag via `-repoTag` parameter to see that info with the findings. 

## What's next
TBD, plenty of ideas could be added to add functionality, improve output, speed, and much more. Contributions are more than welcome :]

