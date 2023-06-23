package main

import (
	"context"
	"flag"
	"log"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/rootameen/vulpine/pkg/ecr"
	"github.com/rootameen/vulpine/pkg/eks"
	"github.com/rootameen/vulpine/pkg/inspector"
)

func main() {

	// flags

	output := flag.String("output", "stdout", "output: stdout, filename")
	format := flag.String("format", "table", "output format: table, csv")
	repoTag := flag.String("repoTag", "Team", "Repo tag to associate with findings")
	k8sctx := flag.String("k8sctx", "preprod", "comma delimited k8s contexts to scan")
	scanTarget := flag.String("scanTarget", "ecr", "scanTarget: eks (to show findings for pods in eks), ecr (to show findings for all images in ECR)")
	scanType := flag.String("scanType", "short", "scanType type: short (100 findings), full")
	ecrImageRegistry := flag.String("ecrImageRegistry", "", "ECR Image Registry to scan, e.g. 424851304182")
	ecrProfile := flag.String("ecrProfile", "", "AWS Profile to use which contains ECR Repos")

	flag.Parse()

	var cfg aws.Config
	var err error

	// ECR AWS Account Auth
	if *ecrProfile == "" {
		cfg, err = config.LoadDefaultConfig(context.TODO(), config.WithRegion("eu-central-1"))
		if err != nil {
			log.Fatalf("Unable to load SDK config, %v", err)
		}

	} else {
		cfg, err = config.LoadDefaultConfig(context.TODO(), config.WithRegion("eu-central-1"), config.WithSharedConfigProfile(*ecrProfile))
		if err != nil {
			log.Fatalf("Unable to load SDK config, %v", err)
		}
	}
	// generate list of ECR Repos and images
	ecrRepos := ecr.GenerateEcrImageList(cfg)

	// generate list of k8s pods

	var results []types.Finding
	inspectorClient := inspector.CreateInspectorClient(cfg)

	if *scanTarget == "ecr" {
		// scan ECR
		results = inspector.ListInspectorFindings(inspectorClient, results, scanType, ecrImageRegistry)
	} else if *scanTarget == "eks" {
		ctxs := strings.Split(*k8sctx, ",")

		kubeconfig := eks.LoadKubeconfig()

		var pods []eks.Pod

		for _, ctx := range ctxs {
			eks.SwitchContext(ctx, *kubeconfig)

			clientset := eks.ConfigureKubeconfig(*kubeconfig)
			pods = eks.GenerateClusterPodList(clientset, pods)
		}
		// scan k8s pods
		// loop all the RepoImages in ecrRepos and set ImageDeployed to true if image is found in running k8s pods
		deployedImages := make(map[string]string)
		eks.IsImageDeployed(ecrRepos, pods, deployedImages)
		for repoName, imageTag := range deployedImages {
			results = inspector.ListInspectorFindingsByRepoImage(inspectorClient, results, repoName, imageTag)
		}
	}

	inspector.RenderInspectorOutput(ecrRepos, results, output, format, repoTag, cfg)

}
