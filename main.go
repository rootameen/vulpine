package main

import (
	"context"
	"flag"
	"log"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rootameen/vulpine/pkg/ecr"
	"github.com/rootameen/vulpine/pkg/inspector"
	"github.com/rootameen/vulpine/pkg/metrics"
	"github.com/rootameen/vulpine/pkg/scan"
	"github.com/rootameen/vulpine/pkg/server"
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
	listenAddr := flag.String("listenAddr", ":8080", "Listen address for prometheus metrics")

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

	inspectorClient := inspector.CreateInspectorClient(cfg)

	// instantiate prometheus registry and metrics struct
	reg := prometheus.NewRegistry()
	promMetrics := metrics.NewMetrics(reg)

	// run a scan every hour
	go func() {
		for {
			var results []types.Finding
			results = scan.ScanFindings(scanTarget, results, inspectorClient, scanType, ecrImageRegistry, k8sctx, ecrRepos)
			inspector.RenderInspectorOutput(ecrRepos, results, output, format, repoTag, cfg, promMetrics)
			time.Sleep(3600 * time.Second)
		}
	}()

	server.ExposeMetrics(reg, *listenAddr)

}
