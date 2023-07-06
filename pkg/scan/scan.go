package scan

import (
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/rootameen/vulpine/pkg/ecr"
	"github.com/rootameen/vulpine/pkg/eks"
	"github.com/rootameen/vulpine/pkg/inspector"
)

func ScanFindings(scanTarget *string, results []types.Finding, inspectorClient *inspector2.Client, scanType *string, ecrImageRegistry *string, k8sctx *string, ecrRepos []ecr.ECRRepo) []types.Finding {

	if *scanTarget == "ecr" {
		results = inspector.ListInspectorFindingsEcr(inspectorClient, results, scanType, ecrImageRegistry)
	} else if *scanTarget == "eks" {
		pods := eks.GenerateClusterPodList(k8sctx)
		deployedImages := make(map[string]string)
		eks.IsImageDeployed(ecrRepos, pods, deployedImages)
		for repoName, imageTag := range deployedImages {
			fmt.Println("Obtaining findings for running image: ", repoName, imageTag)
			results = inspector.ListInspectorFindingsByRepoImage(inspectorClient, results, repoName, imageTag)
		}
	}
	return results
}
