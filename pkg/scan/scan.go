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
		pods := eks.GenerateClusterImageList(k8sctx)
		for _, pod := range pods {
			fmt.Printf("** Obtaining findings for running pod: Repo: %s, ImageTag: %s\n", pod.Repo, pod.ImageTag)
			results = inspector.ListInspectorFindingsByRepoImage(inspectorClient, results, pod.Repo, pod.ImageTag)
		}
	}
	return results
}
