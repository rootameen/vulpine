package scan

import (
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/rootameen/vulpine/pkg/ecr"
	"github.com/rootameen/vulpine/pkg/eks"
	"github.com/rootameen/vulpine/pkg/inspector"
)

func ScanFindings(scanTarget *string, results []types.Finding, inspectorClient *inspector2.Client, scanType *string, ecrImageRegistry *string, k8sctx *string, ecrRepos []ecr.ECRRepo) []types.Finding {

	if *scanTarget == "ecr" {

		results = inspector.ListInspectorFindings(inspectorClient, results, scanType, ecrImageRegistry)
	} else if *scanTarget == "eks" {
		ctxs := strings.Split(*k8sctx, ",")

		kubeconfig := eks.LoadKubeconfig()

		var pods []eks.Pod

		for _, ctx := range ctxs {
			eks.SwitchContext(ctx, kubeconfig)

			clientset := eks.ConfigureKubeconfig(kubeconfig)
			pods = eks.GenerateClusterPodList(clientset, pods)
		}

		deployedImages := make(map[string]string)
		eks.IsImageDeployed(ecrRepos, pods, deployedImages)
		for repoName, imageTag := range deployedImages {
			results = inspector.ListInspectorFindingsByRepoImage(inspectorClient, results, repoName, imageTag)
		}
	}
	return results
}
