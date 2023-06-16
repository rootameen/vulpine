package eks

import (
	"context"
	"fmt"
	"strings"

	"github.com/rootameen/vulpine/pkg/ecr"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"
)

type Pod struct {
	Name      string
	Namespace string
	Image     string
	ImageID   string
	ImageTag  string
	Repo      string
}

func SwitchContext(ctx, kubeconfig string) (err error) {
	config, err := clientcmd.LoadFromFile(kubeconfig)

	if err != nil {
		return err
	}

	rawConfig, err := clientcmd.NewDefaultClientConfig(*config, &clientcmd.ConfigOverrides{}).RawConfig()
	if err != nil {
		return err
	}
	if rawConfig.Contexts[ctx] == nil {
		return fmt.Errorf("context %s doesn't exists", ctx)
	}
	rawConfig.CurrentContext = ctx
	err = clientcmd.ModifyConfig(clientcmd.NewDefaultPathOptions(), rawConfig, true)
	return
}

func ConfigureKubeconfig(kubeconfig string) *kubernetes.Clientset {

	config, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		panic(err.Error())
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		panic(err.Error())
	}
	return clientset
}

func GenerateClusterPodList(clientset *kubernetes.Clientset, runningPods []Pod) []Pod {

	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}

	// define vars outside of loop

	var podName, podNamespace, podImage, podImageID, podImageTag, podRepo string

	for _, pod := range pods.Items {
		if len(pod.Status.ContainerStatuses) > 0 {
			podName = pod.Name
			podNamespace = pod.Namespace
			if pod.Status.ContainerStatuses[0].ImageID != "" {
				podImageID = strings.Split(pod.Status.ContainerStatuses[0].ImageID, "@")[1]
				podImage = pod.Status.ContainerStatuses[0].ImageID
			}
			podImageTag = strings.Split(pod.Status.ContainerStatuses[0].Image, ":")[1]
			podRepo = strings.SplitN(strings.Split(pod.Status.ContainerStatuses[0].Image, ":")[0], "/", 2)[1]
			runningPods = append(runningPods, Pod{podName, podNamespace, podImage, podImageID, podImageTag, podRepo})

		}
	}

	return runningPods
}

func IsImageDeployed(ecrRepos []ecr.ECRRepo, pods []Pod, deployedImages map[string]string) {
	for i, repo := range ecrRepos {
		for j, image := range repo.RepoImages {
			for _, pod := range pods {
				if pod.Repo == repo.RepositoryName && pod.ImageID == image.ImageDigest {
					ecrRepos[i].RepoImages[j].ImageDeployed = true
					deployedImages[repo.RepositoryName] = pod.ImageTag
				}
			}
		}
	}
}
