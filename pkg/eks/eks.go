package eks

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
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

func LoadKubeconfig() string {
	var kubeconfig string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = filepath.Join(home, ".kube", "config")
	}
	return kubeconfig
}

func GenerateClusterImageList(k8sctx *string) []Pod {
	var (
		clientSet *kubernetes.Clientset
		// Pods is the struct of pods that will be used to compare with ECR images
		pods []Pod
	)

	if *k8sctx == "" {
		// in-cluster scanning
		config, err := rest.InClusterConfig()
		if err != nil {
			panic(err.Error())
		}
		// create the clientset
		clientSet, err = kubernetes.NewForConfig(config)
		if err != nil {
			panic(err.Error())
		}

		pods = GetPods(clientSet, pods)

		return pods

	} else {
		// out-of-cluster scanning, loop through contexts
		ctxs := strings.Split(*k8sctx, ",")
		kubeconfig := LoadKubeconfig()

		for _, ctx := range ctxs {
			SwitchContext(ctx, kubeconfig)
			clientSet = ConfigureKubeconfig(kubeconfig)
		}
	}

	pods = GetPods(clientSet, pods)

	return pods
}

func GetPods(clientSet *kubernetes.Clientset, pods []Pod) []Pod {
	// k8sPods is the raw data of pods returned from the k8s API
	var k8sPods *v1.PodList

	k8sPods, err := clientSet.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		panic(err.Error())
	}

	var podName, podNamespace, podImage, podImageID, podImageTag, podRepo string

	for _, pod := range k8sPods.Items {
		if len(pod.Status.ContainerStatuses) > 0 {
			podName = pod.Name
			podNamespace = pod.Namespace
			if pod.Status.ContainerStatuses[0].ImageID != "" {
				if strings.Contains(pod.Status.ContainerStatuses[0].ImageID, "@") {
					podImageID = strings.Split(pod.Status.ContainerStatuses[0].ImageID, "@")[1]
					podImage = pod.Status.ContainerStatuses[0].ImageID
				} else {
					podImageID = pod.Status.ContainerStatuses[0].ImageID
					podImage = strings.Split(pod.Status.ContainerStatuses[0].Image, ":")[0]
				}
			}
			podImageTag = strings.Split(pod.Status.ContainerStatuses[0].Image, ":")[1]
			podRepo = strings.SplitN(strings.Split(pod.Status.ContainerStatuses[0].Image, ":")[0], "/", 2)[1]
			pods = append(pods, Pod{podName, podNamespace, podImage, podImageID, podImageTag, podRepo})

		}
	}
	return pods
}
