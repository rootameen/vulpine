package ecr

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
)

type ECRRepo struct {
	RepositoryName string
	RepositoryArn  string
	RepoImages     []RepoImage
	RepoTags       map[string]string
}

type RepoImage struct {
	ImageDigest   string
	ImageTag      string
	ImageDeployed bool
}

func GenerateEcrImageList(cfg aws.Config) []ECRRepo {
	client := ecr.NewFromConfig(cfg)

	var ecrRepo []ECRRepo

	repos, err := client.DescribeRepositories(context.TODO(), &ecr.DescribeRepositoriesInput{
		MaxResults: aws.Int32(350),
	})
	if err != nil {
		fmt.Printf("Unable to list repositories, %v", err.Error())
	}

	for _, repo := range repos.Repositories {

		// Set RepositoryArn and RepoTags
		repoArn := *repo.RepositoryArn
		repoTags := make(map[string]string)

		tags, err := client.ListTagsForResource(context.TODO(), &ecr.ListTagsForResourceInput{
			ResourceArn: &repoArn,
		})

		for _, tag := range tags.Tags {
			repoTags[*tag.Key] = *tag.Value
		}

		if err != nil {
			fmt.Printf("Unable to list repositories, %v", err.Error())
		}

		imgs, _ := client.ListImages(context.TODO(), &ecr.ListImagesInput{
			RepositoryName: aws.String(*repo.RepositoryName),
			// MaxResults:     aws.Int32(2),
		})
		var repoImages []RepoImage
		for _, image := range imgs.ImageIds {
			if image.ImageTag == nil {
				image.ImageTag = aws.String("untagged")
			}
			repoImages = append(repoImages, RepoImage{*image.ImageDigest, *image.ImageTag, false})
		}

		ecrRepo = append(ecrRepo, ECRRepo{*repo.RepositoryName, repoArn, repoImages, repoTags})
	}
	return ecrRepo
}

func ImageLookup(ecrRepos []ECRRepo, digestLookup string) (string, string, bool) {

	if digestLookup != "" {
		digestLookup = strings.Split(digestLookup, "@")[1]
		fmt.Println("Length of ecrRepos:", len(ecrRepos))
		for _, repo := range ecrRepos {
			fmt.Printf("Working on repo: %s\n", repo.RepositoryName)
			for _, image := range repo.RepoImages {
				fmt.Printf("Working on repo image %s\n", image.ImageDigest)
				if digestLookup != "" {

					if image.ImageDigest == digestLookup {
						return repo.RepositoryName, image.ImageDigest, true

					} else {
					}
				}

			}
		}

	}

	return "", "", false
}
