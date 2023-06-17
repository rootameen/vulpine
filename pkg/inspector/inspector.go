package inspector

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/rootameen/vulpine/pkg/ecr"
)

func CreateInspectorClient(cfg aws.Config) *inspector2.Client {

	client := inspector2.NewFromConfig(cfg)
	return client
}

func ListInspectorFindings(client *inspector2.Client, results []types.Finding, scanType *string, ecrImageRegistry *string) []types.Finding {

	defaultFilterCriteria := &types.FilterCriteria{
		// Severity
		Severity: []types.StringFilter{
			{
				Value:      aws.String("CRITICAL"),
				Comparison: "EQUALS",
			},
			{
				Value:      aws.String("HIGH"),
				Comparison: "EQUALS",
			},
		},
		// ECR Registry
		EcrImageRegistry: []types.StringFilter{
			{
				Value:      aws.String(*ecrImageRegistry),
				Comparison: "EQUALS",
			},
		},
		FindingStatus: []types.StringFilter{
			{
				Value:      aws.String("ACTIVE"),
				Comparison: "EQUALS",
			},
		},
	}

	findings, err := client.ListFindings(context.TODO(), &inspector2.ListFindingsInput{
		FilterCriteria: defaultFilterCriteria,
	})

	if err != nil {
		panic("error in Listing Findings, " + err.Error())
	}

	results = append(results, findings.Findings...)

	if *scanType == "full" {
		fmt.Println("Scan Type is full, getting more findings")
		for findings.NextToken != nil {
			fmt.Println("NextToken is not nil, getting more findings")
			findings, err = client.ListFindings(context.TODO(), &inspector2.ListFindingsInput{
				NextToken:      findings.NextToken,
				FilterCriteria: defaultFilterCriteria,
			})
			if err != nil {
				panic("Error in Listing findings from Next Token, " + err.Error())
			}
			results = append(results, findings.Findings...)
			fmt.Println(len(results))
		}
	}

	return results
}

func ListInspectorFindingsByImageID(client *inspector2.Client, results []types.Finding, imageID string) []types.Finding {

	defaultFilterCriteria := &types.FilterCriteria{

		EcrImageHash: []types.StringFilter{
			{
				Value:      aws.String(imageID),
				Comparison: "EQUALS",
			},
		},

		FindingStatus: []types.StringFilter{
			{
				Value:      aws.String("ACTIVE"),
				Comparison: "EQUALS",
			},
		},
	}

	findings, err := client.ListFindings(context.TODO(), &inspector2.ListFindingsInput{
		FilterCriteria: defaultFilterCriteria,
	})

	if err != nil {
		panic("error in Listing Findings, " + err.Error())
	}

	results = append(results, findings.Findings...)

	return results
}

func ListInspectorFindingsByRepoImage(client *inspector2.Client, results []types.Finding, repoName string, imageTag string) []types.Finding {

	defaultFilterCriteria := &types.FilterCriteria{

		EcrImageRepositoryName: []types.StringFilter{
			{
				Value:      aws.String(repoName),
				Comparison: "EQUALS",
			},
		},

		EcrImageTags: []types.StringFilter{
			{
				Value:      aws.String(imageTag),
				Comparison: "EQUALS",
			},
		},

		FindingStatus: []types.StringFilter{
			{
				Value:      aws.String("ACTIVE"),
				Comparison: "EQUALS",
			},
		},
	}

	findings, err := client.ListFindings(context.TODO(), &inspector2.ListFindingsInput{
		FilterCriteria: defaultFilterCriteria,
	})

	if err != nil {
		panic("error in Listing Findings, " + err.Error())
	}

	results = append(results, findings.Findings...)

	return results
}

func RenderInspectorOutput(ecrRepos []ecr.ECRRepo, results []types.Finding, output *string, format *string, repoTag *string, cfg aws.Config) {
	t := table.NewWriter()

	if *output == "stdout" {
		t.SetOutputMirror(os.Stdout)
	} else {
		f, err := os.Create(*output)
		if err != nil {
			panic("Error creating output file: " + err.Error())
		}
		defer f.Close()
		t.SetOutputMirror(f)
	}

	t.AppendHeader(table.Row{"#", "Title", "Severity", "Fix Available", "Remediation", "Package Manager", "ECR Repo", "Onwers"})

	for num, finding := range results {

		var repoOwners string

		for _, repo := range ecrRepos {

			if *finding.Resources[0].Details.AwsEcrContainerImage.RepositoryName == repo.RepositoryName {
				repoOwners = repo.RepoTags[*repoTag]
			}
		}
		t.AppendRows([]table.Row{
			{num, *finding.Title, finding.Severity, finding.FixAvailable, *finding.PackageVulnerabilityDetails.VulnerablePackages[0].Remediation, finding.PackageVulnerabilityDetails.VulnerablePackages[0].PackageManager, *finding.Resources[0].Details.AwsEcrContainerImage.RepositoryName, repoOwners},
		})
	}

	if *format == "csv" {
		t.RenderCSV()
	} else {
		t.Render()
	}
}
