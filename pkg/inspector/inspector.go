package inspector

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/inspector2"
	"github.com/aws/aws-sdk-go-v2/service/inspector2/types"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/rootameen/vulpine/pkg/ecr"
	"github.com/rootameen/vulpine/pkg/metrics"
)

type VulpineFinding struct {
	Title          string
	Severity       types.Severity
	FixAvailable   types.FixAvailable
	Remediation    string
	PackageManager types.PackageManager
	RepositoryName string
	ImageTag       string
}

type VulpineFindingsCounts struct {
	CriticalCount      float64
	HighCount          float64
	MediumCount        float64
	LowCount           float64
	InformationalCount float64
}

func CreateInspectorClient(cfg aws.Config) *inspector2.Client {

	client := inspector2.NewFromConfig(cfg)
	return client
}

func ListInspectorFindingsEcr(client *inspector2.Client, results []types.Finding, scanType *string, ecrImageRegistry *string) []types.Finding {

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
			fmt.Println("Loading Paginated Findings ...")
			findings, err = client.ListFindings(context.TODO(), &inspector2.ListFindingsInput{
				NextToken:      findings.NextToken,
				FilterCriteria: defaultFilterCriteria,
			})
			if err != nil {
				panic("Error in Listing findings from Next Token, " + err.Error())
			}
			results = append(results, findings.Findings...)
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

		// Severity: []types.StringFilter{
		// 	{
		// 		Value:      aws.String("CRITICAL"),
		// 		Comparison: "EQUALS",
		// 	},
		// },

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

	for findings.NextToken != nil {
		fmt.Println("Loading Paginated Findings ...")
		findings, err = client.ListFindings(context.TODO(), &inspector2.ListFindingsInput{
			NextToken:      findings.NextToken,
			FilterCriteria: defaultFilterCriteria,
		})
		if err != nil {
			panic("Error in Listing findings from Next Token, " + err.Error())
		}
		results = append(results, findings.Findings...)
	}

	return results
}

func RenderInspectorOutput(ecrRepos []ecr.ECRRepo, results []types.Finding, output *string, format *string, repoTag *string, cfg aws.Config, m *metrics.Metrics) {
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

	t.AppendHeader(table.Row{"#", "Title", "Severity", "Fix Available", "Remediation", "Package Manager", "ECR Repo", "Image Tag", "Onwers"})

	// loop through findings and render output and prometheus metrics

	// reset prometheus metrics for the next run
	m.CriticalSeverity.Reset()
	m.HighSeverity.Reset()
	m.MediumSeverity.Reset()
	m.LowSeverity.Reset()
	m.InformationalSeverity.Reset()

	for num, finding := range results {

		vFinding := VulpineFinding{
			Title:          *finding.Title,
			Severity:       finding.Severity,
			FixAvailable:   finding.FixAvailable,
			Remediation:    *finding.PackageVulnerabilityDetails.VulnerablePackages[0].Remediation,
			PackageManager: finding.PackageVulnerabilityDetails.VulnerablePackages[0].PackageManager,
			RepositoryName: *finding.Resources[0].Details.AwsEcrContainerImage.RepositoryName,
			ImageTag:       finding.Resources[0].Details.AwsEcrContainerImage.ImageTags[0],
		}

		var repoOwners string

		for _, repo := range ecrRepos {

			if vFinding.RepositoryName == repo.RepositoryName {
				repoOwners = repo.RepoTags[*repoTag]
			}
		}
		t.AppendRows([]table.Row{
			{num, vFinding.Title, vFinding.Severity, vFinding.FixAvailable, vFinding.Remediation, vFinding.PackageManager, vFinding.RepositoryName, vFinding.ImageTag, repoOwners},
		})

		// calculate the total number of findings for each severity by cases and increment prometheus metrics
		switch vFinding.Severity {
		case "CRITICAL":
			m.CriticalSeverity.With(prometheus.Labels{"team": repoOwners, "repo": vFinding.RepositoryName, "tag": vFinding.ImageTag, "packagemanager": string(vFinding.PackageManager)}).Inc()
		case "HIGH":
			m.HighSeverity.With(prometheus.Labels{"team": repoOwners, "repo": vFinding.RepositoryName, "tag": vFinding.ImageTag, "packagemanager": string(vFinding.PackageManager)}).Inc()
		case "MEDIUM":
			m.MediumSeverity.With(prometheus.Labels{"team": repoOwners, "repo": vFinding.RepositoryName, "tag": vFinding.ImageTag, "packagemanager": string(vFinding.PackageManager)}).Inc()
		case "LOW":
			m.LowSeverity.With(prometheus.Labels{"team": repoOwners, "repo": vFinding.RepositoryName, "tag": vFinding.ImageTag, "packagemanager": string(vFinding.PackageManager)}).Inc()
		case "INFORMATIONAL":
			m.InformationalSeverity.With(prometheus.Labels{"team": repoOwners, "repo": vFinding.RepositoryName, "tag": vFinding.ImageTag, "packagemanager": string(vFinding.PackageManager)}).Inc()
		}

	}

	if *format == "csv" {
		t.RenderCSV()
	} else {
		t.Render()
	}
}
