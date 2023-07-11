package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

type Metrics struct {
	CriticalSeverity      *prometheus.GaugeVec
	HighSeverity          *prometheus.GaugeVec
	MediumSeverity        *prometheus.GaugeVec
	LowSeverity           *prometheus.GaugeVec
	InformationalSeverity *prometheus.GaugeVec
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		CriticalSeverity: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "vulpine",
			Name:      "critical_vulns",
			Help:      "Number of Critical Vulnerabilities",
		}, []string{"team", "repo", "tag", "packagemanager"}),
		HighSeverity: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "vulpine",
			Name:      "high_vulns",
			Help:      "Number of High Vulnerabilities",
		}, []string{"team", "repo", "tag", "packagemanager"}),
		MediumSeverity: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "vulpine",
			Name:      "medium_vulns",
			Help:      "Number of Medium Vulnerabilities",
		}, []string{"team", "repo", "tag", "packagemanager"}),
		LowSeverity: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "vulpine",
			Name:      "low_vulns",
			Help:      "Number of Low Vulnerabilities",
		}, []string{"team", "repo", "tag", "packagemanager"}),
		InformationalSeverity: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Namespace: "vulpine",
			Name:      "informational_vulns",
			Help:      "Number of Informational Vulnerabilities",
		}, []string{"team", "repo", "tag", "packagemanager"}),
	}
	reg.MustRegister(m.CriticalSeverity)
	reg.MustRegister(m.HighSeverity)
	reg.MustRegister(m.MediumSeverity)
	reg.MustRegister(m.LowSeverity)
	reg.MustRegister(m.InformationalSeverity)

	return m
}
