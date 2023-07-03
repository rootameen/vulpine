package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

type Metrics struct {
	CriticalSeverity      *prometheus.CounterVec
	HighSeverity          *prometheus.CounterVec
	MediumSeverity        *prometheus.CounterVec
	LowSeverity           *prometheus.CounterVec
	InformationalSeverity *prometheus.CounterVec
}

func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		CriticalSeverity: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "vulpine",
			Name:      "critical_vulns_total",
			Help:      "Number of Critical Vulnerabilities",
		}, []string{"team", "repo", "tag", "packagemanager"}),
		HighSeverity: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "vulpine",
			Name:      "high_vulns_total",
			Help:      "Number of High Vulnerabilities",
		}, []string{"team", "repo", "tag", "packagemanager"}),
		MediumSeverity: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "vulpine",
			Name:      "medium_vulns_total",
			Help:      "Number of Medium Vulnerabilities",
		}, []string{"team", "repo", "tag", "packagemanager"}),
		LowSeverity: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "vulpine",
			Name:      "low_vulns_total",
			Help:      "Number of Low Vulnerabilities",
		}, []string{"team", "repo", "tag", "packagemanager"}),
		InformationalSeverity: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: "vulpine",
			Name:      "informational_vulns_total",
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
