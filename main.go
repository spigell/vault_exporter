package main

import (
	"os"
	"time"
	"io/ioutil"
	"net/http"
	_ "net/http/pprof"


	vault_api "github.com/hashicorp/vault/api"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"github.com/prometheus/common/version"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v2"
)

var (
	config = kingpin.Flag("config", "path to config file").Default("/etc/vault_exporter.yml").String()
	listenAddress = kingpin.Flag("web.listen-address",
		"Address to listen on for web interface and telemetry.").
		Default(":9410").String()
	metricsPath = kingpin.Flag("web.telemetry-path",
		"Path under which to expose metrics.").
		Default("/metrics").String()
	vaultCACert = kingpin.Flag("vault-tls-cacert",
		"The path to a PEM-encoded CA cert file to use to verify the Vault server SSL certificate.").String()
	vaultClientCert = kingpin.Flag("vault-tls-client-cert",
		"The path to the certificate for Vault communication.").String()
	vaultClientKey = kingpin.Flag("vault-tls-client-key",
		"The path to the private key for Vault communication.").String()
	sslInsecure = kingpin.Flag("insecure-ssl",
		"Set SSL to ignore certificate validation.").
		Default("false").Bool()
)

const (
	namespace = "vault"
)

var (
	up = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "up"),
		"Was the last query of Vault successful.",
		nil, nil,
	)
	initialized = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "initialized"),
		"Is the Vault initialised (according to this node).",
		nil, nil,
	)
	sealed = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "sealed"),
		"Is the Vault node sealed.",
		nil, nil,
	)
	standby = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "standby"),
		"Is this Vault node in standby.",
		nil, nil,
	)
	info = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "info"),
		"Version of this Vault node.",
		[]string{"version", "cluster_name", "cluster_id"}, nil,
	)
	tokenStatus = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "tokens_time_of_expire"),
		"Expire time for token by accessor id",
		[]string{"accessor_id"}, nil,
	)
)

// Exporter collects Vault health from the given server and exports them using
// the Prometheus metrics package.
type Exporter struct {
	client *vault_api.Client
	Config *Config
}

type Config struct {
	AccessorIds    []string `yaml:accessorids`
}


// NewExporter returns an initialized Exporter.
func NewExporter(c *Config) (*Exporter, error) {
	vaultConfig := vault_api.DefaultConfig()


	if *sslInsecure {
		tlsconfig := &vault_api.TLSConfig{
			Insecure: true,
		}
		err := vaultConfig.ConfigureTLS(tlsconfig)
		if err != nil {
			return nil, err
		}
	}

	if *vaultCACert != "" || *vaultClientCert != "" || *vaultClientKey != "" {

		tlsconfig := &vault_api.TLSConfig{
			CACert:     *vaultCACert,
			ClientCert: *vaultClientCert,
			ClientKey:  *vaultClientKey,
			Insecure:   *sslInsecure,
		}
		err := vaultConfig.ConfigureTLS(tlsconfig)
		if err != nil {
			return nil, err
		}
	}

	client, err := vault_api.NewClient(vaultConfig)
	if err != nil {
		return nil, err
	}

	return &Exporter{
		client: client,
		Config: c,
	}, nil
}

// Describe describes all the metrics ever exported by the Vault exporter. It
// implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	ch <- up
	ch <- initialized
	ch <- sealed
	ch <- standby
	ch <- info
	ch <- tokenStatus
}

func bool2float(b bool) float64 {
	if b {
		return 1
	}
	return 0
}

// Collect fetches the stats from configured Vault and delivers them
// as Prometheus metrics. It implements prometheus.Collector.
func (e *Exporter) checkTokens ( accessorId string) ( float64, error ) {

	data, err := e.client.Auth().Token().LookupAccessor(accessorId)

	if err != nil {
		return 0, err
	}

	metadata := data.Data
	ex := metadata["expire_time"]

	str := ex.(string)
		t, errStr := time.Parse(time.RFC3339, str)

	if errStr != nil {
		return 0, err
	}

	timestamp := float64(t.Unix())

        return timestamp, nil
}

func (e *Exporter) Collect(ch chan<- prometheus.Metric) {

	if os.Getenv("VAULT_TOKEN") != "" {

		e.client.SetToken(os.Getenv("VAULT_TOKEN"))

		accessorIds := e.Config.AccessorIds

		for _, accessorId := range accessorIds {
			timestamp, err := e.checkTokens(accessorId)

			if err != nil {
				log.Errorf("Get info AccessorId `%s` failed. Error: %s", accessorId, err)
				ch <- prometheus.MustNewConstMetric(
					tokenStatus, prometheus.GaugeValue, 0, accessorId,
				)
				continue
			}

			ch <- prometheus.MustNewConstMetric(
				tokenStatus, prometheus.GaugeValue, timestamp, accessorId,
			)
		}

	}

	health, err := e.client.Sys().Health()
	if err != nil {
		ch <- prometheus.MustNewConstMetric(
			up, prometheus.GaugeValue, 0,
		)
		log.Errorf("Failed to collect health from Vault server: %v", err)
		return
	}

	ch <- prometheus.MustNewConstMetric(
		up, prometheus.GaugeValue, 1,
	)
	ch <- prometheus.MustNewConstMetric(
		initialized, prometheus.GaugeValue, bool2float(health.Initialized),
	)
	ch <- prometheus.MustNewConstMetric(
		sealed, prometheus.GaugeValue, bool2float(health.Sealed),
	)
	ch <- prometheus.MustNewConstMetric(
		standby, prometheus.GaugeValue, bool2float(health.Standby),
	)
	ch <- prometheus.MustNewConstMetric(
		info, prometheus.GaugeValue, 1, health.Version, health.ClusterName, health.ClusterID,
	)

}

func init() {
	prometheus.MustRegister(version.NewCollector("vault_exporter"))
}

func main() {
	log.AddFlags(kingpin.CommandLine)
	kingpin.Version(version.Print("vault_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	log.Infoln("Starting vault_exporter", version.Info())
	log.Infoln("Build context", version.BuildContext())

	file, err := os.Open(*config)
        if err != nil {
                log.Fatalln(err2)
        }

	configuration := Config{}
	target, err := ioutil.ReadAll(file)

        if err != nil {
                log.Fatalln(err)
        }

	if err := yaml.Unmarshal(target, &configuration); err != nil {

                log.Fatalln(err)
	}

	exporter, err := NewExporter(&configuration)
	if err != nil {
		log.Fatalln(err)
	}
	prometheus.MustRegister(exporter)

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(`<html>
             <head><title>Vault Exporter</title></head>
             <body>
             <h1>Vault Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             <h2>Build</h2>
             <pre>` + version.Info() + ` ` + version.BuildContext() + `</pre>
             </body>
             </html>`))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	log.Infoln("Listening on", *listenAddress)
	log.Fatal(http.ListenAndServe(*listenAddress, nil))
}
