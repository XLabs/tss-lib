package tss

import (
	"fmt"
	"time"

	// TODO: Consider what to do with metrics.
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	common "github.com/xlabs/tss-common"

	"go.uber.org/zap"
)

var (
	// counter of expired. and state it might be bad due to the distributed nature of the system.
	// Same with inProgressSigs.

	sigProducedCntr = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "wormhole_tss_signature_produced",
			Help: "total number of tss signatures produced",
		}, []string{"chain_name"}, // followed example from ccq
	)

	tooManySimulSigsErrCntr = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "wormhole_tss_too_many_somultaneous_signatures",
			Help: "total number of tss signing requests that were rejected due to too many simultaneous signature requests",
		},
	)

	sigLatency = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "wormhole_tss_signature_latency",
			Help: "Histogram of the times taken to produce a signature",
		}, []string{"chain_name"}, //followed example from ccq
	)

	signatureEndingWithError = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "wormhole_tss_signature_ending_with_error",
			Help: "total number of tss signatures that ended with an error",
		},
	)
)

// used for collecting metrics.
type signatureMetadata struct {
	timeOfCreation time.Time
}

func (t *Engine) createSignatureMetrics(tid *common.TrackingID) {
	key := trackingIdIntoSigKey(tid)
	t.SignatureMetrics.Store(key, &signatureMetadata{
		timeOfCreation: time.Now(),
	})
}

func (t *Engine) sigMetricDone(trackid *common.TrackingID, hadIssue bool) {
	key := trackingIdIntoSigKey(trackid)

	metrics, ok := t.loadMetric(key, trackid)
	if !ok {
		return
	}

	if hadIssue {
		signatureEndingWithError.Inc()

		return
	}

	protocoltype, _ := trackid.GetProtocolType()
	sigProducedCntr.
		WithLabelValues(protocoltype.ToString()).
		Inc()

	latency := time.Since(metrics.timeOfCreation)
	sigLatency.WithLabelValues(protocoltype.ToString()).Observe(float64(latency.Milliseconds()))

	t.SignatureMetrics.Delete(key)

	t.logger.Info("tss signature produced",
		zap.String("tid", trackid.ToString()),
		zap.Duration("protocol duration", latency),
	)
}

func (t *Engine) loadMetric(key sigKey, trackid *common.TrackingID) (*signatureMetadata, bool) {
	tmp, loaded := t.SignatureMetrics.Load(key)
	if !loaded {
		return nil, false
	}

	metrics, ok := tmp.(*signatureMetadata)
	if !ok {
		t.logger.Error("signature metrics stored is of wrong type",
			zap.String("digest", fmt.Sprintf("%x", trackid.Digest)),
			zap.Any("metrics", tmp),
		)

		return nil, false
	}

	return metrics, true
}
