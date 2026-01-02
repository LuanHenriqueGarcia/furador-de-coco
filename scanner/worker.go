package scanner

import (
	"net/http"
	"sync"
	"time"
)

// WorkerPool gerencia workers para processar formulários em paralelo
type WorkerPool struct {
	workers   int
	jobs      chan ScanJob
	results   chan ScanJobResult
	wg        sync.WaitGroup
	rateLimit time.Duration
}

// ScanJob representa um trabalho de scan
type ScanJob struct {
	Form      Form
	BaseURL   string
	FormIndex int
}

// ScanJobResult representa o resultado de um scan
type ScanJobResult struct {
	FormIndex   int
	Form        Form
	XSSVuln     bool
	SQLiVuln    bool
	XSSResults  []XSSResult
	SQLiResults []SQLiResult
	Error       error
}

// NewWorkerPool cria um novo pool de workers
func NewWorkerPool(workers int, rateLimit time.Duration) *WorkerPool {
	return &WorkerPool{
		workers:   workers,
		jobs:      make(chan ScanJob, workers*2),
		results:   make(chan ScanJobResult, workers*2),
		rateLimit: rateLimit,
	}
}

// Start inicia os workers
func (wp *WorkerPool) Start(client *http.Client) {
	for i := 0; i < wp.workers; i++ {
		wp.wg.Add(1)
		go wp.worker(client)
	}
}

// Submit envia um job para o pool
func (wp *WorkerPool) Submit(job ScanJob) {
	wp.jobs <- job
}

// Close fecha o pool e aguarda conclusão
func (wp *WorkerPool) Close() {
	close(wp.jobs)
	wp.wg.Wait()
	close(wp.results)
}

// Results retorna o canal de resultados
func (wp *WorkerPool) Results() <-chan ScanJobResult {
	return wp.results
}

// worker processa jobs do pool
func (wp *WorkerPool) worker(client *http.Client) {
	defer wp.wg.Done()

	for job := range wp.jobs {
		result := ScanJobResult{
			FormIndex: job.FormIndex,
			Form:      job.Form,
		}

		// Testa XSS com resultados detalhados
		result.XSSResults = TestXSSDetailed(job.Form, job.BaseURL, client)
		for _, xssResult := range result.XSSResults {
			if xssResult.Vulnerable {
				result.XSSVuln = true
				break
			}
		}

		// Rate limiting entre testes
		time.Sleep(wp.rateLimit)

		// Testa SQLi com resultados detalhados
		result.SQLiResults = TestSQLiDetailed(job.Form, job.BaseURL, client)
		for _, sqliResult := range result.SQLiResults {
			if sqliResult.Vulnerable {
				result.SQLiVuln = true
				break
			}
		}

		wp.results <- result

		// Rate limiting após conclusão do job
		time.Sleep(wp.rateLimit)
	}
}
