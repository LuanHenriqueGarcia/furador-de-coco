package loadtest

import (
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// LoadTestResult contém os resultados do teste de carga
type LoadTestResult struct {
	TotalRequests    int64
	SuccessRequests  int64
	FailedRequests   int64
	TotalDuration    time.Duration
	RequestsPerSec   float64
	AvgResponseTime  time.Duration
	MinResponseTime  time.Duration
	MaxResponseTime  time.Duration
	StatusCodeCounts map[int]int64
}

// LoadTestConfig configura o teste de carga
type LoadTestConfig struct {
	URL              string
	TotalRequests    int
	Concurrency      int
	Timeout          time.Duration
	DelayBetweenReqs time.Duration
}

// RunLoadTest executa teste de carga com controle responsável
func RunLoadTest(config LoadTestConfig) (*LoadTestResult, error) {
	fmt.Println("\n=== TESTE DE CARGA ===")
	fmt.Printf("AVISO: Use apenas em servidores próprios ou com autorização!\n")
	fmt.Printf("URL: %s\n", config.URL)
	fmt.Printf("Total de requisições: %d\n", config.TotalRequests)
	fmt.Printf("Concorrência: %d workers\n", config.Concurrency)
	fmt.Printf("Delay entre requisições: %v\n", config.DelayBetweenReqs)
	fmt.Println("Iniciando em 3 segundos...")
	time.Sleep(3 * time.Second)

	result := &LoadTestResult{
		StatusCodeCounts: make(map[int]int64),
		MinResponseTime:  time.Hour, // Valor alto inicial
	}

	var (
		wg            sync.WaitGroup
		requestCount  int64
		successCount  int64
		failedCount   int64
		responseTimes []time.Duration
		mutex         sync.Mutex
	)

	startTime := time.Now()

	// Cria canal de trabalho
	jobs := make(chan int, config.TotalRequests)

	// Cria workers
	for i := 0; i < config.Concurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()

			client := &http.Client{
				Timeout: config.Timeout,
			}

			for range jobs {
				// Delay controlado
				if config.DelayBetweenReqs > 0 {
					time.Sleep(config.DelayBetweenReqs)
				}

				reqStart := time.Now()
				resp, err := client.Get(config.URL)
				reqDuration := time.Since(reqStart)

				atomic.AddInt64(&requestCount, 1)

				if err != nil {
					atomic.AddInt64(&failedCount, 1)
					fmt.Printf("\r[ERRO] Worker %d: %v", workerID, err)
					continue
				}

				resp.Body.Close()

				atomic.AddInt64(&successCount, 1)

				// Atualiza estatísticas
				mutex.Lock()
				responseTimes = append(responseTimes, reqDuration)
				result.StatusCodeCounts[resp.StatusCode]++

				if reqDuration < result.MinResponseTime {
					result.MinResponseTime = reqDuration
				}
				if reqDuration > result.MaxResponseTime {
					result.MaxResponseTime = reqDuration
				}
				mutex.Unlock()

				// Mostra progresso
				current := atomic.LoadInt64(&requestCount)
				fmt.Printf("\rProgresso: %d/%d (%.1f%%) | Sucesso: %d | Falhas: %d",
					current, config.TotalRequests,
					float64(current)/float64(config.TotalRequests)*100,
					atomic.LoadInt64(&successCount),
					atomic.LoadInt64(&failedCount))
			}
		}(i)
	}

	// Envia jobs
	for i := 0; i < config.TotalRequests; i++ {
		jobs <- i
	}
	close(jobs)

	// Aguarda conclusão
	wg.Wait()

	totalDuration := time.Since(startTime)

	// Calcula estatísticas finais
	result.TotalRequests = requestCount
	result.SuccessRequests = successCount
	result.FailedRequests = failedCount
	result.TotalDuration = totalDuration
	result.RequestsPerSec = float64(requestCount) / totalDuration.Seconds()

	if len(responseTimes) > 0 {
		var totalResponseTime time.Duration
		for _, rt := range responseTimes {
			totalResponseTime += rt
		}
		result.AvgResponseTime = totalResponseTime / time.Duration(len(responseTimes))
	}

	return result, nil
}

// PrintResults imprime os resultados do teste
func PrintResults(result *LoadTestResult) {
	fmt.Println("\n\n=== RESULTADOS DO TESTE DE CARGA ===")
	fmt.Printf("Duração total: %v\n", result.TotalDuration)
	fmt.Printf("Total de requisições: %d\n", result.TotalRequests)
	fmt.Printf("Requisições bem-sucedidas: %d\n", result.SuccessRequests)
	fmt.Printf("Requisições falhadas: %d\n", result.FailedRequests)
	fmt.Printf("Taxa de sucesso: %.2f%%\n",
		float64(result.SuccessRequests)/float64(result.TotalRequests)*100)
	fmt.Printf("Requisições por segundo: %.2f\n", result.RequestsPerSec)
	fmt.Printf("\nTempo de resposta:\n")
	fmt.Printf("  Mínimo: %v\n", result.MinResponseTime)
	fmt.Printf("  Médio: %v\n", result.AvgResponseTime)
	fmt.Printf("  Máximo: %v\n", result.MaxResponseTime)

	fmt.Println("\nCódigos de status HTTP:")
	for code, count := range result.StatusCodeCounts {
		fmt.Printf("  %d: %d requisições\n", code, count)
	}

	// Avaliação de performance
	fmt.Println("\n=== AVALIAÇÃO ===")
	if result.FailedRequests > result.TotalRequests/10 {
		fmt.Println("CRÍTICO: Mais de 10% das requisições falharam!")
	}
	if result.AvgResponseTime > 5*time.Second {
		fmt.Println("ALERTA: Tempo médio de resposta muito alto (>5s)")
	} else if result.AvgResponseTime > 2*time.Second {
		fmt.Println("ATENÇÃO: Tempo médio de resposta alto (>2s)")
	} else if result.AvgResponseTime < 500*time.Millisecond {
		fmt.Println("EXCELENTE: Tempo de resposta rápido (<500ms)")
	} else {
		fmt.Println("BOM: Tempo de resposta aceitável")
	}

	if result.RequestsPerSec < 10 {
		fmt.Println("BAIXO THROUGHPUT: Servidor processando menos de 10 req/s")
	} else if result.RequestsPerSec > 100 {
		fmt.Println("ALTO THROUGHPUT: Servidor processando mais de 100 req/s")
	}
}
