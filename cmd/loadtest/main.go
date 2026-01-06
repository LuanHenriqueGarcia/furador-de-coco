package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"furador-de-coco/loadtest"
)

func main() {
	// Flags do teste de carga
	url := flag.String("url", "", "URL alvo para teste de carga (obrigatório)")
	requests := flag.Int("requests", 1000, "Número total de requisições")
	concurrency := flag.Int("concurrency", 50, "Número de workers concorrentes")
	timeout := flag.Int("timeout", 30, "Timeout em segundos para cada requisição")
	delay := flag.Int("delay", 0, "Delay em milissegundos entre requisições (0 = sem delay)")

	flag.Parse()

	if *url == "" {
		fmt.Println("ERRO: URL é obrigatória")
		fmt.Println("\nUso: go run cmd/loadtest/main.go -url <URL> [opções]")
		fmt.Println("\nOpções:")
		flag.PrintDefaults()
		fmt.Println("\nAVISO: Use apenas em servidores próprios ou com autorização explícita!")
		fmt.Println("Testes de carga não autorizados podem ser considerados ataques DoS.")
		os.Exit(1)
	}

	// Confirmação de segurança
	fmt.Println("\n╔════════════════════════════════════════════════════════════╗")
	fmt.Println("║  TESTE DE CARGA - FURADOR DE COCO                         ║")
	fmt.Println("╚════════════════════════════════════════════════════════════╝")
	fmt.Println("\nAVISO IMPORTANTE:")
	fmt.Println("- Use apenas em servidores de sua propriedade")
	fmt.Println("- Obtenha autorização antes de testar servidores de terceiros")
	fmt.Println("- Testes não autorizados podem ser considerados crimes")
	fmt.Println("\nDeseja continuar? (s/N): ")

	var response string
	fmt.Scanln(&response)

	if response != "s" && response != "S" {
		fmt.Println("Teste cancelado.")
		os.Exit(0)
	}

	// Configura teste
	config := loadtest.LoadTestConfig{
		URL:              *url,
		TotalRequests:    *requests,
		Concurrency:      *concurrency,
		Timeout:          time.Duration(*timeout) * time.Second,
		DelayBetweenReqs: time.Duration(*delay) * time.Millisecond,
	}

	// Limites de segurança
	if config.TotalRequests > 100000 {
		fmt.Println("AVISO: Limitando para 100.000 requisições por segurança")
		config.TotalRequests = 100000
	}
	if config.Concurrency > 500 {
		fmt.Println("AVISO: Limitando para 500 workers por segurança")
		config.Concurrency = 500
	}
	if config.DelayBetweenReqs < 0 {
		fmt.Println("AVISO: Delay não pode ser negativo")
		config.DelayBetweenReqs = 0
	}

	// Executa teste
	result, err := loadtest.RunLoadTest(config)
	if err != nil {
		fmt.Printf("Erro ao executar teste: %v\n", err)
		os.Exit(1)
	}

	// Mostra resultados
	loadtest.PrintResults(result)
}
