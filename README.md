# Rinha de Backend 2026 — Detecção de Fraude

Implementação em C#/.NET para a edição 2026 da Rinha de Backend, focada em baixa latência e uso restrito de recursos na classificação de transações.

O serviço recebe uma transação em `POST /fraud-score`, converte seus atributos em um vetor numérico e consulta referências pré-processadas com busca aproximada de vizinhos. A resposta informa se a transação foi aprovada e a pontuação de fraude.

## Decisões técnicas

- ASP.NET Core minimal API em .NET 10
- Parsing manual do corpo JSON para reduzir alocações
- `ArrayPool`, `stackalloc` e buffers de resposta pré-alocados
- Índice vetorial binário carregado no início da aplicação
- Busca aproximada de 5 vizinhos para a decisão de fraude
- Duas instâncias da API atrás de HAProxy
- Comunicação entre proxy e APIs por Unix Domain Sockets
- Imagens Alpine e limites de CPU/memória definidos no Compose

## Executar

Pré-requisito: Docker com Docker Compose.

```bash
docker compose up --build
```

O HAProxy expõe a aplicação em `http://localhost:9999`.

### Endpoints

| Método | Rota | Finalidade |
| --- | --- | --- |
| `GET` | `/ready` | Verifica se o índice de referências foi carregado. |
| `POST` | `/fraud-score` | Calcula a decisão e a pontuação de fraude para uma transação. |

O endpoint de fraude segue o payload definido pela competição e retorna uma resposta neste formato:

```json
{
  "approved": true,
  "fraud_score": 0.2
}
```

## Estrutura

```text
src/                 API e mecanismo de busca vetorial
src/Data/            referências compactadas e índice binário
tools/Preprocessor/  geração do índice a partir das referências
haproxy.cfg          balanceamento entre as duas instâncias
docker-compose.yml   topologia e limites de recursos
```

Durante o build, o pré-processador gera `references.bin` a partir de `references.json.gz`; em seguida, a API publica somente os artefatos necessários para consulta.

## Licença

[MIT](LICENSE)
