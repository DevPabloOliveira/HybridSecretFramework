# Guia do Repositório

## Propósito

O HybridSecretFramework varre artefatos recuperados do GitHub em busca de segredos
expostos, tentando evitar o principal problema de scanners baseados apenas em
Regex: confundir credenciais reais com exemplos, hashes, identificadores,
capturas de tela, placeholders e símbolos de código.

O repositório usa uma arquitetura híbrida em cinco camadas:

1. Recuperação
2. Parsing
3. Extração de Features
4. Classificação
5. Relato, Priorização e Validação

## Fluxo de Alto Nível

```text
busca de padrões no GitHub
  -> recuperação de arquivos brutos
  -> extração inicial por Regex e entropia
  -> seleção do parser por linguagem/caminho
  -> extração de AST e contexto
  -> engenharia de features
  -> baseline heurístico ou modelo supervisionado
  -> findings explicáveis
  -> validação opcional por provedor
```

## Estrutura de Diretórios

```text
config/
docs/
models/
modules/
results/
tests/
main.py
label_features.py
train_classifier.py
evaluate_classifier.py
```

## Pontos de Entrada

### `main.py`

CLI principal para:

- recuperação no GitHub
- análise nas cinco camadas
- relatório explicável
- validação opcional
- exportação de features

Argumentos principais:

- `--token`: token do GitHub
- `--input`: CSV com padrões
- `--pages`: páginas por padrão
- `--classifier-model`: modelo supervisionado `.joblib`
- `--export-features`: exporta todas as features analisadas
- `--validate`: habilita validação pós-classificação
- `--service auto`: roteia a validação pelo tipo de segredo
- `--validation-threshold`: confiança mínima para tentar validação

### `label_features.py`

Script de rotulagem assistida. Ele:

- classifica negativos óbvios
- propõe positivos conservadores
- gera uma fila de revisão para casos ambíguos

### `train_classifier.py`

Treina um classificador supervisionado a partir de um CSV rotulado e salva um
bundle `.joblib` com:

- modelo treinado
- ordem das features
- nome do modelo
- métricas de treino

### `evaluate_classifier.py`

Avalia:

- o baseline heurístico
- ou um modelo supervisionado

Saídas principais:

- accuracy
- confusion matrix
- precisão
- recall
- F1-score
- linhas de revisão ignoradas

## Módulos

## `modules/core/`

Núcleo compartilhado da pipeline.

- `models.py`: contratos e dataclasses
- `pipeline.py`: orquestração das cinco camadas
- `masking.py`: mascaramento seguro
- `language.py`: heurísticas de linguagem e caminho

## `modules/layer1_retrieval/`

Camada de recuperação.

- `signatures.py`
- `entropy.py`
- `candidate_retriever.py`
- `content_fetcher.py`

Objetivo:
- maximizar recall
- não decidir sozinho o que é segredo real

## `modules/layer2_parsing/`

Camada de parsing e estrutura.

- `parser_registry.py`
- `python_parser.py`
- `python_data_flow.py`
- `config_parser.py`
- `tree_sitter_parser.py`

Objetivo:
- ligar o candidato ao contexto de código ou configuração
- entender bindings, chamadas e estrutura local

## `modules/layer3_features/`

Camada de features.

- `feature_extractor.py`
- `syntactic_features.py`
- `contextual_features.py`
- `statistical_features.py`
- `placeholder_detection.py`
- `asset_features.py`

Objetivo:
- transformar evidências locais em um vetor classificável

## `modules/layer4_classification/`

Camada de decisão.

- `classifier.py`
- `heuristic_baseline.py`
- `feature_encoding.py`
- `sklearn_classifier.py`
- `threshold_policy.py`

Objetivo:
- separar segredos reais de falsos positivos
- manter o modelo supervisionado disciplinado quando o candidato é genérico

## `modules/layer5_reporting/`

Camada de explicabilidade e priorização.

- `risk.py`
- `explanation.py`
- `reporter.py`

Objetivo:
- produzir findings acionáveis

## `modules/validators/`

Estratégias de validação pós-classificação.

- `shodan.py`
- `google.py`
- `scrapingbee.py`
- `generic.py`
- `passive.py`

Política atual:

- `auto` tenta escolher o validador a partir do `Secret Type`
- provedores sensíveis como GitHub e AWS caem em modo passivo
- candidatos genéricos nunca são tratados como válidos só por formato

## Pasta `results/`

Artefatos mais comuns:

- `*_1_SCAN_RAW.csv`
  - arquivos recuperados do GitHub

- `*_2_HYBRID_FINDINGS.csv`
  - findings finais que passaram pela classificação

- `*_3_VALID_KEYS_CONFIRMED.csv`
  - validações ativas confirmadas

- `features.csv`
  - features exportadas de todos os candidatos

- `features_labeled*.csv`
  - datasets rotulados ou bootstrapados

- `*_review_queue.csv`
  - fila de revisão humana

## Ciclo de Rotulagem e Treino

### 1. Exportar features

```powershell
python main.py --token SEU_TOKEN_GITHUB --input config/shodan_patterns.csv --export-features results/features.csv
```

### 2. Preparar rótulos base

Você pode usar:

- coluna `label`
- colunas `real_secret` e `false_positive`
- sementes de revisão anterior

### 3. Bootstrap e fila de revisão

```powershell
python label_features.py --input results/features_labeled.csv --output results/features_labeled_bootstrapped.csv --target-positive-count 10 --review-queue-limit 80
```

### 4. Revisar a fila

Promova com cuidado apenas casos com:

- binding explícito de provedor
- nome de variável sensível
- contexto forte de código/config

Rejeite:

- IDs operacionais
- placeholders
- imagens, hashes e exemplos

### 5. Treinar

```powershell
python train_classifier.py --input results/features_labeled_bootstrapped.csv --output models/secret_classifier.joblib --label-column label
```

### 6. Avaliar

```powershell
python evaluate_classifier.py --input results/features_labeled_bootstrapped.csv --label-column label
python evaluate_classifier.py --input results/features_labeled_bootstrapped.csv --label-column label --classifier-model models/secret_classifier.joblib
```

### 7. Rodar a varredura em modo de produção

```powershell
python main.py --token SEU_TOKEN_GITHUB --input config/shodan_patterns.csv --classifier-model models/secret_classifier.joblib --service auto --validate --export-features results/features_next.csv
```

## Como Interpretar Findings

### Positivos fortes costumam ter:

- formato específico de provedor
- variável sensível associada
- uso posterior em chamada cliente/autenticação
- referência de ativo próxima
- pouco ruído de documentação e placeholder

### Falsos positivos comuns:

- hashes
- UUIDs operacionais
- nomes de imagens
- URLs de gist
- templates de documentação

### Casos ambíguos:

- dumps documentais de múltiplos provedores
- IDs de provedor em formato UUID
- genéricos de 32/64 caracteres perto de termos como `ApiKey`

Esses devem ir para revisão humana antes de virar verdade de treino.

## Política Segura de Validação

O repositório evita testar indiscriminadamente credenciais possivelmente vazadas.

Exemplos:

- `GitHub Token` -> passivo
- `AWS Access Key` -> passivo
- `Google API Key` -> validador ativo disponível
- `Shodan` -> validador ativo disponível

Isso mantém o projeto alinhado com AppSec e evita transformar a ferramenta em
um verificador agressivo de credenciais de terceiros.
