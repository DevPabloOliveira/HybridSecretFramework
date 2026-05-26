# Catálogo de Testes

Este documento organiza os tipos de teste do HybridSecretFramework, em que situação
cada um deve ser usado, qual comando executar e como interpretar o resultado.

## Estratégia Geral

O repositório mistura:

- recuperação assíncrona
- parsing sensível à linguagem
- engenharia de features
- treino supervisionado
- avaliação
- explicabilidade
- validação por provedor

Por isso, ele precisa de mais de uma família de testes.

## 1. Testes de Fumaça

### Objetivo

Confirmar que o repositório importa corretamente, os scripts sobem e o formato
das CLIs continua válido.

### Aplicação

Use:

- após instalar dependências
- após refatorações
- antes de varreduras longas

### Comandos

```powershell
python -m compileall main.py label_features.py train_classifier.py evaluate_classifier.py modules tests
python main.py --help
python label_features.py --help
python train_classifier.py --help
python evaluate_classifier.py --help
```

## 2. Testes Unitários

### Objetivo

Validar comportamentos isolados como:

- parsing
- AST
- data flow
- baseline heurístico
- rotulagem bootstrap
- roteamento de validação
- regras do classificador supervisionado

### Aplicação

Use em toda mudança de código.

### Comando

```powershell
python -m unittest discover -s tests
```

## 3. Testes de Contrato

### Objetivo

Garantir compatibilidade entre artefatos do fluxo:

- CSV de features
- CSV rotulado
- bundle `.joblib`
- relatórios finais

### Aplicação

Use quando houver mudança em:

- nome de coluna
- schema de features
- serialização do modelo
- estrutura dos relatórios

## 4. Testes de Engenharia de Features

### Objetivo

Checar se os sinais extraídos continuam coerentes.

### Sinais principais

- `variable_is_sensitive`
- `has_secret_term_nearby`
- `has_placeholder_signal`
- `has_asset_reference`
- `has_downstream_usage`
- `is_assignment_context`

### Aplicação

Use sempre que mexer em:

- heurísticas de contexto
- placeholders
- regras de documentação
- associação segredo-ativo

## 5. Teste do Baseline

### Objetivo

Medir o classificador heurístico como referência estável.

### Comando

```powershell
python evaluate_classifier.py --input results/features_labeled.csv --label-column label
```

### Interpretação

O baseline tende a:

- ter precisão alta
- ter recall menor
- ser conservador

## 6. Teste de Bootstrap de Rótulos

### Objetivo

Verificar se o `label_features.py` está ajudando, e não contaminando o dataset.

### Comando

```powershell
python label_features.py --input results/features_labeled.csv --output results/features_labeled_bootstrapped.csv --target-positive-count 10 --review-queue-limit 80
```

### O que revisar

- quantos positivos foram promovidos
- quantas linhas ficaram em revisão
- se placeholders e IDs operacionais foram rejeitados
- se documentação genérica não virou positiva sozinha

## 7. Teste de Treino Supervisionado

### Objetivo

Confirmar que o repositório consegue treinar e persistir um modelo.

### Comando

```powershell
python train_classifier.py --input results/features_labeled_bootstrapped.csv --output models/secret_classifier.joblib --label-column label
```

### Saída esperada

- bundle `.joblib` criado
- métricas de treino
- total de positivos e negativos
- total de linhas ignoradas por estarem em revisão

## 8. Teste de Avaliação Supervisionada

### Objetivo

Comparar o modelo treinado com o baseline.

### Comandos

```powershell
python evaluate_classifier.py --input results/features_labeled_bootstrapped.csv --label-column label
python evaluate_classifier.py --input results/features_labeled_bootstrapped.csv --label-column label --classifier-model models/secret_classifier.joblib
```

### Métricas principais

- precisão da classe positiva
- recall da classe positiva
- F1 da classe positiva
- confusion matrix

## 9. Teste End-to-End

### Objetivo

Validar o fluxo inteiro:

- discovery
- análise
- relatório
- validação opcional

### Comando

```powershell
python main.py --token SEU_TOKEN_GITHUB --input config/shodan_patterns.csv --classifier-model models/secret_classifier.joblib --service auto --validate --export-features results/features_next.csv
```

### Artefatos esperados

- `*_1_SCAN_RAW.csv`
- `*_2_HYBRID_FINDINGS.csv`
- `*_3_VALID_KEYS_CONFIRMED.csv`, quando houver validação positiva
- CSV de features exportadas

## 10. Teste de Roteamento de Validação

### Objetivo

Garantir que `--service auto` escolha a estratégia correta.

### O que verificar

- `GitHub Token` -> `passive`
- `AWS Access Key` -> `passive`
- `Google API Key` -> `google`
- segredos Shodan -> `shodan`
- tipos desconhecidos -> `generic`

## 11. Teste de Curadoria da Review Queue

### Objetivo

Transformar casos ambíguos em exemplos realmente úteis para treino, sem deixar
o bootstrap “se apaixonar” por documentação genérica.

### Fluxo

1. abrir `*_review_queue.csv`
2. separar:
   - IDs operacionais
   - placeholders
   - credenciais de provedor com binding forte
   - dumps documentais genéricos
3. promover só os casos com contexto realmente forte
4. rejeitar ou manter em revisão o resto

## Fluxo Completo dos Testes

### Fase 1. Sanidade

```powershell
python -m compileall main.py label_features.py train_classifier.py evaluate_classifier.py modules tests
python -m unittest discover -s tests
```

### Fase 2. Exportar Features

```powershell
python main.py --token SEU_TOKEN_GITHUB --input config/shodan_patterns.csv --export-features results/features.csv
```

### Fase 3. Preparar Rótulos Base

Atualize:

- `results/features_labeled.csv`

Use:

- rótulos manuais
- sementes revisadas
- revisões anteriores

### Fase 4. Bootstrap e Fila de Revisão

```powershell
python label_features.py --input results/features_labeled.csv --output results/features_labeled_bootstrapped.csv --target-positive-count 10 --review-queue-limit 80
```

Depois revise:

- `results/features_labeled_bootstrapped.csv`
- `results/features_labeled_bootstrapped_review_queue.csv`

### Fase 5. Avaliar o Baseline

```powershell
python evaluate_classifier.py --input results/features_labeled_bootstrapped.csv --label-column label
```

### Fase 6. Treinar Modelo

```powershell
python train_classifier.py --input results/features_labeled_bootstrapped.csv --output models/secret_classifier.joblib --label-column label
```

### Fase 7. Avaliar Modelo Supervisionado

```powershell
python evaluate_classifier.py --input results/features_labeled_bootstrapped.csv --label-column label --classifier-model models/secret_classifier.joblib
```

### Fase 8. Comparar Qualidade

Promova o modelo supervisionado para uso real só se:

- mantiver boa precisão
- melhorar recall da classe positiva
- não explodir achados genéricos em documentação

### Fase 9. Rodar Varredura em Modo Produção

```powershell
python main.py --token SEU_TOKEN_GITHUB --input config/shodan_patterns.csv --classifier-model models/secret_classifier.joblib --service auto --validate --export-features results/features_next.csv
```

### Fase 10. Revisar Findings e Validação

Inspecione:

- `results/*_2_HYBRID_FINDINGS.csv`
- `results/*_3_VALID_KEYS_CONFIRMED.csv`

Perguntas-chave:

- o volume de findings continua controlado?
- segredos específicos de provedor sobreviveram?
- genéricos documentais voltaram a inflar?
- a validação roteou de forma segura?

## Artefatos por Finalidade

| Artefato | Finalidade |
| --- | --- |
| `features.csv` | export bruto de features |
| `features_labeled.csv` | base rotulada inicial |
| `features_labeled_bootstrapped.csv` | dataset pronto para treino |
| `*_review_queue.csv` | candidatos ambíguos para revisão |
| `secret_classifier.joblib` | modelo supervisionado treinado |
| `*_SCAN_RAW.csv` | recuperação bruta |
| `*_HYBRID_FINDINGS.csv` | findings explicáveis aprovados |
| `*_VALID_KEYS_CONFIRMED.csv` | validações confirmadas |

## Checklist de Aceite

Antes de considerar uma versão pronta, confirme:

- testes de fumaça ok
- testes unitários ok
- export de features ok
- bootstrap sem inflar ruído documental
- baseline avaliado
- modelo supervisionado avaliado
- fluxo end-to-end gerando todos os artefatos
- roteamento de validação correto
- findings compreensíveis e controlados
