# Alinhamento da Arquitetura do HybridSecretFramework

Este documento mapeia a implementação atual do repositório para a arquitetura
derivada da revisão sistemática sobre uso de Machine Learning e análise baseada
em AST para redução de falsos positivos na detecção de segredos.

## Resumo do Alinhamento

O repositório implementa a arquitetura de cinco camadas:

| Camada do Artigo | Implementação | Status |
| --- | --- | --- |
| Camada 1: recuperação com Regex e entropia | `modules/layer1_retrieval/` | Implementada |
| Camada 2: parsing estrutural e AST | `modules/layer2_parsing/` | Implementada para Python e configs; adapter Tree-sitter disponível |
| Camada 3: features sintáticas, contextuais e estatísticas | `modules/layer3_features/` | Implementada |
| Camada 4: classificação preparada para ML | `modules/layer4_classification/`, `train_classifier.py` | Implementada com baseline e Scikit-Learn |
| Camada 5: priorização e explicabilidade | `modules/layer5_reporting/` | Implementada |

## Mapeamento por Questão de Pesquisa

| Questão | Evidência no Repositório | Dependência Científica Restante |
| --- | --- | --- |
| QP1: modelos supervisionados para classificar segredos | `SklearnSecretClassifier`, `FeatureEncoder`, `train_classifier.py` | ainda depende de dataset rotulado representativo |
| QP2: uso de AST e contexto semântico | `PythonAstParser`, `ConfigParser`, `TreeSitterParser`, `PythonDataFlowAnalyzer` | análise interprocedural e fluxo global ainda são extensões futuras |
| QP3: precisão, recall, F1 e taxa de falsos positivos | `evaluate_classifier.py` | as métricas só ganham valor científico com curadoria humana consistente |
| QP4: limitação do Regex puro | Regex ficou restrito à recuperação inicial | tuning contínuo deve ser guiado por benchmark e revisão |

## Capacidades Científicas Já Implementadas

- Regex e entropia funcionam como camada de alto recall, não como decisão final.
- AST em Python identifica nós literais, variáveis associadas, funções e contexto de chamada.
- Parsing de configuração extrai semântica de chaves em `.env`, YAML-like, JSON-like e arquivos de propriedades.
- Data flow intra-arquivo liga segredos a chamadas posteriores em Python.
- Associação segredo-ativo detecta URLs, hosts e referências de banco próximas ao candidato.
- A extração de features combina sinais sintáticos, contextuais, estatísticos, de placeholder, de ativo e de caminho.
- A camada de classificação suporta baseline transparente e artefatos persistidos de Scikit-Learn.
- A validação ativa é acionada apenas depois do gate da classificação e mantém o padrão Strategy.
- Os relatórios incluem valor mascarado, tipo, arquivo, linha, nó AST, variável associada, confiança, risco e evidências.

## Fluxo Reproduzível

1. Recuperar candidatos e exportar features:

```powershell
python main.py --token SEU_TOKEN --input config/shodan_patterns.csv --export-features results/features.csv
```

2. Rotular o CSV exportado com `label`, `real_secret`/`false_positive` ou curadoria assistida.

3. Treinar um classificador supervisionado:

```powershell
python train_classifier.py --input results/features_labeled.csv --output models/secret_classifier.joblib --label-column label
```

4. Avaliar baseline e modelo supervisionado:

```powershell
python evaluate_classifier.py --input results/features_labeled.csv --label-column label
python evaluate_classifier.py --input results/features_labeled.csv --label-column label --classifier-model models/secret_classifier.joblib
```

5. Rodar a varredura com o modelo treinado:

```powershell
python main.py --token SEU_TOKEN --input config/shodan_patterns.csv --classifier-model models/secret_classifier.joblib
```

## Critério Honesto de Fechamento

No nível de implementação, a arquitetura está alinhada ao artigo. O que falta
para um fechamento acadêmico completo é principalmente empírico:

- ampliar dataset rotulado
- comparar baseline vs modelo supervisionado
- registrar precisão, recall, F1, falsos positivos e falsos negativos com revisão humana
