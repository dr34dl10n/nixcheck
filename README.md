# nixcheck

**Un check-up santé pour serveurs Linux — rapide, déterministe, avec analyse IA optionnelle.**

```bash
nixcheck                  # rapport interactif dans le terminal
nixcheck --json           # sortie JSON pour l'automatisation
nixcheck --fast --quiet   # mode rapide, résumé en une ligne
nixcheck --fast --ai      # checks + diagnostic IA
```

## Pourquoi nixcheck ?

Vous vous connectez à un serveur, et vous voulez comprendre ce qui ne va pas — sans passer 20 minutes à enchaîner les `systemctl`, `df`, `free`, `journalctl` et `ps auxf`.

nixcheck fait tout ça en une commande : services, conteneurs, ressources, logs, processus Java, signaux de compromission. Il structure les résultats de façon lisible dans le terminal ou les expose en JSON propre.

## Origine du projet

nixcheck a été conçu autour de [LangGraph](https://github.com/langchain-ai/langgraph) : l'idée initiale était de laisser une IA conduire les checks et analyser les résultats. L'architecture en graphe est restée — c'est un modèle élégant pour orchestrer des étapes de diagnostic — mais **les checks sont 100 % déterministes**. Pas d'appel LLM pendant la collecte, pas d'incertitude sur les données.

Par-dessus ces checks déterministes, nixcheck propose une **couche d'analyse IA optionnelle** : le state complet est sérialisé et envoyé à un LLM (compatible OpenAI) qui produit un diagnostic en langage naturel avec des recommandations priorisées. C'est activé uniquement si vous le demandez avec `--ai` — sans ce flag, aucun appel réseau, aucune clé d'API, nada.

## Analyse IA (--ai)

Le flag `--ai` déclenche l'analyse après les checks déterministes. Le state complet (services, ressources, logs, JVM, sécurité) est sérialisé et envoyé à un LLM avec un prompt d'admin système expert.

```bash
# Avec un LLM local (Ollama) — aucune clé nécessaire
nixcheck --fast --ai --model gemma4:e2b

# Avec OpenAI — exporter la clé en variable d'environnement (jamais en CLI :
# un argument de commande est visible dans `ps aux` et l'historique shell)
export OPENAI_API_KEY="sk-..."
nixcheck --fast --ai --model gpt-4o-mini --ai-base-url https://api.openai.com/v1

# Mode JSON (le diagnostic IA est inclus dans la sortie)
nixcheck --fast --ai --json --model gpt-4o-mini
```

Priorité de résolution : argument CLI > variable d'environnement (`OPENAI_BASE_URL`,
`OPENAI_API_KEY`) > défaut local (Ollama `http://localhost:11434/v1`, clé factice).

⚠️ **Confidentialité** : avec `--ai`, le state (logs filtrés, détails des issues
de sécurité) est envoyé au LLM. Vers un endpoint local (Ollama) rien ne quitte
la machine ; vers un endpoint distant, un avertissement est logué. Les lignes
de logs brutes (`raw_line`) et les lignes de commande des processus (`cmdline`)
sont systématiquement rédacées avant l'envoi.

L'IA produit un rapport Markdown structuré :
- **Overall Health** — synthèse en un paragraphe
- **Findings** — liste des problèmes avec sévérité (CRITICAL → INFO)
- **Recommendations** — actions concrètes, priorisées

Installation de la dépendance IA :

```bash
pip install -e ".[ai]"
```

> Sans `--ai`, nixcheck ne charge jamais le client `openai` et n'a pas besoin de l'extra. Le package `openai` est une dépendance optionnelle (groupe `[ai]`).

## Ce que ça check

| Catégorie | Ce qui est vérifié |
|---|---|
| **Services** | Services systemd actifs, PID, mémoire, CPU (top 15) |
| **Conteneurs** | Docker et Podman — détection auto, IDs |
| **Ressources** | CPU, RAM, disque (`/`), load average, swap — avec seuil configurable |
| **Logs** | Erreurs `journalctl` + `/var/log/*`, classées par sévérité |
| **JVM** | Processus Java détectés, Heap `-Xmx`/`-Xms`, recommandations |
| **Sécurité** | Crypto-miners, processus CPU-hauts, crons suspects (`curl|bash`, `base64 -d`) |

## Pas besoin d'être root

nixcheck fonctionne **sans permissions root**. La majorité des checks passent nativement :

- `psutil` pour CPU/RAM/disk/processus — aucun privilege requis
- `systemctl` liste les services même pour un user lambda
- `journalctl` remonte les logs de la session courante
- Docker/Podman répondent si votre user est dans le bon groupe

Les seules choses qui nécessitent root sont les lectures partielles de `/var/log/syslog`, `/var/log/kern.log` et `/var/spool/cron/`. Quand l'accès est refusé, nixcheck l'indique proprement et continue — il ne crash pas.

En pratique, lancer `nixcheck` sans `sudo` vous donne déjà un diagnostic solide.

## Installation

```bash
git clone https://github.com/dr34dl10n/nixcheck.git
cd nixcheck
python -m venv .venv
source .venv/bin/activate
pip install -e .

# Pour le dev (ruff, pytest)
pip install -e ".[dev]"

# Pour l'analyse IA
pip install -e ".[ai]"
```

**Prérequis** : Python 3.11+, Linux avec systemd. Docker/Podman optionnels.

## Utilisation

```bash
# Check complet
nixcheck

# Mode rapide (pas de mesure CPU bloquante)
nixcheck --fast

# Sauter des checks
nixcheck --no-containers --no-security

# Sortie JSON pour scripts/CI/agents
nixcheck --json > health.json

# Personnaliser
nixcheck --hostname prod-server --log-lines 500 --threshold 90

# Résumé minimal (une ligne)
nixcheck --fast --quiet

# Checks + diagnostic IA (LLM local via Ollama)
nixcheck --fast --ai
```

### Codes de sortie

| Code | Signification |
|---|---|
| `0` | RAS — aucun warning critique |
| `1` | Erreur d'exécution |
| `2` | Problèmes détectés (logs critiques ou failles de sécurité) |

### Sortie JSON

Le flag `--json` produit un dictionnaire structuré :

```json
{
  "hostname": "prod-server",
  "services_count": 29,
  "containers_count": 3,
  "resources": {
    "cpu_percent": 45.2,
    "memory_percent": 72.0,
    "disk_percent": 88.5
  },
  "errors_count": 14,
  "java_detected": true,
  "jvm_configs_count": 2,
  "security_issues_count": 1,
  "has_warnings": true
}
```

Avec `--ai --json`, un champ `ai_diagnosis` (rapport Markdown) est ajouté à ce dictionnaire ; en cas d'échec de l'appel LLM, un champ `ai_error` le remplace.

Idéal pour du monitoring, du CI, ou pour nourrir un agent IA qui analysera les problèmes.

## Personnaliser la liste des miners

Par défaut, nixcheck détecte une liste intégrée de crypto-miners (xmrig, cgminer, etc.). Vous pouvez fournir la vôtre :

```bash
nixcheck --miner-list /etc/nixcheck/miners.yaml
```

Formats supportés : YAML (`miners: [...]`), JSON, ou texte simple (un nom par ligne).

## Architecture

```
nixcheck/
├── cli.py           # Point d'entrée CLI (argparse)
├── graph.py         # Orchestration LangGraph — les noeuds et le workflow
├── collectors.py    # Collecte brute : systemctl, journalctl, psutil, docker...
├── models.py       # Modèles Pydantic (état, résultats, sévérité)
├── reporter.py      # Rapport texte + résumé JSON
├── rich_reporter.py # Rapport Rich (tables colorées)
├── ai_analyzer.py   # Couche IA optionnelle (appel LLM OpenAI-compatible)
└── miners.yaml      # Liste intégrée des noms de crypto-miners
```

Le workflow LangGraph :

```
collect_services → collect_containers → collect_resources → collect_logs
    → detect_java → collect_security → [java?] → analyze_jvm → report
                                                └→ report
```

Chaque noeud est une fonction pure qui prend l'état enrichi et retourne ses résultats. Pas d'effets de bord cachés. C'est testable, debuggable, et extensible : ajoutez un noeud, branchez-le.

L'analyse IA n'est **pas** un noeud du graphe : elle tourne après `report`, de façon strictement optionnelle, pour ne pas impacter le chemin déterministe.

## Développement

```bash
ruff check .
pytest
```

## Licence

MIT