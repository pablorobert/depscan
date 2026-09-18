# depscan — SPEC v2

CLI que varre um diretório recursivamente e reporta dependências desatualizadas e
vulneráveis em projetos JavaScript/TypeScript.

> v2 substitui `specs.md` (v1). A mudança central: o depscan **não invoca package
> managers** como fonte de dados. Ele interpreta lockfiles e consulta o registry
> diretamente. Justificativa e medições no Apêndice A.

---

## 1. Objetivo

> "Tenho um diretório com muitos projetos JS/TS. Me diga quais têm dependência
> desatualizada ou vulnerável, sem eu inspecionar projeto por projeto."

Prioridades, em ordem:

1. **Honestidade** — nunca apresentar "não verifiquei" como "está limpo" (§3)
2. Velocidade
3. Read-only absoluto
4. Saída útil no terminal
5. JSON para automação e agentes
6. Zero configuração

---

## 2. Non-goals (v1 do produto)

Não implementar: atualizar dependências, alterar `package.json`/lockfile, instalar,
apagar `node_modules`, visualização de grafo, integração com LLM, UI web, modo daemon,
publicação de pacote, análise de licença, detecção de abandono, análise de código, AST.

---

## 3. Regra central — tri-estado obrigatório

**Todo resultado de análise carrega um estado explícito.** Esta é a regra que governa
o modelo de dados, a saída no terminal, o JSON e os exit codes.

```
"clean"        verificado, nada encontrado
"findings"     verificado, encontrado
"not_checked"  não verificado por escolha (--offline, --only-*, cache ausente)
"error"        tentei verificar e falhou (rede, lockfile ilegível, timeout)
```

Vale independentemente para **outdated** e para **security**. Um projeto pode ter
`outdated.status = "findings"` e `security.status = "not_checked"` ao mesmo tempo.

Proibido:

- coleção vazia significando "limpo" sem `status` acompanhando
- colapsar `not_checked` ou `error` em `clean`
- omitir do summary os projetos que não foram totalmente verificados

---

## 4. Plataformas e tecnologia

Linux, macOS, Windows. Binário nativo único.

**Go.** Cross-compile trivial para os três alvos, concorrência nativa para as Fases 1
e 2, stdlib cobre HTTP/JSON. Sem dependência de runtime de Node.js, bun, npm, pnpm ou
yarn — com uma única exceção opcional e encapsulada (§7.2).

Dependências externas esperadas: parser YAML, parser JSONC, biblioteca semver.

---

## 5. Arquitetura — três fases

A inversão em relação à v1: **não existe pipeline por projeto**. Projetos compartilham
dependências em massa; a rede é batelada por *pacote único*, não por projeto.

```
FASE 1 — local, paralelo, sem rede
  walk  →  package.json + lockfile  →  parse
                  ↓
       resolved dep set por projeto
                  ↓
       dedupe global: map[name] → set[version]

FASE 2 — rede, batelada por pacote único
  1 POST bulk advisories        (todos os pares name@version de uma vez)
  N × dist-tags                 (N = nomes únicos; cache em disco)
  M × packument                 (M = só os fora-de-range; apenas com --wanted)

FASE 3 — join de volta nos projetos
  normalized model  →  terminal | JSON
```

Módulos:

```
cli         parsing de argumentos, exit codes
scanner     walk, exclusões, symlink-safe, worker pool
project     parse de package.json → deps declaradas + categoria
lockfile    interface + adapters (§7)
resolve     dedupe global, semver (ranges, wanted, prerelease)
registry    dist-tags + packument, cache em disco
advisory    POST bulk, chunking, retry
model       representação normalizada (§10)
output      formatter de terminal | formatter de JSON
cache       leitura/escrita atômica, TTL, ETag
```

Interface só onde há mais de uma implementação real: `lockfile.Parser` (6 adapters).
Não introduzir interface para registry/advisory no MVP.

---

## 6. Descoberta de projetos

Projeto = diretório contendo `package.json`. Busca recursiva. O diretório raiz **não**
é assumido como projeto.

Não percorrer: `node_modules`, `.git`. Um `package.json` dentro de um projeto que tem
`node_modules` continua sendo detectado — a exclusão é de travessia, não de detecção.

Não seguir symlink de diretório (evita ciclo). Registrar o skip, não abortar.

Lista de exclusão mínima e não agressiva. Override pelo usuário fica para depois.

**Monorepo:** se `package.json` declara `workspaces`, os `package.json` filhos são
detectados normalmente como projetos independentes no MVP, mas marcados
`workspaceRoot: "<path do pai>"` para que o consumidor possa agrupar. Resolução de
dependência entre workspaces é fora do escopo.

---

## 7. Lockfiles

O lockfile é a fonte da verdade para **"qual versão está efetivamente em uso"**. Nunca
ler `node_modules`.

### 7.1 Adapters

| Arquivo | Formato | Extração |
|---|---|---|
| `bun.lock` | **JSONC** — trailing commas, `encoding/json` falha | declarado: `workspaces[""].{dependencies,devDependencies,...}`; resolvido: `packages[<name>][0]` = `"axios@1.20.0"` |
| `bun.lockb` | binário | fallback §7.2 |
| `package-lock.json` | JSON, `lockfileVersion` 2 e 3 | declarado: `packages[""]`; resolvido: `packages["node_modules/<path>"].version`; flags `dev`, `optional` |
| `pnpm-lock.yaml` | YAML, `'6.0'` e `'9.0'` | `importers[<dir>].{dependencies,devDependencies}.<name>.{specifier, version}` — já traz range **e** resolvido **e** categoria |
| `yarn.lock` (v1) | formato próprio, não-YAML | parser dedicado |
| `yarn.lock` (berry) | YAML | parser dedicado; distinguir por `__metadata.version` |

Armadilhas obrigatórias de tratar:

- `bun.lock` exige parser tolerante a trailing comma. `JSON.parse` estrito falha com
  `Property name must be a string literal`.
- `pnpm-lock.yaml` sufixa peers na versão: `vite@5.4.21(@types/node@20.0.0)`. Strip do
  parêntese antes de usar como versão.
- `package-lock.json` aninhado (`node_modules/a/node_modules/b`) permite **múltiplas
  versões do mesmo pacote**. O modelo deve suportar isso, não colapsar para uma.
- `packageManager` no `package.json` (ex.: `"yarn@4.1.0"`) é sinal auxiliar de versão
  do PM, não substitui a detecção pelo lockfile.

Sem lockfile: `packageManager: "unknown"`, e **não inventar versão instalada**. As
versões declaradas em `package.json` alimentam apenas `declared`; `current` fica nulo,
`outdated.status = "error"` com `kind: "no_lockfile"`. Não chutar.

### 7.2 Fallback do `bun.lockb`

`bun.lockb` é binário e não será parseado. Regra:

```
bun.lockb presente
    ↓
bun no PATH?
    ├── sim → um único spawn: `bun pm ls --all` (cwd = projeto)
    └── não → erro daquele projeto, kind: "binary_lockfile_no_bun"
```

Verificado: `bun pm ls --all` lê do lockfile sem exigir `node_modules` e **não altera
o lockfile** (md5 idêntico antes/depois). Saída é árvore `name@version`, parseável;
`--json` não existe nesse subcomando.

Restrições:

- **um spawn por projeto**, nunca por dependência
- sem interpolação de shell; executável localizado e verificado antes
- timeout (§13)
- direto vs transitivo vem de cruzar com `package.json` **e** com a posição na árvore:
  só a entrada de primeiro nível (sem indentação sob outro pacote) pode ser a direta
- **encapsulado no adapter do Bun.** O núcleo do depscan continua sem conhecer package
  manager. Nenhum outro adapter tem permissão de spawn.

---

## 8. Dependências e categorias

Lidas de `package.json`: `dependencies`, `devDependencies`, `peerDependencies`,
`optionalDependencies`. As quatro preservadas no modelo; as duas primeiras são as
obrigatórias de analisar.

`direct` e `category` são **dimensões ortogonais**:

```
direct:   true | false
category: dependency | devDependency | peerDependency | optionalDependency | null
```

`category` é a seção do `package.json` onde o pacote foi declarado. Transitivo não tem
categoria (`direct: false`, `category: null`). **`transitive` não é um valor de
`category`.**

`direct` é decidido **por cópia instalada, não por nome.** O mesmo nome aparece em mais
de uma versão quando uma dependência pede outra faixa (projeto declara `zod ^4`, uma
ferramenta traz `zod 3` aninhado). Só a cópia do próprio projeto é direta:

| Lockfile | Cópia do projeto |
|---|---|
| `bun.lock` | chave igual ao nome (`"zod"`); aninhada tem prefixo do pai (`"tool/zod"`) |
| `bun.lockb` | linha de primeiro nível do `bun pm ls --all` |
| `package-lock.json` v2/v3 | `node_modules/<nome>`; v1: primeiro nível de `dependencies` |
| `pnpm-lock.yaml` | versão listada em `importers["."]` (9.0) ou nas seções da raiz (6.0) |
| `yarn.lock` | entrada cujo descriptor contém o range declarado (`zod@^4.6.2`, `zod@npm:^4.6.2`) |

Se o lockfile não permite distinguir (nenhuma cópia casa), todas as cópias daquele nome
ficam diretas: pode sobrar linha, mas a dependência declarada nunca some.

Medido: marcar por nome fazia `zod 3.25.76`, `oxlint 1.76.0` e `globals 14.0.0`
aparecerem como diretos desatualizados num projeto bun real — o último com um "major"
falso, já que o `globals` declarado estava no latest.

---

## 9. Outdated — `current` → `wanted` → `latest`

Três coisas distintas:

```
declared: ^1.6.0     range no package.json
current:  1.6.0      resolvido no lockfile — o que está em uso
wanted:   1.18.0     maior versão que satisfaz `declared`
latest:   1.20.0     dist-tag `latest` no registry
```

### 9.1 Classificação

`updateType` = `current → wanted` — o que sobe sem quebrar o range.
`latestUpdateType` = `current → latest` — o salto real.

Valores: `patch`, `minor`, `major`, `none`, `unknown`. `unknown` quando semver não se
aplica (versão de git, `file:`, `workspace:`, tag). **Nunca inventar classificação.**

### 9.2 Procedência de `wanted` — `wantedSource`

`latest` custa 79 bytes; a lista completa de versões custa ~54 KB comprimido por
pacote (Apêndice A). Então `wanted` é calculado em dois níveis:

| `wantedSource` | Quando | Custo |
|---|---|---|
| `equals-latest` | `latest` satisfaz `declared` ⇒ `wanted == latest` por prova local | zero request |
| `registry` | `latest` **não** satisfaz `declared`, e `--wanted` foi passado: packument buscado, máximo dentro do range calculado | 1 packument |
| `not-computed` | `latest` não satisfaz `declared` e `--wanted` não foi passado | zero |

`equals-latest` **não** é default universal — é emitido apenas onde a inferência é
demonstrável (o range aceita `latest`). Com `wantedSource: "not-computed"`, `wanted` é
`null` e nenhum consumidor tem licença para tratar como atualizado.

`--wanted` é opt-in porque medido em ~48s adicionais em 100 projetos.

### 9.3 `minimum-release-age`

Se a configuração do projeto suprimir versões recentes, `latest` do dist-tag pode não
ser o latest efetivo para aquele projeto. Fora do escopo do MVP; não emitir campo.

---

## 10. Segurança

### 10.1 Fonte

```
POST https://registry.npmjs.org/-/npm/v1/security/advisories/bulk
Content-Type: application/json
{"axios":["1.6.0"],"vite":["5.0.0"]}
```

Sem autenticação. Filtragem por versão é **server-side** (`axios@1.6.0` → 29
advisories; `axios@1.20.0` → 0) — nenhum matching de range no cliente. Pacotes sem
advisory são omitidos da resposta.

Escopo: **o lockfile inteiro, incluindo transitivos.** Medido: 1708 pacotes em um único
POST, 400ms. Não há motivo para limitar a diretos.

Chunking defensivo em 1000 pacotes por request mesmo sem teto observado.

Campos da resposta: `id`, `url`, `title`, `severity`, `vulnerable_versions`, `cwe`,
`cvss{score, vectorString}`.

### 10.2 Severidade

`critical`, `high`, `moderate`, `low`, `unknown`. Já é exatamente o vocabulário do
endpoint — nenhuma tradução necessária. Preservar o valor original.

### 10.3 Campos derivados e seus limites

O endpoint **não** devolve versão instalada nem versão corrigida.

- `installedVersion` vem do **lockfile**, não da API.
- `fixedVersion` é **inferido** do limite superior de `vulnerable_versions` e marcado
  `fixedVersionInferred: true`.

Regra da inferência, por advisory do pacote:

| Limite | O que estabelece |
|---|---|
| `<1.8.2` | **nomeia** uma versão segura: `1.8.2` |
| `<=1.13.4` | não nomeia versão, só um **piso** que a resposta precisa superar |
| sem limite superior | nenhuma versão conhecida é segura |

`fixedVersion` = a maior versão *nomeada*, **desde que** supere todos os pisos. Se o
maior limite for um piso, ou não houver versão nomeada, o campo é `null` — não chutar.

Exemplo real (axios, 29 advisories): limites `<1.18.0` (nomeia), `<=1.13.4` e `<=1.7.3`
(pisos). `1.18.0 > 1.13.4` → `fixedVersion: "1.18.0"`. Já em vite, o piso `<=6.4.2`
supera qualquer versão nomeada → `null`, corretamente.

### 10.4 Agregação

Um pacote acumula muitos advisories (axios sozinho: 29; vite: 17). Portanto:

- **`summary.vulnerablePackages` conta pacotes afetados** — é o número que o humano lê
- `summary.advisories` conta advisories — disponível, secundário
- o JSON preserva **todos** os advisories, agrupados por pacote
- severidade exibida por pacote = a **máxima** entre seus advisories

---

## 11. Saída no terminal

Default. Legível sem cor; cor é realce, nunca portadora de informação.

```text
depscan

Scanning ~/projects ...

✓ my-game
    up to date · no advisories

⚠ cadencia
    3 outdated
      vite       5.0.0 → 5.4.21   minor
      eslint     9.32  → 9.35     minor
      react      18.2.0 → 19.2.8  major   (wanted not computed — use --wanted)

✗ foradacurva
    7 outdated
    3 affected packages

      direct
        axios      HIGH       29 advisories   1.6.0 → 1.18.0
        vite       MODERATE   17 advisories   5.0.0 → 5.4.21

      transitive
        esbuild    MODERATE    1 advisory     0.21.5 → 0.25.0

⚠ legacy-project
    package.json could not be parsed

⚠ project-a
    outdated: ok
    security: unavailable (network error)

──────────────────────────────────────
Projects:              12
Fully analyzed:        10
Outdated packages:     14
Affected packages:      3   (advisories: 47)
Not checked:            1
Errors:                 1

Completed in 2.4s
```

Regras:

- **Diretos antes de transitivos**, com rótulo. Transitivo nunca é escondido — uma
  vulnerabilidade transitiva pode ser justo a que importa.
- Estado `not_checked` e `error` aparecem por projeto **e** no summary. Um projeto que
  não foi verificado nunca recebe `✓`.
- `--quiet` suprime progresso, mantém o resultado final.

---

## 12. Saída JSON

`depscan --json <dir>`. Stdout recebe **só** JSON válido; todo log e progresso vai para
stderr.

```json
{
  "root": "/home/user/projects",
  "depscanVersion": "1.0.0",
  "startedAt": "2026-09-12T14:03:11Z",
  "durationMs": 2412,
  "options": {
    "offline": false,
    "wanted": false,
    "cache": true
  },
  "projects": [
    {
      "path": "/home/user/projects/cadencia",
      "name": "cadencia",
      "packageManager": "bun",
      "lockfile": "bun.lock",
      "workspaceRoot": null,
      "outdated": {
        "status": "findings",
        "packages": [
          {
            "name": "axios",
            "declared": "^1.6.0",
            "current": "1.6.0",
            "wanted": "1.18.0",
            "latest": "1.20.0",
            "updateType": "minor",
            "latestUpdateType": "major",
            "wantedSource": "registry",
            "direct": true,
            "category": "dependency"
          },
          {
            "name": "react",
            "declared": "18.2.0",
            "current": "18.2.0",
            "wanted": null,
            "latest": "19.2.8",
            "updateType": "unknown",
            "latestUpdateType": "major",
            "wantedSource": "not-computed",
            "direct": true,
            "category": "dependency"
          }
        ]
      },
      "security": {
        "status": "findings",
        "packages": [
          {
            "name": "axios",
            "installedVersion": "1.6.0",
            "maxSeverity": "high",
            "direct": true,
            "category": "dependency",
            "fixedVersion": "1.18.0",
            "fixedVersionInferred": true,
            "advisories": [
              {
                "id": 1111035,
                "url": "https://github.com/advisories/GHSA-jr5f-v2jv-69x6",
                "title": "axios Requests Vulnerable To Possible SSRF and Credential Leakage via Absolute URL",
                "severity": "high",
                "vulnerableVersions": ">=1.0.0 <1.8.2",
                "cwe": ["CWE-918"],
                "cvss": { "score": 0, "vectorString": null }
              }
            ]
          }
        ]
      },
      "errors": []
    },
    {
      "path": "/home/user/projects/project-a",
      "name": "project-a",
      "packageManager": "pnpm",
      "lockfile": "pnpm-lock.yaml",
      "workspaceRoot": null,
      "outdated": { "status": "clean", "packages": [] },
      "security": { "status": "error", "packages": [] },
      "errors": [
        {
          "kind": "network",
          "phase": "security",
          "message": "advisory request failed after 3 attempts: connection reset"
        }
      ]
    }
  ],
  "summary": {
    "projects": 12,
    "fullyAnalyzed": 10,
    "outdatedPackages": 14,
    "vulnerablePackages": 3,
    "advisories": 47,
    "bySeverity": { "critical": 0, "high": 1, "moderate": 2, "low": 0 },
    "byUpdateType": { "patch": 6, "minor": 5, "major": 3, "unknown": 0 },
    "projectsNotChecked": 1,
    "projectsWithErrors": 1
  }
}
```

`errors[].kind` — enum fechado:

```
no_lockfile
binary_lockfile_no_bun
parse_package_json
parse_lockfile
unsupported_lockfile_version
network
timeout
cache_miss_offline
internal
```

`errors[].phase`: `discovery` | `lockfile` | `outdated` | `security`.

O schema é versionado por `depscanVersion` e documentado no README.

---

## 13. Rede, cache e offline

### 13.1 Cache

Diretório: `os.UserCacheDir()/depscan/`

```
registry/     dist-tags e packuments por pacote
advisories/   respostas de audit
```

| Recurso | Estratégia |
|---|---|
| `dist-tags` | TTL **6h**. Medido: sem `ETag`, sem `Cache-Control` — revalidação não é possível, TTL cego é a única opção |
| packument | `ETag` + `If-None-Match`. Medido: 304 em 183ms com 0 bytes. TTL 6h como piso, ETag revalida depois |
| advisories | TTL 6h |

TTL e ETag são complementares, não alternativas: usar ambos onde disponíveis.

**Payload gravado comprimido.** O transport do Go descomprime o gzip da resposta de
forma transparente, então guardar o corpo como veio significa guardar o documento
inflado — e o envelope JSON ainda aplica base64 por cima, somando mais um terço. Medido
num `--wanted` sobre 83 projetos: **235 MB cru contra 57 MB comprimido**, 4,1x. Entrada
que não infla é tratada como corrompida, removida e rebuscada, o que cobre de graça
qualquer entrada deixada por versão anterior.

Requisitos do cache:

- **transparente** — nenhuma flag necessária para se beneficiar
- **seguro contra corrupção** — escrita em arquivo temporário + rename atômico; entrada
  ilegível é tratada como miss, nunca como erro fatal
- **concorrente** — múltiplas instâncias de depscan em paralelo não se corrompem
- **nunca toca o projeto analisado** — vive só no cache do usuário

MVP expõe `--no-cache` para ignorar o cache num run, mais dois comandos que agem sobre
o próprio cache e não recebem diretório:

```
--cache-list    diretório, contagem por bucket, tamanho total e as entradas mais
                pesadas, nomeadas pela chave e não pelo hash do arquivo
--cache-clean   apaga e reporta o que foi liberado
```

Apagar é sempre seguro: toda entrada é cópia de algo que o registry serve de novo.

TTL fica fixo em 6h, configurável em versão futura — sem criar flag agora.

### 13.2 `--offline`

Zero requests. Consequência obrigatória: o resultado **declara** o que não foi possível
determinar.

- cache válido para o pacote → usa, `status` normal
- cache ausente/expirado → `status: "not_checked"`, erro `kind: "cache_miss_offline"`
- `options.offline: true` no JSON

Nunca converter "não consultei" em "nenhuma vulnerabilidade". Terminal:

```text
⚠ cadencia
    3 outdated
      vite  5.0.0 → 5.4.21  minor
    Security information unavailable — offline, no cached advisories
```

### 13.3 Robustez

Timeout por request: 15s. Timeout por spawn (§7.2): 30s. Retry com backoff
exponencial, 3 tentativas, só em erro transitório (5xx, timeout, reset).

Concorrência de rede default 64; ajustável por `--concurrency`, teto 256. Medido:
conc64 = 100 pkg/s, conc256 = 167 pkg/s, sem throttle observado — 64 é o default
educado.

Falha de um projeto nunca aborta o scan. Falha da Fase 2 marca os projetos afetados
como `error`, e o summary continua reportando os demais.

---

## 14. Exit codes

```
0  todas as verificações completaram, nada encontrado
1  findings acima do threshold
2  erro operacional (argumento inválido, raiz inexistente, falha interna)
3  nada encontrado, mas uma ou mais verificações ficaram incompletas
   (not_checked ou error)
```

Precedência: `2` > `1` > `3` > `0`. `3` só ocorre quando não há findings — findings
já falham com `1`, e o summary declara a incompletude nos dois casos.

Threshold default: **qualquer vulnerabilidade** dispara `1`. Dependência desatualizada
**não** dispara por si — patch disponível deixando CI vermelho para sempre é inútil.

- `--fail-on <low|moderate|high|critical>` eleva a barra de severidade
- `--fail-on-outdated` faz outdated também disparar `1`

---

## 15. CLI

```
depscan [flags] <directory>

Output
  --json                 saída JSON em stdout; logs em stderr
  --quiet                suprime progresso, mantém resultado

Scope
  --only-outdated        só outdated; security fica "not_checked"
  --only-vulnerable      só security; outdated fica "not_checked"
  --direct-only          exibe só dependências diretas (transitivos seguem no JSON)
  --manager <pm>         filtra por package manager detectado

Depth
  --wanted               calcula `wanted` quando exige packument (mais lento)

Network
  --offline              zero requests
  --no-cache             ignora o cache em disco
  --concurrency <n>      requests concorrentes (default 64, máx 256)
  --timeout <dur>        timeout por request (default 15s)

Exit
  --fail-on <sev>        severidade mínima para exit 1
  --fail-on-outdated     outdated também dispara exit 1
  --ignore <GHSA|id>     ignora advisory (repetível)

  --help
  --version
```

`--only-outdated` e `--only-vulnerable` produzem `not_checked` no eixo suprimido — não
`clean`. `--help` documenta uso, flags, modos de saída, exit codes e package managers
suportados.

---

## 16. Garantia de read-only

O depscan **não escreve nada** dentro do diretório analisado. Verificado nesta
investigação: `bun outdated`, `bun audit` e `bun pm ls --all` deixam `package.json` e
`bun.lock` com md5 idêntico.

Como a v2 elimina a invocação de package manager, restam zero superfícies de escrita
além do fallback de §7.2 — que usa apenas `bun pm ls`, jamais `install`, `update`,
`upgrade`, `add`, `remove` ou `audit fix`.

**Teste obrigatório na suíte:** hash recursivo da árvore de fixtures antes e depois de
um scan completo, comparação exata.

---

## 17. Performance

Alvo: diretório com ~100 projetos, ~1700 pacotes únicos.

| Etapa | Custo medido/projetado |
|---|---|
| walk + parse de 100 lockfiles (~3 MB) | ~100ms |
| advisories (1 POST) | ~0.4s |
| `latest` (1700 × dist-tags, conc 64) | ~17s frio |
| `latest` (cache quente) | <0.5s |
| `wanted` (só fora-de-range, opt-in) | +~48s |

**Run frio sem `--wanted`: ~11-17s. Run quente: <1s.** O "1.8s" da v1 só existe com
cache quente — a meta foi ajustada para refletir a medição. O depscan exibe o tempo
total.

---

## 18. Testes

### Unitários

`package.json` parsing · extração de dependências · detecção de package manager pelo
lockfile · **cada um dos 6 adapters de lockfile** · classificação semver
(`patch`/`minor`/`major`/`unknown`, prerelease, ranges exóticos) · lógica de
`wantedSource` · inferência de `fixedVersion` (incluindo os casos que devem retornar
`null`) · serialização JSON · filtro de diretórios · transições do tri-estado (§3) ·
precedência de exit code · TTL e recuperação de cache corrompido.

### Integração (fixtures, sem internet)

```
projeto bun (bun.lock texto)
projeto bun (bun.lockb binário)
projeto npm (lockfileVersion 2)
projeto npm (lockfileVersion 3)
projeto npm com node_modules aninhado (mesma dep em 2 versões)
projeto pnpm (lockfile 6.0)
projeto pnpm (lockfile 9.0, com sufixo de peer na versão)
projeto yarn v1
projeto yarn berry
projeto sem lockfile
projeto com package.json malformado
projeto com bun.lock com trailing comma  ← regressão do parser JSONC
projetos aninhados
projeto contendo node_modules
raiz de workspace + filhos
symlink circular
```

Nota sobre `bun.lockb`: bun 1.4 grava lockfile texto por default e a flag
`--no-save-text-lockfile` **não** produz binário. O que funciona é `bunfig.toml` com
`[install] saveTextLockfile = false` — aí `bun install --lockfile-only` grava um
`bun.lockb` binário de verdade. A fixture `bun-binary/` foi gerada assim (1.6 KB,
sintética) e o `bunfig.toml` fica commitado ao lado documentando a regeneração.

Os testes desse caminho fazem skip quando `bun` não está no PATH — é o único lugar em
que depscan depende de programa externo.

### Race detector

`go test ./... -race` é obrigatório antes de release. Exige `CGO_ENABLED=1` e um
compilador C — que **não** é dependência do produto: o binário é Go puro e
cross-compila para os três SOs com cgo desligado.

Status atual: limpo em linux/amd64 (gcc 15, inclusive `-count=5` nos pacotes
concorrentes `cache`, `registry` e `resolve`) e em windows/amd64 (mingw-w64 UCRT
gcc 16).

### HTTP

Registry e endpoint de advisory atrás de um servidor de teste local. Zero dependência
de serviço ao vivo na suíte. Cobrir: 200, 304, 404, 5xx com retry, timeout, corpo
malformado, resposta vazia.

---

## 19. README

O que o depscan faz · instalação · uso básico · exemplo de saída · uso do JSON (com o
schema e a semântica do tri-estado) · package managers suportados · exit codes ·
comportamento de cache e offline · limitações · instruções de desenvolvimento.

Prático, não marketing.

---

## 20. Critérios de aceite do MVP

- [x] Diretório varrido recursivamente; múltiplos projetos independentes detectados
- [x] `node_modules` e `.git` não percorridos; symlink circular não trava
- [x] `package.json` parseado com segurança
- [x] Os 6 adapters de lockfile implementados, incluindo JSONC do `bun.lock`
- [x] Fallback de `bun.lockb` com um único spawn, encapsulado no adapter, com fixture
- [x] bun, npm, pnpm e yarn detectados pelo lockfile
- [x] Outdated reportado com `current`/`wanted`/`latest` e `wantedSource`
- [x] `--wanted` calcula `wanted` via packument
- [x] Vulnerabilidades reportadas do lockfile inteiro, diretas e transitivas
- [x] Updates classificados em patch/minor/major/unknown, sem invenção
- [x] **Tri-estado (§3) presente no modelo, no terminal e no JSON**
- [x] Diretos exibidos antes de transitivos, transitivos nunca escondidos
- [x] Summary conta pacotes afetados; JSON preserva todos os advisories
- [x] Saída de terminal legível sem cor
- [x] Saída JSON válida, stdout limpo, schema documentado
- [x] Cache em `os.UserCacheDir()/depscan` com TTL 6h + ETag, atômico e concorrente
- [x] `--offline` funciona e declara o que não foi verificado
- [x] **Nenhuma modificação em projeto analisado, com teste de hash da árvore**
- [x] Um projeto quebrado não aborta o scan
- [x] Exit codes 0/1/2/3 com a precedência de §14
- [x] Testes unitários e fixtures de integração — 140 testes, sem rede
- [x] README e schema JSON
- [x] `depscan --help` e `depscan --version`

Nenhuma pendência.

---

## 21. Roadmap — não implementar agora

`--context` (saída compacta para agente) · `depscan graph` · `depscan impact <pkg>` ·
resolução real de workspace/monorepo · idade da versão em uso · pacotes deprecados ·
análise de licença · OSV como fonte secundária de advisory (cobre ecossistemas
não-npm) · `.depscan.toml` · TTL de cache configurável · `depscan update` / `fix`
(sempre opt-in explícito, jamais parte do scanner read-only).

---

## 22. Princípio de design

> **Faça uma coisa muito bem: dizer rápido o que está errado nas dependências de todos
> os meus projetos JS/TS.**

Rápido · pequeno · read-only · previsível · scriptável · amigável a agente. E, acima de
tudo, **honesto sobre o que não sabe** (§3).

---

## Apêndice A — Medições

Máquina Windows 11, 2026-09-12. bun 1.4.2, npm 11.6.1, pnpm 10.12.1, yarn 1.22.22,
node 24.19.0. Todos os números abaixo foram medidos, não estimados.

### Endpoint bulk de advisories

`POST https://registry.npmjs.org/-/npm/v1/security/advisories/bulk`

| Teste | Resultado |
|---|---|
| Autenticação | nenhuma |
| Campos | `id, url, title, severity, vulnerable_versions, cwe, cvss{score,vectorString}` |
| vs `bun audit --json` | conjunto de campos **idêntico** — bun não acrescenta dado |
| Filtro por versão | **server-side**: axios@1.6.0 → 29 advisories; axios@1.20.0 → **0** |
| Múltiplas versões por pacote | aceito, retorna união |
| Pacotes limpos | omitidos da resposta |
| 250 pacotes | http 200, resposta 4.1 KB, 257ms |
| 1000 pacotes | http 200, payload 31.6 KB, resposta 10.8 KB, 296ms |
| **1708 pacotes** | http 200, payload 56.2 KB, resposta 17.0 KB, **400ms** |

Teto não encontrado.

### Fontes de versão

| Fonte | Bytes/pacote | 200 pacotes | Throughput |
|---|---|---|---|
| `/-/package/<pkg>/dist-tags` | **79 B** | 1196ms @conc256 | **167 pkg/s** |
| packument abreviado + gzip | 53.6 KB (301 KB sem gzip) | **23832ms** @conc64, 9.7 MB | 8.4 pkg/s |
| packument full + gzip | 97 KB (858 KB sem gzip) | — | — |
| `/<pkg>/latest` | 6.7 KB | — | — |
| jsdelivr version list | ~80 KB | 3576ms @conc64, 16 MB | terceiro, pesado |

Escala do `dist-tags` (200 pacotes, inclui 68 scoped): conc16 5818ms → conc64 1991ms →
conc128 1666ms → conc256 **1196ms**. Todos http 200, zero falha.

Headers: packument tem `ETag` + `Cache-Control: public, max-age=300`; `If-None-Match`
→ **304 em 183ms, 0 bytes**. `dist-tags` **não tem ETag nem Cache-Control**.
`http_version=1.1` (sem multiplexação h2).

### Bulk de versões — não existe

| Tentativa | Resultado |
|---|---|
| `replicate.npmjs.com/registry/_all_docs?keys=[...]` | http 200, mas devolve só `rev` |
| idem com `include_docs=true` | **http 400** (bloqueado) |
| `registry.npmjs.org/-/all` | 404 (removido) |

Conclusão: `latest` por `dist-tags`, um request por nome único, cacheado.

### Comandos do bun

| Comando | Achado |
|---|---|
| `bun audit --json` | `--json` existe; `--audit-level`, `--ignore` existem |
| `bun audit` exit code | **1 tanto para "vulns encontradas" quanto para "falta lockfile"** — ambíguo |
| `bun outdated` | **não tem `--json`**; só tabela ASCII `Package \| Current \| Update \| Latest`, `(dev)` sufixando o nome, `*` marcando release-age |
| `bun outdated` exit code | **0 mesmo com deps desatualizadas** |
| sem lockfile | ambos falham: `error: missing lockfile, nothing to audit` |
| mutação | nenhuma — md5 de `package.json` e `bun.lock` idênticos |
| `bun pm ls --all` | lê do lockfile sem `node_modules`; não muta; árvore `name@version`; sem `--json` |

### Lockfiles gerados sem instalar

`bun install --lockfile-only`, `npm install --package-lock-only`,
`pnpm install --lockfile-only` — todos produzem lockfile sem criar `node_modules`.

| Arquivo | Tamanho | Nota |
|---|---|---|
| `bun.lock` | 20.2 KB | `lockfileVersion: 2`; **JSONC** — `JSON.parse` falha: `Property name must be a string literal` |
| `package-lock.json` | 43.1 KB | `lockfileVersion: 3` |
| `pnpm-lock.yaml` | 25.4 KB | `'9.0'`; `importers` traz specifier + version + categoria |

### OSV

`POST api.osv.dev/v1/querybatch` → http 200, 1513ms, mas devolve **só IDs de vuln**,
exigindo segunda rodada por advisory. Inferior ao endpoint npm para o ecossistema npm.
Roadmap como fonte secundária.
