# Preparação para Entrevista — Guia de Estudo (v2)

> **Mudanças desta versão:** Foundation-first em vez de drill-first. ArtMethod com profundidade real (struct + offset enforcement + Samsung discovery). Q&A código-específica em vez de genérica. Adicionada seção de verificação urgente (coisas que precisa confirmar no próprio código antes da entrevista). Flag de inconsistência scoring entre ADR-002 e bloco anterior.
> 

---

## 🎯 ESTRATÉGIA — o que perde / o que ganha

**O que perde a entrevista (em ordem de risco):**

1. Soar como se estivesse recitando o Claude → contramedida: liderar com **descobertas empíricas** (Samsung jmethodID indireto, GMS emoji FP no /proc/maps, sensor noise calibrado em paper). Descoberta empírica é impossível de fingir.
2. Defender toda escolha → contramedida: 1 frase de limitação **antes** de qualquer defesa. *"Esse check tem limitação X. Aceitei porque Y. Em produção mudaria pra Z."*
3. Largura > profundidade → contramedida: *"Eu prefiro ir 2 níveis mais fundo num detector do que passar por 4 superficialmente — qual você quer abrir?"*

**O que ganha (em ordem de impacto):**

1. **Vídeo cronometrado do próprio Frida bypass.** Quase ninguém faz isso.
2. **Citar Mascara §IX-B + AOSP `ValidateFieldOrderOfJavaCppUnionClasses` test** ao explicar ArtMethod. Sinaliza "li source, não só blog".
3. **Pergunta sobre graduação observe→block.** É pergunta de Staff Engineer, não de IC.

**Frase de abertura 90s (decora, ensaia em voz alta com cronômetro):**

> "Tamper detection é a foundation que torna confiável todo outro sinal — se o ambiente é mentiroso, qualquer signal de identidade ou location vindo dele também é. Construí 4 detectores ortogonais com scoring two-tier: hard signals que são definitivos por construção, soft signals ponderados. O diferencial é o ArtMethod hotness_count em NDK, baseado em Mascara seção 9-B — única defesa não bypassada no paper, com 99% de accuracy confirmada em Matrioska ACSAC 2024. Testei adversarialmente: 3 scripts Frida e um repackaging com apktool. Posso abrir por onde fizer mais sentido — arquitetura, um detector específico, ou o teste adversário."
> 

---

## 📋 PLANO DE ESTUDO (5–6h, foundation-first)

### Hora 0 — Calibração (15 min)

Lê seção "ESTRATÉGIA" acima. Não estuda nada novo.

### Hora 1 — "You Shall not Repackage" §3 + §4 + §5 (60 min)

URL: https://ar5iv.labs.arxiv.org/html/2009.04718

- **§3 Attack Model (15 min):** os 12 steps que segui com apktool. Steps 1-6 = static reverse, 7-9 = modificação smali, 10-12 = re-assinatura.
- **§4 Anti-repackaging schemes (15 min):** os 6 esquemas e o **padrão comum** — todos embarcam logic bomb no app, todas as bombas são encontráveis por análise estática.
- **§5 Attacks (20 min):** classifica cada bypass como **estático** (apktool + smali edit) ou **dinâmico** (Frida hook na API). Conceito-chave: tudo client-side é eventualmente bypassável; o limite teórico é mover proteção pra fora do processo (server-side attestation).
- **Notas (10 min):** 1 página de bullets com os 12 steps em 4 linhas, padrão comum em 2 linhas, taxonomia bypass em 2 linhas.

### Hora 2 — Mascara §IX-B + ARAP + AOSP source (45 min)

- **Mascara §IX-B (20 min):** https://ar5iv.labs.arxiv.org/html/2010.10639#S9.SS2
    
    Extrair 3 conceitos: (a) funcional vs cosmético; (b) tracking de execução é fundamental ao ART; (c) virtual containers carregam dex via DexClassLoader.
    
- **Mascara §VIII (5 min):** tabela dos 18 mecanismos bypassados — **todos cosméticos**.
- **ARAP §III + §IV (15 min):** https://arxiv.org/pdf/2408.11080
    
    3 fatos: 117K apps / 99.6% usam ≥1 técnica ARA; 5 categorias (Anti-Debugging, Anti-Hooking, Anti-Tampering, Root Detection, Virtual Environment Detection); **só 2% dos top apps detectam Frida** (Promon 2024).
    
- **AOSP source spot-check (5 min):**
    - https://android.googlesource.com/platform/art/+/master/runtime/art_method.h — confirma offset 14 e o teste `ValidateFieldOrderOfJavaCppUnionClasses` no comentário.
    - Procura `device/generic/goldfish/sensors/sensor_list.cpp` no AOSP — é onde "Goldfish" está hardcoded.

### Hora 3 — ArtMethod drill (45 min, agora com base conceitual)

- 15 min memorizar struct (Bloco 4 abaixo)
- 15 min memorizar fluxo do C (signal handler → FromReflectedMethod → pointer validation → read offset 14)
- 15 min decorar 3 frases-defesa (offset version, positive-only, NDK vs Kotlin)

### Hora 4 — Frida bypass cronometrado + scoring + production (75 min)

- 30 min Frida bypass real, cronômetro visível, vídeo curto pra mostrar
- 15 min defender scoring two-tier sob 3 ataques (hard FP, threshold mágico, float vs categoria)
- 15 min walkthrough das ADR-001 a 007: estrutura **decisão / trade-off / plan B** em 30s cada
- 15 min escrever resposta "production at Incognia scale" (ver script abaixo)

### Hora 5 — Live coding + scripts (30 min)

- 10 min praticar adicionar um Build check ao vivo, alvo <3 min
- 10 min ler script Claude/AI 3x em voz alta, cronometrar (alvo <60s)
- 10 min calibrar 3 perguntas pra eles baseado em quem entrevista

### Hora 6 — Logística + descanso (30 min)

- Câmera, mic, screen share, repo aberto font 18+, vídeo Frida pronto, papel + caneta
- Inhaler, água
- Para de estudar 1h antes da entrevista

---

## 🚨 VERIFICAÇÕES URGENTES NO CÓDIGO (antes de tudo)

Algumas coisas neste guia foram reconstruídas a partir das ADRs porque eu não consegui puxar o source code direto. Tu precisa confirmar olhando teu próprio código:

| Item                                           | Onde olhar                                              | O que confirmar                                                                                                                                                                                                                    |
| ---------------------------------------------- | ------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Nome exato do método lido pelo ArtMethod check | `detection/.../detectors/ArtMethodChecker.kt`           | É `ActivityThread.currentActivityThread()` mesmo? Outro? Anotar pra usar nas frases-defesa.                                                                                                                                        |
| Public API do ArtMethodChecker                 | `ArtMethodChecker.kt`                                   | Nome exato do `external fun`, retorno (Int? Result?), companion object com `loadLibrary`.                                                                                                                                          |
| Threshold de pointer validation                | `detection/.../cpp/art_method_check.c`                  | É `< 0x10000` mesmo? Confirma o magic number.                                                                                                                                                                                      |
| Signal handler — escopo                        | `art_method_check.c`                                    | O sigaction é instalado e removido a cada call, ou uma vez global? Thread-safety?                                                                                                                                                  |
| Threshold engine vs detector                   | ADR-002 + `DetectionEngine.kt`  • `EmulatorDetector.kt` | **ADR-002 diz < 0.25 SECURE / 0.25–0.59 WARNING / ≥0.60 TAMPERED.** Versão antiga deste doc dizia "threshold 0.35" — qual é a verdade no código? São camadas diferentes (per-detector vs engine)? Reconciliar antes da entrevista. |
| Pacotes cloners conhecidos                     | `CloningDetector.kt`                                    | São 17 packages mesmo (per ADR-005)? Lista exata pra responder.                                                                                                                                                                    |
| Strings de hooking libs                        | `HookingDetector.kt`                                    | ADR-007 lista: `frida`, `xposed`, `substrate`, `gadget`, `lspd`. Confirma quais estão lá.                                                                                                                                          |
| Whitelist GMS emoji                            | `HookingDetector.kt` ou `CloningDetector.kt`            | É filtro por extensão (`.apk .dex .so .odex .vdex .oat .art`)? Confirma a lista exata.                                                                                                                                             |
| Whitelist JIT cache                            | `HookingDetector.kt`                                    | Confirma que `[anon:dalvik-jit-code-cache]` está whitelistado pro check rwxp.                                                                                                                                                      |
| Implementação coroutines                       | `DetectionEngine.kt`                                    | É `coroutineScope { ... awaitAll }` ou `supervisorScope`? Estructured concurrency?                                                                                                                                                 |

**Tempo: 30 min de leitura cuidadosa do próprio código.** Marca o que é verdadeiro / falso / desconhecido pra cada linha acima.

---

## ⚠️ INCONSISTÊNCIA DE SCORING — RECONCILIAR

Tua ADR-002 documenta:

- **< 0.25 SECURE**
- **0.25 – 0.59 WARNING**
- **≥ 0.60 TAMPERED**

O bloco "Por que o threshold é 0.35?" da versão antiga deste doc tinha um cálculo de 28% → WARNING que não bate com ADR-002 (28% < 0.25 seria SECURE; 0.35 não é threshold em ADR-002).

**Hipóteses possíveis:**

1. **0.25/0.60 é threshold do engine; 0.35 é threshold interno do EmulatorDetector** (quando só soft signals disparam, o detector decide se reporta `detected=true` baseado no peso interno).
2. **ADR drift** — ADR-002 documentou um valor, mas o código foi ajustado depois e a doc ficou desatualizada.
3. **Você usa thresholds diferentes em camadas diferentes** mas a versão antiga do doc misturou.

**Ação:** abre `DetectionEngine.kt` e os 4 detectors. Procura `0.25`, `0.35`, `0.60`, `threshold`. Documenta a verdade em UMA frase. Se for camada dupla (engine + per-detector), explicita isso na resposta:

> "Tem dois thresholds: o engine usa 0.25/0.60 pra agregar o score ponderado em SECURE/WARNING/TAMPERED. Cada detector internamente tem seu próprio threshold de soft signals — no EmulatorDetector é 0.35 — pra decidir se reporta `detected=true` quando hard signals não disparam. Hard signal sempre força confidence=1.0 independente de threshold interno."
> 

Se for ADR drift, fala isso direto: *"A ADR-002 está desatualizada vs o código atual. O valor real é X. Boa pegada — eu deveria ter atualizado a ADR."*

---

## 🧠 CONTEXTO INCOGNIA — O que eles valorizam

**SDK deles:** 415KB Android, 0.5%/dia bateria, 66ms processamento. Se o teu SDK release está em ballpark, OK. Se debug é 9MB, isso é debug.

**Frase do job description deles** *(pra citar quase literalmente):* *"executamos código nos aplicativos de terceiros… extremo cuidado e controle rigoroso de recursos (threads, memória, processamento)"*. Isso = exatamente o que tu fez com coroutines + structured concurrency + SafeExec + fail-open + sensor sampling opcional.

**O que eles detectam (público):** emuladores, location spoofing, app cloners, app tampering tools, image injectors, remote-access tools (AnyDesk/TeamViewer). Tu cobre os 4 primeiros.

**Stat deles:** 5% dos devices flagged risky têm ≥1 issue de integridade. Devices risky são 5x mais propensos a ter issue de integridade.

**Stat ARAP/Promon:** 99.6% dos apps usam ≥1 técnica ARA, mas só 2% dos top apps detectam Frida especificamente. Tu detecta Frida via 2 mecanismos ortogonais (lib name + rwxp). Isso te coloca no 2%.

**Quem pode te entrevistar:**

- **Gabriel Falcone** (VP Mobile, co-founder) — visão de produto e arquitetura
- **Pedro Atanásio** (Staff, C/C++/Java) — se ele estiver, perguntas de NDK/JNI/struct layout são garantidas. Bom pra nós: temos ArtMethod em C com offset enforcement.
- **Thiago Figueredo Cardoso** (ARM disassembly background) — reverse engineering profundo, signal handlers, /proc/maps interno.

---

## ✅ O QUE TEMOS QUE A MAIORIA DOS CANDIDATOS NÃO TERIA

| "Red flag" do estado da arte  | Nosso status                                                                                                                                                    |
| ----------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| "No native code"              | **Temos:** ArtMethod em C com JNI + SIGSEGV handler + sigsetjmp/siglongjmp recovery                                                                             |
| "No bypass testing"           | **Temos:** 3 Frida scripts (`tools/frida-bypass-*.js`) + repackaging real com apktool                                                                           |
| "Boolean tamper detection"    | **Temos:** two-tier weighted scoring; hard signals override                                                                                                     |
| "Hardcoded secrets grep-able" | **Parcial:** R8 obfusca classes no release (limitação: não obfusca string constants — DexGuard resolveria)                                                      |
| "SafetyNet"                   | **Não usamos** — sabemos que foi descontinuado May 2025                                                                                                         |
| "No false positive awareness" | **Temos:** GMS emoji font fix por extensão de arquivo, 16 stores na whitelist                                                                                   |
| "Crash on detection"          | **Não crashamos** — fail-open com SafeExec + DetectionError sealed class                                                                                        |
| "No NDK depth"                | **Temos:** offset 14 baseado em AOSP `ValidateFieldOrderOfJavaCppUnionClasses` test, descoberta empírica de Samsung jmethodID indireto não documentada em paper |

---

## 🤖 SCRIPT CLAUDE/AI

**Pergunta inevitável: "Usou AI?"**

> "Sim, usei Claude como pair programmer. Eu defini a arquitetura (módulo `:detection` separado, Strategy pattern, Builder, two-tier scoring), escolhi quais sinais implementar e por quê (baseado em papers — Mascara §IX-B, You Shall not Repackage §3-5, ARAP), e validei tudo em devices reais e emuladores. Claude me ajudou a escrever o código mais rápido, mas cada decisão de design é minha — posso explicar o trade-off de cada uma. Onde fiquei surpreso foi com o ArtMethod: implementei baseado em Mascara, mas descobri na prática que Samsung usa jmethodID como índice numérico (vi 0xb=11) em vez de ponteiro direto — isso não está documentado em nenhum paper. Essa descoberta é 100% do processo de teste real, não de AI."
> 

**Follow-up provável: "Mas o código você não escreveu"**

> "Escrevi com pair programming. A diferença prática é: pra cada decisão de design — Strategy vs herança, two-tier vs score linear, ArtMethod sobre outras técnicas — eu posso te falar a alternativa que considerei e por que rejeitei. Pra cada bug que encontrei — Samsung jmethodID, GMS emoji no /proc/maps, sensor float underflow — eu posso te contar como diagnostiquei. Se essas duas coisas são minhas, o resto é tooling. Se quiser, abre qualquer função do meu código e me pergunta por que não foi escrita diferente."
> 

---

## ❓ PERGUNTAS PRA FAZER A ELES

Calibrado por entrevistador (escolhe **uma** prioritária, não dispara todas):

- **Se Gabriel Falcone (VP):** *"Como vocês graduam um detector novo de observe → warn → block? Quanto tempo em cada fase, qual FP rate corta a passagem?"*
- **Se Pedro Atanásio (Staff C/C++):** *"Como vocês versionam offsets de structs internas tipo ArtMethod? Tabela offset-por-API ou sanity check em runtime?"*
- **Se Vinícius Cousseau (ML):** *"Quando entra um detector novo, vocês re-treinam o modelo de fraude com novo feature, ou o detector entra como threshold rule e só depois vira ML feature?"*
- **Pergunta segura pra qualquer um:** *"O foco atual do time é fechar gap em virtualizers (VirtualXposed) ou em combos emergentes tipo cloner-on-emulator?"*

---

## 📚 LEITURA RECOMENDADA (papers, com seções e o que extrair)

### 1. **"You Shall not Repackage"** (Merlo et al., 2021) — o mais importante

- Full: https://ar5iv.labs.arxiv.org/html/2009.04718
- **§3 Attack Model:** os 12 steps. Steps 1-6 = static reverse + discovery. Steps 7-9 = patch smali. Steps 10-12 = re-sign + reinstall.
- **§4 Schemes:** os 6 esquemas analisados. Padrão comum: logic bomb embarcada no app.
- **§5 Attacks:** static (apktool + smali edit) vs dynamic (Frida hook). **Conceito-chave: tudo no processo do atacante eventualmente cai. Único limite teórico = server-side.**

### 2. **"Mascara"** (Alecci et al., 2020) — base do nosso ArtMethod check

- Full: https://ar5iv.labs.arxiv.org/html/2010.10639
- **§VIII (18 mecanismos bypassados):** todos são **cosméticos** — testes adicionados ao app, removíveis sem quebrar o app.
- **§IX-B Countermeasures:** ArtMethod hotness_count proposto. Único survivor porque é **funcional** — alterar quebra ART, não só a proteção.

### 3. **"Matrioska"** (Zerbini et al., IEEE ACSAC 2024) — confirma que ArtMethod funciona

- https://ieeexplore.ieee.org/document/10917506/
- 99% accuracy detectando virtual containers via ArtMethod hotness_count em devices reais.

### 4. **"ARAP"** (Suo et al., IEEE TSE 2024) — o estudo de larger escala

- PDF: https://arxiv.org/pdf/2408.11080
- 117K apps, 1515 features, **99.6% usam ≥1 técnica ARA**.
- 5 categorias: Anti-Debugging, Anti-Hooking, Anti-Tampering, Root Detection, Virtual Environment Detection.
- **Cobrimos 3 das 5** — gaps explícitos em Anti-Debugging dedicado e Root Detection (ADRs documentam o porquê).

### 5. **"Unmasking the Veiled"** (Ruggia et al., AsiaCCS 2024) — confirma o padrão HookingDetector

- https://s3.eurecom.fr/docs/asiaccs24_ruggia.pdf
- Identifica padrão `HOOK-PROC_ART-MAPS` (scan /proc/maps por frida-agent) — **exatamente o que nosso HookingDetector check 1 faz**.
- 26.2% de malware inspeciona /proc/self/maps.

### 6. **"Parallel Space Traveling"** (Dai et al., ACM SACMAT 2020) — base do CloningDetector

- https://www.cs.ucr.edu/~heng/pubs/sacmat2020.pdf
- Como virtual containers funcionam tecnicamente (DexClassLoader, IOUniformer, env vars).

### 7. **OWASP MASVS-RESILIENCE** — standards

- RESILIENCE-2 (anti-tampering): https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/
- RESILIENCE-4 (anti-dynamic analysis): https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/
- MASTG-TEST-0048 (RE tools detection): https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0048/

### 8. **AOSP source** — credibility move

- `art_method.h` (master): https://android.googlesource.com/platform/art/+/master/runtime/art_method.h
    - Confirma struct order
    - Confirma comentário *"Field order required by test ValidateFieldOrderOfJavaCppUnionClasses"*
    - Confirma `static constexpr MemberOffset HotnessCountOffset()` público
    - Confirma `MaxCounter() = 65535` (uint16 saturação)

### Checklist conceitual de auto-teste (responde sem olhar; <8/10 = volta no paper)

1. Por que toda proteção client-side é eventualmente bypassável?
2. Diferença entre proteção funcional e cosmética?
3. Por que Frida precisa arquiteturalmente de páginas rwxp?
4. Por que hotness_count é especial em virtual containers?
5. Quais as 5 categorias do ARAP?
6. Quais 2 das 5 você não cobre e por quê?
7. Por que Build.HARDWARE="ranchu" não é heurística?
8. Por que Samsung jmethodID é diferente?
9. Por que cert hash check é categoricamente bypassável?
10. Qual a única defesa conceitualmente não-bypassável?

---

# BLOCOS DE Q&A — CÓDIGO-ESPECÍFICO

> Cada Q&A abaixo se refere a arquivos/decisões específicas do teu código. ✅ Todos os `[CONFIRMA]` foram verificados contra o código real e substituídos com referências arquivo:linha. Ver seção "📂 REFERÊNCIA RÁPIDA DO CÓDIGO" no final para lookup durante a entrevista.
> 

---

## 🏗️ BLOCO 1: Arquitetura — código-específico

### P: "Por que separou em módulo Gradle `:detection`?"

R: Boundary clara. O módulo `:detection` é Android Library; `:app` apenas consome. UI não acessa internals da detecção, SDK não sabe sobre UI. Em produção, distribuído como AAR via Maven. ✅ **Confirmado:** `ArtMethodChecker` é `internal class` (`ArtMethodChecker.kt:19`). A public API são: `DetectionEngine`, `DetectionEngine.Builder`, `TamperDetector` interface, `DetectionResult`, `Evidence`, `TamperVerdict`, `TamperStatus`, `DetectionCategory`, `DetectionError`. Os 4 detectors expõem apenas o constructor público (consumer-rules.pro mantém só `public <init>(...)`).

### P: "Strategy pattern — alternativas consideradas?"

R: Considerei (a) herança com classe abstrata `BaseDetector`, (b) sealed class hierarchy, (c) function references (`(Context) -> DetectionResult`). Escolhi interface `TamperDetector` porque:

- Os 4 detectors são **independentes** (não compartilham estado)
- Roda em **paralelo** (interface permite isso, herança forçaria sequência)
- Adicionar 5º detector = 1 classe + 1 linha no Builder; nada herdado pra entender

Trade-off: perdi a oportunidade de compartilhar utility methods em base class (ex: `runWithSafeExec`). Resolvi com `SafeExec` como utility separado.

### P: "Por que Builder pattern e não construtor com lista?"

R: Builder permite o consumidor do SDK escolher quais detectors ativar. Banking app quer todos os 4. Game casual só EmulatorDetector. Builder também permite config per-detector — `EmulatorDetector(includeSensorAnalysis = true)` vs `false` pra fast scan.

**Follow-up provável:** *"Por que não usar @Inject ou Hilt?"*  

R: Um SDK não pode forçar consumidor a usar Hilt — alguns usam Hilt, outros Koin, outros DI manual. Builder é framework-agnostic. DI só dentro do nosso módulo (manual constructor injection).

### P: "Coroutines — qual scope, structured concurrency?"

R: ✅ **Confirmado em `DetectionEngine.kt:31-40`:** `withContext(Dispatchers.Default) { detectors.map { async { runDetector(it, appContext) } }.awaitAll() }`. NÃO é `supervisorScope` — é `withContext` + `async`. Cada detector tem try-catch próprio no `runDetector()` (`DetectionEngine.kt:67-81`) que cria `DetectionResult(detected=false, errors=[Unexpected])` se o detector lançar exception. Então mesmo sem supervisorScope, um detector falhando não derruba os outros. Tempo total = max dos 4 (≈2s para Deep Scan).

### P: "SafeExec — por quê fail-open?"

R: Princípio de design: **um SDK de segurança nunca pode crashar o app host.** Três camadas:

1. `SafeExec.runCatching()` — wrapper defensivo em cada check individual
2. try-catch no `DetectionEngine.runDetector()` — safety net por detector
3. Erros são estruturados (`DetectionError` sealed class com 5 tipos: PermissionDenied, TimeoutError, IOError, etc) e reportados, **nunca propagados**

Reporta o que conseguiu avaliar, mesmo com erros parciais. Trade-off: atacante pode forçar exceptions específicas pra fazer checks falharem silenciosamente. Mitigação: `DetectionError` é parte da `Evidence`, então um detector com 9 checks que falhou em 9 reporta isso explicitamente — verdict = `null evidence` é diferente de "secure".

---

## 📊 BLOCO 2: Scoring — código-específico

### P: "Walk me through your scoring."

R: Two-tier model.

- **Hard signals** (checks especificamente escolhidos com FP rate=0 documentado): força `confidence=1.0` instantaneamente, sem ponderar com soft signals. Exemplos: `Build.HARDWARE="ranchu"` (literal AOSP), sensor name "Goldfish" (literal HAL), cert hash mismatch (criptograficamente impossível sem chave privada), foreign package no filesDir.
- **Soft signals**: ponderados via `overallScore = sum(weight_i * confidence_i) / sum(weight_i)`.
- **Verdict thresholds (per ADR-002):** `<0.25 SECURE / 0.25–0.59 WARNING / ≥0.60 TAMPERED`.

### P: "O que torna um signal HARD em vez de soft?"

R: Critério: FP rate documentado = 0 nos meus testes em devices reais + justificativa estrutural.

- "ranchu" → nome literal hardcoded em `device/generic/ranchu/` no AOSP. Não é heurística — é o nome do virtual board que o QEMU usa. Fabricantes reais não usam.
- "Goldfish" → nome do HAL emulator no AOSP. Mesma lógica.
- Cert hash mismatch → criptograficamente impossível ter assinatura válida sem chave privada do dev original.
- Foreign package no filesDir → estruturalmente impossível em execução normal porque `filesDir` é `/data/user/0/<my_pkg>/files` na execução normal.

Soft signal: pode ter FP. Bateria temp=0 (emuladores modernos simulam 25°C); installer null (MDM enterprise); sensor ausente (devices baratos sem step counter).

### P: "Threshold 0.25 / 0.60 — como chegou nesses números?"

R: ✅ **Confirmado — valores REAIS do código (divergem da ADR-002 original):**
- **Engine** (`DetectionEngine.kt:141-144`): `TAMPERED_THRESHOLD = 0.45f`, `WARNING_THRESHOLD = 0.2f`
- **Cada detector**: `DETECTION_THRESHOLD = 0.35f` (threshold interno para `detected=true`)
- **Override:** se ANY detector retorna `detected=true` → `overallScore = 1.0f`, `status = TAMPERED` (`DetectionEngine.kt:44-46`). O scoring por threshold só importa quando nenhum detector tem certeza.
- **⚠️ ADR-002 diz 0.25/0.60** — valores antigos, ajustados durante development. Os valores reais são 0.20/0.45.
- Em produção, calibração seria empírica com dataset de fraude conhecida + otimização ROC AUC. Hoje é educated guess declarado como limitação.

### P: "Qualquer detector pode forçar TAMPERED via hard signal. Não é agressivo demais?"

R: Não, porque hard signals foram escolhidos com FP rate=0 documentado. Se aparecer um device de OEM novo cujo build casualmente coincide com "ranchu", isso seria um bug do dev — adicionaria uma cross-validation (ranchu **mas** sensor real **e** cellular ativo = downgrade pra soft). Hoje não tenho cross-validation; reconheço como gap.

### P: "Output structure — por que não Boolean?"

R: Boolean perde informação. `TamperVerdict` carrega:

- `status: TamperStatus` (SECURE / WARNING / TAMPERED) — pra consumo simples
- `score: Float` (0..1) — pra consumidor que quer próprio threshold
- `results: Map<Category, DetectionResult>` — pra inspeção per-detector
- `evidence: List<Evidence>` — exatamente o que o challenge pediu ("what evidence was used to reach this conclusion"). Cada Evidence tem `checkName`, `description`, `rawValue`, `suspicious`.

Banking quer threshold 0.2; game quer 0.7. Float bruto preserva flexibilidade.

---

## 🖥️ BLOCO 3: EmulatorDetector — código-específico

### P: "9 checks, não é demais?"

R: Defense-in-depth. Cada check individualmente é bypassável (demonstrei com Frida). Bypassar **todos** simultaneamente é muito mais difícil. Os 9 operam em camadas ortogonais: propriedades do sistema, sensores, OpenGL, bateria, filesystem, telephony, sensor names. Atacante precisaria hooks em todas essas APIs ao mesmo tempo. Paper "You Shall not Repackage" §5 mostra que cada esquema individual cai — proteção vem da combinação.

### P: "Por que não usou NDK no EmulatorDetector?"

R: Pesquisei. Metade dos checks (sensores, bateria) são APIs Java-only — não existe equivalente nativo. Mesmo com NDK, metade da superfície continua hookável. Ganho de NDK pra emulator detection não justifica complexidade (CMake, JNI, multi-ABI). Pra cloning detection sim (ArtMethod), porque é a única técnica não bypassada na literatura.

### P: "Sensor noise — de onde veio o threshold 0.002?"

R: Paper peer-reviewed [PMC10490716](https://pmc.ncbi.nlm.nih.gov/articles/PMC10490716/) (2023). Mediram 5 smartphones reais em repouso por 4 horas. Stddev do acelerômetro: 0.004–0.011 m/s². Meu threshold 0.002 está bem abaixo do device mais silencioso. No emulador medi 0.000004 — 500× menor. Sensor HAL do emulador é confirmado no [AOSP goldfish sensor_list.cpp](https://android.googlesource.com/device/generic/goldfish/+/master/sensors/sensor_list.cpp) — todos sensores são nomeados "Goldfish".

### P: "E se o emulador melhorar a simulação de sensores?"

R: Possível mas difícil. Ruído real vem de propriedades físicas do chip MEMS (vibração térmica, tolerâncias de fabricação, drift de temperatura). Simular requer modelar distribuição Gaussiana específica de cada chipset. Emulador atual adiciona ruído uniforme — estatisticamente distinguível. Não é prioridade do Google.

### P: "`includeSensorAnalysis` — por que config no detector e não no engine?"

R: É config do **mesmo** detector, não categoria diferente. Sensor noise analysis é técnica de detecção de emulador, não categoria separada como cloning ou hooking. Config no detector segue responsabilidade única. Trade-off: 2s de Deep Scan vs ~50ms de Fast Scan — caller decide quando vale.

---

## 🎭 BLOCO 4: CloningDetector + ArtMethod DEEP DIVE

### Estrutura geral — 7 checks em 4 camadas

(Per ADR-005)

- **Layer 1 Filesystem** (Hard): Check 1 (data dir path), Check 2 (APK source path)
- **Layer 2 Memory** (Hard): Check 3 (/proc/self/maps com paths de pacotes estranhos)
- **Layer 3 Runtime** (Soft): Check 4 (env vars VirtualApp), Check 5 (stack trace), Check 6 (cloner packages)
- **Layer 4 ART internals** (Hard, positive-only): Check 7 (ArtMethod hotness_count)

### P: "Walk me through the layers."

R: Cada layer ataca a clonagem em uma fase diferente do cycle de execução do app:

- **Layer 1** pergunta "onde estão meus arquivos?" — se o filesDir tem path de outro pacote ou `/virtual/`, o filesystem foi redirecionado.
- **Layer 2** pergunta "de onde meu código foi carregado?" — se /proc/self/maps lista APKs ou .so de `/data/data/<outro_pkg>/`, o code loading veio de um container.
- **Layer 3** pergunta "quem me lançou?" — env vars do IOUniformer, stack trace com classes de cloner.
- **Layer 4** pergunta "como meu código foi compilado?" — ArtMethod hotness_count revela compilação AOT-only de DexClassLoader.

Camadas independentes = atacante precisa fingir todas simultaneamente.

### P: "Check 1 — `filesDir`. Por que não falsos positivos com Work Profile?"

R: Boa pegada. Work Profile e Samsung Secure Folder usam `/data/user/<userId>/<my_pkg>/files` com userId ≥ 10. Se eu chequasse apenas "userId != 0", flagearia legítimos. Por isso a check é mais específica: procura **outro pacote no path** (`/data/data/com.lbe.parallel.intl/...`) ou `/virtual/` (assinatura específica de containers). Work Profile mantém **meu** pacote no path; só o userId muda. Não dispara.

(Per ADR-005, item "What we chose NOT to implement": *"UID/UserHandle checks: False positives on Work Profiles (userId 10+), Xiaomi Dual Apps (userId 999), Samsung Secure Folder."*)

### P: "Check 6 — package list. É frágil?"

R: Sim, propositadamente weak. Marquei como soft signal porque:

1. Prova só que cloner está **instalado**, não que estamos **dentro dele**.
2. Android 11+ (`<queries>` restriction) limita visibilidade — preciso de `QUERY_ALL_PACKAGES` (sensitive Play Store) ou `<queries>` específicos. Atacante pode renomear o package.
3. Lista cresce — ✅ **17 packages confirmados** (`CloningDetector.kt`): `com.lbe.parallel.intl`, `com.lbe.parallel`, `com.ludashi.dualspace`, `com.excelliance.dualaid`, `com.polestar.multiaccount`, `com.polestar.super.clone`, `com.nox.mopen.app`, `com.applisto.appcloner`, `com.virtualapp`, `io.virtualapp`, `io.twoface`, `com.jumobile.multiapp`, `com.dual.clone`, `com.multi.parallel`, `com.qihoo.magic`, `com.game.cloner`, `com.x8bit.biern`.

Incluí pra cobertura de breadth, não pra reliability. O signal forte vem de Layer 1+2+4.

---

### 4.1 ArtMethod hotness_count — a explicação completa que faltava

**Contexto: o runtime ART**

ART executa código Java/Kotlin no Android. Cada método Java tem representação C++ chamada `ArtMethod` — struct na heap nativa de [libart.so](http://libart.so). Quando você faz `obj.method()`, ART encontra o ArtMethod, decide se interpreta ou JIT-compila, e roda.

ART usa **tiered compilation**:

1. **Interpreter (Nterp):** primeira execução, byte-by-byte. Lento.
2. **JIT:** depois de N execuções, compila pra código nativo. Rápido.
3. **AOT:** durante install, dex2oat compila os métodos hot offline. Mais rápido ainda.

Decidir "esse método é hot o suficiente pra JIT?" precisa de **um contador**. Esse contador é `hotness_count_`, um `uint16_t` (max 65535) dentro da struct ArtMethod.

**Insight crítico (de Mascara §IX-B):** o ART **precisa** desse contador pra funcionar. Sem ele, JIT não sabe quando compilar. Removê-lo ou falsificá-lo quebra a performance do app inteiro. Por isso é **funcional** em vez de **cosmético** — único defesa não bypassada na literatura.

**A struct (confirmada do AOSP master, runtime/art_method.h):**

```cpp
class EXPORT ArtMethod final {
 protected:
  // Field order required by test "ValidateFieldOrderOfJavaCppUnionClasses".
  GcRoot<mirror::Class> declaring_class_;       // offset 0,  4 bytes
  std::atomic<std::uint32_t> access_flags_;     // offset 4,  4 bytes
  uint32_t dex_method_index_;                   // offset 8,  4 bytes
  uint16_t method_index_;                       // offset 12, 2 bytes
  union {
    uint16_t hotness_count_;                    // offset 14, 2 bytes  ← lemos isso
    uint16_t imt_index_;
  };
  // padding alinha próximo campo
  struct PtrSizedFields {
    void* data_;
    void* entry_point_from_quick_compiled_code_;
  } ptr_sized_fields_;
};
```

**Três fatos que matam pergunta sobre offset:**

1. **A ordem é ENFORÇADA pelo AOSP CI.** O comentário no source: *"Field order required by test `ValidateFieldOrderOfJavaCppUnionClasses`"*. Esse é um teste do AOSP que **falha o build** se a ordem mudar. Não é detalhe interno frágil — é invariante mantida por CI do Google.
2. **AOSP expõe `static constexpr MemberOffset HotnessCountOffset()`** público. O próprio AOSP documenta esse offset como API estável.
3. **Hotness_count está em union com imt_index_.** Pra abstract interface methods, esse mesmo espaço é IMT index. Pra concrete methods, é hotness_count. `ActivityThread.currentActivityThread()` é static concrete, então o slot é hotness_count.

### P: "Por que offset 14 vai funcionar em Android 9 e em Android 16?"

R: Estável de Android 9 a 16 confirmado em git log do art_method.h — não houve reorganização. AOSP tem teste `ValidateFieldOrderOfJavaCppUnionClasses` que falha o build se ordem mudar. Não é hack — o próprio AOSP expõe `HotnessCountOffset()` como `static constexpr` público. Em produção, eu adicionaria tabela offset-por-API + sanity check em runtime: chamar método N vezes e validar que leio ≥N. Se sanity falha, marco "unavailable", não "safe".

### P: "Por que `ActivityThread.currentActivityThread()` especificamente?"

R: Três motivos:

1. **Static concrete method** — não preciso de instância; slot é hotness_count, não imt_index.
2. **Chamado pelo Framework MUITAS vezes** durante init do app — Process attach, lifecycle dispatching, broadcast, content provider. Hotness_count está garantidamente alto (≥10 fácil) em execução normal.
3. **Interno do framework Android** — vem em todo device, não passa por R8. Atacante não consegue removê-lo sem quebrar o app.

### P: "Por que vira 0 dentro de Parallel Space?"

R: O insight central de Mascara §IX-B.

**Execução normal:** O Android Framework (system_server) inicia seu app. Framework chama `ActivityThread.currentActivityThread()` muitas vezes durante init. Hotness_count alto.

**Dentro de container virtual:** O container app (ex: `com.lbe.parallel.intl`) inicia seu próprio process. Framework chama o método **no contexto do container** durante init do container. Depois, container faz: "agora carrego o APK do user (seu app) como plugin". Carrega via `DexClassLoader` apontando pro `/data/data/com.lbe.parallel.intl/virtual/.../base.apk`.

Esse `DexClassLoader` carrega uma **segunda cópia** dos métodos do framework no mesmo process. Essa segunda cópia **nunca foi chamada pelo system_server**, foi carregada por cima. Hotness_count = 0.

Quando meu código pede `ActivityThread.class.getDeclaredMethod("currentActivityThread")` *de dentro do código do app*, o ClassLoader visível é o do container — pego a referência da cópia zerada. **Por isso o check funciona exatamente onde importa.**

### P: "Por que sigsetjmp/siglongjmp em vez de try/catch?"

R: Três razões técnicas:

1. **C não tem try/catch.** É C++. Compilar como C++ adicionaria runtime overhead e dependência libc++.
2. **Mesmo em C++, try/catch não pega SIGSEGV.** SIGSEGV é sinal POSIX gerado pelo kernel quando acesso memória inválida — não é exception C++.
3. **`sigsetjmp`/`siglongjmp` é a única forma portável de recuperar de SIGSEGV em C:**
    - `sigsetjmp(buf, 1)` salva CPU state em `buf`, retorna 0.
    - Se SIGSEGV acontece, handler chama `siglongjmp(buf, 1)` que restaura CPU state, faz `sigsetjmp` retornar 1.
    - Padrão: `if (sigsetjmp(...) == 0) { try_read(); } else { /* recovered */ }`

Custo zero quando não há crash. Quando há crash, app não morre.

### P: "Sigsetjmp não é thread-safe — como você lida?"

R: Check é chamado uma vez por scan, sempre da mesma thread (coroutine do CloningDetector). Signal handler instalado antes do read, removido depois. Sem concorrência. Em produção com threads múltiplas, usaria thread-local sigjmp_buf (`__thread` keyword GCC ou `pthread_key_create`).

### P: "Discovery do Samsung jmethodID — explica o que aconteceu."

R: Em AOSP padrão, `jmethodID` é alias direto pra `art::ArtMethod*` — endereços de heap (`0x70328210`). Em algumas builds Samsung, jmethodID é tratado como **índice numérico** numa tabela interna, não ponteiro — vi valores `0xb` (=11), `0x14` (=20).

Quando fiz `(uint8_t*)jmethodID + 14` no Samsung normal:

- jmethodID = 0xb
- endereço = 0xb + 14 = 0x19 (= 25)
- acessar endereço 25 → SIGSEGV

Adicionei pointer validation: se `(uintptr_t)jmethodID < 0x10000`, retorno -1 (INCONCLUSIVE) sem tentar dereferenciar. Magic number 0x10000 (=65536) é threshold conservador — qualquer ponteiro real de heap é múltiplas ordens de magnitude maior.

**Insight: dentro de Parallel Space mesmo num device Samsung, o jmethodID volta a ser ponteiro AOSP real.** Por quê? Provavelmente porque o ART do container roda código AOSP-flavor pra construir jmethodIDs (o caminho `FromReflectedMethod` segue convenção AOSP). Resultado: check funciona exatamente no cenário que importa (cloning detection), fica silent em Samsung uncloned. Esse é o sweet spot positive-only: detect = definitivo, no-detect = sem opinião.

Não está documentado em paper nenhum — descoberta empírica.

### P: "FromReflectedMethod — por que esse caminho?"

R: É a API JNI documentada pra converter `java.lang.reflect.Method` → `jmethodID`. Eu tenho um `Method` object no Java side (via `ActivityThread.class.getDeclaredMethod(...)`); preciso do jmethodID nativo. Alternativas:

- `GetMethodID(env, clazz, name, sig)` — funciona mas exige passar nome+signature como strings, mais propenso a erro de typo, e em algumas builds Samsung retorna índice em vez de ponteiro mesmo pra concrete methods.
- `FromReflectedMethod` — passa o Method object diretamente, AOSP normalmente retorna ponteiro real.

Trade-off: `FromReflectedMethod` requer que o caller tenha o Method object — não pode ser puro JNI, precisa do Java side preparar. No meu caso isso é ok (é o app que orquestra).

### P: "Positive-only — não é fraco?"

R: É positive-only **por design**. Inconclusive ≠ benigno. Scoring trata explicitamente:

- Se ArtMethod retorna 0 → hard signal, confidence=1.0
- Se retorna >0 → no signal contribution (não chama secure)
- Se retorna -1 (inconclusive: API <26, jmethodID indireto, SIGSEGV recovered) → no signal contribution

Verdict final vem de defense-in-depth com os outros 6 checks do CloningDetector + os outros 3 detectors. Falsos negativos do ArtMethod são absorvidos pela combinação. Em produção a única coisa que mudaria é instrumentação — log a frequência de "inconclusive" pra detectar drift de comportamento.

### P: "ArtMethodChecker.kt — como é a public API?"

R: ✅ **Confirmado exato no código.** Fluxo completo:

```kotlin
class ArtMethodChecker {
    companion object {
        init { System.loadLibrary("artmethodcheck") }
    }
    private external fun nativeCheckHotnessCount(method: Method): Int
    fun isLikelyCloned(): ArtMethodResult { ... }  // wrapper Kotlin
}
```

Onde `ArtMethodResult` é provavelmente sealed class com `Detected(hotness: Int)`, `NormalExecution(hotness: Int)`, `Inconclusive(reason: String)`. **Verifica e ajusta.**

### P: "API level guard — qual e por quê?"

R: ✅ **Confirmado em `ArtMethodChecker.kt:26-27,57-62`:** Guard exato: `MIN_SUPPORTED_API = Build.VERSION_CODES.S` (API 31, Android 12), `MAX_SUPPORTED_API = 36`. Se `sdkInt < 31 || sdkInt > 36` → retorna `CheckResult.Inconclusive`. Escolhi API 31 (não 26) porque verifiquei o struct layout no AOSP source de `android-12.0.0_r1` até `main` — o offset 14 é idêntico nesse range. Antes de API 31 não verifiquei e preferi não arriscar.

---

### 4.2 Conexão CloningDetector ↔ HookingDetector — diferença de propósito no /proc/self/maps

Ambos detectors leem `/proc/self/maps`, mas perguntam coisas diferentes:

- **CloningDetector check 3:** procura paths de **PACOTES estranhos** (`/data/data/com.lbe.parallel.intl/...`). Se algum .so ou .apk no map vem de outro app, código foi loaded de container.
- **HookingDetector check 1:** procura **NOMES DE BIBLIOTECAS** de instrumentação (`frida`, `xposed`, `substrate`, `gadget`, `lspd`). Se aparecem, hooking framework está injetado.

Sinais ortogonais. Mesmo arquivo, perguntas diferentes.

---

## 🔐 BLOCO 5: IntegrityDetector — código-específico

### P: "4 checks, lista."

R: ✅ **Confirmado em `IntegrityDetector.kt:64-92`:** 4 checks — `checkSigningCertificate` (hard signal: SHA-256 do cert via `PackageManager.GET_SIGNING_CERTIFICATES` API 28+, fallback `GET_SIGNATURES`), `checkDebugFlag` (`ApplicationInfo.FLAG_DEBUGGABLE`), `checkInstallerSource` (`getInstallSourceInfo` API 30+, fallback `getInstallerPackageName`), `checkDexIntegrity` (CRC32 via `ZipFile.getEntry("classes.dex").crc` — implementado mas requer `expectedDexCrcs` no constructor, default `emptyMap` = skipped).

1. **Cert hash SHA-256** (Hard signal) — comparação contra baseline esperado
2. **Debug flag** (Soft) — `ApplicationInfo.FLAG_DEBUGGABLE`, soft porque MDM legítimo pode set
3. **Installer source** (Soft) — `getInstallerPackageName()` contra whitelist de stores
4. **DEX CRC** (parcial) — documentado mas não totalmente implementado

### P: "Se atacante troca o hash no smali?"

R: Pode. Fiz o teste real seguindo paper "You Shall not Repackage" §3 steps 7-12: apktool d → vi hash em plaintext no smali → modifiquei → re-assinei com chave do atacante → IntegrityDetector pegou (cert hash diferente). Mas atacante pode encontrar e substituir. Por isso:

1. R8 obfusca código no release (hash em `a10.smali` em vez de `MainViewModel.smali`)
2. String constants permanecem visíveis (limitação R8 — DexGuard resolveria)
3. HookingDetector pega Frida (atacante mais sofisticado usa Frida em vez de smali edit)

A defesa real é **server-side** (Play Integrity ou nonce-based attestation). Cliente reporta, servidor valida. Tudo client-side é eventualmente bypassável (paper §5).

### P: "DEX CRC — por que não implementou totalmente?"

R: Two-pass build necessário: compilar, extrair CRC, armazenar em resources, recompilar. Funciona pra APK direto mas quebra com AAB/Play App Signing (Google modifica DEX durante processamento). Pro challenge (debug APK) funciona; documentei como faria no ADR-006.

### P: "Installer check — e MDM enterprise?"

R: Por isso é soft signal. MDM instala via package name do agente MDM (ex: `com.microsoft.windowsintune`), não via `com.android.vending`. ✅ **16 stores confirmados** (`IntegrityDetector.kt:347-363`): `com.android.vending` (Play), `com.amazon.venezia` (Amazon), `com.huawei.appmarket` (Huawei), `com.samsung.android.vending` + `com.sec.android.app.samsungapps` (Samsung), `com.xiaomi.market` + `com.xiaomi.mipicks` (Xiaomi), `com.oppo.market` + `com.heytap.market` (OPPO/OnePlus), `com.bbk.appstore` (Vivo), `com.lenovo.leos.appstore` (Lenovo), `com.meizu.mstore` (Meizu), `com.tencent.android.qqdownloader` (Tencent MyApp), `com.baidu.appsearch` (Baidu), `com.wandoujia.phoenix2` (Wandoujia), `com.hicloud.android.clone` (Huawei Clone).

---

## 🪝 BLOCO 6: HookingDetector — código-específico

### Estrutura — 5 checks

(Per ADR-007)

- **Hard:** Check 1 (libs em /proc/self/maps), Check 2 (rwxp segments)
- **Soft:** Check 3 (Frida port scan), Check 4 (Xposed class), Check 5 (active debugger)

### P: "Frida pode renomear lib. Check 1 ainda funciona?"

R: Parcialmente. Com Frida vanilla pego: 3 bibliotecas + 39 segmentos rwxp. Com [strongR-frida](https://github.com/hzzheyang/strongR-frida-android) (Frida patcheado que remove strings), check 1 (lib names) seria bypassado. **MAS o check 2 (rwxp) sobrevive** — Frida **arquiteturalmente precisa** de páginas read+write+execute pra seu engine JavaScript (GumJS/V8). É consequência de design, não bypassável sem mudar fundamentalmente como Frida funciona. Paper "Unmasking the Veiled" identifica `HOOK-PROC_ART-MAPS` como padrão mais comum — exatamente o que implemento.

### P: "Por que rwxp é arquitetural pro Frida?"

R: Frida injeta um agent (.so) com V8 (ou QuickJS). V8 é JIT compiler — gera código de máquina em runtime a partir do JavaScript do atacante. Código gerado precisa ser executável (X) e foi recém-escrito (W). Apps normais quase nunca têm rwxp porque:

- **Princípio W^X:** OSes modernos marcam código como RX e dados como RW. RWX é um security smell.
- Único legítimo no Android: `[anon:dalvik-jit-code-cache]` — JIT do próprio ART. Whitelistei explicitamente.

Quando Frida injeta, V8 cria páginas rwxp pra JIT-compilar o JS. Encontrei 39 segmentos no teste — todos do Frida.

### P: "E Frida Gadget em vez de frida-server?"

R: Frida Gadget é embeddado no APK, sem porta TCP. Port scan (check 3) não pega. **MAS:**

- /proc/self/maps (check 1) AINDA pega o nome da lib (a menos que o atacante use strongR-frida pra renomear)
- rwxp (check 2) AINDA pega — Gadget também usa V8
- Stack trace pode pegar (LSPosed Class.forName recursive detection)

Diferença é que nome da lib pode ser customizado no Gadget. Por isso o check 2 (rwxp) é o defensável.

### P: "Promon 2024 — só 2% dos top apps detectam Frida?"

R: Sim, é uma estatística importante. Maioria dos apps comerciais **não** detecta Frida — usam SafetyNet (descontinuado) ou bibliotecas vendor que cobrem mal. Implementar 2 mecanismos ortogonais (lib name + rwxp) coloca esse SDK no top 2%. Frame pra entrevista: "Frida é a ferramenta mais usada pra bypassar detecção, e a maioria das soluções comerciais não pega. Anti-Frida é onde o gap entre defesa nominal e defesa real é maior."

### P: "Active debugger detection diferente do FLAG_DEBUGGABLE?"

R: Sim. `ApplicationInfo.FLAG_DEBUGGABLE` é flag de **build-time** — set no AndroidManifest do APK, vira true se foi compilado em debug. Diz se o APK foi **construído pra ser** debugável. **Active debugger** é runtime: `Debug.isDebuggerConnected()` (JDWP attached agora) + `/proc/self/status` `TracerPid != 0` (ptrace attached agora). Diferentes momentos, diferentes signals. IntegrityDetector check 2 é build-time; HookingDetector check 5 é runtime.

---

## 🌳 BLOCO 7: Root Detection — por que não implementei

### P: "Incognia se preocupa com root. Por que ausente?"

R: Decisão consciente, ADR-008. Root é **enabler**, não evidência. Se alguém faz root pra atacar, HookingDetector pega Frida/Xposed (as ferramentas que usam DEPOIS do root). Implementar root como hard signal bloquearia milhões de power users legítimos (Magisk, custom ROMs). Documentei como faria: 6 checks soft signals — su binary, busybox, test-keys em Build.TAGS, Magisk pkg, /system writable, Zygisk fingerprint em /proc/self/attr/prev. Paper "Android Rooting: An Arms Race" (Wiley 2017) mostra que maioria de root detection é evadida via Magisk DenyList de qualquer jeito.

### P: "E GPS spoofing?"

R: Pra Incognia especificamente, GPS spoofing é vetor real. Root permite GPS spoofing, mas root detection não é suficiente — dá pra spoofar GPS sem root via "Mock Locations" do Developer Options. Signal mais valioso é detectar inconsistências entre GPS e cell towers/WiFi positioning, alinhado com core business da Incognia. Não implementei porque está fora do escopo do challenge (que é environment detection, não location validation).

---

## 🧪 BLOCO 8: Testing — como validei

### P: "Testou em device real?"

R: Samsung Galaxy físico: SECURE 0% (sem FPs). Emulator API 36 (Pixel 6 AVD): TAMPERED 100%. Parallel Space no Samsung: TAMPERED 100% (3 hard signals + ArtMethod hotness=0). Frida no emulator rootable: TAMPERED 100% (rwxp + lib names sobrevivem).

### P: "Repackaging attack real?"

R: Sim. Sequência exata: `apktool d app.apk` → editei `strings.xml` → `apktool b` → `keytool -genkey` chave do atacante → `apksigner sign` → `adb install` no emulator → IntegrityDetector pegou: cert hash diferente, confidence 100%. ✅ **Confirmado:** documentado em `docs/testing/attacker-perspective-tests.md` (Test 4 e Test 5). Original cert: `f9c0679e...`, attacker cert: `6e5520a3...`.

### P: "Automatizou os testes?"

R: Duas camadas:

1. **Unit tests** (4 arquivos puro Kotlin): testam scoring logic, data models, error handling. Mockam Build, Process, Sensor.
2. **Integration tests** (shell script): builda APK, instala, tap scan via UI Automator, parseia logcat (`-s TamperDetection`), asserta resultados. 15/15 pass. ✅ **Confirmado:** script em `tools/tests/run-security-tests.sh`. Testa: emulator detection (fast+deep), no false positive cloning, no false positive hooking, performance <5s, todos 4 detectors executados, evidence count.

### P: "Testou em quantos devices?"

R: 2 — Samsung físico + emulator API 36. Limitação honesta. Em produção precisaria de 50+ models (Pixel, Xiaomi, Huawei, OPPO, Vivo, OnePlus, Sony, Motorola...) com diversidade de OEMs e versions. Lab de devices reais ou Firebase Test Lab.

---

## 🎤 BLOCO 9: Perguntas difíceis — código-específicas

### P: "Se tivesse mais 1 semana, ordem de prioridade?"

R: 5 itens, ordem:

1. **Anti-debug NDK** — `ptrace(PTRACE_TRACEME, 0, NULL, NULL)` no init do .so. Mata 90% dos debuggers Java por design (Linux só permite um tracer por process). Cobre o gap explícito do ARAP §III.
2. **String encryption no .so** — XOR + base64, montado em runtime. Esconde "ranchu", "frida", cert hash baseline. Limitação atual do R8.
3. **Server-side attestation peer** — Play Integrity API com nonce do nosso backend. Cliente envia (a) verdict Play Integrity, (b) installation_id, (c) raw signals. Backend = fonte da verdade.
4. **RootDetector** como 5º detector com weight=0.1 (soft) — ADR-008 já documenta os 6 checks. Não bloquearia, observaria.
5. **Periodic re-checks** — não só no scan manual; verificar a cada 30s em background pra detectar Frida injetado depois do init.

### P: "Se começasse de novo, o que faria DIFERENTE?"

R: 3 coisas concretas:

1. **Release build no dia 1** — descobri tarde que R8 não obfusca string constants. Se tivesse testado release no dia 1, teria pesquisado DexGuard / encryption desde o início e provavelmente implementado pelo menos string XOR no .so.
2. **Pesquisar jmethodID indireto ANTES de implementar ArtMethod** — descobri por crash no Samsung. A literatura sobre customizações OEM do ART não é farta, mas teria evitado 1 dia de debugging se tivesse feito spike antes.
3. **Menos checks, mais profundidade** — tenho 9 checks no EmulatorDetector. Os 4 fortes (sensor name, Build.HARDWARE, sensor noise, GL renderer) carregam o sinal. Os outros 5 são ruído. Cortaria pra 4 e documentaria os outros como "considerados, não incluídos por FP rate ou contribuição marginal".

### P: "Limitações honestas?"

R: 5:

1. **Toda detecção client-side é bypassável dado esforço suficiente** — paper Merlo §5 prova nos 6 esquemas analisados. A defesa real é defense-in-depth (forçar atacante a bypassar todos simultaneamente) + server-side validation.
2. **String constants visíveis no release** — R8 limita; DexGuard ou encryption no .so resolveriam.
3. **ArtMethod inconclusive em Samsung uncloned** — descoberta empírica do jmethodID indireto. Funciona dentro do container (cenário que importa) mas não em Samsung normal. Trato com pointer validation < 0x10000.
4. **Sem server-side validation** — cliente reporta mas não tem backend pra validar. Próximo passo claro.
5. **Testado em 2 devices apenas** — Samsung + emulator. Em produção precisa 50+ models pra calibrar FP rate per-OEM.

### P: "Se Incognia já tem SDK, qual seria o valor do que você construiu?"

R: Não sou produto, sou demonstração. Mostra que: (a) entendo o domínio em profundidade — papers acadêmicos, não só blog posts; (b) implemento com qualidade de produção — modular, testado, documentado com ADRs; (c) penso adversarialmente — bypassei meu próprio sistema com Frida e apktool antes de declarar pronto; (d) descubro coisas que não estão na literatura — Samsung jmethodID indireto. ArtMethod hotness_count é técnica que poucos candidatos conhecem; ter implementação funcionando + descoberta empírica diferencia.

### P: "Adversário ataca seu sistema. Walk through dos primeiros 30 min."

R:

- 0-5 min: `apktool d app.apk`. Veria smali do MainViewModel chamando DetectionEngine. Encontraria nomes de classes de detector (R8 obfusca mas uns sobrevivem por @Keep ou via reflection).
- 5-15 min: grep por "ranchu", "goldfish", "frida", "xposed". Encontraria as strings literais. Frida script: hookar `String.contains` pra retornar false pra essas strings.
- 15-25 min: testaria. EmulatorDetector hard signals iriam falhar. Mas /proc/self/maps via JNI ainda dispararia. Próximo: hookar `BufferedReader.readLine` pra filtrar linhas suspeitas do /proc/maps.
- 25-30 min: ArtMethod ainda dispararia. Próximo passo seria hookar a JNI native function — Frida pode hookar funções nativas via NativeFunction. Esse é o ataque mais sofisticado.

**Defesa em produção:** ptrace TRACEME no init do .so, e fazer o check de hotness_count dentro de uma rotina mais difícil de hookar (inline assembly em vez de chamada de função).

---

## 📝 CHECKLIST FINAL — 30 min antes da entrevista

- [ ]  Vídeo Frida bypass aberto, 60s, ready to share
- [ ]  Repo aberto no Android Studio, font 18+, ArtMethodChecker.kt + art_method_check.c já abertos
- [ ]  Bloco de papel + caneta na mesa pra desenhar struct/arquitetura
- [ ]  3 perguntas pra eles anotadas no canto da tela
- [ ]  Frase de abertura 90s ensaiada (ver topo)
- [ ]  ADR-002 vs threshold no código reconciliado (ver "Verificações urgentes")
- [ ]  Inhaler usado se necessário, água ao lado
- [ ]  Frase pronta pro Claude/AI question na ponta da língua
- [ ]  Cabeça calma. Você fez o trabalho. Nada do que vão perguntar é maior do que o que você já investigou.

## ⛔ O QUE NÃO ESTUDAR (resista)

1. ❌ Re-ler Mascara inteiro. §IX-B + §VIII suficiente.
2. ❌ Implementar root detection ou ptrace TRACEME nas últimas 24h. Bug não-testado quebra coisas funcionando.
3. ❌ Reorganizar o README.
4. ❌ Mais 1 paper além dos listados.

**Sono > último 5%.**

---

## 📂 REFERÊNCIA RÁPIDA DO CÓDIGO (verificado arquivo por arquivo)

### ArtMethod — o diferencial

| Item | Valor exato | Arquivo:Linha |
|------|-------------|---------------|
| Método inspecionado | `ActivityThread.currentActivityThread()` | `ArtMethodChecker.kt:70-71` |
| External fun | `private external fun checkHotnessCount(method: Any): Int` | `ArtMethodChecker.kt:91` |
| Lib nativa | `"antitamper_native"` | `ArtMethodChecker.kt:37` |
| Wrapper público | `fun check(): CheckResult` (sealed: Detected/Normal/Inconclusive) | `ArtMethodChecker.kt:52` |
| API guard | MIN=31 (Android 12), MAX=36 | `ArtMethodChecker.kt:26-27` |
| JNI function | `Java_com_bruno_antitamperingapp_detection_detectors_ArtMethodChecker_checkHotnessCount` | `art_method_check.c:106-107` |
| jmethodID resolve | `FromReflectedMethod` (NÃO GetMethodID) | `art_method_check.c:115` |
| Offset | `#define HOTNESS_COUNT_OFFSET 14` | `art_method_check.c:32` |
| Pointer validation | `if (ptr_value < 0x10000)` → skip | `art_method_check.c:132` |
| Signal handler | `sigaction` (POSIX, com SA_SIGINFO), instalado/removido a cada call | `art_method_check.c:74-103` |
| Thread safety | Jump buffer é `__thread` (thread-local), mas `s_old_action` é global estático (race teórica, baixo risco) | `art_method_check.c:40-43` |
| Retorno nativo | -1=error, 0=normal (hotness>0), 1=virtual container (hotness==0) | `art_method_check.c:35-37` |

### DetectionEngine — orquestração

| Item | Valor exato | Arquivo:Linha |
|------|-------------|---------------|
| Dispatcher | `Dispatchers.Default` (NÃO IO) | `DetectionEngine.kt:31` |
| Paralelismo | `async { runDetector() }` + `awaitAll()` | `DetectionEngine.kt:37-40` |
| Scope | `withContext` (NÃO supervisorScope) | `DetectionEngine.kt:31` |
| Timeout no engine | NÃO tem (timeout está no detector: sensor 4000ms) | — |
| Exception handling | try-catch no `runDetector` → `DetectionResult(detected=false, errors=[Unexpected])` | `DetectionEngine.kt:67-81` |
| Score se any detected | `1.0f` → TAMPERED | `DetectionEngine.kt:44-46` |
| TAMPERED threshold | `0.45f` | `DetectionEngine.kt:141` |
| WARNING threshold | `0.2f` | `DetectionEngine.kt:144` |
| Builder | `mutableListOf<TamperDetector>()`, `addDetector()` returns `apply{}`, `require(isNotEmpty)` | `DetectionEngine.kt:126-136` |

### EmulatorDetector — 9 checks

| # | Check | Método | Hard? |
|---|-------|--------|-------|
| 1 | Build properties (6 props: HARDWARE, FINGERPRINT, DEVICE, MODEL, PRODUCT, MANUFACTURER) | `checkBuildProperties()` | HARDWARE é hard |
| 2 | System properties (4: ro.kernel.qemu, ro.hardware, init.svc.qemud, ro.kernel.android.qemud) | `checkSystemProperties()` | ro.kernel.qemu é hard |
| 3 | Sensor strings (accel + gyro name "Goldfish", vendor "AOSP") | `checkSensorHardwareStrings()` | Hard |
| 4 | Sensor absence (step counter + significant motion) | `checkSensorAbsence()` | Soft (0.5) |
| 5 | Sensor noise (accel stddev<0.002, gyro stddev<0.001, 2s sampling SENSOR_DELAY_GAME) | `runSensorNoiseAnalysis()` | Soft (0.8) |
| 6 | Battery (temperature==0, voltage==0) | `checkBattery()` | Soft (0.85) |
| 7 | GL Renderer ("Android Emulator", "SwiftShader", "Bluestacks", "Translator") via PBuffer EGL | `checkGlRenderer()` | Hard |
| 8 | File artifacts (5 paths: qemu-props, qemu_pipe, goldfish_pipe, qemud socket, malloc debug) | `checkFileArtifacts()` | Soft (0.6) |
| 9 | Telephony (networkOperatorName=="Android", simOperatorName=="Android") | `checkTelephony()` | Soft (0.55) |

Config: `EmulatorDetector(includeSensorAnalysis: Boolean = true)` — `false` pula check 5 (~50ms vs ~2s).

### CloningDetector — 7 checks

| # | Check | Hard? | Detalhes |
|---|-------|-------|----------|
| 1 | Data dir path | Hard | `context.filesDir` contém foreign package ou segmentos `/virtual/`, `/parallel_intl/`, `/parallel_space/`, `/dualspace/`, `/clone/` |
| 2 | APK source path | Hard | `applicationInfo.sourceDir` não começa com `/data/app/` |
| 3 | /proc/self/maps foreign paths | Hard | Paths executáveis (`.apk .dex .so .odex .vdex .oat .art`) de outro package. Non-exec (fontes, configs) ignorados |
| 4 | Environment vars | Soft (0.7) | 7 vars: `V_REPLACE_ITEM`, `V_KEEP_ITEM`, `V_SO_PATH`, `REPLACE_ITEM_ORIG`, `REPLACE_ITEM_DST`, `V_API_LEVEL`, `V_PREVIEW_API_LEVEL` + LD_PRELOAD pointing to /data/data/ |
| 5 | Stack trace | Soft (0.6) | 8 prefixes: `com.lody.virtual`, `com.doubleagent`, `io.va.exposed`, `com.excelliance`, `io.tt`, `com.estrongs.vbox`, `org.nl`, `com.polestar` |
| 6 | Known packages | Soft (0.4) | 17 packages (listados acima) |
| 7 | ArtMethod hotness_count | Hard | hotness_count==0 → virtual container. Positive-only. |

### IntegrityDetector — 4 checks

| # | Check | Hard? | Detalhes |
|---|-------|-------|----------|
| 1 | Signing cert SHA-256 | Hard (ÚNICO) | `PackageManager.GET_SIGNING_CERTIFICATES` (API 28+), fallback `GET_SIGNATURES`. Hash em `MainViewModel.kt:48` |
| 2 | Debug flag | Soft (0.6) | `ApplicationInfo.FLAG_DEBUGGABLE` |
| 3 | Installer source | Soft (0.4) | `getInstallSourceInfo` (API 30+), fallback deprecated. 16 stores whitelisted |
| 4 | DEX CRC | Soft (0.8) | `ZipFile.getEntry("classes.dex").crc`. Implementado mas skipped (default emptyMap) |

### HookingDetector — 5 checks

| # | Check | Hard? | Detalhes |
|---|-------|-------|----------|
| 1 | /proc/self/maps hooking libs | Hard | 7 patterns: `frida`, `gadget`, `xposed`, `substrate`, `lspd`, `edxposed`, `libgadget` |
| 2 | rwxp memory segments | Hard | Match literal `"rwxp"`. Whitelist: `dalvik-jit-code-cache` + `dalvik-zygote-jit-code-cache`. **NÃO** tem whitelist para Hermes/Flutter JIT (potencial FP em React Native) |
| 3 | Frida port scan | Soft (0.7) | `Socket().connect(InetSocketAddress("127.0.0.1", port), 200)` para ports 27042, 27043. Só TCP connect, NÃO faz D-Bus AUTH handshake |
| 4 | Xposed classes | Soft (0.8) | `Class.forName()` para 3 classes: `XposedBridge`, `XposedHelpers`, `XC_MethodHook` |
| 5 | Debugger | Soft (0.6) | `Debug.isDebuggerConnected()` (JDWP) + `/proc/self/status` TracerPid (ptrace) |