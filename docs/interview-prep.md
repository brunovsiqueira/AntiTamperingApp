# Preparação para Entrevista — Guia de Estudo

Este documento NÃO vai para o deliverable. É para estudo pessoal.

---

## PLANO DE ESTUDO (5-6h)

### Hora 1: Entender o que Incognia quer ouvir
- Ler esta seção inteira (CONTEXTO INCOGNIA) + a seção de Leitura Recomendada
- Frase-chave para usar no início da entrevista: **"tamper detection é a camada que torna todos os outros sinais confiáveis"** — isso é literalmente o framing deles no blog
- Ler: https://incognia.com/device-tamper-detection (o que eles oferecem como produto)

### Hora 2: Dominar a arquitetura e scoring
- Blocos 1 e 2 abaixo — ler cada P/R em voz alta
- Abrir `DetectionEngine.kt`, `TamperDetector.kt`, `DetectionResult.kt` no Android Studio enquanto lê
- Praticar desenhar a arquitetura de memória (DetectionEngine → Builder → async detectores → verdict)

### Hora 3: Dominar os detectors (EmulatorDetector + CloningDetector)
- Blocos 3 e 4 abaixo
- Abrir `EmulatorDetector.kt` e `CloningDetector.kt` — navegar por cada check
- A história do ArtMethod é o diferencial: crash → signal handler → jmethodID indireto → funciona dentro do container
- Ler Mascara §IX-B: https://ar5iv.labs.arxiv.org/html/2010.10639#S9.SS2

### Hora 4: Dominar IntegrityDetector + HookingDetector + Root Decision
- Blocos 5, 6, 7 abaixo
- O rwxp check é o mais forte contra Frida — entender por quê
- Saber explicar por que NÃO implementou root (ADR-008) e como faria

### Hora 5: Estudar os papers (seções específicas)
- "You Shall not Repackage" §3 (Attack Model) + §4-5 (6 esquemas e bypasses): https://ar5iv.labs.arxiv.org/html/2009.04718
- "Mascara" §VIII (18 mecanismos bypassados) + §IX-B (ArtMethod): https://ar5iv.labs.arxiv.org/html/2010.10639
- OWASP MASVS-RESILIENCE: https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/

### Hora 6: Preparação estratégica
- Reler Bloco 8 (testing) e Bloco 9 (perguntas difíceis)
- Praticar o script do Claude/AI (ver seção SCRIPT CLAUDE abaixo)
- Dry run 10min: compartilhar tela e apresentar README → arquitetura → 1 detector → teste Frida
- Preparar 3 perguntas para fazer a ELES (ver seção PERGUNTAS PARA ELES abaixo)

---

## CONTEXTO INCOGNIA — O que eles valorizam

**SDK deles:** 415KB Android, 0.5%/dia bateria, 66ms processamento. Se seu SDK é 9MB debug / 968KB release, o release está no ballpark.

**Frase do job description deles:** *"executamos código nos aplicativos de terceiros... extremo cuidado e controle rigoroso de recursos (threads, memória, processamento)"*. Isso = tudo que fizemos com coroutines, SafeExec, fail-open, sensor sampling opcional.

**O que eles detectam (público):** emuladores, location spoofing, app cloners, app tampering tools, image injectors, remote-access tools (AnyDesk/TeamViewer). Nós cobrimos os 4 primeiros.

**Stat deles:** 5% dos devices flagged como risky têm pelo menos 1 issue de integridade. Devices risky são 5x mais propensos a ter issue de integridade.

**Framing para usar:** "Tamper detection é a foundation — se o ambiente não é confiável, os sinais de identidade e localização vindos dele também não são."

**Quem pode te entrevistar:**
- **Gabriel Falcone** (VP Mobile, co-founder) — visão de produto e arquitetura
- **Pedro Atanásio** (Staff, C/C++/Java) — se ele estiver, perguntas de NDK/JNI são garantidas. Bom pra nós: temos ArtMethod em C
- **Thiago Figueredo Cardoso** (ARM disassembly background) — reverse engineering profundo

## O QUE TEMOS QUE A MAIORIA DOS CANDIDATOS NÃO TERIA

O research lista como "biggest gap" que candidatos não têm NDK. **Nós temos.** Isso muda a dinâmica:

| "Red flag" do research | Nosso status |
|----------------------|-------------|
| "No native code — biggest gap" | **Temos:** ArtMethod em C com JNI + SIGSEGV handler |
| "No bypass testing" | **Temos:** 3 Frida scripts + repackaging attack com apktool |
| "Boolean tamper detection" | **Temos:** multi-signal weighted scoring com two-tier |
| "No multi-signal scoring" | **Temos:** hard signals + soft scoring ponderado |
| "Hardcoded secrets grep-able" | **Parcial:** R8 obfusca internals no release, mas strings visíveis (limitação R8) |
| "SafetyNet" | **Não usamos** — sabemos que foi descontinuado May 2025 |
| "No false positive awareness" | **Temos:** GMS emoji font fix, extensão-based filter, 16 stores na whitelist |
| "Crash on detection" | **Não crashamos** — fail-open com SafeExec |

## SCRIPT CLAUDE/AI — Preparar esta resposta EXATA

Se perguntarem "usou AI?":

> "Sim, usei Claude como pair programmer. Eu defini a arquitetura (módulo separado, Strategy pattern, Builder, two-tier scoring), escolhi quais sinais implementar e por quê (baseado em papers como Mascara e 'You Shall not Repackage'), e validei tudo em devices reais e emuladores. Claude me ajudou a escrever o código mais rápido, mas cada decisão de design é minha — posso explicar o trade-off de cada uma. Onde fiquei surpreso foi com o ArtMethod: implementei baseado no paper Mascara, mas descobri na prática que Samsung usa jmethodID indireto — isso não está documentado em nenhum paper. Essa descoberta é 100% do processo de teste real, não de AI."

**Se pedirem para modificar código ao vivo:** estar preparado para adicionar um check novo (ex: `Build.HOST`) no EmulatorDetector em 2 minutos. Praticar isso.

## PERGUNTAS PARA FAZER A ELES

1. "Como o SDK da Incognia atualiza regras de detecção sem update do app? Remote config, scoring server-side, ou algo diferente?"
2. "Qual é o target de false positive rate para um sinal de tampering que pode ser 'blocking' vs um que só pode ser 'observing'? Como vocês graduam um detector?"
3. "Onde está o foco atual do time — fechar o gap em virtualizers como VirtualXposed, ou em combinações emergentes como cloner-on-emulator?"

## Leitura recomendada (papers)

Ler pelo menos as seções indicadas de cada paper:

1. **"You Shall not Repackage"** (Merlo et al., 2021) — o mais importante
   - Full: https://ar5iv.labs.arxiv.org/html/2009.04718
   - Seção 3 (Attack Model): como um atacante repackageia — Steps 7-12
   - Seção 4 (Anti-repackaging schemes): os 6 esquemas analisados e por que cada um falha
   - Seção 5 (Attacks): como bypassaram cada esquema

2. **"Mascara"** (Alecci et al., 2020) — ArtMethod hotness_count
   - Full: https://ar5iv.labs.arxiv.org/html/2010.10639
   - Seção VIII: 18 mecanismos de defesa que Mascara bypassou
   - Seção IX-B (Countermeasures): proposta do ArtMethod hotness_count — ÚNICA defesa não bypassada

3. **"ARAP"** (Suo et al., 2024) — maior estudo de anti-runtime analysis
   - PDF: https://arxiv.org/pdf/2408.11080
   - Abstract: 117K apps, 1515 features, 99.6% usam pelo menos 1 técnica ARA
   - 5 categorias: Anti-Debugging, Anti-Hooking, Anti-Tampering, Root Detection, Virtual Environment Detection

4. **"Parallel Space Traveling"** (Dai et al., SACMAT 2020) — cloning
   - PDF: https://www.cs.ucr.edu/~heng/pubs/sacmat2020.pdf
   - Como virtual containers funcionam tecnicamente
   - 160+ apps de virtualização analisados

5. **"Cat-and-Mouse Game"** (ISSRE 2024) — hooking arms race
   - PDF: https://diaowenrui.github.io/paper/issre24-li.pdf
   - 108K apps benignos + 11K maliciosos
   - 68.1% dos apps do Play Store usam técnicas de evasão

6. **OWASP MASVS-RESILIENCE** — standards
   - RESILIENCE-2 (anti-tampering): https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-2/
   - RESILIENCE-4 (anti-dynamic analysis): https://mas.owasp.org/MASVS/controls/MASVS-RESILIENCE-4/
   - MASWE-0098 (virtual environment detection): https://mas.owasp.org/MASWE/MASVS-RESILIENCE/MASWE-0098/

---

## BLOCO 1: Arquitetura — "Por que fez assim?"

### P: Por que separou em módulo Gradle?
R: Porque o challenge pede "componente Android" — o módulo `:detection` é um Android Library que qualquer app pode importar via `implementation(project(":detection"))`. Isso garante boundary limpo: a UI não acessa internals da detecção, e o SDK não sabe nada sobre a UI. Em produção, seria distribuído como AAR via Maven.

### P: Por que Strategy pattern e não herança?
R: Os 4 detectores são independentes — não compartilham estado, não dependem um do outro, e rodam em paralelo. Strategy pattern permite adicionar um novo detector (ex: RootDetector) com UMA classe nova e UMA linha no Builder. Se usasse herança, teria acoplamento desnecessário e não poderia rodar em paralelo facilmente.

### P: Por que Builder e não construtor direto?
R: O Builder permite que o consumidor do SDK escolha quais detectores ativar. Um app de banking pode querer todos os 4. Um app de jogos pode querer só EmulatorDetector. Flexibilidade sem complexidade.

### P: Por que coroutines e não threads?
R: Coroutines são o padrão Android moderno para concorrência. Structured concurrency garante que se o caller cancelar, todos os detectores são cancelados automaticamente. `async`/`awaitAll` paralleliza os 4 detectores com código legível. O tempo total é o do detector mais lento (~2s), não a soma.

### P: Como garantiu que o SDK nunca crasha o app host?
R: Três camadas:
1. `SafeExec.runCatching()` — wrapper defensivo em cada check individual
2. try-catch no `DetectionEngine.runDetector()` — safety net por detector
3. Erros são estruturados (`DetectionError` sealed class) e reportados, nunca propagados
Princípio: fail-open com observabilidade. O detector reporta o que CONSEGUIU avaliar, mesmo com erros parciais.

---

## BLOCO 2: Scoring — "Como decide se é tampered?"

### P: Por que two-tier e não só score?
R: Descobri na prática. No primeiro teste, o emulador deu 59% (WARNING) apesar de 6/9 grupos de checks dispararem. Porque o scoring diluía: 3 grupos limpos (bateria, arquivos, telephony) puxavam a média pra baixo. Hard signals como Build.HARDWARE="ranchu" são DEFINITIVOS — não faz sentido ponderar com outros sinais. Se um hard signal dispara, é 100%.

### P: O que é hard signal vs soft signal?
R: Hard signal = zero falso positivo documentado. Exemplos:
- Build.HARDWARE="ranchu" → nenhum fabricante real usa esse nome (é o virtual board do QEMU)
- Sensor "Goldfish" → nome exclusivo do HAL de sensor do emulador
- Cert hash mismatch → criptograficamente impossível sem a chave privada

Soft signal = pode ter falso positivo. Exemplos:
- Bateria temp=0 → emuladores modernos simulam 25°C
- Installer null → pode ser MDM empresarial legítimo
- Sensor ausente → devices baratos podem não ter step counter

### P: Por que o threshold é 0.35?
R: Significa que ~2-3 sinais soft independentes precisam disparar antes de flagear. Calibrado empiricamente — no teste com Frida bypass, os sinais soft que sobreviveram (sensor noise + sensor absence) deram 28%. Com threshold 0.35 isso é WARNING, não TAMPERED. Faz sentido porque o atacante conseguiu spoofar 5 hard signals, então a confiança reduzida é esperada.

### P: Se qualquer detector diz "detected", o verdict é TAMPERED. Não é agressivo demais?
R: Não, porque cada detector só retorna `detected=true` quando a confiança interna está alta o suficiente. O EmulatorDetector precisa que hard signals disparem OU que soft signals ultrapassem 0.35. Não é "qualquer sinal fraco = TAMPERED". É "pelo menos um detector está confiante o suficiente = TAMPERED".

---

## BLOCO 3: EmulatorDetector — "Por que esses checks?"

### P: Por que 9 checks? Não é demais?
R: Defense-in-depth. Cada check individualmente é bypassável (demonstrei com Frida). Mas bypassar TODOS simultaneamente é muito mais difícil. Os 9 checks operam em camadas diferentes: propriedades do sistema, sensores, OpenGL, bateria, filesystem, telephony. Um atacante precisaria de hooks em todas essas APIs ao mesmo tempo. O paper "You Shall not Repackage" ([Seção 5](https://ar5iv.labs.arxiv.org/html/2009.04718#S5)) mostra que cada esquema individual é bypassável — a proteção vem da combinação.

### P: Por que não usou NDK para emulator detection?
R: Pesquisei a fundo. Metade dos checks (sensores, bateria) são APIs Java-only — não existe equivalente nativo. Então mesmo com NDK, metade da superfície continua hookável por Frida. O ganho de NDK para emulator detection não justifica a complexidade (CMake, JNI, multi-ABI). Para cloning detection sim, porque ArtMethod é a única técnica não bypassada na literatura.

### P: Sensor noise — de onde veio o threshold 0.002?
R: Paper peer-reviewed ([PMC10490716](https://pmc.ncbi.nlm.nih.gov/articles/PMC10490716/), 2023). Mediram 5 smartphones reais em repouso por 4 horas. Stddev do acelerômetro: 0.004-0.011 m/s². Nosso threshold 0.002 está bem abaixo do dispositivo real mais silencioso. No emulador medimos 0.000004 — 500x menor que qualquer device real. O sensor HAL do emulador é confirmado no [AOSP goldfish sensor_list.cpp](https://android.googlesource.com/device/generic/goldfish/+/84ae32bd0199a5a54e245cac08e625021e0db785/sensors/sensor_list.cpp) — todos os sensores são nomeados "Goldfish".

### P: E se o emulador melhorar a simulação de sensores?
R: Possível, mas difícil. O ruído real vem de propriedades físicas do chip MEMS (vibração térmica, tolerâncias de fabricação, drift de temperatura). Simular isso requer modelar a distribuição Gaussiana específica de cada chipset. O emulador atual adiciona ruído uniforme, que é estatisticamente distinguível. Seria um esforço significativo do Google para melhorar isso, e não é prioridade deles.

### P: `includeSensorAnalysis` — por que não é um detector separado?
R: Porque é uma configuração do MESMO detector, não uma categoria diferente de ameaça. Sensor noise analysis é uma técnica de detecção de emulador, não uma categoria separada como cloning ou hooking. Colocar a config no detector (não no engine) segue o princípio de responsabilidade única.

---

## BLOCO 4: CloningDetector — "O que mais diferencia?"

### P: O que é ArtMethod hotness_count?
R: O ART (runtime do Android) tem uma struct C++ chamada ArtMethod para cada método Java. O campo `hotness_count` (offset 14, uint16) conta quantas vezes o método foi executado — [struct definida no AOSP art_method.h](https://android.googlesource.com/platform/art/+/refs/heads/main/runtime/art_method.h). Quando um virtual container carrega o app via DexClassLoader (em vez do installer do sistema), os métodos são compilados AOT-only, deixando hotness_count=0. Em execução normal, `ActivityThread.currentActivityThread()` é chamado constantemente pelo framework, então hotness_count > 0.

### P: Mas no seu teste deu "inconclusive" no Samsung. Funciona ou não?
R: Funciona DENTRO de virtual containers (onde importa), não funciona na execução normal em Samsung. Descobrimos que Samsung usa `jmethodID` como índice (valor 0xb = 11), não como ponteiro direto para ArtMethod. Mas dentro do Parallel Space, o VirtualApp usa encoding AOSP (jmethodID é ponteiro real: 0x70328210). O check dispara EXATAMENTE no cenário que importa. Positive-only: se detecta = definitivo, se não detecta = sem opinião.

### P: De onde veio essa técnica?
R: Paper "Mascara" ([Seção IX-B — Countermeasures](https://ar5iv.labs.arxiv.org/html/2010.10639#S9.SS2)). Propõe inspecionar hotness_count como a única defesa que o ataque Mascara não conseguiu bypassar. A [Seção VIII](https://ar5iv.labs.arxiv.org/html/2010.10639#S8) mostra os 18 mecanismos que FORAM bypassados. Implementamos, descobrimos a limitação do jmethodID indireto (não documentada em nenhum paper), e tratamos com signal handler + pointer validation.

### P: O que fez quando crashou no Samsung?
R: Primeiro adicionei SIGSEGV signal handler com sigsetjmp/siglongjmp para recuperar gracefully. Depois adicionei validação do ponteiro (jmethodID < 0x10000 = claramente um índice, skip). O check nunca mais crashou. Adicionei logs de debug que mostraram o valor exato (0xb no Samsung, 0x70328210 dentro do container).

### P: /proc/self/maps — não é o mesmo check no CloningDetector e HookingDetector?
R: Mesmo arquivo, perguntas diferentes. CloningDetector procura por paths de PACOTES estranhos (ex: `/data/data/com.lbe.parallel.intl/`). HookingDetector procura por NOMES DE BIBLIOTECAS de instrumentação (ex: "frida", "xposed", "substrate"). São sinais ortogonais.

### P: Teve false positive no /proc/self/maps?
R: Sim! Google Play Services mapeia fontes emoji (`Noto_COLR_Emoji_Compat`) do diretório do GMS no processo de outros apps. Detectamos no primeiro teste em Samsung real. Fix: em vez de whitelist por package (frágil — quebraria em devices chineses), filtramos por extensão de arquivo. Só flagamos paths com `.apk`, `.dex`, `.so`, `.odex`, `.vdex`, `.oat`, `.art`. Fontes e configs são ignoradas.

---

## BLOCO 5: IntegrityDetector — "Assinatura é suficiente?"

### P: Se o atacante trocar o hash no smali?
R: Pode. Fizemos o teste real com apktool seguindo o attack model do paper "You Shall not Repackage" ([Seção 3, Steps 7-12](https://ar5iv.labs.arxiv.org/html/2009.04718#S3)): decompilamos, vimos o hash em plaintext no smali, modificamos o app, re-assinamos com chave do atacante. O IntegrityDetector pegou (100%). Mas sim, um atacante pode encontrar o hash e substituir. Por isso:
1. R8 obfusca o código no release (o hash está em `a10.smali` em vez de `MainViewModel.smali`)
2. Strings constants permanecem visíveis (limitação do R8, precisaria DexGuard)
3. O HookingDetector pega Frida — que é a ferramenta que o atacante usaria para hookar PackageManager

### P: DEX CRC — por que não implementou totalmente?
R: Two-pass build necessário: compilar, extrair CRC, armazenar em resources, recompilar. Funciona para APK direto mas quebra com AAB/Play App Signing (Google modifica o DEX durante processamento). Para o challenge (debug APK) funciona. Documentamos como fazer no ADR-006.

### P: Installer check — e apps enterprise?
R: Exatamente por isso é soft signal. MDM instala via package name do agente MDM (ex: `com.microsoft.windowsintune`), não via `com.android.vending`. Se fosse hard signal, bloquearia todo deployment enterprise. Colocamos 16 stores na whitelist incluindo chinesas (Tencent MyApp, Baidu, Wandoujia).

---

## BLOCO 6: HookingDetector — "Consegue pegar Frida?"

### P: Frida pode se renomear. Seu check de /proc/self/maps ainda funciona?
R: Parcialmente. Com Frida vanilla (padrão), pegamos: 3 bibliotecas + 39 segmentos rwxp. Com [strongR-frida](https://github.com/hzzheyang/strongR-frida-android) (Frida patcheado que remove strings), o check de nomes de biblioteca seria bypassado. MAS o check de rwxp sobrevive — Frida PRECISA de memória read+write+execute para seu engine JavaScript (GumJS/V8). Isso é arquitetural, não bypassável sem mudar fundamentalmente como Frida funciona. O paper "Unmasking the Veiled" ([AsiaCCS 2024](https://s3.eurecom.fr/docs/asiaccs24_ruggia.pdf)) identifica `HOOK-PROC_ART-MAPS` como o padrão mais comum de detecção — exatamente o que implementamos.

### P: O que é rwxp?
R: Read+Write+Execute+Private. Flags de permissão de segmentos de memória no Linux. Apps normais quase nunca têm rwxp — o único caso legítimo é o JIT cache do ART (`dalvik-jit-code-cache`), que whitelistamos. Quando Frida injeta, seu V8 JavaScript engine cria páginas rwxp para JIT compilation do código JS do atacante. Encontramos 39 segmentos rwxp no teste — todos do Frida.

### P: E se o atacante usar Frida Gadget em vez de frida-server?
R: Frida Gadget é embeddado no APK, sem porta TCP. Nosso port scan não pegaria. Mas /proc/self/maps e rwxp AINDA pegariam — o Gadget ainda injeta bibliotecas e precisa de rwxp. A diferença é que o nome da lib pode ser customizado.

---

## BLOCO 7: Root Detection — "Por que não implementou?"

### P: Incognia se preocupa com root. Por que não tem?
R: Decisão consciente, documentada no ADR-008. Root é enabler, não evidência. Se alguém faz root para atacar, nosso HookingDetector pega Frida/Xposed (as ferramentas que usam DEPOIS do root). Implementar root detection como hard signal bloquearia milhões de power users legítimos. Documentei como faria: 6 checks, todos soft signals. O paper "Android Rooting: An Arms Race" ([open access](https://onlinelibrary.wiley.com/doi/10.1155/2017/4121765)) mostra que a maioria dos métodos de root detection pode ser evadida via Magisk DenyList.

### P: E GPS spoofing?
R: Para Incognia especificamente, GPS spoofing é o vetor real de ataque. Root permite GPS spoofing, mas root detection não é suficiente — dá pra spoofar GPS sem root usando "Mock Locations" do Developer Options. O sinal mais valioso seria detectar inconsistências entre GPS e cell towers/WiFi positioning, que está mais alinhado com o core business da Incognia.

---

## BLOCO 8: Testing — "Como validou?"

### P: Testou em device real?
R: Samsung Galaxy physical: SECURE 0% (sem false positives). Emulator API 36: TAMPERED 100%. Parallel Space no Samsung: TAMPERED 100% (3 hard signals + ArtMethod). Frida bypass no emulator rootable: TAMPERED 100% (rwxp sobrevive).

### P: Fez repackaging attack real?
R: Sim. apktool d → modifiquei strings.xml → apktool b → keytool + apksigner com chave do atacante → instalei no emulador → IntegrityDetector pegou: cert hash diferente, 100% confidence.

### P: Automatizou os testes?
R: Duas camadas:
1. Unit tests: 4 arquivos, testam scoring logic, data models, error handling (puro Kotlin)
2. Integration tests: shell script que builda, instala, tap scan via UI automator, parseia logcat, asserta resultados. 15/15 pass.

---

## BLOCO 9: Perguntas difíceis — "O que faria diferente?"

### P: O que melhoraria se tivesse mais tempo?
R:
1. String encryption (DexGuard) para esconder "ranchu", "frida", cert hash no release
2. RootDetector como 5º detector (6 checks soft, já documentado no ADR-008)
3. Server-side attestation via Play Integrity API (complementar ao client-side)
4. Periodic re-checks (não só no scan manual — verificar a cada 30s em background)
5. Response strategies no SDK (block, degrade, report silently — hoje só reportamos)

### P: O que faria DIFERENTE se começasse de novo?
R:
1. Começaria com release build desde o início para testar R8 mais cedo
2. ArtMethod: pesquisaria o jmethodID indireto ANTES de implementar, evitando o crash
3. Menos checks por detector — focaria em 4-5 checks realmente fortes em vez de 9 que incluem sinais fracos

### P: Limitações honestas?
R:
1. Toda detecção client-side é bypassável dado esforço suficiente — [paper "You Shall not Repackage", Seção 5](https://ar5iv.labs.arxiv.org/html/2009.04718#S5) prova isso nos 6 esquemas analisados
2. String constants visíveis no release (limitação do R8)
3. ArtMethod inconclusivo em Samsung/devices com jmethodID indireto
4. Sem server-side validation — o client reporta mas não tem backend para validar
5. Testado em 2 devices (Samsung + emulator) — precisaria de mais diversidade (Pixel, Xiaomi, Huawei)

### P: Se Incognia já tem um SDK, qual seria o valor do que você construiu?
R: O projeto demonstra que entendo o domínio, pesquisei o estado da arte (papers acadêmicos, não só blog posts), implementei com qualidade de produção (modular, testado, documentado), e pensei como atacante (Frida bypass scripts, repackaging attack). A abordagem ArtMethod hotness_count é algo que a maioria dos candidatos não conheceria.
