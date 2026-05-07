# ADR-008: Root Detection — Por que não implementamos e como faríamos

**Status:** Deferred (decisão consciente de não implementar na v1)
**Date:** 2026-05-07

## Contexto

Root detection é uma técnica comum em SDKs de segurança mobile. A pergunta natural é: por que implementamos 4 detectors (emulador, clonagem, integridade, hooking) mas não root detection?

## Decisão: Não implementar root como detector separado na v1

### Justificativa

**Root é um *enabler*, não uma *evidência* de tampering.**

Um dispositivo rootado não prova que o app está sendo atacado — prova que *poderia* ser. Os 4 detectors que implementamos detectam ataques *reais em andamento*:

| Detector | O que detecta | É ataque real? |
|----------|--------------|----------------|
| EmulatorDetector | App rodando em emulador | Sim — ambiente não-genuíno |
| CloningDetector | App dentro de container virtual | Sim — sandbox compartilhado, dados expostos |
| IntegrityDetector | APK foi recompilado e re-assinado | Sim — código foi modificado |
| HookingDetector | Frida/Xposed injetados no processo | Sim — comportamento sendo interceptado |
| **RootDetector** | **Dispositivo tem acesso root** | **Não necessariamente — pode ser power user legítimo** |

### O que fizemos instead

Já cobrimos sinais *adjacentes* a root nos detectors existentes:

- **HookingDetector** detecta Frida e Xposed — que são as ferramentas que um atacante usa *depois* de fazer root
- **HookingDetector** detecta rwxp memory segments — Frida precisa de root para injetar
- **HookingDetector** detecta debugger via TracerPid — normalmente requer root
- **IntegrityDetector** detecta debug flag — apps repackaged em devices rootados frequentemente habilitam

Ou seja: se alguém usa root para atacar, nossos detectors já pegam as *consequências* do root (Frida, hooking, repackaging), não apenas a *possibilidade*.

### Falsos positivos do root detection

Root detection tem a maior taxa de falso positivo entre todas as técnicas de segurança mobile:

- Milhões de usuários legítimos fazem root (power users, desenvolvedores, custom ROMs)
- O Google Play Integrity API com hardware-backed attestation (May 2025) já bloqueia root — muitos apps de banking usam isso, causando frustração em usuários legítimos
- Xiaomi/OnePlus permitem unlock de bootloader oficialmente — rootear esses devices é um cenário esperado pelo fabricante

## Como faríamos se implementássemos

### Arquitetura

Um 5º detector (`RootDetector`) implementando a interface `TamperDetector`, seguindo o mesmo padrão dos outros. **Todos os sinais seriam soft** — root sozinho nunca deveria ser hard signal (bloquear usuário).

### Checks propostos

| # | Check | Como funciona | Weight (soft) | Evasão |
|---|-------|---------------|---------------|--------|
| 1 | **su binary** | `File.exists()` em paths conhecidos: `/system/bin/su`, `/system/xbin/su`, `/sbin/su`, `/data/local/bin/su` | 0.6 | Fácil — Magisk DenyList esconde o binário do app |
| 2 | **SELinux permissive** | Ler `/sys/fs/selinux/enforce`. Valor "0" = Permissive (suspeito). Devices de produção são sempre Enforcing. | 0.7 | Médio — Magisk moderno mantém Enforcing e usa custom policies |
| 3 | **Root management packages** | Query `PackageManager` para `com.topjohnwu.magisk`, `eu.chainfire.supersu`, `com.koushikdutta.superuser` | 0.4 | Fácil — Magisk randomiza o package name ao esconder |
| 4 | **Magisk artifacts** | `File.exists()` para `/data/adb/magisk/`, `/data/adb/modules/` | 0.5 | Fácil — DenyList + Shamiko escondem do mount namespace do app |
| 5 | **System partition writability** | Verificar se `/system` está montado como read-write via `/proc/mounts` | 0.6 | Médio — systemless root (Magisk) não modifica /system |
| 6 | **Test-keys build** | `Build.TAGS == "test-keys"` indica build não-oficial | 0.5 | N/A — é um fato estático do build |

### Por que todos soft?

Cada check individual é facilmente bypassável pelo Magisk (a ferramenta de root mais popular). Magisk DenyList + Zygisk + Shamiko conseguem:
- Esconder su binary do `File.exists()`
- Remover Magisk do package list
- Criar mount namespace separado para o app (escondendo `/data/adb/`)
- Manter SELinux em Enforcing

O valor estaria na **combinação** de sinais root com sinais dos outros detectors. Exemplo: `root detectado + Frida detectado` é muito mais suspeito que `root detectado` sozinho.

### Referências acadêmicas

- **"Android Rooting: An Arms Race between Evasion and Detection"** (Nguyen-Vu et al., Security and Communication Networks, 2017) — Open access: https://onlinelibrary.wiley.com/doi/10.1155/2017/4121765. Documenta o arms race entre root detection e evasion. Mostra que a maioria dos métodos de detecção pode ser evadida via API hooking ou renomeação de arquivos.

- **ARAP (arXiv 2408.11080)** — Categoriza Root Detection (RD) como uma das 5 categorias de anti-runtime analysis. 99.6% dos apps benignos implementam pelo menos uma técnica ARA.

- **OWASP MASTG-TEST-0045** — Testing Root Detection: https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0045/

- **OWASP MASTG-KNOW-0027** — Root Detection knowledge base: documenta técnicas de detecção e suas limitações.

### Relevância para Incognia especificamente

Para uma empresa de identidade por localização, root é relevante porque permite **GPS spoofing** — o principal vetor de ataque contra sistemas de location identity. Porém, detectar GPS spoofing é diferente de detectar root:

- Um device rootado com GPS genuíno não é ameaça
- Um device não-rootado usando "Mock Locations" do Developer Options também pode spoofar GPS
- O sinal mais valioso seria detectar **apps de GPS spoofing** (Fake GPS, Mock Locations) ou **inconsistências entre GPS e outras fontes de localização** (cell towers, WiFi positioning)

Isso está mais alinhado com o core business da Incognia do que root detection genérico.

## Status

Decisão consciente de não implementar na v1 do challenge. A arquitetura modular (`TamperDetector` interface + `DetectionEngine.Builder`) permite adicionar `RootDetector` como um 5º detector sem modificar nenhum código existente — exatamente o cenário que o Strategy pattern foi projetado para suportar.
