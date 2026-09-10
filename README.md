# Cybersecurity Second Brain

Eu criei este projeto para transformar o acompanhamento diário de cibersegurança em aprendizado aplicado. O pipeline coleta sinais de fontes confiáveis, filtra o que tem utilidade prática, gera um experimento defensivo e publica um briefing HTML que posso acessar de qualquer dispositivo.

## Arquitetura

1. Eu uso o GitHub Actions para iniciar o workflow diariamente às 08:00 em `America/Sao_Paulo` ou manualmente por `workflow_dispatch`.
2. O arquivo `scripts/generate_brief.py` coleta apenas as URLs definidas em `config/sources.json`.
3. O OpenRouter recebe os itens coletados e retorna um relatório JSON estruturado usando exclusivamente o roteador gratuito `openrouter/free`.
4. O script escapa o conteúdo, gera `site/index.html` e preserva o último resultado válido se houver falha.
5. O GitHub Pages publica o diretório `site` como uma página web acessível remotamente.

## Configuração

1. Eu mantenho este projeto em um repositório público do GitHub.
2. Eu crio uma chave no [OpenRouter](https://openrouter.ai/settings/keys). Não adiciono créditos e não habilito modelos pagos.
3. Em `Settings > Secrets and variables > Actions`, eu cadastro a chave somente no secret `OPENROUTER_API_KEY`.
4. O workflow usa `openrouter/free` diretamente e não possui fallback para modelos pagos.
5. Em `Settings > Pages`, eu seleciono `GitHub Actions` como fonte de publicação.
6. Eu executo `Daily Cybersecurity Brief` manualmente uma vez para validar a configuração.

## Controle de custo e volume

Eu mantive o projeto deliberadamente pequeno: uma execução automática por dia, uma única requisição ao OpenRouter por execução, sem retry automático e sem fallback pago. O workflow usa `openrouter/free`, impede execuções concorrentes e preserva o último relatório válido quando a cota ou o provedor falhar. Não existe cartão, crédito ou modelo pago configurado no código.

## Segurança

- Eu nunca coloco a chave da API no código ou em arquivos commitados.
- As fontes externas são tratadas como dados não confiáveis e limitadas por allowlist.
- O relatório não deve conter credenciais, dados pessoais ou detalhes de ambientes reais.
- Experimentos são limitados a laboratórios autorizados, aplicações intencionalmente vulneráveis e dados sintéticos.
- Eu reviso permissões e ações de terceiros antes de usar o workflow em produção.

## Notificações

Eu acompanho falhas pelas notificações do GitHub, conforme as preferências da minha conta. O resultado publicado fica disponível em [GitHub Pages](https://luisglauria.github.io/cybersecurity-second-brain/). Para receber notificações de sucesso por Telegram, Discord ou e-mail transacional, posso adicionar um canal externo depois da primeira execução e guardar o webhook em GitHub Secrets.
