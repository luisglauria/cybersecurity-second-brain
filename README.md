# Cybersecurity Second Brain

Pipeline diário para coletar sinais de cibersegurança, filtrar o que tem aplicação prática, gerar um experimento defensivo e publicar um briefing HTML.

## Arquitetura

1. GitHub Actions inicia o workflow diariamente às 08:00 em `America/Sao_Paulo` ou manualmente por `workflow_dispatch`.
2. `scripts/generate_brief.py` coleta apenas as URLs em `config/sources.json`.
3. O modelo recebe os itens coletados e retorna um relatório JSON.
4. O script escapa o conteúdo, gera `site/index.html` e preserva o último resultado válido se houver falha.
5. GitHub Pages publica o diretório `site`.

## Configuração

1. Crie um repositório GitHub e envie estes arquivos para a branch padrão.
2. Crie uma chave gratuita no [Google AI Studio](https://aistudio.google.com/apikey), sem ativar Cloud Billing.
3. Em `Settings > Secrets and variables > Actions`, crie o secret `GEMINI_API_KEY` com essa chave.
4. Opcionalmente, crie a variável `GEMINI_MODEL`; o padrão é `gemini-3.1-flash-lite`.
5. Em `Settings > Pages`, escolha `GitHub Actions` como fonte de publicação.
6. Execute `Daily Cybersecurity Brief` manualmente uma vez para validar a configuração.

O workflow usa o Gemini Free Tier. Não ative Cloud Billing no projeto Google para impedir migração para a camada paga. O nível gratuito possui limites de taxa; quando a cota for excedida, o workflow preserva o último relatório válido.

## Segurança

- Nunca coloque a chave da API no código ou em arquivos commitados.
- As fontes externas são tratadas como dados não confiáveis e limitadas por allowlist.
- O relatório não deve conter credenciais, dados pessoais ou detalhes de ambientes reais.
- Experimentos são limitados a laboratórios autorizados, aplicações intencionalmente vulneráveis e dados sintéticos.
- Revise permissões e ações de terceiros antes de usar o workflow em produção.

## Notificações

O GitHub pode notificar falhas conforme as preferências de notificações da sua conta. Para notificações de sucesso por Telegram, Discord ou e-mail transacional, adicione um canal externo depois da primeira execução e guarde o webhook em GitHub Secrets.
