# 🛡️ Manual do Administrador Parceiro - Sistema de Gestão de Leads

## Bem-vindo ao Painel Administrativo!

Este manual foi criado para **Administradores Parceiros** que gerenciam equipes de consultores no sistema de gestão de leads.

---

## 📑 Índice

1. [Visão Geral](#1-visão-geral)
2. [Acesso e Navegação](#2-acesso-e-navegação)
3. [Dashboard do Parceiro](#3-dashboard-do-parceiro)
4. [Gestão de Usuários](#4-gestão-de-usuários)
5. [Monitor de Equipe](#5-monitor-de-equipe)
6. [Dashboard de Performance](#6-dashboard-de-performance)
7. [Exportação de Relatórios](#7-exportação-de-relatórios)
8. [Atividades em Tempo Real](#8-atividades-em-tempo-real)
9. [Limites e Quotas](#9-limites-e-quotas)
10. [Boas Práticas de Gestão](#10-boas-práticas-de-gestão)
11. [Perguntas Frequentes](#11-perguntas-frequentes)

---

## 1. Visão Geral

### 1.1 O Papel do Admin Parceiro

Como **Administrador Parceiro**, você é responsável por:
- ✅ Gerenciar sua equipe de consultores
- ✅ Monitorar performance e atividades
- ✅ Configurar limites individuais de usuários
- ✅ Acompanhar consumo de leads
- ✅ Extrair relatórios gerenciais
- ✅ Garantir produtividade da equipe

### 1.2 Diferenças de Acesso

**Você TEM acesso a:**
- Dashboard do parceiro
- Gestão de usuários da sua equipe
- Monitor de atividades da equipe
- Dashboard de performance
- Relatórios de exportação
- Visualização de atividades em tempo real

**Você NÃO TEM acesso a:**
- Configurações globais do sistema
- Gestão de produtos e layouts
- Gestão de tabulações
- Upload de mailings
- Usuários de outras equipes
- Configurações de Super Admin

---

## 2. Acesso e Navegação

### 2.1 Login
1. Acesse a URL do sistema
2. Use suas credenciais de **Admin Parceiro**
3. Após login, você será direcionado ao Dashboard do Parceiro

### 2.2 Menu de Navegação

O menu principal oferece:
- **Dashboard**: Visão geral da equipe
- **Gerenciar Usuários**: Criar e editar consultores
- **Monitor**: Acompanhamento em tempo real
- **Performance**: Métricas e estatísticas
- **Atividades**: Feed de atividades da equipe
- **Configurações**: Seu perfil e preferências

---

## 3. Dashboard do Parceiro

### 3.1 Visão Geral

O dashboard principal mostra:

#### **Informações da Equipe**
- **Nome do Grupo**: Nome da sua equipe/parceria
- **Logotipo**: Logo personalizado (se configurado)
- **Limite Mensal**: Quota mensal de leads para a equipe
- **Consumo Mensal**: Quantidade já consumida no mês

#### **Estatísticas do Mês Atual**
- Total de leads puxados
- Progresso em relação ao limite mensal
- Barra visual de consumo

#### **Atividades Recentes**
- Últimas 15 atividades da equipe
- Quem puxou, tabulou ou atendeu leads
- Timestamps em horário de Brasília

### 3.2 Interpretando o Dashboard

**Barra de Progresso:**
- 🟢 Verde (0-70%): Consumo normal
- 🟡 Amarelo (70-90%): Atenção ao limite
- 🔴 Vermelho (90-100%): Próximo ao limite

**Atividades Recentes:**
- 📥 Puxada de lead
- 📝 Tabulação
- 👁️ Visualização
- ♻️ Retabulação

---

## 4. Gestão de Usuários

### 4.1 Visualizar Usuários

Em **"Gerenciar Usuários"** você vê:
- Lista completa de consultores da sua equipe
- Username, e-mail, status
- Limites configurados
- Ações disponíveis

### 4.2 Criar Novo Usuário

1. Clique em **"Adicionar Novo Usuário"**
2. Preencha o formulário:
   - **Username**: Nome de usuário único
   - **E-mail**: E-mail válido e único
   - **Senha**: Senha inicial (usuário pode alterar)
   - **Tipo**: Selecione "Consultor"
   - **Equipe**: Sua equipe (pré-selecionada)
   - **Limite da Carteira**: Quantidade máxima de leads simultâneos
   - **Limite Diário de Puxada**: Quantidade máxima de leads por dia

3. Clique em **"Salvar"**

### 4.3 Editar Usuário

1. Localize o usuário na lista
2. Clique em **"Editar"**
3. Modifique os campos desejados:
   - E-mail
   - Limite da carteira
   - Limite diário de puxada
   - Senha (opcional)

4. Clique em **"Salvar Alterações"**

### 4.4 Configurar Limites

#### **Limite da Carteira**
- Define quantos leads o consultor pode ter simultaneamente em atendimento
- Recomendado: 30-100 leads (depende do perfil do produto)
- Leads tabulados liberam espaço automaticamente

#### **Limite Diário de Puxada**
- Define quantos leads o consultor pode puxar por dia
- Reseta à meia-noite
- Recomendado: 50-200 leads/dia (ajuste conforme produtividade)

### 4.5 Excluir Usuário

⚠️ **ATENÇÃO:** Excluir um usuário é **irreversível**!

1. Localize o usuário
2. Clique em **"Excluir"**
3. Confirme a exclusão
4. Todos os leads do usuário precisarão ser reatribuídos manualmente

**Recomendação:** Em vez de excluir, considere:
- Reduzir limites a zero
- Alterar senha
- Solicitar ao Super Admin a desativação

### 4.6 Resetar Senha

1. Clique em **"Editar"** no usuário
2. Digite nova senha temporária
3. Salve
4. Informe o usuário da nova senha
5. Oriente o usuário a alterá-la no primeiro login

---

## 5. Monitor de Equipe

### 5.1 Funcionalidade

O **Monitor** mostra em tempo real:
- Status de cada consultor
- Leads em atendimento
- Tempo no status atual
- Última atividade

### 5.2 Status dos Consultores

- 🟢 **Ocioso**: Logado e disponível
- 🔵 **Em Atendimento**: Atendendo leads atualmente
- ⚫ **Offline**: Não logado no sistema

### 5.3 Usando o Monitor

1. Acesse **"Monitor"** no menu
2. A tela atualiza automaticamente a cada 30 segundos
3. Visualize:
   - Nome do consultor
   - Status atual
   - Quantidade de leads em carteira
   - **Leads puxados hoje**: Quantidade de leads que o consultor já pegou no dia
   - Tempo no status

### 5.4 Dicas de Uso

✅ Use para identificar consultores ociosos  
✅ Verifique distribuição de trabalho  
✅ Identifique gargalos de produtividade  
✅ Monitore em tempo de pico

---

## 6. Dashboard de Performance

### 6.1 Acesso

Menu **"Performance"** ou **"Dashboard de Performance"**

### 6.2 Métricas Disponíveis

#### **Filtros de Período**
- Selecione data inicial e final
- Filtre por consultor específico
- Filtre por produto
- Filtre por tipo de tabulação

#### **Métricas Principais**

**Por Consultor:**
- Total de leads puxados
- Total de tabulações realizadas
- Taxa de conversão
- Tabulações por tipo
- Média de atendimentos por dia

**Por Produto:**
- Leads distribuídos por produto
- Performance por tipo de oferta
- Taxa de sucesso por produto

**Por Tabulação:**
- Distribuição de tabulações
- Tabulações positivas vs negativas
- Leads recicláveis
- Taxa de aproveitamento

### 6.3 Gráficos Visuais

O dashboard inclui:
- 📊 Gráficos de barras (leads por usuário)
- 🥧 Gráficos de pizza (distribuição de tabulações)
- 📈 Gráficos de linha (evolução temporal)
- 🎨 Código de cores por tabulação

### 6.4 Interpretando os Dados

**Alta Performance:**
- Taxa de conversão acima da média da equipe
- Alto volume de tabulações diárias
- Baixa taxa de "Não Atende"

**Performance a Melhorar:**
- Muitas tabulações negativas
- Baixo volume de atendimentos
- Alta taxa de leads retornados

---

## 7. Exportação de Relatórios

### 7.1 Tipos de Exportação

Você pode exportar:
- ✅ Leads puxados pela equipe
- ✅ Tabulações realizadas
- ✅ Histórico de atividades
- ✅ Performance por período

### 7.2 Como Exportar

1. Acesse **"Dashboard de Performance"**
2. Configure os **filtros** desejados:
   - Período (data inicial e final)
   - Consultor específico (opcional)
   - Produto (opcional)
   - Tipo de tabulação (opcional)

3. Clique em **"Exportar"** ou **"Baixar CSV"**
4. O arquivo será baixado em formato CSV

### 7.3 Formato do Arquivo

**CSV (Separado por ponto-e-vírgula)**
- Compatível com Excel
- Codificação UTF-8 com BOM
- Todos os campos entre aspas
- Fácil importação em ferramentas de BI

### 7.4 Campos Exportados

Dependendo do tipo de relatório:
- Dados do lead (nome, CPF, telefones, endereço)
- Dados do consultor (quem atendeu/tabulou)
- Produto e mailing
- Tipo de tabulação
- Timestamps
- Notas e observações

---

## 8. Atividades em Tempo Real

### 8.1 Feed de Atividades

**Dashboard Principal:**
- Últimas 15 atividades da equipe

**Modo Fullscreen:**
- Todas as atividades da equipe
- Ideal para monitores/TVs
- Atualização automática

### 8.2 Acessar Modo Fullscreen

1. No dashboard, clique em **"Ver Todas as Atividades"**
2. Ou acesse **"Atividades Fullscreen"** no menu
3. A tela mostra feed completo e atualiza automaticamente

### 8.3 Informações Exibidas

Cada atividade mostra:
- ⏰ Data e hora (horário de Brasília)
- 👤 Nome do consultor
- 📋 Tipo de ação (puxada, tabulação, visualização)
- 📝 Detalhes do lead
- 🏷️ Tabulação aplicada (se houver)

### 8.4 Tipos de Atividade

- **LEAD_PULLED**: Consultor puxou um lead
- **LEAD_TABULATED**: Consultor tabulou um lead
- **LEAD_RETABULATED**: Consultor retabulou um lead
- **LEAD_VIEWED**: Consultor visualizou detalhes de um lead

---

## 9. Limites e Quotas

### 9.1 Limite Mensal da Equipe

**O que é:**
- Quantidade total de leads que sua equipe pode consumir por mês
- Configurado pelo Super Admin
- Compartilhado entre todos os consultores

**Como acompanhar:**
- Dashboard principal mostra progresso
- Barra visual indica porcentagem consumida
- Notificações quando próximo ao limite

**O que acontece ao atingir:**
- Consultores não conseguem mais puxar leads
- Apenas resetado no início do próximo mês
- Entre em contato com Super Admin para ajustes

### 9.2 Limites Individuais

**Cada consultor tem:**
- **Limite de Carteira**: Leads simultâneos máximos
- **Limite Diário**: Leads que pode puxar por dia

**Gerenciamento:**
- Você pode ajustar esses limites
- Considere performance individual
- Balance carga de trabalho

### 9.3 Estratégias de Quota

**Para Maximizar Produtividade:**

1. **Distribua estrategicamente**
   - Consultores experientes: limites maiores
   - Consultores novos: limites menores
   - Ajuste conforme performance

2. **Monitore consumo**
   - Acompanhe diariamente o uso
   - Projete se atingirá o limite mensal
   - Redistribua se necessário

3. **Planeje com antecedência**
   - Saiba quantos dias faltam no mês
   - Calcule média diária disponível
   - Ajuste estratégia da equipe

---

## 10. Boas Práticas de Gestão

### 10.1 Gestão de Equipe

#### **Onboarding de Novos Consultores**
1. Crie o usuário com limites conservadores
2. Forneça treinamento adequado
3. Monitore primeiros dias de perto
4. Aumente limites gradualmente

#### **Acompanhamento Diário**
- [ ] Verificar status de todos consultores
- [ ] Revisar atividades do dia
- [ ] Identificar baixa produtividade
- [ ] Oferecer suporte quando necessário

#### **Revisão Semanal**
- [ ] Analisar métricas de performance
- [ ] Comparar produtividade entre consultores
- [ ] Ajustar limites se necessário
- [ ] Reunião de feedback com equipe

#### **Análise Mensal**
- [ ] Exportar relatório completo do mês
- [ ] Calcular taxa de conversão média
- [ ] Identificar melhores e piores performers
- [ ] Planejar metas para próximo mês

### 10.2 Otimização de Performance

#### **Identifique Padrões**
- Quais tabulações são mais frequentes?
- Quais produtos têm melhor conversão?
- Quais horários são mais produtivos?
- Quais consultores precisam de coaching?

#### **Ajuste Estratégias**
- Direcione melhores produtos aos melhores consultores
- Treine equipe nas tabulações mais comuns
- Incentive uso de notas e WhatsApp
- Crie metas e gamificação

#### **Comunique-se**
- Feedback regular individual
- Reuniões de equipe semanais
- Compartilhe boas práticas
- Reconheça bons resultados

### 10.3 Resolução de Problemas

**Consultor não consegue puxar leads:**
- ✅ Verifique limite da carteira
- ✅ Verifique limite diário
- ✅ Verifique limite mensal da equipe
- ✅ Verifique se há leads disponíveis no produto

**Performance baixa:**
- ✅ Analise tipos de tabulação
- ✅ Verifique tempo médio de atendimento
- ✅ Converse individualmente
- ✅ Ofereça treinamento adicional

**Equipe atingindo limite mensal cedo:**
- ✅ Revise distribuição de leads
- ✅ Analise desperdício (tabulações negativas)
- ✅ Solicite aumento de quota ao Super Admin
- ✅ Otimize processo de atendimento

---

## 11. Perguntas Frequentes

### ❓ Posso alterar meu próprio limite?
**R:** Não. Limites de Admin Parceiro são definidos pelo Super Admin.

### ❓ Posso criar outro Admin Parceiro?
**R:** Não. Apenas Super Admins podem criar outros administradores.

### ❓ Como sei quantos leads restam no mês?
**R:** No dashboard principal, veja "Consumo Mensal" e calcule a diferença com o "Limite Mensal".

### ❓ Posso ver leads de outras equipes?
**R:** Não. Você só tem acesso a dados da sua própria equipe.

### ❓ Como faço backup dos dados?
**R:** Exporte relatórios regularmente. O Super Admin gerencia backups do sistema.

### ❓ Posso deletar leads?
**R:** Não. Apenas Super Admins podem fazer higienização de base.

### ❓ Como solicito mais quota mensal?
**R:** Entre em contato com o Super Admin com justificativa e projeções.

### ❓ Consultores podem ver dados uns dos outros?
**R:** Não. Consultores veem apenas seus próprios dados.

### ❓ Como resetar senha de um consultor?
**R:** Edite o usuário e defina nova senha temporária.

### ❓ Posso transferir leads entre consultores?
**R:** Não diretamente. Leads tabulados como recicláveis voltam ao pool geral.

---

## 📊 Checklist do Admin Parceiro

### Diário
- [ ] Verificar consumo mensal da equipe
- [ ] Revisar atividades do dia
- [ ] Monitorar status dos consultores
- [ ] Responder dúvidas da equipe

### Semanal
- [ ] Analisar dashboard de performance
- [ ] Comparar produtividade entre consultores
- [ ] Ajustar limites se necessário
- [ ] Reunião de alinhamento com equipe
- [ ] Exportar relatório semanal

### Mensal
- [ ] Revisar quota mensal consumida
- [ ] Exportar relatório completo do mês
- [ ] Análise detalhada de conversão
- [ ] Avaliação individual de consultores
- [ ] Planejar metas do próximo mês
- [ ] Solicitar ajustes de quota se necessário

---

## 🎯 Métricas-Chave para Acompanhar

### Performance Individual
- **Taxa de Conversão**: (Tabulações positivas / Total de tabulações) × 100
- **Produtividade Diária**: Média de leads atendidos por dia
- **Taxa de Contato**: (Leads contatados / Leads puxados) × 100
- **Tempo Médio de Atendimento**: Tempo entre puxada e tabulação

### Performance da Equipe
- **Consumo Mensal**: % do limite mensal usado
- **Leads Ativos**: Total de leads em atendimento na equipe
- **Taxa de Reciclagem**: % de leads que retornam ao pool
- **Aproveitamento**: % de leads que geram conversão

---

## 📞 Suporte e Escalação

### Para Questões Técnicas
- Problemas no sistema: Contate Super Admin
- Bugs ou erros: Reporte ao suporte técnico
- Solicitações de features: Envie ao Super Admin

### Para Questões Administrativas
- Aumento de quota: Super Admin
- Criação de novos produtos: Super Admin
- Configurações globais: Super Admin
- Permissões especiais: Super Admin

---

## 🔐 Segurança e Privacidade

### Responsabilidades
- ✅ Proteja credenciais dos consultores
- ✅ Não compartilhe relatórios externamente
- ✅ Siga LGPD ao manusear dados pessoais
- ✅ Oriente equipe sobre uso ético dos dados

### Controle de Acesso
- Configure IPs permitidos (se disponível)
- Revise usuários ativos periodicamente
- Desative acessos de ex-colaboradores imediatamente
- Use senhas fortes

---

## 📚 Recursos Adicionais

### Documentação Relacionada
- Manual do Usuário (para consultores)
- Manual do Super Admin (solicite acesso)
- Guia de Tabulações (solicite ao Super Admin)

### Treinamento
- Solicite sessões de treinamento ao Super Admin
- Compartilhe este manual com novos consultores
- Crie materiais de referência rápida para sua equipe

---

**Versão do Manual:** 1.0  
**Última Atualização:** Janeiro 2026  

*Este manual está sujeito a atualizações conforme melhorias no sistema.*

---

## 💡 Dicas Finais

**Para ser um excelente Admin Parceiro:**

1. **Esteja presente** - Acompanhe sua equipe diariamente
2. **Seja data-driven** - Use os relatórios para tomar decisões
3. **Comunique-se** - Mantenha canal aberto com consultores
4. **Seja proativo** - Identifique problemas antes que escalem
5. **Capacite** - Invista em treinamento contínuo
6. **Reconheça** - Valorize bons resultados
7. **Otimize** - Sempre busque melhorar processos
8. **Colabore** - Trabalhe junto com o Super Admin

**Sucesso na gestão da sua equipe! 🚀**
