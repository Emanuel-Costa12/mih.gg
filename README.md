# MIH.GG — Gaming Hub

Site completo da Mih com backend real, autenticação JWT, painel admin e perfis de usuários.

## Como rodar localmente

```bash
# 1. Instale as dependências
npm install

# 2. Rode o servidor
npm start

# 3. Acesse no navegador
http://localhost:3000
```

## Login da Mih (Admin)
- **Usuário:** `Mih`
- **Senha:** `1234`

## Estrutura dos arquivos

```
mih-gg/
├── server.js              ← Backend Node.js (API + autenticação)
├── database.json          ← Banco de dados (usuários, config, posts)
├── package.json
└── public/
    ├── index.html         ← Site principal
    ├── login.html         ← Página de login
    ├── admin.html         ← Painel da Mih (admin only)
    ├── css/
    │   └── shared.css     ← Estilos compartilhados
    ├── js/
    │   └── shared.js      ← JS utilitário compartilhado
    └── avatars/           ← Fotos de perfil (criado automaticamente)
```

## Como hospedar no Railway

1. Crie uma conta em [railway.app](https://railway.app)
2. Crie um novo projeto → "Deploy from GitHub"
3. Suba os arquivos no GitHub e conecte
4. O Railway detecta o `package.json` automaticamente
5. Adicione a variável de ambiente:
   - `JWT_SECRET` = qualquer string longa e aleatória (ex: `minha-chave-secreta-super-segura-2026`)
6. O site vai rodar em um domínio `.railway.app`

## Como hospedar no Render

1. Crie conta em [render.com](https://render.com)
2. New → Web Service → conecte o GitHub
3. Build Command: `npm install`
4. Start Command: `node server.js`
5. Adicione `JWT_SECRET` nas variáveis de ambiente

## O que a Mih pode fazer no painel Admin (/admin)

- **Visão Geral** — dashboard com stats e status atual
- **Status & Live** — ligar/desligar online, ativar banner de live, mudar mensagem
- **Ranks & Agentes** — atualizar rank do Valorant, OW2, Minecraft e agentes favoritos
- **Posts** — criar e deletar posts (com opção de exclusivo para logados)
- **Agenda** — adicionar/remover eventos do mês
- **Usuários** — criar contas para viewers (com cor, efeito de nome, apelido)

## O que os Viewers podem fazer

- Ver ranks, stats e agentes da Mih em tempo real
- Fazer login com conta criada pela Mih
- Curtir e comentar posts
- Personalizar perfil: foto, bio, cor e efeito do nome
- Ver conteúdo exclusivo (só para logados)

## Segurança

- Senhas são criptografadas com bcrypt (salt rounds: 10)
- Autenticação por JWT com expiração de 7 dias
- Apenas admin pode criar contas, deletar usuários e alterar config
- Upload de avatar limitado a 2MB e apenas imagens
- **Troque o `JWT_SECRET` em produção!**
